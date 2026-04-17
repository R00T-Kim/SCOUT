#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from aiedge.pair_eval import (
    aggregate_tier_metrics,
    build_threshold_rows,
    choose_primary_finding,
    determine_ground_truth,
    extract_target_cve_hits,
    load_pairs_manifest,
    write_csv,
)


def _load_json(path: Path) -> Any | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return None


def _run_record(index: dict[str, Any], pair_id: str, side: str) -> dict[str, Any] | None:
    for row in index.get('rows', []):
        if row.get('pair_id') == pair_id and row.get('side') == side:
            return row
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description='Score pair-eval runs into summary/ROC outputs.')
    parser.add_argument('--pairs', default='benchmarks/pair-eval/pairs.json')
    parser.add_argument('--results-dir', default='benchmark-results/pair-eval')
    args = parser.parse_args()

    results_dir = Path(args.results_dir).resolve()
    run_index = json.loads((results_dir / 'run_index.json').read_text(encoding='utf-8'))
    pairs = load_pairs_manifest(Path(args.pairs).resolve())

    pair_rows: list[dict[str, Any]] = []
    finding_rows: list[dict[str, Any]] = []

    for pair in pairs:
        for side_name in ('vulnerable', 'patched'):
            row = _run_record(run_index, pair.pair_id, side_name)
            if row is None:
                continue
            run_dir = Path(row.get('run_dir') or '') if row.get('run_dir') else None
            findings_payload = _load_json(run_dir / 'stages' / 'findings' / 'findings.json') if run_dir else None
            cve_payload = _load_json(run_dir / 'stages' / 'cve_scan' / 'cve_matches.json') if run_dir else None
            primary = choose_primary_finding(findings_payload)
            cve_hits = extract_target_cve_hits(cve_payload, pair.cve_id)
            extraction_status = row.get('extraction_status') or 'missing'
            inventory_status = row.get('inventory_quality_status') or 'missing'
            if row.get('status') == 'success':
                extraction_status = extraction_status if extraction_status != 'missing' else 'ok'
                inventory_status = inventory_status if inventory_status != 'missing' else 'sufficient'
            elif row.get('status') == 'partial':
                extraction_status = extraction_status if extraction_status != 'missing' else 'partial'
                inventory_status = inventory_status if inventory_status != 'missing' else 'insufficient'
            elif row.get('status') in {'fatal', 'error', 'missing'}:
                extraction_status = 'missing'
                inventory_status = 'missing'

            gt = determine_ground_truth(side_name, status=row.get('status') or '', extraction_status=extraction_status, target_hit=bool(cve_hits))
            finding_rows.append({
                'pair_id': pair.pair_id,
                'vendor': pair.vendor,
                'model': pair.model,
                'side': side_name,
                'cve_id': pair.cve_id,
                'run_dir': row.get('run_dir') or '',
                'run_status': row.get('status') or '',
                'extraction_status': extraction_status,
                'inventory_quality_status': inventory_status,
                'finding_id': (primary or {}).get('id', ''),
                'category': (primary or {}).get('category', ''),
                'evidence_tier': (primary or {}).get('evidence_tier', ''),
                'confidence': (primary or {}).get('confidence', 0.0),
                'priority_score': (primary or {}).get('priority_score', 0.0),
                'matched_cve_id': pair.cve_id if cve_hits else '',
                'target_cve_hits': len(cve_hits),
                'ground_truth': gt,
            })

        vuln = next(r for r in finding_rows if r['pair_id']==pair.pair_id and r['side']=='vulnerable')
        patched = next(r for r in finding_rows if r['pair_id']==pair.pair_id and r['side']=='patched')
        pair_rows.append({
            'pair_id': pair.pair_id,
            'vendor': pair.vendor,
            'model': pair.model,
            'cve_id': pair.cve_id,
            'vulnerable_status': vuln['run_status'],
            'patched_status': patched['run_status'],
            'vulnerable_ground_truth': vuln['ground_truth'],
            'patched_ground_truth': patched['ground_truth'],
            'recall_hit': 1 if vuln['ground_truth']=='tp' else (0 if vuln['ground_truth']=='fn' else ''),
            'fp_hit': 1 if patched['ground_truth']=='fp' else (0 if patched['ground_truth']=='tn' else ''),
        })

    tier_metrics = aggregate_tier_metrics(finding_rows)
    thresholds = build_threshold_rows(finding_rows)

    resolved_vuln = [r for r in finding_rows if r['side']=='vulnerable' and r['ground_truth'] in {'tp','fn'}]
    resolved_patch = [r for r in finding_rows if r['side']=='patched' and r['ground_truth'] in {'fp','tn'}]
    tp = sum(r['ground_truth']=='tp' for r in resolved_vuln)
    fn = sum(r['ground_truth']=='fn' for r in resolved_vuln)
    fp = sum(r['ground_truth']=='fp' for r in resolved_patch)
    tn = sum(r['ground_truth']=='tn' for r in resolved_patch)
    recall = tp / (tp + fn) if (tp + fn) else None
    fpr = fp / (fp + tn) if (fp + tn) else None

    summary = {
        'pair_corpus_size': len(pairs),
        'resolved_vulnerable_runs': len(resolved_vuln),
        'resolved_patched_runs': len(resolved_patch),
        'tp': tp,
        'fn': fn,
        'fp': fp,
        'tn': tn,
        'recall': recall,
        'false_positive_rate': fpr,
        'tier_metrics': tier_metrics,
        'threshold_rows': thresholds,
    }

    write_csv(results_dir / 'pair_eval_summary.csv', pair_rows)
    write_csv(results_dir / 'pair_eval_findings.csv', finding_rows)
    (results_dir / 'pair_eval_summary.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    report_lines = [
        '# Pair Eval Report',
        '',
        '> This M0 run reuses extraction-success fresh baseline runs from 2C.6 rather than launching a second Codex-full rerun wave.',
        '',
        f'- pair_corpus_size: **{len(pairs)}**',
        f'- resolved vulnerable runs: **{len(resolved_vuln)}**',
        f'- resolved patched runs: **{len(resolved_patch)}**',
        f'- recall: **{recall if recall is not None else "TBD"}**',
        f'- false_positive_rate: **{fpr if fpr is not None else "TBD"}**',
        '',
        '## Tier metrics',
        '',
        '| tier | tp | fp | fn | tn | excluded |',
        '|---|---:|---:|---:|---:|---:|',
    ]
    for tier, metrics in tier_metrics.items():
        report_lines.append(f"| {tier} | {metrics.get('tp',0)} | {metrics.get('fp',0)} | {metrics.get('fn',0)} | {metrics.get('tn',0)} | {metrics.get('excluded',0)} |")
    report_lines.extend(['', '## Pair outcomes', '', '| pair_id | vuln | patched | recall_hit | fp_hit |', '|---|---|---|---:|---:|'])
    for row in pair_rows:
        report_lines.append(f"| {row['pair_id']} | {row['vulnerable_ground_truth']} | {row['patched_ground_truth']} | {row['recall_hit']} | {row['fp_hit']} |")
    (results_dir / 'pair_eval_report.md').write_text('\n'.join(report_lines) + '\n', encoding='utf-8')

    print(json.dumps({'pairs': len(pairs), 'recall': recall, 'fpr': fpr}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
