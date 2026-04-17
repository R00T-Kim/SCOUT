#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

STATUS_PRIORITY = {
    "success": 5,
    "partial": 4,
    "fatal": 3,
    "error": 2,
    "": 1,
    None: 1,
}

FIRMWARE_ALIASES = {
    ("netgear", "WNDR3700v4-V1.0.2.80"): ("netgear", "WNDR3700v4-V1.0.2.80.zip"),
}

# Out-of-corpus bookkeeping anomaly observed in restart chains.
EXCLUDED_ROWS = {
    ("dlink", "DIR503AA1_FW1.09.00kr_20150717"),
}


def load_rows(path: Path, source_name: str) -> list[dict[str, str]]:
    with path.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        row["_source"] = source_name
    return rows


def normalize_key(row: dict[str, str]) -> tuple[str, str]:
    vendor = row.get("vendor") or ""
    firmware = row.get("firmware") or ""
    return FIRMWARE_ALIASES.get((vendor, firmware), (vendor, firmware))


def pick_best_rows(summary_paths: list[Path]) -> tuple[list[dict[str, str]], dict[str, Any]]:
    source_priority = {path.parent.name: idx for idx, path in enumerate(summary_paths, start=1)}
    best: dict[tuple[str, str], tuple[tuple[int, int], dict[str, str]]] = {}
    anomaly_counts = Counter()

    for path in summary_paths:
        source_name = path.parent.name
        for row in load_rows(path, source_name):
            key = normalize_key(row)
            if key in EXCLUDED_ROWS:
                anomaly_counts["excluded_out_of_corpus"] += 1
                continue
            if key != (row.get("vendor") or "", row.get("firmware") or ""):
                anomaly_counts["normalized_alias"] += 1
                row["firmware"] = key[1]
                row["vendor"] = key[0]
            rank = (STATUS_PRIORITY.get(row.get("status"), 0), source_priority[source_name])
            if key not in best or rank > best[key][0]:
                best[key] = (rank, row)

    picked = [value[1] for value in best.values()]
    picked.sort(key=lambda r: (r.get("vendor") or "", r.get("firmware") or ""))
    meta = {
        "sources": [str(path) for path in summary_paths],
        "anomalies": dict(anomaly_counts),
    }
    return picked, meta


def build_summary(rows: list[dict[str, str]], *, corpus_target: int, meta: dict[str, Any]) -> dict[str, Any]:
    status = Counter((row.get("status") or "missing") for row in rows)
    extraction = Counter((row.get("extraction_status") or "missing") for row in rows)
    inventory = Counter((row.get("inventory_quality_status") or "missing") for row in rows)
    llm = Counter((row.get("llm_triage_status") or "missing") for row in rows)
    analyst = Counter((row.get("analyst_readiness") or "missing") for row in rows)
    vendor_status: dict[str, Counter[str]] = defaultdict(Counter)
    holdouts: list[dict[str, Any]] = []

    for row in rows:
        vendor_status[row.get("vendor") or "missing"][row.get("status") or "missing"] += 1
        if row.get("status") != "success":
            holdouts.append(
                {
                    "vendor": row.get("vendor") or "",
                    "firmware": row.get("firmware") or "",
                    "status": row.get("status") or "missing",
                    "extraction_status": row.get("extraction_status") or "missing",
                    "inventory_quality_status": row.get("inventory_quality_status") or "missing",
                    "analyst_reasons": row.get("analyst_reasons") or "",
                    "source": row.get("_source") or "",
                }
            )

    successful = [row for row in rows if row.get("status") == "success"]
    nonzero_cve = sum(int(row.get("cve_count") or 0) > 0 for row in successful)
    nonzero_findings = sum(int(row.get("findings_count") or 0) > 0 for row in successful)
    actionable = sum(int(row.get("actionable_candidate_count") or 0) > 0 for row in successful)
    digest_pass = sum((row.get("digest_verifier_ok") or "") == "1" for row in successful)
    report_pass = sum((row.get("report_verifier_ok") or "") == "1" for row in successful)

    return {
        "corpus_target": corpus_target,
        "resolved_rows": len(rows),
        "status": dict(status),
        "extraction_status": dict(extraction),
        "inventory_quality_status": dict(inventory),
        "llm_triage_status": dict(llm),
        "analyst_readiness": dict(analyst),
        "successful": {
            "count": len(successful),
            "nonzero_cve": nonzero_cve,
            "nonzero_findings": nonzero_findings,
            "actionable_candidate_nonzero": actionable,
            "digest_verifier_pass": digest_pass,
            "report_verifier_pass": report_pass,
        },
        "vendor_status": {vendor: dict(counter) for vendor, counter in sorted(vendor_status.items())},
        "holdouts": holdouts,
        "meta": meta,
    }


def write_csv(rows: list[dict[str, str]], out_path: Path) -> None:
    fieldnames = list(rows[0].keys())
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(summary: dict[str, Any], out_path: Path) -> None:
    lines = [
        "# Carry-over Benchmark v2.6 — Fresh Corpus Refresh",
        "",
        f"- corpus_target: **{summary['corpus_target']}**",
        f"- resolved_rows: **{summary['resolved_rows']}**",
        f"- success / partial / fatal: **{summary['status'].get('success', 0)} / {summary['status'].get('partial', 0)} / {summary['status'].get('fatal', 0)}**",
        "",
        "> This is a baseline refresh, not a proof-of-value report. Pair-labeled recall/FP and tier ROC remain follow-on evaluation lanes.",
        "",
        "## Success quality",
        "",
        f"- nonzero findings: **{summary['successful']['nonzero_findings']} / {summary['successful']['count']}**",
        f"- nonzero CVE: **{summary['successful']['nonzero_cve']} / {summary['successful']['count']}**",
        f"- actionable candidates > 0: **{summary['successful']['actionable_candidate_nonzero']} / {summary['successful']['count']}**",
        f"- digest verifier pass: **{summary['successful']['digest_verifier_pass']} / {summary['successful']['count']}**",
        f"- report verifier pass: **{summary['successful']['report_verifier_pass']} / {summary['successful']['count']}**",
        "",
        "## Extraction / inventory breakdown",
        "",
        "| metric | count |",
        "|---|---:|",
    ]
    for key, value in summary["extraction_status"].items():
        lines.append(f"| extraction:{key} | {value} |")
    for key, value in summary["inventory_quality_status"].items():
        lines.append(f"| inventory:{key} | {value} |")

    lines.extend([
        "",
        "## Vendor breakdown",
        "",
        "| vendor | success | partial | fatal | error |",
        "|---|---:|---:|---:|---:|",
    ])
    for vendor, counts in summary["vendor_status"].items():
        lines.append(
            f"| {vendor} | {counts.get('success', 0)} | {counts.get('partial', 0)} | {counts.get('fatal', 0)} | {counts.get('error', 0)} |"
        )

    lines.extend([
        "",
        "## Holdouts",
        "",
        "| vendor | firmware | status | extraction | inventory | analyst_reasons |",
        "|---|---|---|---|---|---|",
    ])
    for item in summary["holdouts"]:
        lines.append(
            f"| {item['vendor']} | {item['firmware']} | {item['status']} | {item['extraction_status']} | {item['inventory_quality_status']} | {item['analyst_reasons'] or '-'} |"
        )

    if summary["meta"]["anomalies"]:
        lines.extend([
            "",
            "## Bookkeeping anomalies",
            "",
        ])
        for key, value in summary["meta"]["anomalies"].items():
            lines.append(f"- {key}: {value}")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate 2C.6 benchmark waves into one best-view corpus summary.")
    parser.add_argument("--summary", nargs="+", required=True, help="benchmark_summary.csv paths")
    parser.add_argument("--corpus-target", type=int, default=1123)
    parser.add_argument("--csv-out", required=True)
    parser.add_argument("--json-out", required=True)
    parser.add_argument("--md-out", required=True)
    args = parser.parse_args()

    summary_paths = [Path(item).resolve() for item in args.summary]
    rows, meta = pick_best_rows(summary_paths)
    summary = build_summary(rows, corpus_target=args.corpus_target, meta=meta)

    csv_out = Path(args.csv_out)
    json_out = Path(args.json_out)
    md_out = Path(args.md_out)
    csv_out.parent.mkdir(parents=True, exist_ok=True)
    write_csv(rows, csv_out)
    json_out.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(summary, md_out)

    print(json.dumps({
        "resolved_rows": summary["resolved_rows"],
        "status": summary["status"],
        "anomalies": summary["meta"]["anomalies"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
