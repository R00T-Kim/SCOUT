#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from aiedge.pair_eval import PairSpec, load_pairs_manifest


def _run_one(pair: PairSpec, side: str, firmware_path: str, results_root: Path, time_budget_s: int, driver: str) -> dict[str, Any]:
    side_root = results_root / "runs" / pair.pair_id / side
    side_root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["AIEDGE_LLM_DRIVER"] = driver
    cmd = [
        "./scout",
        "analyze",
        firmware_path,
        "--ack-authorization",
        "--profile",
        "analysis",
        "--time-budget-s",
        str(time_budget_s),
    ]
    start = time.time()
    proc = subprocess.run(cmd, cwd=Path.cwd(), env=env, text=True, capture_output=True)
    duration_s = round(time.time() - start, 3)
    stdout_lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    run_dir = stdout_lines[-1] if stdout_lines else ""
    result = {
        "pair_id": pair.pair_id,
        "vendor": pair.vendor,
        "model": pair.model,
        "cve_id": pair.cve_id,
        "side": side,
        "firmware_path": firmware_path,
        "returncode": proc.returncode,
        "duration_s": duration_s,
        "run_dir": run_dir,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "status": "success" if proc.returncode == 0 else ("partial" if proc.returncode == 10 else "fatal"),
    }
    if run_dir:
        link = side_root / "latest"
        if link.exists() or link.is_symlink():
            link.unlink()
        try:
            link.symlink_to(Path(run_dir).resolve())
        except Exception:
            pass
    (side_root / "last_run.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def _status_rank(status: str) -> int:
    return {"success": 4, "partial": 3, "fatal": 2, "error": 1}.get(status or "", 0)


def _build_rows_from_summaries(pairs: list[PairSpec], summary_paths: list[Path], results_root: Path) -> list[dict[str, Any]]:
    candidates: dict[tuple[str, str], tuple[tuple[int, int], dict[str, Any]]] = {}
    for idx, summary_path in enumerate(summary_paths, start=1):
        with summary_path.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        for row in rows:
            key = (row.get("vendor") or "", row.get("firmware") or "")
            rank = (_status_rank(row.get("status") or ""), idx)
            if key not in candidates or rank > candidates[key][0]:
                candidates[key] = (rank, row)

    out: list[dict[str, Any]] = []
    for pair in pairs:
        for side, side_spec in (("vulnerable", pair.vulnerable), ("patched", pair.patched)):
            firmware_name = Path(side_spec.firmware_path).name
            row = candidates.get((pair.vendor, firmware_name), (None, {}))[1]
            run_dir = row.get("run_dir") or ""
            side_root = results_root / "runs" / pair.pair_id / side
            side_root.mkdir(parents=True, exist_ok=True)
            if run_dir:
                link = side_root / "latest"
                if link.exists() or link.is_symlink():
                    link.unlink()
                try:
                    link.symlink_to(Path(run_dir).resolve())
                except Exception:
                    pass
            record = {
                "pair_id": pair.pair_id,
                "vendor": pair.vendor,
                "model": pair.model,
                "cve_id": pair.cve_id,
                "side": side,
                "firmware_path": side_spec.firmware_path,
                "returncode": int(row.get("exit_code") or 0) if row else 0,
                "duration_s": float(row.get("duration_s") or 0) if row else 0,
                "run_dir": run_dir,
                "stdout": "",
                "stderr": "",
                "status": row.get("status") or "missing",
                "source_summary": str(summary_paths[0]) if row else "",
            }
            (side_root / "last_run.json").write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            out.append(record)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the M0 pair-eval corpus with Codex-full pipeline.")
    parser.add_argument("--pairs", default="benchmarks/pair-eval/pairs.json")
    parser.add_argument("--results-dir", default="benchmark-results/pair-eval")
    parser.add_argument("--driver", default="codex")
    parser.add_argument("--parallel", type=int, default=2)
    parser.add_argument("--time-budget-s", type=int, default=3600)
    parser.add_argument("--source-summary", nargs='*', default=[])
    args = parser.parse_args()

    results_root = Path(args.results_dir).resolve()
    results_root.mkdir(parents=True, exist_ok=True)
    pairs = load_pairs_manifest(Path(args.pairs).resolve())

    if args.source_summary:
        rows = _build_rows_from_summaries(pairs, [Path(p).resolve() for p in args.source_summary], results_root)
    else:
        tasks: list[tuple[PairSpec, str, str]] = []
        for pair in pairs:
            tasks.append((pair, "vulnerable", pair.vulnerable.firmware_path))
            tasks.append((pair, "patched", pair.patched.firmware_path))

        rows = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.parallel)) as pool:
            futs = [pool.submit(_run_one, pair, side, firmware, results_root, args.time_budget_s, args.driver) for pair, side, firmware in tasks]
            for fut in concurrent.futures.as_completed(futs):
                row = fut.result()
                rows.append(row)
                print(json.dumps({k: row[k] for k in ['pair_id','side','status','returncode','run_dir']}, ensure_ascii=False), flush=True)

    rows.sort(key=lambda r: (r['pair_id'], r['side']))
    (results_root / 'run_index.json').write_text(json.dumps({'driver': ('summary-reuse' if args.source_summary else args.driver), 'time_budget_s': args.time_budget_s, 'rows': rows}, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
