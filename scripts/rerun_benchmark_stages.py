#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from aiedge.benchmark_eval import collect_run_metrics, evaluate_analyst_readiness, run_bundle_verifier


def _load_json(path: Path) -> object | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _find_bundle_run_root(bundle_dir: Path) -> Path | None:
    if (bundle_dir / "stages").is_dir():
        return bundle_dir
    candidates = sorted(
        {p.parent for p in bundle_dir.glob("**/stages") if p.is_dir()},
        key=lambda p: (len(p.parts), str(p)),
    )
    return candidates[0] if candidates else None


def _normalize_bundle(bundle_dir: Path, out_run_dir: Path) -> Path:
    run_root = _find_bundle_run_root(bundle_dir)
    if run_root is None:
        raise FileNotFoundError(f"could not find run root under {bundle_dir}")
    if out_run_dir.exists():
        shutil.rmtree(out_run_dir)
    out_run_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(run_root, out_run_dir, symlinks=True)
    report_dir = out_run_dir / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    for name in (
        "analyst_digest.json",
        "analyst_digest.md",
        "analyst_overview.json",
        "analyst_report.json",
        "analyst_report_v2.json",
        "analyst_report_v2.md",
        "report.json",
        "viewer.html",
        "executive_report.md",
    ):
        src = bundle_dir / name
        if src.is_file():
            shutil.copy2(src, report_dir / name)
    for name in ("manifest.json", "firmware_handoff.json", "metrics.json", "quality_gate.json"):
        src = bundle_dir / name
        if src.is_file():
            shutil.copy2(src, out_run_dir / name)
    return out_run_dir


def _bundle_dirs(results_dir: Path) -> list[Path]:
    archives_dir = results_dir / "archives"
    bundles: list[Path] = []
    for vendor_dir in sorted(p for p in archives_dir.iterdir() if p.is_dir()):
        for bundle_dir in sorted(p for p in vendor_dir.iterdir() if p.is_dir()):
            bundles.append(bundle_dir)
    return bundles


def _base_row_index(results_dir: Path) -> dict[tuple[str, str], dict[str, object]]:
    detail = _load_json(results_dir / "benchmark_detail.json")
    if not isinstance(detail, dict):
        return {}
    rows_any = cast(dict[str, object], detail).get("rows", [])
    if not isinstance(rows_any, list):
        return {}
    out: dict[tuple[str, str], dict[str, object]] = {}
    for row_any in rows_any:
        if not isinstance(row_any, dict):
            continue
        row = cast(dict[str, object], row_any)
        vendor = str(row.get("vendor", "") or "")
        sha = str(row.get("sha256", "") or "")
        if vendor and sha:
            out[(vendor, sha)] = row
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize archived benchmark bundles and rerun a stage subset.")
    parser.add_argument("--results-dir", required=True, help="Existing benchmark results dir with archives/")
    parser.add_argument("--out-dir", required=True, help="Output directory for normalized rerun bundles")
    parser.add_argument(
        "--stages",
        default="attribution,graph,attack_surface,llm_triage",
        help="Comma-separated stages to rerun (default: attribution,graph,attack_surface,llm_triage)",
    )
    parser.add_argument("--time-budget-s", type=int, default=3600)
    parser.add_argument("--no-llm", action="store_true")
    args = parser.parse_args()

    results_dir = Path(args.results_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    base_rows = _base_row_index(results_dir)
    rows: list[dict[str, object]] = []

    for bundle_dir in _bundle_dirs(results_dir):
        vendor = bundle_dir.parent.name
        sha = bundle_dir.name
        normalized_run = out_dir / "runs" / vendor / sha
        _normalize_bundle(bundle_dir, normalized_run)

        cmd = [
            sys.executable,
            "-m",
            "aiedge",
            "stages",
            str(normalized_run),
            "--stages",
            args.stages,
            "--time-budget-s",
            str(args.time_budget_s),
        ]
        if args.no_llm:
            cmd.append("--no-llm")

        started = time.time()
        cp = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        duration_s = round(time.time() - started, 2)

        metrics = collect_run_metrics(normalized_run)
        digest_verifier = run_bundle_verifier(
            REPO_ROOT, "scripts/verify_analyst_digest.py", normalized_run
        )
        report_verifier = run_bundle_verifier(
            REPO_ROOT, "scripts/verify_aiedge_analyst_report.py", normalized_run
        )
        readiness = evaluate_analyst_readiness(
            metrics=metrics,
            digest_verifier=digest_verifier,
            report_verifier=report_verifier,
        )

        row = dict(base_rows.get((vendor, sha), {}))
        row.update(
            {
                "vendor": vendor,
                "sha256": sha,
                "source_bundle_dir": str(bundle_dir),
                "rerun_run_dir": str(normalized_run),
                "rerun_stages": args.stages,
                "rerun_returncode": cp.returncode,
                "rerun_duration_s": duration_s,
                "rerun_stdout": cp.stdout.strip()[:2000],
                "rerun_stderr": cp.stderr.strip()[:2000],
                "digest_verifier_ok": bool(digest_verifier.get("ok")),
                "report_verifier_ok": bool(report_verifier.get("ok")),
                **metrics,
                **readiness,
            }
        )
        rows.append(row)

    rows = sorted(rows, key=lambda row: (str(row.get("vendor", "")), str(row.get("firmware", "")), str(row.get("sha256", ""))))
    fieldnames = sorted({k for row in rows for k in row.keys()})

    csv_path = out_dir / "rerun_summary.csv"
    json_path = out_dir / "rerun_summary.json"
    txt_path = out_dir / "rerun_summary.txt"

    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    ready = sum(1 for row in rows if row.get("analyst_readiness") == "ready")
    degraded = sum(1 for row in rows if row.get("analyst_readiness") == "degraded")
    blocked = sum(1 for row in rows if row.get("analyst_readiness") == "blocked")

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "results_dir": str(results_dir),
        "out_dir": str(out_dir),
        "rerun_stages": args.stages,
        "overall": {
            "total": len(rows),
            "ready": ready,
            "degraded": degraded,
            "blocked": blocked,
            "digest_verifier_ok": sum(1 for row in rows if row.get("digest_verifier_ok")),
            "report_verifier_ok": sum(1 for row in rows if row.get("report_verifier_ok")),
        },
        "rows": rows,
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    txt_lines = [
        "SCOUT Benchmark Stage Rerun Summary",
        "=" * 60,
        f"results_dir: {results_dir}",
        f"out_dir: {out_dir}",
        f"rerun_stages: {args.stages}",
        f"ready/degraded/blocked: {ready}/{degraded}/{blocked}",
        f"digest verifier ok: {payload['overall']['digest_verifier_ok']}/{len(rows)}",
        f"report verifier ok: {payload['overall']['report_verifier_ok']}/{len(rows)}",
    ]
    txt_path.write_text("\n".join(txt_lines) + "\n", encoding="utf-8")

    print(f"Wrote {csv_path}")
    print(f"Wrote {json_path}")
    print(f"Wrote {txt_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
