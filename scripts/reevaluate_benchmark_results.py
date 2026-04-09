#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import shutil
import sys
import tempfile
from collections import defaultdict
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


def _repo_root() -> Path:
    return REPO_ROOT


def _find_bundle_run_root(bundle_dir: Path) -> Path | None:
    if (bundle_dir / "stages").is_dir():
        return bundle_dir
    candidates = sorted(
        {p.parent for p in bundle_dir.glob("**/stages") if p.is_dir()},
        key=lambda p: (len(p.parts), str(p)),
    )
    if not candidates:
        return None
    return candidates[0]


def _normalize_bundle(bundle_dir: Path, temp_root: Path) -> Path:
    run_root = _find_bundle_run_root(bundle_dir)
    if run_root is None:
        raise FileNotFoundError(f"could not find run root under {bundle_dir}")
    normalized = temp_root / "run"
    if normalized.exists():
        shutil.rmtree(normalized)
    shutil.copytree(run_root, normalized, symlinks=True)

    report_dir = normalized / "report"
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
            shutil.copy2(src, normalized / name)

    return normalized


def _load_row_index(results_dir: Path) -> dict[tuple[str, str], dict[str, object]]:
    detail = _load_json(results_dir / "benchmark_detail.json")
    if not isinstance(detail, dict):
        return {}
    rows_any = cast(dict[str, object], detail).get("rows", [])
    if not isinstance(rows_any, list):
        return {}
    index: dict[tuple[str, str], dict[str, object]] = {}
    for row_any in rows_any:
        if not isinstance(row_any, dict):
            continue
        row = cast(dict[str, object], row_any)
        vendor = str(row.get("vendor", "") or "")
        sha = str(row.get("sha256", "") or "")
        if vendor and sha:
            index[(vendor, sha)] = row
    return index


def _bundle_dirs(results_dir: Path) -> list[Path]:
    archives_dir = results_dir / "archives"
    if not archives_dir.is_dir():
        return []
    bundles: list[Path] = []
    for vendor_dir in sorted(p for p in archives_dir.iterdir() if p.is_dir()):
        for bundle_dir in sorted(p for p in vendor_dir.iterdir() if p.is_dir()):
            bundles.append(bundle_dir)
    return bundles


def _summarize(rows: list[dict[str, object]]) -> dict[str, object]:
    per_vendor: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "total": 0,
            "ready": 0,
            "degraded": 0,
            "blocked": 0,
            "digest_verifier_ok": 0,
            "report_verifier_ok": 0,
        }
    )
    overall = {
        "total": 0,
        "ready": 0,
        "degraded": 0,
        "blocked": 0,
        "digest_verifier_ok": 0,
        "report_verifier_ok": 0,
    }
    for row in rows:
        vendor = str(row.get("vendor", "") or "unknown")
        state = str(row.get("analyst_readiness", "blocked") or "blocked")
        per_vendor[vendor]["total"] += 1
        overall["total"] += 1
        if state == "ready":
            per_vendor[vendor]["ready"] += 1
            overall["ready"] += 1
        elif state == "degraded":
            per_vendor[vendor]["degraded"] += 1
            overall["degraded"] += 1
        else:
            per_vendor[vendor]["blocked"] += 1
            overall["blocked"] += 1
        if bool(row.get("digest_verifier_ok")):
            per_vendor[vendor]["digest_verifier_ok"] += 1
            overall["digest_verifier_ok"] += 1
        if bool(row.get("report_verifier_ok")):
            per_vendor[vendor]["report_verifier_ok"] += 1
            overall["report_verifier_ok"] += 1
    return {"overall": overall, "per_vendor": dict(per_vendor)}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Re-evaluate an existing benchmark-results directory under analyst-readiness rules."
    )
    parser.add_argument("--results-dir", required=True, help="Path to benchmark-results/<run>")
    parser.add_argument(
        "--out-prefix",
        default="benchmark_analyst_readiness",
        help="Output filename prefix inside results dir (default: benchmark_analyst_readiness)",
    )
    args = parser.parse_args()

    repo_root = _repo_root()
    results_dir = Path(args.results_dir).resolve()
    if not results_dir.is_dir():
        raise SystemExit(f"results dir not found: {results_dir}")

    row_index = _load_row_index(results_dir)
    output_rows: list[dict[str, object]] = []

    with tempfile.TemporaryDirectory(prefix="scout-benchmark-reeval-") as temp_dir:
        temp_root = Path(temp_dir)
        for bundle_dir in _bundle_dirs(results_dir):
            vendor = bundle_dir.parent.name
            sha = bundle_dir.name
            normalized = _normalize_bundle(bundle_dir, temp_root / vendor / sha)
            metrics = collect_run_metrics(normalized)
            digest_verifier = run_bundle_verifier(
                repo_root, "scripts/verify_analyst_digest.py", normalized
            )
            report_verifier = run_bundle_verifier(
                repo_root, "scripts/verify_aiedge_analyst_report.py", normalized
            )
            readiness = evaluate_analyst_readiness(
                metrics=metrics,
                digest_verifier=digest_verifier,
                report_verifier=report_verifier,
            )

            base_row = dict(row_index.get((vendor, sha), {}))
            base_row.update(
                {
                    "vendor": vendor,
                    "sha256": sha,
                    "bundle_dir": str(bundle_dir),
                    "normalized_run_dir": str(normalized),
                    "digest_verifier_ok": bool(digest_verifier.get("ok")),
                    "digest_verifier_reason": digest_verifier.get("reason", ""),
                    "report_verifier_ok": bool(report_verifier.get("ok")),
                    "report_verifier_reason": report_verifier.get("reason", ""),
                    **metrics,
                    **readiness,
                }
            )
            output_rows.append(base_row)

    output_rows = sorted(
        output_rows,
        key=lambda row: (
            str(row.get("vendor", "")),
            str(row.get("firmware", "")),
            str(row.get("sha256", "")),
        ),
    )

    summary = _summarize(output_rows)
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    prefix = args.out_prefix

    csv_path = results_dir / f"{prefix}.csv"
    json_path = results_dir / f"{prefix}.json"
    txt_path = results_dir / f"{prefix}.txt"

    fieldnames: list[str] = sorted({key for row in output_rows for key in row.keys()})
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in output_rows:
            writer.writerow(row)

    json_path.write_text(
        json.dumps(
            {
                "generated_at": generated_at,
                "results_dir": str(results_dir),
                "summary": summary,
                "rows": output_rows,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    overall = cast(dict[str, int], summary["overall"])
    lines = [
        "SCOUT Benchmark Analyst Readiness Re-evaluation",
        "=" * 60,
        f"generated_at: {generated_at}",
        f"results_dir: {results_dir}",
        "",
        f"total bundles: {overall['total']}",
        f"ready/degraded/blocked: {overall['ready']}/{overall['degraded']}/{overall['blocked']}",
        f"digest verifier ok: {overall['digest_verifier_ok']}/{overall['total']}",
        f"report verifier ok: {overall['report_verifier_ok']}/{overall['total']}",
        "",
        "Per vendor:",
    ]
    for vendor, stats_any in sorted(cast(dict[str, object], summary["per_vendor"]).items()):
        stats = cast(dict[str, int], stats_any)
        lines.append(
            f"- {vendor}: total={stats['total']} ready={stats['ready']} degraded={stats['degraded']} "
            f"blocked={stats['blocked']} digest_ok={stats['digest_verifier_ok']} report_ok={stats['report_verifier_ok']}"
        )
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Wrote {csv_path}")
    print(f"Wrote {json_path}")
    print(f"Wrote {txt_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
