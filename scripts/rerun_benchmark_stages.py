#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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


def _read_json_object(path: Path) -> dict[str, object] | None:
    if not path.is_file():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    return cast(dict[str, object], obj)


def _cve_matches_look_current(cve_matches_path: Path) -> bool:
    payload = _read_json_object(cve_matches_path)
    if payload is None:
        return False
    findings_any = payload.get("finding_candidates")
    if not isinstance(findings_any, list):
        return False
    for finding_any in cast(list[object], findings_any):
        if not isinstance(finding_any, dict):
            return False
        finding = cast(dict[str, object], finding_any)
        if "priority_score" not in finding or "evidence_tier" not in finding:
            return False
    return True


def _resume_outputs_are_current(normalized_run: Path) -> bool:
    report_json = normalized_run / "report" / "report.json"
    sbom_stage = normalized_run / "stages" / "sbom" / "stage.json"
    sbom_json = normalized_run / "stages" / "sbom" / "sbom.json"
    cve_stage = normalized_run / "stages" / "cve_scan" / "stage.json"
    cve_matches = normalized_run / "stages" / "cve_scan" / "cve_matches.json"

    if not report_json.is_file():
        return False
    if not sbom_stage.is_file() or not sbom_json.is_file():
        return False
    if not cve_stage.is_file():
        return False

    sbom_stage_obj = _read_json_object(sbom_stage)
    cve_stage_obj = _read_json_object(cve_stage)
    if sbom_stage_obj is None or cve_stage_obj is None:
        return False

    sbom_status = sbom_stage_obj.get("status")
    if sbom_status not in {"ok", "partial"}:
        return False

    cve_status = cve_stage_obj.get("status")
    if cve_status in {"ok", "partial"}:
        if not cve_matches.is_file():
            return False
        if not _cve_matches_look_current(cve_matches):
            return False
    elif cve_status == "skipped":
        if cve_matches.exists():
            return False
    else:
        return False

    return True


def _rerun_one_bundle(
    *,
    bundle_dir: Path,
    out_dir: Path,
    stages: str,
    time_budget_s: int,
    no_llm: bool,
    base_rows: dict[tuple[str, str], dict[str, object]],
    resume: bool,
) -> dict[str, object]:
    vendor = bundle_dir.parent.name
    sha = bundle_dir.name
    normalized_run = out_dir / "runs" / vendor / sha
    skipped_existing = False
    if resume and normalized_run.is_dir():
        if _resume_outputs_are_current(normalized_run):
            skipped_existing = True
        else:
            _normalize_bundle(bundle_dir, normalized_run)
    else:
        _normalize_bundle(bundle_dir, normalized_run)

    if skipped_existing:
        cp = subprocess.CompletedProcess(
            args=["resume-skip"],
            returncode=0,
            stdout="[resume] reused existing normalized run",
            stderr="",
        )
        duration_s = 0.0
    else:
        for stage_name in [s.strip() for s in stages.split(",") if s.strip()]:
            stage_dir = normalized_run / "stages" / stage_name
            if stage_dir.exists():
                shutil.rmtree(stage_dir, ignore_errors=True)
        cmd = [
            sys.executable,
            "-m",
            "aiedge",
            "stages",
            str(normalized_run),
            "--stages",
            stages,
            "--time-budget-s",
            str(time_budget_s),
        ]
        if no_llm:
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
    stage_set = {s.strip() for s in stages.split(",") if s.strip()}
    if stage_set.issubset({"sbom", "cve_scan"}):
        digest_verifier = {"ok": None}
        report_verifier = {"ok": None}
        readiness = {
            "analyst_readiness": "not_applicable",
            "analyst_ready": False,
            "analyst_degraded": False,
            "analyst_blocked": False,
            "analyst_reason_codes": ["subset_sbom_cve_only"],
        }
    else:
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
            "resume_skipped_existing": skipped_existing,
            "source_bundle_dir": str(bundle_dir),
            "rerun_run_dir": str(normalized_run),
            "rerun_stages": stages,
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
    return row


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


def _write_outputs(
    *,
    rows: list[dict[str, object]],
    results_dir: Path,
    out_dir: Path,
    rerun_stages: str,
) -> None:
    rows = sorted(
        rows,
        key=lambda row: (
            str(row.get("vendor", "")),
            str(row.get("firmware", "")),
            str(row.get("sha256", "")),
        ),
    )

    csv_path = out_dir / "rerun_summary.csv"
    json_path = out_dir / "rerun_summary.json"
    txt_path = out_dir / "rerun_summary.txt"

    fieldnames = sorted({k for row in rows for k in row.keys()}) if rows else []
    if fieldnames:
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
        "rerun_stages": rerun_stages,
        "overall": {
            "total": len(rows),
            "ready": ready,
            "degraded": degraded,
            "blocked": blocked,
            "digest_verifier_ok": sum(
                1 for row in rows if row.get("digest_verifier_ok")
            ),
            "report_verifier_ok": sum(
                1 for row in rows if row.get("report_verifier_ok")
            ),
        },
        "rows": rows,
    }
    json_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    txt_lines = [
        "SCOUT Benchmark Stage Rerun Summary",
        "=" * 60,
        f"results_dir: {results_dir}",
        f"out_dir: {out_dir}",
        f"rerun_stages: {rerun_stages}",
        f"ready/degraded/blocked: {ready}/{degraded}/{blocked}",
        f"digest verifier ok: {payload['overall']['digest_verifier_ok']}/{len(rows)}",
        f"report verifier ok: {payload['overall']['report_verifier_ok']}/{len(rows)}",
    ]
    txt_path.write_text("\n".join(txt_lines) + "\n", encoding="utf-8")


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
    parser.add_argument("--parallel", type=int, default=4)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    results_dir = Path(args.results_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    base_rows = _base_row_index(results_dir)
    bundle_dirs = _bundle_dirs(results_dir)
    if args.limit > 0:
        bundle_dirs = bundle_dirs[: int(args.limit)]

    rows: list[dict[str, object]] = []
    max_workers = max(1, int(args.parallel))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                _rerun_one_bundle,
                bundle_dir=bundle_dir,
                out_dir=out_dir,
                stages=args.stages,
                time_budget_s=args.time_budget_s,
                no_llm=bool(args.no_llm),
                base_rows=base_rows,
                resume=bool(args.resume),
            ): bundle_dir
            for bundle_dir in bundle_dirs
        }
        for future in as_completed(futures):
            bundle_dir = futures[future]
            vendor = bundle_dir.parent.name
            sha = bundle_dir.name
            try:
                rows.append(future.result())
            except Exception as exc:
                rows.append(
                    {
                        "vendor": vendor,
                        "sha256": sha,
                        "source_bundle_dir": str(bundle_dir),
                        "rerun_run_dir": str(out_dir / "runs" / vendor / sha),
                        "rerun_stages": args.stages,
                        "rerun_returncode": -1,
                        "rerun_duration_s": 0.0,
                        "rerun_stdout": "",
                        "rerun_stderr": f"internal_rerun_exception:{type(exc).__name__}:{exc}",
                        "digest_verifier_ok": False,
                        "report_verifier_ok": False,
                        "analyst_readiness": "blocked",
                    }
                )
            _write_outputs(
                rows=rows,
                results_dir=results_dir,
                out_dir=out_dir,
                rerun_stages=args.stages,
            )

    _write_outputs(
        rows=rows,
        results_dir=results_dir,
        out_dir=out_dir,
        rerun_stages=args.stages,
    )

    print(f"Wrote {out_dir / 'rerun_summary.csv'}")
    print(f"Wrote {out_dir / 'rerun_summary.json'}")
    print(f"Wrote {out_dir / 'rerun_summary.txt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
