#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> object | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _iter_runs(rerun_dir: Path):
    runs_dir = rerun_dir / "runs"
    if not runs_dir.is_dir():
        return
    for vendor_dir in sorted(p for p in runs_dir.iterdir() if p.is_dir()):
        for run_dir in sorted(p for p in vendor_dir.iterdir() if p.is_dir()):
            yield vendor_dir.name, run_dir


def _stage_status(run_dir: Path, stage_name: str) -> str:
    path = run_dir / "stages" / stage_name / "stage.json"
    obj = _load_json(path)
    if isinstance(obj, dict):
        status = obj.get("status")
        if isinstance(status, str) and status:
            return status
    report_path = run_dir / "report" / "report.json"
    report_obj = _load_json(report_path)
    if isinstance(report_obj, dict):
        stage_obj = report_obj.get(stage_name)
        if isinstance(stage_obj, dict):
            status = stage_obj.get("status")
            if isinstance(status, str) and status:
                return status
    return "missing"


def _inventory_quality(run_dir: Path) -> str:
    path = run_dir / "stages" / "inventory" / "inventory.json"
    obj = _load_json(path)
    if isinstance(obj, dict):
        quality = obj.get("quality")
        if isinstance(quality, dict):
            status = quality.get("status")
            if isinstance(status, str) and status:
                return status
    return "unknown"


def _sbom_components(run_dir: Path) -> int | None:
    path = run_dir / "stages" / "sbom" / "sbom.json"
    obj = _load_json(path)
    if isinstance(obj, dict):
        comps = obj.get("components")
        if isinstance(comps, list):
            return len(comps)
    return None


def _cve_info(run_dir: Path) -> tuple[str, int | None]:
    path = run_dir / "stages" / "cve_scan" / "cve_matches.json"
    obj = _load_json(path)
    if isinstance(obj, dict):
        source = obj.get("source")
        src = source if isinstance(source, str) and source else "<none>"
        summary = obj.get("summary")
        if isinstance(summary, dict):
            total = 0
            for key in ("critical", "high", "medium", "low"):
                value = summary.get(key)
                if isinstance(value, int):
                    total += value
            return src, total
        return src, None
    return "missing", None


def _format_counter(counter: Counter[str]) -> list[dict[str, Any]]:
    return [
        {"key": key, "count": counter[key]}
        for key in sorted(counter.keys())
    ]


def build_summary(rerun_dir: Path) -> dict[str, Any]:
    extraction = Counter[str]()
    inventory = Counter[str]()
    cve_source = Counter[str]()
    vendor_counts = Counter[str]()
    sbom_nonzero_by_extraction = Counter[str]()
    sbom_zero_by_extraction = Counter[str]()
    rows: list[dict[str, Any]] = []

    for vendor, run_dir in _iter_runs(rerun_dir):
        vendor_counts[vendor] += 1
        extraction_status = _stage_status(run_dir, "extraction")
        inventory_quality = _inventory_quality(run_dir)
        sbom_count = _sbom_components(run_dir)
        cve_src, cve_total = _cve_info(run_dir)

        extraction[extraction_status] += 1
        inventory[inventory_quality] += 1
        cve_source[cve_src] += 1
        if sbom_count is not None and sbom_count > 0:
            sbom_nonzero_by_extraction[extraction_status] += 1
        else:
            sbom_zero_by_extraction[extraction_status] += 1

        rows.append(
            {
                "vendor": vendor,
                "run_dir": str(run_dir),
                "extraction_status": extraction_status,
                "inventory_quality_status": inventory_quality,
                "sbom_components": sbom_count,
                "cve_source": cve_src,
                "cve_total": cve_total,
            }
        )

    subset: dict[str, dict[str, int]] = {}
    for key in sorted(set(extraction) | set(sbom_nonzero_by_extraction) | set(sbom_zero_by_extraction)):
        subset[key] = {
            "total": extraction[key],
            "sbom_nonzero": sbom_nonzero_by_extraction[key],
            "sbom_zero_or_missing": sbom_zero_by_extraction[key],
        }

    return {
        "rerun_dir": str(rerun_dir),
        "overall": {
            "runs_total": len(rows),
        },
        "vendor_counts": _format_counter(vendor_counts),
        "extraction_breakdown": _format_counter(extraction),
        "inventory_quality_breakdown": _format_counter(inventory),
        "cve_source_breakdown": _format_counter(cve_source),
        "sbom_by_extraction_status": subset,
        "rows": rows,
    }


def write_markdown(summary: dict[str, Any], out_path: Path) -> None:
    lines = [
        "# 2C.6 Extraction Breakdown",
        "",
        f"- rerun_dir: `{summary['rerun_dir']}`",
        f"- runs_total: **{summary['overall']['runs_total']}**",
        "",
        "## Extraction breakdown",
        "",
        "| extraction_status | count |",
        "|---|---:|",
    ]
    for item in summary["extraction_breakdown"]:
        lines.append(f"| {item['key']} | {item['count']} |")

    lines.extend(
        [
            "",
            "## Inventory quality breakdown",
            "",
            "| inventory_quality_status | count |",
            "|---|---:|",
        ]
    )
    for item in summary["inventory_quality_breakdown"]:
        lines.append(f"| {item['key']} | {item['count']} |")

    lines.extend(
        [
            "",
            "## SBOM recovery by extraction status",
            "",
            "| extraction_status | total | sbom_nonzero | sbom_zero_or_missing |",
            "|---|---:|---:|---:|",
        ]
    )
    for key, item in summary["sbom_by_extraction_status"].items():
        lines.append(
            f"| {key} | {item['total']} | {item['sbom_nonzero']} | {item['sbom_zero_or_missing']} |"
        )

    lines.extend(
        [
            "",
            "## CVE source breakdown",
            "",
            "| cve_source | count |",
            "|---|---:|",
        ]
    )
    for item in summary["cve_source_breakdown"]:
        lines.append(f"| {item['key']} | {item['count']} |")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize 2C.6 rerun outputs with extraction-first breakdown."
    )
    parser.add_argument("--rerun-dir", required=True)
    parser.add_argument("--json-out", default="")
    parser.add_argument("--md-out", default="")
    args = parser.parse_args()

    rerun_dir = Path(args.rerun_dir).resolve()
    summary = build_summary(rerun_dir)

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    if args.md_out:
        write_markdown(summary, Path(args.md_out))

    print(json.dumps(summary["overall"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
