#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import cast


class _Args(argparse.Namespace):
    run_dir: str = ""


def _parse_run_dir() -> Path:
    parser = argparse.ArgumentParser(
        description="Validate operator audit package artifacts and required keys."
    )
    _ = parser.add_argument(
        "--run-dir",
        required=True,
        help="Run directory containing manifest/report/metrics/quality artifacts.",
    )
    args = parser.parse_args(namespace=_Args())
    return Path(args.run_dir).resolve()


def _load_json(path: Path, errors: list[str], token: str) -> dict[str, object] | None:
    if not path.is_file():
        errors.append(f"{token}: missing file {path}")
        return None
    try:
        payload_obj = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except json.JSONDecodeError as exc:
        errors.append(f"{token}: invalid json {path} ({exc.msg})")
        return None
    if not isinstance(payload_obj, dict):
        errors.append(f"{token}: top-level object required in {path}")
        return None
    payload_dict = cast(dict[object, object], payload_obj)
    normalized: dict[str, object] = {}
    for key_obj, value_obj in payload_dict.items():
        if not isinstance(key_obj, str):
            errors.append(f"{token}: top-level keys must be strings in {path}")
            return None
        normalized[key_obj] = value_obj
    return normalized


def _get_nested_str(
    payload: dict[str, object], keys: tuple[str, ...], errors: list[str], token: str
) -> str | None:
    cur: object = payload
    for key in keys:
        if not isinstance(cur, Mapping) or key not in cur:
            dotted = ".".join(keys)
            errors.append(f"{token}: missing key {dotted}")
            return None
        cur_map = cast(Mapping[str, object], cur)
        cur = cur_map[key]
    if not isinstance(cur, str) or not cur.strip():
        dotted = ".".join(keys)
        errors.append(f"{token}: non-empty string required for {dotted}")
        return None
    return cur


def _resolve_commit_sha(run_dir: Path) -> str | None:
    for env_name in ("GITHUB_SHA", "CI_COMMIT_SHA"):
        value = os.environ.get(env_name, "").strip()
        if value:
            return value
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=run_dir,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    out = proc.stdout.strip()
    return out or None


def main() -> int:
    run_dir = _parse_run_dir()
    errors: list[str] = []

    if not run_dir.is_dir():
        summary = {
            "commit_sha": _resolve_commit_sha(Path.cwd()),
            "corpus_id": None,
            "errors": [f"RUN_DIR: missing directory {run_dir}"],
            "metrics_verdict": None,
            "ok": False,
            "ref_md_sha256": None,
            "run_dir": str(run_dir),
        }
        print(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=True))
        return 1

    manifest = _load_json(run_dir / "manifest.json", errors, "MANIFEST")
    report = _load_json(run_dir / "report" / "report.json", errors, "REPORT")
    metrics = _load_json(run_dir / "metrics.json", errors, "METRICS")
    quality = _load_json(run_dir / "quality_gate.json", errors, "QUALITY_GATE")

    ref_md_sha256_manifest: str | None = None
    ref_md_sha256_report: str | None = None
    corpus_id: str | None = None
    metrics_verdict: str | None = None

    if manifest is not None:
        ref_md_sha256_manifest = _get_nested_str(
            manifest, ("ref_md_sha256",), errors, "MANIFEST"
        )

    if report is not None:
        ref_md_sha256_report = _get_nested_str(
            report, ("overview", "ref_md_sha256"), errors, "REPORT"
        )

    if (
        ref_md_sha256_manifest is not None
        and ref_md_sha256_report is not None
        and ref_md_sha256_manifest != ref_md_sha256_report
    ):
        errors.append(
            "REF_MD_SHA256_MISMATCH: manifest.ref_md_sha256 != report.overview.ref_md_sha256"
        )

    if metrics is not None:
        corpus_id = _get_nested_str(metrics, ("corpus_id",), errors, "METRICS")

    if quality is not None:
        verdict = _get_nested_str(quality, ("verdict",), errors, "QUALITY_GATE")
        if verdict is not None and verdict not in {"pass", "fail"}:
            errors.append("QUALITY_GATE: verdict must be one of {pass, fail}")
        else:
            metrics_verdict = verdict

    summary = {
        "commit_sha": _resolve_commit_sha(run_dir),
        "corpus_id": corpus_id,
        "errors": errors,
        "metrics_verdict": metrics_verdict,
        "ok": len(errors) == 0,
        "ref_md_sha256": ref_md_sha256_manifest,
        "run_dir": str(run_dir),
    }
    print(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if len(errors) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
