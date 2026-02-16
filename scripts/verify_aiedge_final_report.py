#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import cast

_CANONICAL_8MB_SHA256 = (
    "387d97fd925125471691d5c565fcc0ff009e111bdbdfd2ddb057f9212a939c8a"
)
_CANONICAL_8MB_SHA256_PREFIX = _CANONICAL_8MB_SHA256[:12]
_CANONICAL_8MB_SIZE_BYTES = 8_388_608


def _as_object_dict(value: object, *, path: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be object")
    return cast(dict[str, object], value)


def _load_json_object(path: Path) -> dict[str, object]:
    try:
        obj = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception as exc:
        raise ValueError(f"invalid JSON: {path}: {exc}") from exc
    return _as_object_dict(obj, path=str(path))


def _require_true(obj: dict[str, object], path: str) -> None:
    cur: object = obj
    for part in path.split("."):
        cur_obj = _as_object_dict(cur, path=path)
        if part not in cur_obj:
            raise ValueError(f"missing {path}")
        cur = cur_obj[part]
    if cur is not True:
        raise ValueError(f"{path} != true: {cur!r}")


def _get_nested(obj: dict[str, object], path: str) -> object:
    cur: object = obj
    for part in path.split("."):
        cur_obj = _as_object_dict(cur, path=path)
        if part not in cur_obj:
            raise ValueError(f"missing {path}")
        cur = cur_obj[part]
    return cur


def _is_run_relative_path(path: str) -> bool:
    if not path:
        return False
    if path.startswith("/"):
        return False
    if re.match(r"^[A-Za-z]:\\", path):
        return False
    return True


def _validate_linked_path(run_dir: Path, rel_path: str, *, field_path: str) -> Path:
    if not _is_run_relative_path(rel_path):
        raise ValueError(f"{field_path} must be run-relative path: {rel_path!r}")

    candidate = (run_dir / rel_path).resolve()
    run_root = run_dir.resolve()
    try:
        _ = candidate.relative_to(run_root)
    except ValueError as exc:
        raise ValueError(f"{field_path} escapes run dir: {rel_path!r}") from exc

    if not candidate.exists():
        raise ValueError(f"dangling path at {field_path}: {rel_path!r}")
    return candidate


def _verify_final_report(run_dir: Path) -> None:
    report_path = run_dir / "report" / "report.json"
    manifest_path = run_dir / "manifest.json"
    if not report_path.is_file():
        raise ValueError(f"missing report: {report_path}")
    if not manifest_path.is_file():
        raise ValueError(f"missing manifest: {manifest_path}")

    report = _load_json_object(report_path)
    manifest = _load_json_object(manifest_path)

    _require_true(report, "report_completeness.gate_passed")
    _require_true(report, "run_completion.is_final")
    _require_true(report, "run_completion.conclusion_ready")

    findings_status = _get_nested(
        report, "run_completion.required_stage_statuses.findings"
    )
    if findings_status == "pending":
        raise ValueError("run_completion.required_stage_statuses.findings is pending")

    track = _as_object_dict(manifest.get("track"), path="manifest.track")
    if track.get("track_id") != "8mb":
        raise ValueError(f"manifest.track.track_id != '8mb': {track.get('track_id')!r}")
    if track.get("canonical_sha256_prefix") != _CANONICAL_8MB_SHA256_PREFIX:
        raise ValueError(
            f"manifest.track.canonical_sha256_prefix mismatch: {track.get('canonical_sha256_prefix')!r}"
        )
    if track.get("canonical_size_bytes") != _CANONICAL_8MB_SIZE_BYTES:
        raise ValueError(
            f"manifest.track.canonical_size_bytes mismatch: {track.get('canonical_size_bytes')!r}"
        )

    for field in (
        "input_sha256",
        "source_input_sha256",
        "analyzed_input_sha256",
    ):
        val = manifest.get(field)
        if val != _CANONICAL_8MB_SHA256:
            raise ValueError(f"manifest.{field} mismatch: {val!r}")

    for field in (
        "input_size_bytes",
        "source_input_size_bytes",
        "analyzed_input_size_bytes",
    ):
        val = manifest.get(field)
        if val != _CANONICAL_8MB_SIZE_BYTES:
            raise ValueError(f"manifest.{field} mismatch: {val!r}")

    duplicate_gate_any = report.get("duplicate_gate")
    duplicate_gate = _as_object_dict(duplicate_gate_any, path="report.duplicate_gate")
    taxonomy_version = duplicate_gate.get("taxonomy_version")
    if taxonomy_version != "duplicate-taxonomy-v1":
        raise ValueError(
            f"report.duplicate_gate.taxonomy_version != 'duplicate-taxonomy-v1': {taxonomy_version!r}"
        )
    duplicate_artifact_rel = duplicate_gate.get("artifact")
    if not isinstance(duplicate_artifact_rel, str):
        raise ValueError("report.duplicate_gate.artifact must be string")
    duplicate_artifact_path = _validate_linked_path(
        run_dir,
        duplicate_artifact_rel,
        field_path="report.duplicate_gate.artifact",
    )

    duplicate_artifact = _load_json_object(duplicate_artifact_path)
    duplicate_schema = duplicate_artifact.get("schema_version")
    if duplicate_schema != "duplicate-gate-v1":
        raise ValueError(
            f"{duplicate_artifact_rel}.schema_version != 'duplicate-gate-v1': {duplicate_schema!r}"
        )
    novelty_any = duplicate_artifact.get("novelty")
    if not isinstance(novelty_any, list):
        raise ValueError(f"{duplicate_artifact_rel}.novelty must be list")
    ranked_any = duplicate_artifact.get("ranked")
    if not isinstance(ranked_any, list):
        raise ValueError(f"{duplicate_artifact_rel}.ranked must be list")

    firmware_lineage_any = report.get("firmware_lineage")
    firmware_lineage = _as_object_dict(
        firmware_lineage_any,
        path="report.firmware_lineage",
    )
    details_any = firmware_lineage.get("details")
    details = _as_object_dict(details_any, path="report.firmware_lineage.details")

    lineage_rel = details.get("lineage")
    if not isinstance(lineage_rel, str):
        raise ValueError("report.firmware_lineage.details.lineage must be string")
    lineage_path = _validate_linked_path(
        run_dir,
        lineage_rel,
        field_path="report.firmware_lineage.details.lineage",
    )

    lineage_diff_rel = details.get("lineage_diff")
    if not isinstance(lineage_diff_rel, str):
        raise ValueError("report.firmware_lineage.details.lineage_diff must be string")
    lineage_diff_path = _validate_linked_path(
        run_dir,
        lineage_diff_rel,
        field_path="report.firmware_lineage.details.lineage_diff",
    )

    lineage_obj = _load_json_object(lineage_path)
    lineage_schema = lineage_obj.get("schema_version")
    if lineage_schema != 1:
        raise ValueError(f"{lineage_rel}.schema_version != 1: {lineage_schema!r}")

    lineage_diff_obj = _load_json_object(lineage_diff_path)
    lineage_diff_schema = lineage_diff_obj.get("schema_version")
    if lineage_diff_schema != 1:
        raise ValueError(
            f"{lineage_diff_rel}.schema_version != 1: {lineage_diff_schema!r}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify finalized AIEdge report contract for canonical 8MB track."
    )
    _ = parser.add_argument(
        "--run-dir", required=True, help="Path to AIEdge run directory"
    )
    args = parser.parse_args(argv)
    run_dir_raw = getattr(args, "run_dir", None)
    if not isinstance(run_dir_raw, str) or not run_dir_raw:
        print("[FAIL] --run-dir must be a non-empty path")
        return 1
    run_dir = Path(run_dir_raw).resolve()
    if not run_dir.is_dir():
        print(f"[FAIL] run_dir is not a directory: {run_dir}")
        return 1

    try:
        _verify_final_report(run_dir)
    except ValueError as exc:
        print(f"[FAIL] {exc}")
        return 1
    except Exception as exc:
        print(f"[FAIL] unexpected verifier error: {exc}")
        return 1

    print(f"[OK] finalized report contract verified: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
