#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import cast

REQUIRED_SECTIONS: tuple[str, ...] = (
    "attribution",
    "endpoints",
    "surfaces",
    "graph",
    "attack_surface",
    "threat_model",
    "functional_spec",
    "poc_validation",
    "llm_synthesis",
)

STAGE_ARTIFACTS: dict[str, str] = {
    "attribution": "stages/attribution/attribution.json",
    "endpoints": "stages/endpoints/endpoints.json",
    "surfaces": "stages/surfaces/surfaces.json",
    "graph": "stages/graph/comm_graph.json",
    "attack_surface": "stages/attack_surface/attack_surface.json",
    "threat_model": "stages/threat_model/threat_model.json",
    "functional_spec": "stages/functional_spec/functional_spec.json",
    "poc_validation": "stages/poc_validation/poc_validation.json",
    "llm_synthesis": "stages/llm_synthesis/llm_synthesis.json",
    "findings_pattern_scan": "stages/findings/pattern_scan.json",
    "findings_binary_strings_hits": "stages/findings/binary_strings_hits.json",
}

REQUIRED_STAGE_SCHEMAS: dict[str, str] = {
    "findings_pattern_scan": "pattern-scan-v1",
    "findings_binary_strings_hits": "binary-strings-hits-v1",
}


def _as_object(value: object, *, path: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be object")
    src = cast(dict[object, object], value)
    out: dict[str, object] = {}
    for key, item in src.items():
        out[str(key)] = item
    return out


def _load_json_obj(path: Path) -> dict[str, object]:
    try:
        raw = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception as exc:
        raise ValueError(f"invalid JSON: {path}: {exc}") from exc
    return _as_object(raw, path=str(path))


def _iter_object_items(value: object) -> list[tuple[str, object]]:
    if not isinstance(value, dict):
        return []
    src = cast(dict[object, object], value)
    out: list[tuple[str, object]] = []
    for key, item in src.items():
        out.append((str(key), item))
    return sorted(out, key=lambda pair: pair[0])


def _iter_object_list(value: object) -> list[object]:
    if not isinstance(value, list):
        return []
    return list(cast(list[object], value))


def _is_run_relative_path(path: str) -> bool:
    if not path:
        return False
    if path.startswith("/"):
        return False
    if re.match(r"^[A-Za-z]:\\", path):
        return False
    return True


def _validate_linked_path(run_dir: Path, rel_path: str, *, field_path: str) -> None:
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


def _has_absolute_path_prefix(value: str) -> bool:
    return value.startswith("/") or bool(re.match(r"^[A-Za-z]:\\", value))


def _walk_string_values(obj: object, *, field_path: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for key, value in _iter_object_items(obj):
        key_path = f"{field_path}.{key}" if field_path else key
        if isinstance(value, str):
            found.append((key_path, value))
        found.extend(_walk_string_values(value, field_path=key_path))
    for idx, item in enumerate(_iter_object_list(obj)):
        idx_path = f"{field_path}[{idx}]"
        if isinstance(item, str):
            found.append((idx_path, item))
        found.extend(_walk_string_values(item, field_path=idx_path))
    return found


def _walk_evidence_refs(obj: object, *, field_path: str) -> list[tuple[str, str]]:
    refs: list[tuple[str, str]] = []
    for key, value in _iter_object_items(obj):
        key_path = f"{field_path}.{key}" if field_path else key
        if key == "evidence_refs":
            for idx, ref_any in enumerate(_iter_object_list(value)):
                if isinstance(ref_any, str):
                    refs.append((f"{key_path}[{idx}]", ref_any))
        refs.extend(_walk_evidence_refs(value, field_path=key_path))
    for idx, item in enumerate(_iter_object_list(obj)):
        refs.extend(_walk_evidence_refs(item, field_path=f"{field_path}[{idx}]"))
    return refs


def _walk_evidence_paths(obj: object, *, field_path: str) -> list[tuple[str, str]]:
    paths: list[tuple[str, str]] = []
    for key, value in _iter_object_items(obj):
        key_path = f"{field_path}.{key}" if field_path else key
        if key == "evidence":
            for idx, ev_any in enumerate(_iter_object_list(value)):
                if not isinstance(ev_any, dict):
                    continue
                ev_obj = _as_object(
                    cast(dict[object, object], ev_any),
                    path=f"{key_path}[{idx}]",
                )
                path_any = ev_obj.get("path")
                if isinstance(path_any, str):
                    paths.append((f"{key_path}[{idx}].path", path_any))
        paths.extend(_walk_evidence_paths(value, field_path=key_path))
    for idx, item in enumerate(_iter_object_list(obj)):
        paths.extend(_walk_evidence_paths(item, field_path=f"{field_path}[{idx}]"))
    return paths


def _verify_claim_refs(
    report_obj: dict[str, object],
    *,
    report_field: str,
    claims_field: str,
    run_dir: Path,
) -> None:
    claims_any = report_obj.get(claims_field)
    if not isinstance(claims_any, list):
        raise ValueError(f"{report_field}.{claims_field} must be list")
    for idx, claim_any in enumerate(cast(list[object], claims_any)):
        if not isinstance(claim_any, dict):
            raise ValueError(f"{report_field}.{claims_field}[{idx}] must be object")
        claim = cast(dict[str, object], claim_any)
        refs_any = claim.get("evidence_refs")
        if not isinstance(refs_any, list) or not refs_any:
            raise ValueError(
                f"{report_field}.{claims_field}[{idx}].evidence_refs must be non-empty list"
            )
        for ref_idx, ref_any in enumerate(cast(list[object], refs_any)):
            if not isinstance(ref_any, str):
                raise ValueError(
                    f"{report_field}.{claims_field}[{idx}].evidence_refs[{ref_idx}] must be string"
                )
            _validate_linked_path(
                run_dir,
                ref_any,
                field_path=(
                    f"{report_field}.{claims_field}[{idx}].evidence_refs[{ref_idx}]"
                ),
            )


def _verify_section_evidence_artifacts(
    report_obj: dict[str, object],
    *,
    run_dir: Path,
) -> None:
    artifacts_any = report_obj.get("artifacts")
    if not isinstance(artifacts_any, dict):
        return
    artifacts = _as_object(
        cast(object, artifacts_any),
        path="analyst_report.artifacts",
    )
    section_paths_any = artifacts.get("section_evidence_paths")
    if not isinstance(section_paths_any, dict):
        return

    section_paths = _as_object(
        cast(object, section_paths_any),
        path="analyst_report.artifacts.section_evidence_paths",
    )
    for section_name, paths_any in _iter_object_items(section_paths):
        for idx, rel_path_any in enumerate(_iter_object_list(paths_any)):
            if not isinstance(rel_path_any, str):
                raise ValueError(
                    f"analyst_report.artifacts.section_evidence_paths.{section_name}[{idx}] must be string"
                )

            field_path = (
                f"analyst_report.artifacts.section_evidence_paths.{section_name}[{idx}]"
            )
            _validate_linked_path(run_dir, rel_path_any, field_path=field_path)

            if not rel_path_any.lower().endswith(".json"):
                continue

            artifact_obj = _load_json_obj(run_dir / rel_path_any)
            for nested_field_path, nested_ref in _walk_evidence_refs(
                artifact_obj,
                field_path=field_path,
            ):
                _validate_linked_path(run_dir, nested_ref, field_path=nested_field_path)


def _verify_analyst_report(run_dir: Path) -> None:
    analyst_report_path = run_dir / "report" / "analyst_report.json"
    if not analyst_report_path.is_file():
        raise ValueError(f"missing analyst report: {analyst_report_path}")

    report_obj = _load_json_obj(analyst_report_path)

    _verify_claim_refs(
        report_obj,
        report_field="analyst_report",
        claims_field="claims",
        run_dir=run_dir,
    )

    limitations_any = report_obj.get("limitations")
    if not isinstance(limitations_any, list):
        raise ValueError("analyst_report.limitations must be list")

    artifacts_any = report_obj.get("artifacts")
    if not isinstance(artifacts_any, dict):
        raise ValueError("analyst_report.artifacts must be object")
    _verify_section_evidence_artifacts(report_obj, run_dir=run_dir)

    for section in REQUIRED_SECTIONS:
        section_any = report_obj.get(section)
        if not isinstance(section_any, dict):
            raise ValueError(f"analyst_report.{section} must be object")

        evidence_paths = _walk_evidence_paths(
            cast(dict[object, object], section_any), field_path=section
        )
        for field_path, rel_path in evidence_paths:
            _validate_linked_path(run_dir, rel_path, field_path=field_path)

    for stage_name, artifact_rel in STAGE_ARTIFACTS.items():
        artifact_path = run_dir / artifact_rel
        if not artifact_path.is_file():
            raise ValueError(f"missing stage artifact for {stage_name}: {artifact_rel}")
        artifact_obj = _load_json_obj(artifact_path)
        required_schema = REQUIRED_STAGE_SCHEMAS.get(stage_name)
        if required_schema is not None:
            for field_path, raw_value in _walk_string_values(
                artifact_obj,
                field_path=artifact_rel,
            ):
                if _has_absolute_path_prefix(raw_value):
                    raise ValueError(
                        f"absolute path string not allowed at {field_path}: {raw_value!r}"
                    )

        if required_schema is not None:
            schema_version = artifact_obj.get("schema_version")
            if schema_version != required_schema:
                raise ValueError(
                    f"{artifact_rel}.schema_version != {required_schema!r}: {schema_version!r}"
                )

        for field_path, rel_path in _walk_evidence_refs(
            artifact_obj, field_path=artifact_rel
        ):
            _validate_linked_path(run_dir, rel_path, field_path=field_path)

    analyst_report_v2_path = run_dir / "report" / "analyst_report_v2.json"
    if analyst_report_v2_path.is_file():
        report_v2_obj = _load_json_obj(analyst_report_v2_path)
        _verify_claim_refs(
            report_v2_obj,
            report_field="analyst_report_v2",
            claims_field="top_risk_claims",
            run_dir=run_dir,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify AIEdge analyst report linkage for evidence and evidence_refs paths."
        )
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
        _verify_analyst_report(run_dir)
    except ValueError as exc:
        print(f"[FAIL] {exc}")
        return 1
    except Exception as exc:
        print(f"[FAIL] unexpected verifier error: {exc}")
        return 1

    print(f"[OK] analyst report linkage verified: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
