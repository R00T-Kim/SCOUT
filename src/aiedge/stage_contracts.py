from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import cast

from .stage_registry import stage_factories

_STAGE_STATUSES = {"pending", "ok", "partial", "failed", "skipped"}


def _known_stage_names() -> set[str]:
    return set(stage_factories()) | {"findings"}


def _is_run_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if value.startswith("/"):
        return False
    if re.match(r"^[A-Za-z]:\\\\", value):
        return False
    return True


def _is_sha256_hex(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _append_error(errors: list[str], path: Path, message: str) -> None:
    errors.append(f"{path.as_posix()}: {message}")


def _expect_dict(
    data: object, *, path: Path, errors: list[str]
) -> dict[str, object] | None:
    if not isinstance(data, dict):
        _append_error(errors, path, "must be a JSON object")
        return None
    return cast(dict[str, object], data)


def _require_list(
    obj: Mapping[str, object], key: str, *, path: Path, errors: list[str]
) -> list[object] | None:
    value = obj.get(key)
    if not isinstance(value, list):
        _append_error(errors, path, f"{key!r} must be a list")
        return None
    return cast(list[object], value)


def _require_dict(
    obj: Mapping[str, object], key: str, *, path: Path, errors: list[str]
) -> dict[str, object] | None:
    value = obj.get(key)
    if not isinstance(value, dict):
        _append_error(errors, path, f"{key!r} must be an object")
        return None
    return cast(dict[str, object], value)


def _validate_path_list(
    values: Iterable[object], *, path: Path, field: str, errors: list[str]
) -> None:
    for idx, item in enumerate(values):
        if not isinstance(item, str) or not _is_run_relative_path(item):
            _append_error(
                errors,
                path,
                f"{field}[{idx}] must be a run-relative path string",
            )


def _validate_evidence_items(
    values: Iterable[object], *, path: Path, field: str, errors: list[str]
) -> None:
    for idx, item in enumerate(values):
        if not isinstance(item, dict):
            _append_error(errors, path, f"{field}[{idx}] must be an object")
            continue
        item_d = cast(dict[str, object], item)
        p = item_d.get("path")
        if not isinstance(p, str) or not _is_run_relative_path(p):
            _append_error(errors, path, f"{field}[{idx}].path must be run-relative")


def _validate_stage_manifest(
    run_dir: Path, stage_dir: Path, payload: dict[str, object], errors: list[str]
) -> None:
    manifest_path = stage_dir / "stage.json"
    stage_name = stage_dir.name

    stage_name_any = payload.get("stage_name")
    if stage_name_any != stage_name:
        _append_error(
            errors,
            manifest_path,
            f"stage_name must equal directory name {stage_name!r}",
        )

    if stage_name not in _known_stage_names():
        _append_error(errors, manifest_path, f"unknown stage directory {stage_name!r}")

    contract_version = payload.get("contract_version")
    if not isinstance(contract_version, str) or not contract_version:
        _append_error(errors, manifest_path, "contract_version must be non-empty string")

    stage_identity = payload.get("stage_identity")
    if not isinstance(stage_identity, str) or not stage_identity.startswith(
        f"{stage_name}@"
    ):
        _append_error(
            errors,
            manifest_path,
            "stage_identity must be non-empty and start with '<stage_name>@'",
        )

    stage_key = payload.get("stage_key")
    if stage_name != "findings":
        if not _is_sha256_hex(stage_key):
            _append_error(errors, manifest_path, "stage_key must be 64 lowercase hex")

    attempt = payload.get("attempt")
    if not isinstance(attempt, int) or attempt < 1:
        _append_error(errors, manifest_path, "attempt must be integer >= 1")

    status = payload.get("status")
    if not isinstance(status, str) or status not in _STAGE_STATUSES:
        _append_error(
            errors, manifest_path, f"status must be one of {sorted(_STAGE_STATUSES)}"
        )

    limitations = payload.get("limitations")
    if not isinstance(limitations, list) or not all(
        isinstance(item, str) for item in limitations
    ):
        _append_error(errors, manifest_path, "limitations must be a list[str]")

    artifacts_any = payload.get("artifacts")
    if not isinstance(artifacts_any, list):
        _append_error(errors, manifest_path, "artifacts must be a list")
    else:
        for idx, item in enumerate(cast(list[object], artifacts_any)):
            if not isinstance(item, dict):
                _append_error(errors, manifest_path, f"artifacts[{idx}] must be object")
                continue
            item_d = cast(dict[str, object], item)
            rel = item_d.get("path")
            if not isinstance(rel, str) or not _is_run_relative_path(rel):
                _append_error(
                    errors, manifest_path, f"artifacts[{idx}].path must be run-relative"
                )
                continue
            if not (run_dir / rel).exists():
                _append_error(
                    errors,
                    manifest_path,
                    f"artifacts[{idx}].path missing target: {rel}",
                )
            sha_any = item_d.get("sha256")
            if sha_any is not None and not _is_sha256_hex(sha_any):
                _append_error(
                    errors,
                    manifest_path,
                    f"artifacts[{idx}].sha256 must be 64 lowercase hex or null",
                )

    if stage_name == "findings":
        return

    inputs_any = payload.get("inputs")
    if not isinstance(inputs_any, list):
        _append_error(errors, manifest_path, "inputs must be a list for registered stages")
    else:
        for idx, item in enumerate(cast(list[object], inputs_any)):
            if not isinstance(item, dict):
                _append_error(errors, manifest_path, f"inputs[{idx}] must be object")
                continue
            item_d = cast(dict[str, object], item)
            rel = item_d.get("path")
            if not isinstance(rel, str) or not _is_run_relative_path(rel):
                _append_error(errors, manifest_path, f"inputs[{idx}].path must be run-relative")
            sha_any = item_d.get("sha256")
            if not _is_sha256_hex(sha_any):
                _append_error(errors, manifest_path, f"inputs[{idx}].sha256 must be 64 lowercase hex")

    params_any = payload.get("params")
    if not isinstance(params_any, dict):
        _append_error(errors, manifest_path, "params must be an object for registered stages")

    for key in ("started_at", "finished_at"):
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            _append_error(errors, manifest_path, f"{key} must be non-empty string")
    duration_any = payload.get("duration_s")
    if not isinstance(duration_any, (int, float)) or float(duration_any) < 0.0:
        _append_error(errors, manifest_path, "duration_s must be number >= 0")


def _validate_tools_json(path: Path, payload: dict[str, object], errors: list[str]) -> None:
    if not payload:
        _append_error(errors, path, "tools.json must not be empty")
        return
    for tool_name, info_any in payload.items():
        if not isinstance(info_any, dict):
            _append_error(errors, path, f"{tool_name!r} entry must be object")
            continue
        info = cast(dict[str, object], info_any)
        for key in ("available", "required", "resolved"):
            if key not in info or not isinstance(info.get(key), bool):
                _append_error(errors, path, f"{tool_name!r}.{key} must be bool")


def _validate_structure_json(path: Path, payload: dict[str, object], errors: list[str]) -> None:
    if not isinstance(payload.get("status"), str):
        _append_error(errors, path, "status must be string")
    if not isinstance(payload.get("evidence"), list):
        _append_error(errors, path, "evidence must be list")
    if not isinstance(payload.get("discovery"), dict):
        _append_error(errors, path, "discovery must be object")


def _validate_firmware_profile_json(path: Path, payload: dict[str, object], errors: list[str]) -> None:
    if payload.get("schema_version") != 1:
        _append_error(errors, path, "schema_version must equal 1")
    for key in ("firmware_id", "os_type_guess", "emulation_feasibility"):
        if not isinstance(payload.get(key), str):
            _append_error(errors, path, f"{key} must be string")
    if not isinstance(payload.get("branch_plan"), dict):
        _append_error(errors, path, "branch_plan must be object")
    refs_any = payload.get("evidence_refs")
    if not isinstance(refs_any, list):
        _append_error(errors, path, "evidence_refs must be list")
    else:
        _validate_path_list(cast(list[object], refs_any), path=path, field="evidence_refs", errors=errors)


def _validate_inventory_json(path: Path, payload: dict[str, object], errors: list[str]) -> None:
    if not isinstance(payload.get("status"), str):
        _append_error(errors, path, "status must be string")
    summary = _require_dict(payload, "summary", path=path, errors=errors)
    if summary is not None:
        for key in ("roots_scanned", "files", "binaries", "configs", "string_hits"):
            if not isinstance(summary.get(key), int):
                _append_error(errors, path, f"summary.{key} must be int")
    for key in ("service_candidates", "services"):
        if not isinstance(payload.get(key), list):
            _append_error(errors, path, f"{key} must be list")
    roots_any = payload.get("roots")
    if roots_any is not None:
        if not isinstance(roots_any, list):
            _append_error(errors, path, "roots must be list when present")
        else:
            _validate_path_list(cast(list[object], roots_any), path=path, field="roots", errors=errors)


def _validate_string_hits_json(path: Path, payload: dict[str, object], errors: list[str]) -> None:
    counts = _require_dict(payload, "counts", path=path, errors=errors)
    if counts is not None:
        for key, value in counts.items():
            if not isinstance(value, int):
                _append_error(errors, path, f"counts[{key!r}] must be int")


def _validate_binary_analysis_json(path: Path, payload: dict[str, object], errors: list[str]) -> None:
    if not isinstance(payload.get("summary"), dict):
        _append_error(errors, path, "summary must be object")
    hits_any = payload.get("hits", payload.get("binaries", payload.get("entries")))
    if not isinstance(hits_any, list):
        _append_error(errors, path, "hits/binaries/entries must provide a list payload")


def _validate_stage_payload_with_status(
    path: Path,
    payload: dict[str, object],
    errors: list[str],
    *,
    list_field: str,
    require_summary: bool = True,
) -> None:
    if not isinstance(payload.get("status"), str):
        _append_error(errors, path, "status must be string")
    if require_summary and not isinstance(payload.get("summary"), dict):
        _append_error(errors, path, "summary must be object")
    if not isinstance(payload.get(list_field), list):
        _append_error(errors, path, f"{list_field} must be list")


def _validate_attribution_json(path: Path, payload: dict[str, object], errors: list[str]) -> None:
    if not isinstance(payload.get("status"), str):
        _append_error(errors, path, "status must be string")
    if not isinstance(payload.get("claims"), list):
        _append_error(errors, path, "claims must be list")


def _validate_dynamic_validation_json(
    path: Path, payload: dict[str, object], errors: list[str]
) -> None:
    if not isinstance(payload.get("status"), str):
        _append_error(errors, path, "status must be string")
    if not isinstance(payload.get("schema_version"), str):
        _append_error(errors, path, "schema_version must be string")
    if not isinstance(payload.get("limitations"), list):
        _append_error(errors, path, "limitations must be list")
    if not isinstance(payload.get("probes"), dict):
        _append_error(errors, path, "probes must be object")
    if not isinstance(payload.get("verification_reason_codes"), list):
        _append_error(errors, path, "verification_reason_codes must be list")


def _validate_enhanced_source_json(
    path: Path, payload: dict[str, object], errors: list[str]
) -> None:
    if not isinstance(payload.get("status"), str):
        _append_error(errors, path, "status must be string")
    if not isinstance(payload.get("schema_version"), str):
        _append_error(errors, path, "schema_version must be string")
    if not isinstance(payload.get("sources"), list):
        _append_error(errors, path, "sources must be list")


def _validate_ghidra_analysis_json(
    path: Path, payload: dict[str, object], errors: list[str]
) -> None:
    if not isinstance(payload.get("schema_version"), str):
        _append_error(errors, path, "schema_version must be string")
    if not isinstance(payload.get("limitations"), list):
        _append_error(errors, path, "limitations must be list")
    if not isinstance(payload.get("results"), list):
        _append_error(errors, path, "results must be list")


def _validate_llm_synthesis_json(
    path: Path, payload: dict[str, object], errors: list[str]
) -> None:
    if not isinstance(payload.get("status"), str):
        _append_error(errors, path, "status must be string")
    if not isinstance(payload.get("summary"), dict):
        _append_error(errors, path, "summary must be object")
    if not isinstance(payload.get("claims"), list):
        _append_error(errors, path, "claims must be list")


def _validate_llm_triage_json(path: Path, payload: dict[str, object], errors: list[str]) -> None:
    if not isinstance(payload.get("status"), str):
        _append_error(errors, path, "status must be string")
    if not isinstance(payload.get("schema_version"), str):
        _append_error(errors, path, "schema_version must be string")
    if not isinstance(payload.get("rankings"), list):
        _append_error(errors, path, "rankings must be list")


def _validate_ota_json(path: Path, payload: dict[str, object], errors: list[str]) -> None:
    for key in ("candidates", "refusal_reasons"):
        if not isinstance(payload.get(key), list):
            _append_error(errors, path, f"{key} must be list")
    if not isinstance(payload.get("limits"), dict):
        _append_error(errors, path, "limits must be object")


def _validate_ota_fs_json(path: Path, payload: dict[str, object], errors: list[str]) -> None:
    if not isinstance(payload.get("status"), str):
        _append_error(errors, path, "status must be string")
    if not isinstance(payload.get("partitions"), dict):
        _append_error(errors, path, "partitions must be object")
    evidence_any = payload.get("evidence")
    if evidence_any is not None:
        if not isinstance(evidence_any, list):
            _append_error(errors, path, "evidence must be list when present")
        else:
            _validate_evidence_items(cast(list[object], evidence_any), path=path, field="evidence", errors=errors)


def _validate_ota_payload_json(
    path: Path, payload: dict[str, object], errors: list[str]
) -> None:
    if not isinstance(payload.get("status"), str):
        _append_error(errors, path, "status must be string")
    evidence_any = payload.get("evidence")
    if evidence_any is not None:
        if not isinstance(evidence_any, list):
            _append_error(errors, path, "evidence must be list when present")
        else:
            _validate_evidence_items(cast(list[object], evidence_any), path=path, field="evidence", errors=errors)


def _validate_poc_validation_json(
    path: Path, payload: dict[str, object], errors: list[str]
) -> None:
    if not isinstance(payload.get("status"), str):
        _append_error(errors, path, "status must be string")
    if not isinstance(payload.get("checks"), list):
        _append_error(errors, path, "checks must be list")
    verification_reason_codes = payload.get("verification_reason_codes")
    if verification_reason_codes is not None and not isinstance(
        verification_reason_codes, list
    ):
        _append_error(errors, path, "verification_reason_codes must be list")


def _validate_semantic_classification_json(
    path: Path, payload: dict[str, object], errors: list[str]
) -> None:
    if not isinstance(payload.get("status"), str):
        _append_error(errors, path, "status must be string")
    if not isinstance(payload.get("schema_version"), str):
        _append_error(errors, path, "schema_version must be string")
    if not isinstance(payload.get("classifications"), list):
        _append_error(errors, path, "classifications must be list")


def _validate_web_ui_json(path: Path, payload: dict[str, object], errors: list[str]) -> None:
    if not isinstance(payload.get("status"), str):
        _append_error(errors, path, "status must be string")
    if not isinstance(payload.get("summary"), dict):
        _append_error(errors, path, "summary must be object")
    for key in (
        "js_security_patterns",
        "html_security_patterns",
        "api_spec_files",
        "web_content_roots",
    ):
        if not isinstance(payload.get(key), list):
            _append_error(errors, path, f"{key} must be list")


def _validate_firmware_lineage_json(
    path: Path, payload: dict[str, object], errors: list[str]
) -> None:
    if not isinstance(payload.get("schema_version"), int):
        _append_error(errors, path, "schema_version must be int")
    for key in ("nodes", "edges", "limitations"):
        if not isinstance(payload.get(key), list):
            _append_error(errors, path, f"{key} must be list")
    refs_any = payload.get("evidence_refs")
    if refs_any is not None:
        if not isinstance(refs_any, list):
            _append_error(errors, path, "evidence_refs must be list when present")
        else:
            _validate_path_list(cast(list[object], refs_any), path=path, field="evidence_refs", errors=errors)


def _validate_firmware_lineage_diff_json(
    path: Path, payload: dict[str, object], errors: list[str]
) -> None:
    if not isinstance(payload.get("schema_version"), int):
        _append_error(errors, path, "schema_version must be int")
    if not isinstance(payload.get("diff_summary"), dict):
        _append_error(errors, path, "diff_summary must be object")
    if not isinstance(payload.get("limitations"), list):
        _append_error(errors, path, "limitations must be list")


def _validate_source_sink_graph_json(path: Path, payload: dict[str, object], errors: list[str]) -> None:
    if not isinstance(payload.get("summary"), dict):
        _append_error(errors, path, "summary must be object")
    if not isinstance(payload.get("paths"), list):
        _append_error(errors, path, "paths must be list")


def _validate_sbom_json(path: Path, payload: dict[str, object], errors: list[str]) -> None:
    if payload.get("bomFormat") != "CycloneDX":
        _append_error(errors, path, "bomFormat must equal 'CycloneDX'")
    if not isinstance(payload.get("specVersion"), str):
        _append_error(errors, path, "specVersion must be string")
    if not isinstance(payload.get("components"), list):
        _append_error(errors, path, "components must be list")


def _validate_cpe_index_json(path: Path, payload: dict[str, object], errors: list[str]) -> None:
    if not isinstance(payload.get("schema_version"), (int, str)):
        _append_error(errors, path, "schema_version must be int or string")
    if "components" not in payload:
        _append_error(errors, path, "components key must exist")


def _validate_cve_matches_json(path: Path, payload: dict[str, object], errors: list[str]) -> None:
    if not isinstance(payload.get("summary"), dict):
        _append_error(errors, path, "summary must be object")
    for key in ("matches", "finding_candidates"):
        if not isinstance(payload.get(key), list):
            _append_error(errors, path, f"{key} must be list")


def _validate_findings_json(path: Path, payload: dict[str, object], errors: list[str]) -> None:
    if not isinstance(payload.get("status"), str):
        _append_error(errors, path, "status must be string")
    findings_any = payload.get("findings")
    if not isinstance(findings_any, list):
        _append_error(errors, path, "findings must be list")
    for key in ("category_counts", "priority_bucket_counts", "tier_counts"):
        value = payload.get(key)
        if value is not None and not isinstance(value, dict):
            _append_error(errors, path, f"{key} must be object when present")
    evidence_any = payload.get("evidence")
    if not isinstance(evidence_any, list):
        _append_error(errors, path, "evidence must be list")
    else:
        _validate_evidence_items(cast(list[object], evidence_any), path=path, field="evidence", errors=errors)


def _validate_graph_json(path: Path, payload: dict[str, object], errors: list[str]) -> None:
    if not isinstance(payload.get("summary"), dict):
        _append_error(errors, path, "summary must be object")
    if not isinstance(payload.get("nodes"), list):
        _append_error(errors, path, "nodes must be list")
    if not isinstance(payload.get("edges"), list):
        _append_error(errors, path, "edges must be list")


_ARTIFACT_VALIDATORS: dict[str, Callable[[Path, dict[str, object], list[str]], None]] = {
    "attribution.json": _validate_attribution_json,
    "tools.json": _validate_tools_json,
    "structure.json": _validate_structure_json,
    "firmware_profile.json": _validate_firmware_profile_json,
    "inventory.json": _validate_inventory_json,
    "string_hits.json": _validate_string_hits_json,
    "binary_analysis.json": _validate_binary_analysis_json,
    "dynamic_validation.json": _validate_dynamic_validation_json,
    "endpoints.json": lambda p, d, e: _validate_stage_payload_with_status(p, d, e, list_field="endpoints"),
    "sources.json": _validate_enhanced_source_json,
    "ghidra_analysis.json": _validate_ghidra_analysis_json,
    "surfaces.json": lambda p, d, e: _validate_stage_payload_with_status(p, d, e, list_field="surfaces"),
    "source_sink_graph.json": _validate_source_sink_graph_json,
    "attack_surface.json": lambda p, d, e: _validate_stage_payload_with_status(p, d, e, list_field="attack_surface"),
    "functional_spec.json": lambda p, d, e: _validate_stage_payload_with_status(p, d, e, list_field="functional_spec"),
    "threat_model.json": lambda p, d, e: _validate_stage_payload_with_status(p, d, e, list_field="threats"),
    "llm_synthesis.json": _validate_llm_synthesis_json,
    "triage.json": _validate_llm_triage_json,
    "ota.json": _validate_ota_json,
    "fs.json": _validate_ota_fs_json,
    "payload.json": _validate_ota_payload_json,
    "poc_validation.json": _validate_poc_validation_json,
    "classified_functions.json": _validate_semantic_classification_json,
    "web_ui.json": _validate_web_ui_json,
    "lineage.json": _validate_firmware_lineage_json,
    "lineage_diff.json": _validate_firmware_lineage_diff_json,
    "sbom.json": _validate_sbom_json,
    "cpe_index.json": _validate_cpe_index_json,
    "cve_matches.json": _validate_cve_matches_json,
    "alerts.json": lambda p, d, e: _validate_stage_payload_with_status(p, d, e, list_field="alerts", require_summary=False),
    "taint_results.json": lambda p, d, e: _validate_stage_payload_with_status(p, d, e, list_field="results", require_summary=False),
    "verified_alerts.json": lambda p, d, e: _validate_stage_payload_with_status(p, d, e, list_field="verified_alerts", require_summary=False),
    "triaged_findings.json": lambda p, d, e: _validate_stage_payload_with_status(p, d, e, list_field="triaged_findings", require_summary=False),
    "findings.json": _validate_findings_json,
    "communication_graph.json": _validate_graph_json,
}


def validate_run_stage_outputs(run_dir: Path) -> list[str]:
    errors: list[str] = []
    if not run_dir.is_dir():
        return [f"{run_dir.as_posix()}: run directory not found"]

    stages_dir = run_dir / "stages"
    if not stages_dir.is_dir():
        return [f"{stages_dir.as_posix()}: stages directory not found"]

    known_stage_names = _known_stage_names()
    for stage_dir in sorted(p for p in stages_dir.iterdir() if p.is_dir()):
        manifest_path = stage_dir / "stage.json"
        if not manifest_path.is_file():
            if stage_dir.name in known_stage_names:
                _append_error(errors, manifest_path, "missing stage.json")
            continue

        try:
            manifest_any = cast(object, json.loads(manifest_path.read_text(encoding="utf-8")))
        except Exception as exc:
            _append_error(errors, manifest_path, f"invalid JSON ({exc})")
            continue

        manifest = _expect_dict(manifest_any, path=manifest_path, errors=errors)
        if manifest is None:
            continue
        _validate_stage_manifest(run_dir, stage_dir, manifest, errors)

        for artifact_path in sorted(
            p
            for p in stage_dir.iterdir()
            if p.is_file() and p.name != "stage.json" and p.suffix == ".json"
        ):
            try:
                payload_any = cast(object, json.loads(artifact_path.read_text(encoding="utf-8")))
            except Exception as exc:
                _append_error(errors, artifact_path, f"invalid JSON ({exc})")
                continue
            payload = _expect_dict(payload_any, path=artifact_path, errors=errors)
            if payload is None:
                continue
            validator = _ARTIFACT_VALIDATORS.get(artifact_path.name)
            if validator is not None:
                validator(artifact_path, payload, errors)

    return errors
