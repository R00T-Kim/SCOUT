from __future__ import annotations

import re
from typing import TypeAlias, cast

from .exploit_tiering import (
    TIER_EVIDENCE_MISSING,
    TIER_HIGH_SEVERITY_REQUIRES_T2,
    TIER_INVALID_VALUE,
    default_exploitability_tier,
    exploitability_tier_rank,
    has_exploit_artifact_reference,
    is_valid_exploitability_tier,
)

JsonPrimitive: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]

REPORT_SCHEMA_VERSION = "1.1"

ANALYST_REPORT_SCHEMA_VERSION = "0.1"
ANALYST_DIGEST_SCHEMA_VERSION = "analyst_digest-v1"

ANALYST_DIGEST_VERDICTS: tuple[str, ...] = (
    "VERIFIED",
    "ATTEMPTED_INCONCLUSIVE",
    "NOT_ATTEMPTED",
    "NOT_APPLICABLE",
)
_ANALYST_DIGEST_VERDICTS_SET: frozenset[str] = frozenset(ANALYST_DIGEST_VERDICTS)
ANALYST_DIGEST_AGGREGATION_RULE = "worst_state_precedence_v1"
ANALYST_DIGEST_STATE_PRECEDENCE: tuple[str, ...] = (
    "ATTEMPTED_INCONCLUSIVE",
    "NOT_ATTEMPTED",
    "VERIFIED",
    "NOT_APPLICABLE",
)
_ANALYST_DIGEST_STATE_RANK: dict[str, int] = {
    state: idx for idx, state in enumerate(ANALYST_DIGEST_STATE_PRECEDENCE)
}
ANALYST_DIGEST_REASON_CODES: tuple[str, ...] = (
    "ATTEMPTED_EVIDENCE_TAMPERED",
    "ATTEMPTED_VERIFIER_FAILED",
    "ATTEMPTED_REPRO_INSUFFICIENT",
    "ATTEMPTED_EVIDENCE_INCOMPLETE",
    "NOT_ATTEMPTED_REQUIRED_VERIFIER_MISSING",
    "NOT_ATTEMPTED_DYNAMIC_VALIDATION_MISSING",
    "NOT_ATTEMPTED_RUN_INCOMPLETE",
    "NOT_APPLICABLE_NO_RELEVANT_FINDINGS",
    "NOT_APPLICABLE_PLATFORM_UNSUPPORTED",
    "VERIFIED_ALL_GATES_PASSED",
    "VERIFIED_REPRO_3_OF_3",
)
_ANALYST_DIGEST_REASON_SET: frozenset[str] = frozenset(ANALYST_DIGEST_REASON_CODES)
_ANALYST_DIGEST_REASON_RANK: dict[str, int] = {
    code: idx for idx, code in enumerate(ANALYST_DIGEST_REASON_CODES)
}


_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_DISPOSITIONS = {"confirmed", "suspected"}
_STAGE_STATUSES = {"pending", "ok", "partial", "failed", "skipped"}
REQUIRED_FINAL_STAGES: tuple[str, ...] = (
    "tooling",
    "extraction",
    "inventory",
    "findings",
)
TERMINAL_STAGE_STATUSES: frozenset[str] = frozenset(
    {"ok", "partial", "failed", "skipped"}
)
_COMPLETENESS_STATUSES = {"complete", "incomplete"}


def _tier_error(token: str, target: str) -> str:
    return f"{token}: {target}"


def _is_run_relative_path(p: str) -> bool:
    if not p:
        return False
    if p.startswith("/"):
        return False
    if re.match(r"^[A-Za-z]:\\\\", p):
        return False
    return True


def _as_float01(v: object) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        x = float(v)
    elif isinstance(v, str):
        try:
            x = float(v)
        except ValueError:
            return None
    else:
        return None
    if 0.0 <= x <= 1.0:
        return x
    return None


def _is_safe_ascii_text(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if not value.isascii():
        return False
    return all(32 <= ord(ch) <= 126 for ch in value)


def _is_sha256_hex(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _validate_analyst_digest_reason_codes(
    *, value: object, path: str, errors: list[str]
) -> list[str]:
    if not isinstance(value, list) or not value:
        errors.append(f"{path} must be non-empty list")
        return []
    codes: list[str] = []
    for i, code_any in enumerate(cast(list[object], value)):
        if not isinstance(code_any, str) or code_any not in _ANALYST_DIGEST_REASON_SET:
            errors.append(
                f"{path}[{i}] must be one of {sorted(_ANALYST_DIGEST_REASON_SET)}"
            )
            continue
        codes.append(code_any)
    if len(codes) != len(set(codes)):
        errors.append(f"{path} must not contain duplicates")
    if codes:
        ranked = [_ANALYST_DIGEST_REASON_RANK[c] for c in codes]
        if ranked != sorted(ranked):
            errors.append(f"{path} must be sorted by reason precedence")
    return codes


def validate_report(report: object) -> list[str]:
    errors: list[str] = []
    if not isinstance(report, dict):
        return ["report must be an object"]

    r = cast(dict[str, object], report)

    def req_key(key: str, typ: type) -> object | None:
        if key not in r:
            errors.append(f"missing top-level key: {key}")
            return None
        v = r.get(key)
        if not isinstance(v, typ):
            errors.append(f"top-level '{key}' must be {typ.__name__}")
            return None
        return v

    schema_version = req_key("schema_version", str)
    if isinstance(schema_version, str) and not schema_version:
        errors.append("schema_version must be non-empty")

    _ = req_key("overview", dict)

    integrity_any = r.get("ingestion_integrity")
    if integrity_any is not None:
        if not isinstance(integrity_any, dict):
            errors.append("ingestion_integrity must be object")
        else:
            integrity = cast(dict[str, object], integrity_any)

            source_any = integrity.get("source_input")
            if not isinstance(source_any, dict):
                errors.append("ingestion_integrity.source_input must be object")

            analyzed_any = integrity.get("analyzed_input")
            if not isinstance(analyzed_any, dict):
                errors.append("ingestion_integrity.analyzed_input must be object")

            overview_link_any = integrity.get("overview_link")
            if not isinstance(overview_link_any, dict):
                errors.append("ingestion_integrity.overview_link must be object")
            else:
                overview_link = cast(dict[str, object], overview_link_any)
                link_sha = overview_link.get("input_sha256_matches_analyzed")
                if not isinstance(link_sha, bool):
                    errors.append(
                        "ingestion_integrity.overview_link.input_sha256_matches_analyzed must be bool"
                    )
                link_size = overview_link.get("input_size_bytes_matches_analyzed")
                if not isinstance(link_size, bool):
                    errors.append(
                        "ingestion_integrity.overview_link.input_size_bytes_matches_analyzed must be bool"
                    )

            stage_any = integrity.get("stage_consumption")
            if not isinstance(stage_any, dict):
                errors.append("ingestion_integrity.stage_consumption must be object")
            else:
                stage_consumption = cast(dict[str, object], stage_any)
                manifest_any = stage_consumption.get("required_stage_manifest_paths")
                if not isinstance(manifest_any, dict):
                    errors.append(
                        "ingestion_integrity.stage_consumption.required_stage_manifest_paths must be object"
                    )
                evidence_any = stage_consumption.get("required_stage_evidence_paths")
                if not isinstance(evidence_any, dict):
                    errors.append(
                        "ingestion_integrity.stage_consumption.required_stage_evidence_paths must be object"
                    )

    completeness_any = r.get("report_completeness")
    if completeness_any is not None:
        if not isinstance(completeness_any, dict):
            errors.append("report_completeness must be object")
        else:
            completeness = cast(dict[str, object], completeness_any)
            gate = completeness.get("gate_passed")
            if not isinstance(gate, bool):
                errors.append("report_completeness.gate_passed must be bool")
            status_any = completeness.get("status")
            if (
                not isinstance(status_any, str)
                or status_any not in _COMPLETENESS_STATUSES
            ):
                errors.append(
                    f"report_completeness.status must be one of {sorted(_COMPLETENESS_STATUSES)}"
                )
            reasons_any = completeness.get("reasons")
            if not isinstance(reasons_any, list) or not all(
                isinstance(x, str) and x for x in cast(list[object], reasons_any)
            ):
                errors.append(
                    "report_completeness.reasons must be a list of non-empty strings"
                )
            missing_any = completeness.get("missing_required_stage_inputs")
            if not isinstance(missing_any, list) or not all(
                isinstance(x, str) and x for x in cast(list[object], missing_any)
            ):
                errors.append(
                    "report_completeness.missing_required_stage_inputs must be a list of non-empty strings"
                )

    limitations = req_key("limitations", list)
    if isinstance(limitations, list):
        if not all(isinstance(x, str) and x for x in cast(list[object], limitations)):
            errors.append("limitations must be a list of non-empty strings")

    findings = req_key("findings", list)
    if isinstance(findings, list):
        for i, item_any in enumerate(cast(list[object], findings)):
            if not isinstance(item_any, dict):
                errors.append(f"findings[{i}] must be an object")
                continue
            item = cast(dict[str, object], item_any)
            fid = item.get("id")
            if not isinstance(fid, str) or not fid:
                errors.append(f"findings[{i}].id must be non-empty string")
            title = item.get("title")
            if not isinstance(title, str) or not title:
                errors.append(f"findings[{i}].title must be non-empty string")
            sev = item.get("severity")
            if not isinstance(sev, str) or sev not in _SEVERITIES:
                errors.append(
                    f"findings[{i}].severity must be one of {sorted(_SEVERITIES)}"
                )
            conf = _as_float01(item.get("confidence"))
            if conf is None:
                errors.append(f"findings[{i}].confidence must be float in 0..1")
            disp = item.get("disposition")
            if not isinstance(disp, str) or disp not in _DISPOSITIONS:
                errors.append(
                    f"findings[{i}].disposition must be one of {sorted(_DISPOSITIONS)}"
                )
            tier_any = item.get("exploitability_tier")
            if tier_any is not None and not is_valid_exploitability_tier(tier_any):
                errors.append(
                    _tier_error(
                        TIER_INVALID_VALUE,
                        f"findings[{i}].exploitability_tier",
                    )
                )
            tier = (
                cast(str, tier_any)
                if is_valid_exploitability_tier(tier_any)
                else default_exploitability_tier(disposition=disp)
            )
            tier_rank = exploitability_tier_rank(tier)
            ev = item.get("evidence")
            if not isinstance(ev, list) or not ev:
                errors.append(f"findings[{i}].evidence must be non-empty list")
                continue

            if (
                tier_rank is not None
                and tier_rank >= 2
                and not has_exploit_artifact_reference(cast(list[object], ev))
            ):
                errors.append(
                    _tier_error(
                        TIER_EVIDENCE_MISSING,
                        f"findings[{i}] requires exploit artifact evidence for tier '{tier}'",
                    )
                )

            if (
                isinstance(sev, str)
                and sev in {"high", "critical"}
                and disp == "confirmed"
                and (tier_rank is None or tier_rank < 2)
            ):
                errors.append(
                    _tier_error(
                        TIER_HIGH_SEVERITY_REQUIRES_T2,
                        f"findings[{i}] confirmed {sev} requires tier dynamic_repro or exploitability_assessed",
                    )
                )

            for j, ev_item_any in enumerate(cast(list[object], ev)):
                if not isinstance(ev_item_any, dict):
                    errors.append(f"findings[{i}].evidence[{j}] must be object")
                    continue
                ev_item = cast(dict[str, object], ev_item_any)
                allowed_fields = {"path", "note", "snippet", "snippet_sha256"}
                for key in ev_item.keys():
                    if key not in allowed_fields:
                        errors.append(
                            f"findings[{i}].evidence[{j}] contains unsupported field: {key}"
                        )
                path_s = ev_item.get("path")
                if not isinstance(path_s, str) or not _is_run_relative_path(path_s):
                    errors.append(
                        f"findings[{i}].evidence[{j}].path must be run-relative path"
                    )
                elif not _is_safe_ascii_text(path_s):
                    errors.append(
                        f"findings[{i}].evidence[{j}].path must be non-empty printable ASCII"
                    )

                note_any = ev_item.get("note")
                if note_any is not None and not _is_safe_ascii_text(note_any):
                    errors.append(
                        f"findings[{i}].evidence[{j}].note must be non-empty printable ASCII string when present"
                    )

                snippet_any = ev_item.get("snippet")
                if snippet_any is not None:
                    if not _is_safe_ascii_text(snippet_any):
                        errors.append(
                            f"findings[{i}].evidence[{j}].snippet must be non-empty printable ASCII string"
                        )
                    snippet_sha_any = ev_item.get("snippet_sha256")
                    if not _is_safe_ascii_text(snippet_sha_any):
                        errors.append(
                            f"findings[{i}].evidence[{j}].snippet_sha256 must be non-empty printable ASCII string when snippet is present"
                        )

                snippet_sha_any = ev_item.get("snippet_sha256")
                if snippet_sha_any is not None and not _is_safe_ascii_text(
                    snippet_sha_any
                ):
                    errors.append(
                        f"findings[{i}].evidence[{j}].snippet_sha256 must be non-empty printable ASCII string when present"
                    )

    extraction = req_key("extraction", dict)
    if isinstance(extraction, dict):
        extraction = cast(dict[str, object], extraction)
        st = extraction.get("status")
        if not isinstance(st, str) or st not in _STAGE_STATUSES:
            errors.append(f"extraction.status must be one of {sorted(_STAGE_STATUSES)}")
        conf = _as_float01(extraction.get("confidence"))
        if conf is None:
            errors.append("extraction.confidence must be float in 0..1")
        summary = extraction.get("summary")
        if not isinstance(summary, dict):
            errors.append("extraction.summary must be object")
        ev = extraction.get("evidence")
        if not isinstance(ev, list):
            errors.append("extraction.evidence must be list")
        else:
            for i, ev_item_any in enumerate(cast(list[object], ev)):
                if not isinstance(ev_item_any, dict):
                    errors.append(f"extraction.evidence[{i}] must be object")
                    continue
                ev_item = cast(dict[str, object], ev_item_any)
                path_s = ev_item.get("path")
                if not isinstance(path_s, str) or not _is_run_relative_path(path_s):
                    errors.append(
                        f"extraction.evidence[{i}].path must be run-relative path"
                    )

    inventory = req_key("inventory", dict)
    if isinstance(inventory, dict):
        inventory = cast(dict[str, object], inventory)
        st = inventory.get("status")
        if not isinstance(st, str) or st not in _STAGE_STATUSES:
            errors.append(f"inventory.status must be one of {sorted(_STAGE_STATUSES)}")

        summary = inventory.get("summary")
        if not isinstance(summary, dict):
            errors.append("inventory.summary must be object")
        else:
            summary = cast(dict[str, object], summary)
            for k in [
                "roots_scanned",
                "files",
                "binaries",
                "configs",
                "string_hits",
            ]:
                v = summary.get(k)
                if not isinstance(v, int) or v < 0:
                    errors.append(f"inventory.summary.{k} must be non-negative int")

        ev = inventory.get("evidence")
        if not isinstance(ev, list):
            errors.append("inventory.evidence must be list")
        else:
            for i, ev_item_any in enumerate(cast(list[object], ev)):
                if not isinstance(ev_item_any, dict):
                    errors.append(f"inventory.evidence[{i}] must be object")
                    continue
                ev_item = cast(dict[str, object], ev_item_any)
                path_s = ev_item.get("path")
                if not isinstance(path_s, str) or not _is_run_relative_path(path_s):
                    errors.append(
                        f"inventory.evidence[{i}].path must be run-relative path"
                    )

        candidates = inventory.get("service_candidates")
        if not isinstance(candidates, list):
            errors.append("inventory.service_candidates must be list")
        else:
            for i, cand_any in enumerate(cast(list[object], candidates)):
                if not isinstance(cand_any, dict):
                    errors.append(f"inventory.service_candidates[{i}] must be object")
                    continue
                cand = cast(dict[str, object], cand_any)
                name = cand.get("name")
                if not isinstance(name, str) or not name:
                    errors.append(
                        f"inventory.service_candidates[{i}].name must be non-empty string"
                    )
                kind = cand.get("kind")
                if not isinstance(kind, str) or not kind:
                    errors.append(
                        f"inventory.service_candidates[{i}].kind must be non-empty string"
                    )
                conf = _as_float01(cand.get("confidence"))
                if conf is None:
                    errors.append(
                        f"inventory.service_candidates[{i}].confidence must be float in 0..1"
                    )
                ev = cand.get("evidence")
                if not isinstance(ev, list) or not ev:
                    errors.append(
                        f"inventory.service_candidates[{i}].evidence must be non-empty list"
                    )
                    continue
                ev0 = cast(list[object], ev)[0]
                if isinstance(ev0, dict):
                    path_s = cast(dict[str, object], ev0).get("path")
                    if not isinstance(path_s, str) or not _is_run_relative_path(path_s):
                        errors.append(
                            f"inventory.service_candidates[{i}].evidence[0].path must be run-relative path"
                        )
                else:
                    errors.append(
                        f"inventory.service_candidates[{i}].evidence[0] must be object"
                    )

        services = inventory.get("services")
        if not isinstance(services, list):
            errors.append("inventory.services must be list")

    llm = req_key("llm", dict)
    if isinstance(llm, dict):
        pass

    llm_synthesis = req_key("llm_synthesis", dict)
    if isinstance(llm_synthesis, dict):
        llm_synthesis_obj = cast(dict[str, object], llm_synthesis)
        st = llm_synthesis_obj.get("status")
        if not isinstance(st, str) or st not in _STAGE_STATUSES:
            errors.append(
                f"llm_synthesis.status must be one of {sorted(_STAGE_STATUSES)}"
            )
        claims_any = llm_synthesis_obj.get("claims")
        if not isinstance(claims_any, list):
            errors.append("llm_synthesis.claims must be list")
        else:
            for i, claim_any in enumerate(cast(list[object], claims_any)):
                if not isinstance(claim_any, dict):
                    errors.append(f"llm_synthesis.claims[{i}] must be object")
                    continue
                claim = cast(dict[str, object], claim_any)
                claim_type_any = claim.get("claim_type")
                if not isinstance(claim_type_any, str) or not claim_type_any:
                    errors.append(
                        f"llm_synthesis.claims[{i}].claim_type must be non-empty string"
                    )
                if "value" not in claim:
                    errors.append(f"llm_synthesis.claims[{i}].value is required")
                conf = _as_float01(claim.get("confidence"))
                if conf is None:
                    errors.append(
                        f"llm_synthesis.claims[{i}].confidence must be float in 0..1"
                    )
                tier_any = claim.get("exploitability_tier")
                if tier_any is not None and not is_valid_exploitability_tier(tier_any):
                    errors.append(
                        _tier_error(
                            TIER_INVALID_VALUE,
                            f"llm_synthesis.claims[{i}].exploitability_tier",
                        )
                    )
                tier = (
                    cast(str, tier_any)
                    if is_valid_exploitability_tier(tier_any)
                    else default_exploitability_tier(disposition="confirmed")
                )
                tier_rank = exploitability_tier_rank(tier)
                refs_any = claim.get("evidence_refs")
                if not isinstance(refs_any, list) or not refs_any:
                    errors.append(
                        f"llm_synthesis.claims[{i}].evidence_refs must be non-empty list"
                    )
                    continue

                if (
                    tier_rank is not None
                    and tier_rank >= 2
                    and not has_exploit_artifact_reference(cast(list[object], refs_any))
                ):
                    errors.append(
                        _tier_error(
                            TIER_EVIDENCE_MISSING,
                            (
                                "llm_synthesis.claims"
                                f"[{i}] requires exploit artifact refs for tier '{tier}'"
                            ),
                        )
                    )

                for j, ref_any in enumerate(cast(list[object], refs_any)):
                    if not isinstance(ref_any, str) or not _is_run_relative_path(
                        ref_any
                    ):
                        errors.append(
                            f"llm_synthesis.claims[{i}].evidence_refs[{j}] must be run-relative path"
                        )

        evidence_any = llm_synthesis_obj.get("evidence")
        if not isinstance(evidence_any, list):
            errors.append("llm_synthesis.evidence must be list")
        else:
            for i, ev_item_any in enumerate(cast(list[object], evidence_any)):
                if not isinstance(ev_item_any, dict):
                    errors.append(f"llm_synthesis.evidence[{i}] must be object")
                    continue
                ev_item = cast(dict[str, object], ev_item_any)
                path_s = ev_item.get("path")
                if not isinstance(path_s, str) or not _is_run_relative_path(path_s):
                    errors.append(
                        f"llm_synthesis.evidence[{i}].path must be run-relative path"
                    )

    poc_validation_any = r.get("poc_validation")
    if poc_validation_any is not None:
        if not isinstance(poc_validation_any, dict):
            errors.append("poc_validation must be object")
        else:
            poc_validation = cast(dict[str, object], poc_validation_any)
            st = poc_validation.get("status")
            if not isinstance(st, str) or st not in _STAGE_STATUSES:
                errors.append(
                    f"poc_validation.status must be one of {sorted(_STAGE_STATUSES)}"
                )
            ev = poc_validation.get("evidence")
            if not isinstance(ev, list):
                errors.append("poc_validation.evidence must be list")
            else:
                for i, ev_item_any in enumerate(cast(list[object], ev)):
                    if not isinstance(ev_item_any, dict):
                        errors.append(f"poc_validation.evidence[{i}] must be object")
                        continue
                    ev_item = cast(dict[str, object], ev_item_any)
                    path_s = ev_item.get("path")
                    if not isinstance(path_s, str) or not _is_run_relative_path(path_s):
                        errors.append(
                            f"poc_validation.evidence[{i}].path must be run-relative path"
                        )

    run_completion_any = r.get("run_completion")
    if run_completion_any is not None:
        if not isinstance(run_completion_any, dict):
            errors.append("run_completion must be object")
        else:
            run_completion = cast(dict[str, object], run_completion_any)
            is_final = run_completion.get("is_final")
            if not isinstance(is_final, bool):
                errors.append("run_completion.is_final must be bool")
            is_partial = run_completion.get("is_partial")
            if not isinstance(is_partial, bool):
                errors.append("run_completion.is_partial must be bool")
            reason = run_completion.get("reason")
            if not isinstance(reason, str):
                errors.append("run_completion.reason must be string")
            conclusion_ready = run_completion.get("conclusion_ready")
            if conclusion_ready is not None and not isinstance(conclusion_ready, bool):
                errors.append("run_completion.conclusion_ready must be bool")
            conclusion_note = run_completion.get("conclusion_note")
            if conclusion_note is not None and not isinstance(conclusion_note, str):
                errors.append("run_completion.conclusion_note must be string")

            required_any = run_completion.get("required_stage_statuses")
            if not isinstance(required_any, dict):
                errors.append("run_completion.required_stage_statuses must be object")
            else:
                required = cast(dict[str, object], required_any)
                for stage_name in REQUIRED_FINAL_STAGES:
                    st = required.get(stage_name)
                    if not isinstance(st, str) or st not in _STAGE_STATUSES:
                        errors.append(
                            f"run_completion.required_stage_statuses.{stage_name} must be one of {sorted(_STAGE_STATUSES)}"
                        )

    return errors


def empty_report() -> dict[str, JsonValue]:
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "overview": {},
        "extraction": {
            "status": "pending",
            "confidence": 0.0,
            "summary": {
                "tool": "binwalk",
                "binwalk_available": False,
                "extracted_dir": "stages/extraction/_firmware.bin.extracted",
                "extracted_file_count": 0,
            },
            "evidence": [],
            "reasons": [],
            "details": {},
        },
        "inventory": {
            "status": "pending",
            "summary": {
                "roots_scanned": 0,
                "files": 0,
                "binaries": 0,
                "configs": 0,
                "string_hits": 0,
            },
            "evidence": [],
            "service_candidates": [],
            "services": [],
        },
        "endpoints": {
            "status": "pending",
            "summary": {
                "roots_scanned": 0,
                "files_scanned": 0,
                "endpoints": 0,
                "matches_seen": 0,
                "classification": "candidate",
                "observation": "static_reference",
            },
            "evidence": [],
            "endpoints": [],
        },
        "surfaces": {
            "status": "pending",
            "summary": {
                "service_candidates_seen": 0,
                "surfaces": 0,
                "unknowns": 0,
                "classification": "candidate",
                "observation": "static_reference",
            },
            "evidence": [],
            "surfaces": [],
            "unknowns": [],
        },
        "graph": {
            "status": "pending",
            "summary": {
                "nodes": 0,
                "edges": 0,
                "components": 0,
                "endpoints": 0,
                "surfaces": 0,
                "vendors": 0,
                "classification": "candidate",
                "observation": "static_reference",
            },
            "evidence": [],
            "nodes": [],
            "edges": [],
            "details": {},
        },
        "attack_surface": {
            "status": "pending",
            "summary": {
                "surfaces": 0,
                "endpoints": 0,
                "graph_nodes": 0,
                "graph_edges": 0,
                "attack_surface_items": 0,
                "unknowns": 0,
                "classification": "candidate",
                "observation": "static_reference",
            },
            "evidence": [],
            "attack_surface": [],
            "unknowns": [],
            "details": {},
        },
        "functional_spec": {
            "status": "pending",
            "summary": {
                "components": 0,
                "components_with_inputs": 0,
                "components_with_endpoints": 0,
                "classification": "candidate",
                "observation": "deterministic_static_inference",
            },
            "evidence": [],
            "functional_spec": [],
            "details": {},
        },
        "threat_model": {
            "status": "pending",
            "summary": {
                "taxonomy": [
                    "spoofing",
                    "tampering",
                    "repudiation",
                    "information_disclosure",
                    "denial_of_service",
                    "elevation_of_privilege",
                ],
                "attack_surface_items": 0,
                "threats": 0,
                "assumptions": 0,
                "mitigations": 0,
                "unknowns": 0,
                "classification": "candidate",
                "observation": "deterministic_static_inference",
            },
            "evidence": [],
            "threats": [],
            "assumptions": [],
            "mitigations": [],
            "unknowns": [],
            "details": {},
        },
        "poc_validation": {
            "status": "pending",
            "evidence": [],
            "details": {},
        },
        "findings": [],
        "limitations": [],
        "llm": {},
        "llm_synthesis": {
            "status": "pending",
            "summary": {
                "input_artifacts": 0,
                "candidate_claims": 0,
                "claims_emitted": 0,
                "claims_dropped": 0,
                "max_claims": 0,
                "bounded_output": True,
            },
            "claims": [],
            "reason": "",
            "evidence": [],
            "details": {},
        },
        "ingestion_integrity": {
            "source_input": {},
            "analyzed_input": {},
            "overview_link": {
                "input_sha256_matches_analyzed": False,
                "input_size_bytes_matches_analyzed": False,
            },
            "stage_consumption": {
                "required_stage_manifest_paths": {},
                "required_stage_evidence_paths": {},
            },
        },
        "report_completeness": {
            "gate_passed": False,
            "status": "incomplete",
            "reasons": ["analysis not finalized"],
            "missing_required_stage_inputs": [],
        },
        "run_completion": {
            "is_final": False,
            "is_partial": True,
            "reason": "initialized report; analysis not finalized",
            "conclusion_ready": False,
            "conclusion_note": "Analysis incomplete; conclusions are provisional.",
            "required_stage_statuses": {
                "tooling": "pending",
                "extraction": "pending",
                "inventory": "pending",
                "findings": "pending",
            },
        },
    }


def validate_analyst_report(report: object) -> list[str]:
    errors: list[str] = []
    if not isinstance(report, dict):
        return ["analyst_report must be an object"]

    r = cast(dict[str, object], report)

    def req_key(key: str, typ: type) -> object | None:
        if key not in r:
            errors.append(f"missing top-level key: {key}")
            return None
        v = r.get(key)
        if not isinstance(v, typ):
            errors.append(f"top-level '{key}' must be {typ.__name__}")
            return None
        return v

    schema_version = req_key("schema_version", str)
    if schema_version != ANALYST_REPORT_SCHEMA_VERSION:
        errors.append(f"schema_version must equal {ANALYST_REPORT_SCHEMA_VERSION!r}")

    claims_any = req_key("claims", list)
    if isinstance(claims_any, list):
        for i, claim_any in enumerate(cast(list[object], claims_any)):
            if not isinstance(claim_any, dict):
                errors.append(f"claims[{i}] must be an object")
                continue
            claim = cast(dict[str, object], claim_any)

            ct = claim.get("claim_type")
            if not isinstance(ct, str) or not ct:
                errors.append(f"claims[{i}].claim_type must be non-empty string")

            if "value" not in claim:
                errors.append(f"claims[{i}].value is required")

            conf = _as_float01(claim.get("confidence"))
            if conf is None:
                errors.append(f"claims[{i}].confidence must be float in 0..1")

            ev_any = claim.get("evidence_refs")
            if not isinstance(ev_any, list) or not ev_any:
                errors.append(f"claims[{i}].evidence_refs must be non-empty list")
            else:
                for j, ev_item_any in enumerate(cast(list[object], ev_any)):
                    if not isinstance(ev_item_any, str) or not _is_run_relative_path(
                        ev_item_any
                    ):
                        errors.append(
                            f"claims[{i}].evidence_refs[{j}] must be run-relative path"
                        )

            alt_any = claim.get("alternatives_considered")
            if alt_any is not None and not isinstance(alt_any, list):
                errors.append(f"claims[{i}].alternatives_considered must be list")

            unk_any = claim.get("unknowns")
            if unk_any is not None and not isinstance(unk_any, list):
                errors.append(f"claims[{i}].unknowns must be list")

    artifacts_any = r.get("artifacts")
    if artifacts_any is not None and not isinstance(artifacts_any, dict):
        errors.append("artifacts must be object")

    limitations_any = req_key("limitations", list)
    if isinstance(limitations_any, list):
        if not all(
            isinstance(x, str) and x for x in cast(list[object], limitations_any)
        ):
            errors.append("limitations must be a list of non-empty strings")

    return errors


def empty_analyst_report() -> dict[str, JsonValue]:
    return {
        "schema_version": ANALYST_REPORT_SCHEMA_VERSION,
        "claims": [],
        "artifacts": {},
        "limitations": [],
    }


def validate_analyst_digest(digest: object) -> list[str]:
    errors: list[str] = []
    if not isinstance(digest, dict):
        return ["analyst_digest must be an object"]

    d = cast(dict[str, object], digest)
    allowed_top_level = {
        "schema_version",
        "run",
        "top_risk_summary",
        "finding_verdicts",
        "exploitability_verdict",
        "evidence_index",
        "next_actions",
    }
    for key in d.keys():
        if key not in allowed_top_level:
            errors.append(f"unsupported top-level key: {key}")

    def req_key(key: str, typ: type) -> object | None:
        if key not in d:
            errors.append(f"missing top-level key: {key}")
            return None
        value = d.get(key)
        if not isinstance(value, typ):
            errors.append(f"top-level '{key}' must be {typ.__name__}")
            return None
        return value

    schema_version = req_key("schema_version", str)
    if schema_version != ANALYST_DIGEST_SCHEMA_VERSION:
        errors.append(f"schema_version must equal {ANALYST_DIGEST_SCHEMA_VERSION!r}")

    run_any = req_key("run", dict)
    if isinstance(run_any, dict):
        run = cast(dict[str, object], run_any)
        run_id = run.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            errors.append("run.run_id must be non-empty string")
        firmware_sha = run.get("firmware_sha256")
        if not _is_sha256_hex(firmware_sha):
            errors.append("run.firmware_sha256 must be lowercase hex sha256")
        generated_at = run.get("generated_at")
        if not isinstance(generated_at, str) or not generated_at:
            errors.append("run.generated_at must be non-empty string")

    top_risk_any = req_key("top_risk_summary", dict)
    if isinstance(top_risk_any, dict):
        top_risk = cast(dict[str, object], top_risk_any)
        total_findings = top_risk.get("total_findings")
        if not isinstance(total_findings, int) or total_findings < 0:
            errors.append("top_risk_summary.total_findings must be non-negative int")
        severity_counts_any = top_risk.get("severity_counts")
        if not isinstance(severity_counts_any, dict):
            errors.append("top_risk_summary.severity_counts must be object")
        else:
            severity_counts = cast(dict[str, object], severity_counts_any)
            required_severities = {"critical", "high", "medium", "low", "info"}
            if set(severity_counts.keys()) != required_severities:
                errors.append(
                    "top_risk_summary.severity_counts must contain exactly critical/high/medium/low/info"
                )
            for sev, value in severity_counts.items():
                if not isinstance(value, int) or value < 0:
                    errors.append(
                        f"top_risk_summary.severity_counts.{sev} must be non-negative int"
                    )

    finding_verdicts_any = req_key("finding_verdicts", list)
    finding_verdicts: list[dict[str, object]] = []
    if isinstance(finding_verdicts_any, list):
        for i, item_any in enumerate(cast(list[object], finding_verdicts_any)):
            if not isinstance(item_any, dict):
                errors.append(f"finding_verdicts[{i}] must be object")
                continue
            item = cast(dict[str, object], item_any)
            finding_verdicts.append(item)
            finding_id = item.get("finding_id")
            if not isinstance(finding_id, str) or not finding_id:
                errors.append(
                    f"finding_verdicts[{i}].finding_id must be non-empty string"
                )
            verdict = item.get("verdict")
            if (
                not isinstance(verdict, str)
                or verdict not in _ANALYST_DIGEST_VERDICTS_SET
            ):
                errors.append(
                    f"finding_verdicts[{i}].verdict must be one of {sorted(_ANALYST_DIGEST_VERDICTS_SET)}"
                )
            _ = _validate_analyst_digest_reason_codes(
                value=item.get("reason_codes"),
                path=f"finding_verdicts[{i}].reason_codes",
                errors=errors,
            )
            evidence_refs_any = item.get("evidence_refs")
            if not isinstance(evidence_refs_any, list) or not evidence_refs_any:
                errors.append(
                    f"finding_verdicts[{i}].evidence_refs must be non-empty list"
                )
            else:
                for j, ref_any in enumerate(cast(list[object], evidence_refs_any)):
                    if not isinstance(ref_any, str) or not _is_run_relative_path(
                        ref_any
                    ):
                        errors.append(
                            f"finding_verdicts[{i}].evidence_refs[{j}] must be run-relative path"
                        )
            verifier_refs_any = item.get("verifier_refs")
            if not isinstance(verifier_refs_any, list):
                errors.append(
                    f"finding_verdicts[{i}].verifier_refs must be list"
                )
            else:
                for j, ref_any in enumerate(cast(list[object], verifier_refs_any)):
                    if not isinstance(ref_any, str) or not _is_run_relative_path(
                        ref_any
                    ):
                        errors.append(
                            f"finding_verdicts[{i}].verifier_refs[{j}] must be run-relative path"
                        )

    verdict_any = req_key("exploitability_verdict", dict)
    verdict_state: str | None = None
    verdict_reason_codes: list[str] = []
    if isinstance(verdict_any, dict):
        verdict_obj = cast(dict[str, object], verdict_any)
        state_any = verdict_obj.get("state")
        if (
            not isinstance(state_any, str)
            or state_any not in _ANALYST_DIGEST_VERDICTS_SET
        ):
            errors.append(
                f"exploitability_verdict.state must be one of {sorted(_ANALYST_DIGEST_VERDICTS_SET)}"
            )
        else:
            verdict_state = state_any
        verdict_reason_codes = _validate_analyst_digest_reason_codes(
            value=verdict_obj.get("reason_codes"),
            path="exploitability_verdict.reason_codes",
            errors=errors,
        )
        aggregation_rule = verdict_obj.get("aggregation_rule")
        if aggregation_rule != ANALYST_DIGEST_AGGREGATION_RULE:
            errors.append(
                f"exploitability_verdict.aggregation_rule must equal {ANALYST_DIGEST_AGGREGATION_RULE!r}"
            )

    evidence_index_any = req_key("evidence_index", list)
    if isinstance(evidence_index_any, list):
        for i, item_any in enumerate(cast(list[object], evidence_index_any)):
            if not isinstance(item_any, dict):
                errors.append(f"evidence_index[{i}] must be object")
                continue
            item = cast(dict[str, object], item_any)
            ref = item.get("ref")
            if not isinstance(ref, str) or not _is_run_relative_path(ref):
                errors.append(f"evidence_index[{i}].ref must be run-relative path")
            sha = item.get("sha256")
            if not _is_sha256_hex(sha):
                errors.append(
                    f"evidence_index[{i}].sha256 must be lowercase hex sha256"
                )

    next_actions_any = req_key("next_actions", list)
    if isinstance(next_actions_any, list):
        if not next_actions_any:
            errors.append("next_actions must be non-empty list")
        for i, action_any in enumerate(cast(list[object], next_actions_any)):
            if not isinstance(action_any, str) or not action_any:
                errors.append(f"next_actions[{i}] must be non-empty string")

    if isinstance(top_risk_any, dict) and isinstance(finding_verdicts_any, list):
        top_risk = cast(dict[str, object], top_risk_any)
        total_findings = top_risk.get("total_findings")
        if isinstance(total_findings, int) and total_findings != len(finding_verdicts):
            errors.append(
                "top_risk_summary.total_findings must equal len(finding_verdicts)"
            )

    if verdict_state is not None:
        if not finding_verdicts:
            if verdict_state != "NOT_APPLICABLE":
                errors.append(
                    "exploitability_verdict.state must be NOT_APPLICABLE when finding_verdicts is empty"
                )
            if verdict_reason_codes != ["NOT_APPLICABLE_NO_RELEVANT_FINDINGS"]:
                errors.append(
                    "exploitability_verdict.reason_codes must equal ['NOT_APPLICABLE_NO_RELEVANT_FINDINGS'] when finding_verdicts is empty"
                )
        else:
            finding_states = [
                cast(str, item["verdict"])
                for item in finding_verdicts
                if isinstance(item.get("verdict"), str)
                and cast(str, item.get("verdict")) in _ANALYST_DIGEST_STATE_RANK
            ]
            if finding_states:
                expected_state = min(
                    finding_states,
                    key=lambda state: _ANALYST_DIGEST_STATE_RANK[state],
                )
                if verdict_state != expected_state:
                    errors.append(
                        "exploitability_verdict.state must match aggregated worst-state precedence"
                    )

                expected_reason_codes_set: set[str] = set()
                for item in finding_verdicts:
                    item_state_any = item.get("verdict")
                    if item_state_any != expected_state:
                        continue
                    rc_any = item.get("reason_codes")
                    if isinstance(rc_any, list):
                        for code_any in cast(list[object], rc_any):
                            if (
                                isinstance(code_any, str)
                                and code_any in _ANALYST_DIGEST_REASON_SET
                            ):
                                expected_reason_codes_set.add(code_any)

                if set(verdict_reason_codes) != expected_reason_codes_set:
                    errors.append(
                        "exploitability_verdict.reason_codes must equal union of reason_codes for findings in aggregated state"
                    )

    return errors
