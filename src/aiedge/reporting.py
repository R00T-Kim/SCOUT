from __future__ import annotations

import html
import hashlib
import importlib.util
import json
import re
from datetime import datetime
from pathlib import Path
from types import ModuleType
from typing import Callable, cast

from zoneinfo import ZoneInfo

from .exploit_tiering import is_valid_exploitability_tier
from .schema import (
    ANALYST_DIGEST_AGGREGATION_RULE,
    ANALYST_DIGEST_REASON_CODES,
    ANALYST_DIGEST_SCHEMA_VERSION,
    ANALYST_DIGEST_VERDICTS,
    ANALYST_DIGEST_STATE_PRECEDENCE,
    ANALYST_REPORT_SCHEMA_VERSION,
    JsonValue,
    empty_report,
    validate_analyst_digest,
)


ANALYST_REPORT_REQUIRED_SECTIONS: tuple[str, ...] = (
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


ANALYST_REPORT_V2_JSON_RELATIVE_PATH = "report/analyst_report_v2.json"
ANALYST_REPORT_V2_MD_RELATIVE_PATH = "report/analyst_report_v2.md"
ANALYST_REPORT_V2_VIEWER_RELATIVE_PATH = "report/viewer.html"
ANALYST_REPORT_V2_TOP_RISK_LIMIT = 5
ANALYST_REPORT_V2_TOP_RISK_SOURCE_FIELD = "findings"

ANALYST_REPORT_V2_SEVERITY_ORDER: tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
)
ANALYST_REPORT_V2_SEVERITY_RANK: dict[str, int] = {
    severity: len(ANALYST_REPORT_V2_SEVERITY_ORDER) - idx
    for idx, severity in enumerate(ANALYST_REPORT_V2_SEVERITY_ORDER)
}

ANALYST_REPORT_V2_TOP_RISK_TIEBREAK_ORDER: tuple[str, ...] = (
    "severity_desc",
    "confidence_desc",
    "claim_type_asc",
    "first_evidence_ref_asc",
)

ANALYST_REPORT_V2_MARKDOWN_TIMEZONE = "Asia/Seoul"
ANALYST_REPORT_V2_TIME_DISPLAY_POLICY = (
    "In analyst_report_v2.md, render human-readable timestamps in KST "
    "(Asia/Seoul) when a timestamp is present. Preserve v1 machine timestamps "
    "exactly as UTC Z values in manifest.json, stage.json, and report/report.json."
)

ANALYST_REPORT_V2_SCHEMA_VERSION = "0.2"

ANALYST_DIGEST_JSON_RELATIVE_PATH = "report/analyst_digest.json"
ANALYST_DIGEST_MD_RELATIVE_PATH = "report/analyst_digest.md"

ANALYST_OVERVIEW_JSON_RELATIVE_PATH = "report/analyst_overview.json"

# Single-pane aggregated overview payload schema version.
ANALYST_OVERVIEW_SCHEMA_VERSION = "analyst_overview-v1"

# Viewer-only anchors for single-pane navigation in report/viewer.html.
# Keep these IDs stable (not part of analyst_digest-v1 contract).
ANALYST_OVERVIEW_PANE_ANCHOR_OVERVIEW_GATES = "overview-gates"
ANALYST_OVERVIEW_PANE_ANCHOR_VULNERABILITIES_VERDICTS = "vulnerabilities-verdicts"
ANALYST_OVERVIEW_PANE_ANCHOR_STRUCTURE_BINARIES = "structure-binaries"
ANALYST_OVERVIEW_PANE_ANCHOR_PROTOCOLS_ATTACK_SURFACE = "protocols-attack-surface"
ANALYST_OVERVIEW_PANE_ANCHOR_EXPLOIT_CANDIDATE_MAP = "exploit-candidate-map"
ANALYST_OVERVIEW_PANE_ANCHOR_EVIDENCE_NEXT_ACTIONS = "evidence-next-actions"
ANALYST_OVERVIEW_PANE_ANCHOR_ORDER: tuple[str, ...] = (
    ANALYST_OVERVIEW_PANE_ANCHOR_OVERVIEW_GATES,
    ANALYST_OVERVIEW_PANE_ANCHOR_VULNERABILITIES_VERDICTS,
    ANALYST_OVERVIEW_PANE_ANCHOR_STRUCTURE_BINARIES,
    ANALYST_OVERVIEW_PANE_ANCHOR_PROTOCOLS_ATTACK_SURFACE,
    ANALYST_OVERVIEW_PANE_ANCHOR_EXPLOIT_CANDIDATE_MAP,
    ANALYST_OVERVIEW_PANE_ANCHOR_EVIDENCE_NEXT_ACTIONS,
)

ANALYST_OVERVIEW_PANE_TITLES: dict[str, str] = {
    ANALYST_OVERVIEW_PANE_ANCHOR_OVERVIEW_GATES: "Overview & Gates",
    ANALYST_OVERVIEW_PANE_ANCHOR_VULNERABILITIES_VERDICTS: "Vulnerabilities & Verdicts",
    ANALYST_OVERVIEW_PANE_ANCHOR_STRUCTURE_BINARIES: "Structure & Binaries",
    ANALYST_OVERVIEW_PANE_ANCHOR_PROTOCOLS_ATTACK_SURFACE: "Protocols & Attack Surface",
    ANALYST_OVERVIEW_PANE_ANCHOR_EXPLOIT_CANDIDATE_MAP: "Exploit Candidate Map",
    ANALYST_OVERVIEW_PANE_ANCHOR_EVIDENCE_NEXT_ACTIONS: "Evidence & Next Actions",
}

# Single-pane overview gate IDs (viewer-only, additive; keep stable).
ANALYST_OVERVIEW_GATE_ID_REPORT_COMPLETENESS = "report_completeness"
ANALYST_OVERVIEW_GATE_ID_ANALYST_DIGEST = "analyst_digest"
ANALYST_OVERVIEW_GATE_ID_ANALYST_REPORT_LINKAGE = "analyst_report_linkage"
ANALYST_OVERVIEW_GATE_ID_VERIFIED_CHAIN = "verified_chain"
ANALYST_OVERVIEW_GATE_ID_FINAL_REPORT_CONTRACT_8MB = "final_report_contract_8mb"


# Single-pane overview gate statuses.
ANALYST_OVERVIEW_GATE_STATUS_PASS = "pass"
ANALYST_OVERVIEW_GATE_STATUS_FAIL = "fail"
ANALYST_OVERVIEW_GATE_STATUS_BLOCKED = "blocked"
ANALYST_OVERVIEW_GATE_STATUS_NOT_APPLICABLE = "not_applicable"


def resolve_overview_gate_applicability(
    manifest: dict[str, JsonValue],
) -> list[dict[str, JsonValue]]:
    """Resolve which single-pane overview gates apply.

    This resolver is applicability only. It does not run verifiers and does not
    infer outcomes from partial evidence.

    Convention: any applicable-but-unevaluated gate is represented as:
      - status="blocked"
      - reasons includes "not evaluated"
    """

    def gate_item(
        gate_id: str, status: str, reasons: list[str]
    ) -> dict[str, JsonValue]:
        return {
            "id": gate_id,
            "status": status,
            "reasons": cast(list[JsonValue], cast(list[object], list(reasons))),
        }

    not_evaluated = "not evaluated"

    profile: str | None = None
    profile_err: str | None = None
    profile_any = manifest.get("profile")
    if profile_any is None:
        profile_err = "manifest.profile missing"
    elif not isinstance(profile_any, str) or not profile_any:
        profile_err = "manifest.profile malformed (expected non-empty string)"
    elif profile_any not in ("analysis", "exploit"):
        profile_err = "manifest.profile malformed (unexpected value)"
    else:
        profile = profile_any

    track_id: str | None = None
    track_err: str | None = None
    if "track" in manifest:
        track_any = manifest.get("track")
        if not isinstance(track_any, dict):
            track_err = "manifest.track malformed (expected object)"
        else:
            tid_any = track_any.get("track_id")
            if tid_any is None:
                track_err = "manifest.track.track_id missing"
            elif not isinstance(tid_any, str) or not tid_any:
                track_err = (
                    "manifest.track.track_id malformed (expected non-empty string)"
                )
            else:
                track_id = tid_any

    # Deterministic ordering: always return gate list in the same ID order.
    gates: list[dict[str, JsonValue]] = [
        gate_item(
            ANALYST_OVERVIEW_GATE_ID_REPORT_COMPLETENESS,
            ANALYST_OVERVIEW_GATE_STATUS_BLOCKED,
            [not_evaluated],
        ),
        gate_item(
            ANALYST_OVERVIEW_GATE_ID_ANALYST_DIGEST,
            ANALYST_OVERVIEW_GATE_STATUS_BLOCKED,
            [not_evaluated],
        ),
        gate_item(
            ANALYST_OVERVIEW_GATE_ID_ANALYST_REPORT_LINKAGE,
            ANALYST_OVERVIEW_GATE_STATUS_BLOCKED,
            [not_evaluated],
        ),
    ]

    if profile_err is not None:
        gates.append(
            gate_item(
                ANALYST_OVERVIEW_GATE_ID_VERIFIED_CHAIN,
                ANALYST_OVERVIEW_GATE_STATUS_BLOCKED,
                [profile_err],
            )
        )
    elif profile == "exploit":
        gates.append(
            gate_item(
                ANALYST_OVERVIEW_GATE_ID_VERIFIED_CHAIN,
                ANALYST_OVERVIEW_GATE_STATUS_BLOCKED,
                ["requires verifier artifacts"],
            )
        )
    else:
        gates.append(
            gate_item(
                ANALYST_OVERVIEW_GATE_ID_VERIFIED_CHAIN,
                ANALYST_OVERVIEW_GATE_STATUS_NOT_APPLICABLE,
                ["profile!=exploit"],
            )
        )

    if track_err is not None:
        gates.append(
            gate_item(
                ANALYST_OVERVIEW_GATE_ID_FINAL_REPORT_CONTRACT_8MB,
                ANALYST_OVERVIEW_GATE_STATUS_BLOCKED,
                [track_err],
            )
        )
    elif track_id == "8mb":
        gates.append(
            gate_item(
                ANALYST_OVERVIEW_GATE_ID_FINAL_REPORT_CONTRACT_8MB,
                ANALYST_OVERVIEW_GATE_STATUS_BLOCKED,
                ["requires final report verifier"],
            )
        )
    else:
        # Covers both track missing and non-8mb tracks.
        gates.append(
            gate_item(
                ANALYST_OVERVIEW_GATE_ID_FINAL_REPORT_CONTRACT_8MB,
                ANALYST_OVERVIEW_GATE_STATUS_NOT_APPLICABLE,
                ["track!=8mb or track missing"],
            )
        )

    return gates


_ANALYST_DIGEST_REASON_RANK: dict[str, int] = {
    reason: idx for idx, reason in enumerate(ANALYST_DIGEST_REASON_CODES)
}
_ANALYST_DIGEST_STATE_RANK: dict[str, int] = {
    state: idx for idx, state in enumerate(ANALYST_DIGEST_STATE_PRECEDENCE)
}
_ANALYST_DIGEST_SEVERITIES: tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
)

_VERIFIED_CHAIN_REF = "verified_chain/verified_chain.json"
_DYNAMIC_VALIDATION_REQUIRED_REFS: tuple[str, ...] = (
    "stages/dynamic_validation/dynamic_validation.json",
    "stages/dynamic_validation/isolation/firewall_snapshot.txt",
    "stages/dynamic_validation/pcap/dynamic_validation.pcap",
)


def _load_script_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise ValueError(f"invalid verifier module path: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _extract_reason_code(exc: Exception) -> str:
    reason_any = getattr(exc, "reason_code", None)
    if isinstance(reason_any, str) and reason_any:
        return reason_any
    return "invalid_contract"


def _collect_verifier_refs(run_dir: Path) -> list[str]:
    refs: set[str] = set()
    for ref in (_VERIFIED_CHAIN_REF, *list(_DYNAMIC_VALIDATION_REQUIRED_REFS)):
        if (run_dir / ref).is_file():
            refs.add(ref)
    exploits_dir = run_dir / "exploits"
    if exploits_dir.is_dir():
        for chain_dir in sorted(
            [
                path
                for path in exploits_dir.iterdir()
                if path.is_dir() and path.name.startswith("chain_")
            ],
            key=lambda path: path.name,
        ):
            bundle_path = chain_dir / "evidence_bundle.json"
            if bundle_path.is_file():
                refs.add(
                    bundle_path.resolve().relative_to(run_dir.resolve()).as_posix()
                )
    if not refs:
        return []
    return sorted(refs)


def _build_or_load_verified_chain(run_dir: Path) -> None:
    if (run_dir / _VERIFIED_CHAIN_REF).is_file():
        return
    scripts_dir = Path(__file__).resolve().parents[2] / "scripts"
    build_mod = _load_script_module(
        "build_verified_chain", scripts_dir / "build_verified_chain.py"
    )
    build_fn_obj = getattr(build_mod, "build_verified_chain", None)
    if not callable(build_fn_obj):
        return
    build_fn = cast(Callable[[Path], object], build_fn_obj)
    try:
        _ = build_fn(run_dir)
    except Exception:
        return


def _missing_required_verifier_artifacts(run_dir: Path) -> tuple[list[str], bool]:
    missing: list[str] = []
    missing_dynamic = False
    verified_chain_path = run_dir / _VERIFIED_CHAIN_REF
    if not verified_chain_path.is_file():
        missing.append(_VERIFIED_CHAIN_REF)
    for ref in _DYNAMIC_VALIDATION_REQUIRED_REFS:
        if not (run_dir / ref).is_file():
            missing.append(ref)
            missing_dynamic = True
    return sorted(missing), missing_dynamic


def _load_verified_chain_state(run_dir: Path) -> tuple[str, set[str]]:
    path = run_dir / _VERIFIED_CHAIN_REF
    if not path.is_file():
        return "", set()
    try:
        obj_any = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return "", set()
    if not isinstance(obj_any, dict):
        return "", set()
    verdict_any = cast(dict[str, object], obj_any).get("verdict")
    if not isinstance(verdict_any, dict):
        return "", set()
    verdict = cast(dict[str, object], verdict_any)
    state_any = verdict.get("state")
    state = state_any if isinstance(state_any, str) else ""
    codes_any = verdict.get("reason_codes")
    reason_codes: set[str] = set()
    if isinstance(codes_any, list):
        for code_any in cast(list[object], codes_any):
            if isinstance(code_any, str):
                reason_codes.add(code_any)
    return state, reason_codes


def _has_static_chain_attempt_signal(run_dir: Path) -> bool:
    candidates_path = run_dir / "stages" / "findings" / "exploit_candidates.json"
    if not candidates_path.is_file():
        return False
    try:
        obj_any = cast(object, json.loads(candidates_path.read_text(encoding="utf-8")))
    except Exception:
        return False
    if not isinstance(obj_any, dict):
        return False
    obj = cast(dict[str, object], obj_any)

    summary_any = obj.get("summary")
    if isinstance(summary_any, dict):
        summary = cast(dict[str, object], summary_any)
        chain_backed_any = summary.get("chain_backed")
        if isinstance(chain_backed_any, int) and not isinstance(chain_backed_any, bool):
            if chain_backed_any > 0:
                return True

    candidates_any = obj.get("candidates")
    if not isinstance(candidates_any, list):
        return False
    for item_any in cast(list[object], candidates_any):
        if not isinstance(item_any, dict):
            continue
        source_any = cast(dict[str, object], item_any).get("source")
        if isinstance(source_any, str) and source_any == "chain":
            return True
    return False


def _compute_run_verdict(run_dir: Path) -> tuple[str, list[str], list[str]]:
    scripts_dir = Path(__file__).resolve().parents[2] / "scripts"
    evidence_mod = _load_script_module(
        "verify_run_dir_evidence_only", scripts_dir / "verify_run_dir_evidence_only.py"
    )
    network_mod = _load_script_module(
        "verify_network_isolation", scripts_dir / "verify_network_isolation.py"
    )
    meaningful_mod = _load_script_module(
        "verify_exploit_meaningfulness",
        scripts_dir / "verify_exploit_meaningfulness.py",
    )
    verified_mod = _load_script_module(
        "verify_verified_chain", scripts_dir / "verify_verified_chain.py"
    )

    evidence_fn = cast(
        Callable[[Path], None], getattr(evidence_mod, "verify_run_dir_evidence_only")
    )
    network_fn = cast(
        Callable[[Path], object], getattr(network_mod, "_verify_network_isolation")
    )
    meaningful_fn = cast(
        Callable[[Path], object],
        getattr(meaningful_mod, "_verify_exploit_meaningfulness"),
    )
    verified_fn = cast(
        Callable[[Path], object], getattr(verified_mod, "_verify_verified_chain")
    )

    verifier_refs = _collect_verifier_refs(run_dir)
    has_chain_signal = _has_static_chain_attempt_signal(run_dir)

    try:
        evidence_fn(run_dir)
    except Exception as exc:
        reason = _extract_reason_code(exc)
        if reason == "missing_required_artifact":
            if has_chain_signal:
                return (
                    "ATTEMPTED_INCONCLUSIVE",
                    ["ATTEMPTED_EVIDENCE_INCOMPLETE"],
                    verifier_refs,
                )
            return (
                "NOT_ATTEMPTED",
                ["NOT_ATTEMPTED_REQUIRED_VERIFIER_MISSING"],
                verifier_refs,
            )
        return (
            "ATTEMPTED_INCONCLUSIVE",
            ["ATTEMPTED_EVIDENCE_TAMPERED"],
            verifier_refs,
        )

    _build_or_load_verified_chain(run_dir)
    verifier_refs = _collect_verifier_refs(run_dir)

    missing_refs, missing_dynamic = _missing_required_verifier_artifacts(run_dir)
    if missing_refs:
        if missing_dynamic and has_chain_signal:
            return (
                "ATTEMPTED_INCONCLUSIVE",
                ["ATTEMPTED_EVIDENCE_INCOMPLETE"],
                verifier_refs,
            )
        reason = (
            "NOT_ATTEMPTED_DYNAMIC_VALIDATION_MISSING"
            if missing_dynamic
            else "NOT_ATTEMPTED_REQUIRED_VERIFIER_MISSING"
        )
        return "NOT_ATTEMPTED", [reason], verifier_refs

    verified_ok = False
    verified_state = ""
    verified_reason_codes: set[str] = set()
    verifier_failure_reason_codes: set[str] = set()
    try:
        _ = verified_fn(run_dir)
        verified_ok = True
    except Exception as exc:
        verifier_failure_reason_codes.add(_extract_reason_code(exc))
    verified_state, verified_reason_codes = _load_verified_chain_state(run_dir)

    network_ok = False
    try:
        _ = network_fn(run_dir)
        network_ok = True
    except Exception as exc:
        verifier_failure_reason_codes.add(_extract_reason_code(exc))

    meaningful_ok = False
    try:
        _ = meaningful_fn(run_dir)
        meaningful_ok = True
    except Exception as exc:
        verifier_failure_reason_codes.add(_extract_reason_code(exc))

    if (
        verified_ok
        and network_ok
        and meaningful_ok
        and verified_state == "pass"
        and "repro_3_of_3" in verified_reason_codes
        and "isolation_verified" in verified_reason_codes
    ):
        return (
            "VERIFIED",
            ["VERIFIED_ALL_GATES_PASSED", "VERIFIED_REPRO_3_OF_3"],
            verifier_refs,
        )

    evidence_incomplete_reasons = {
        "missing_exploit_bundle",
        "missing_dynamic_bundle",
        "missing_required_artifact",
        "pcap_missing",
        "pcap_parse_unavailable",
        "boot_flaky",
        "boot_timeout",
    }
    repro_insufficient_reasons = {"poc_repro_failed", "repro_incomplete"}

    if verified_state != "pass":
        if "poc_repro_failed" in verified_reason_codes:
            reason_codes = ["ATTEMPTED_REPRO_INSUFFICIENT"]
        elif verified_reason_codes.intersection(evidence_incomplete_reasons):
            reason_codes = ["ATTEMPTED_EVIDENCE_INCOMPLETE"]
        else:
            reason_codes = ["ATTEMPTED_VERIFIER_FAILED"]
    elif verifier_failure_reason_codes.intersection(repro_insufficient_reasons):
        reason_codes = ["ATTEMPTED_REPRO_INSUFFICIENT"]
    elif verifier_failure_reason_codes.intersection(evidence_incomplete_reasons):
        reason_codes = ["ATTEMPTED_EVIDENCE_INCOMPLETE"]
    else:
        reason_codes = ["ATTEMPTED_VERIFIER_FAILED"]

    return "ATTEMPTED_INCONCLUSIVE", reason_codes, verifier_refs


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sort_reason_codes(codes: set[str]) -> list[str]:
    return sorted(codes, key=lambda code: _ANALYST_DIGEST_REASON_RANK.get(code, 10**9))


def _finding_evidence_refs(finding: dict[str, object], *, run_dir: Path) -> list[str]:
    evidence_any = finding.get("evidence")
    if not isinstance(evidence_any, list):
        return []
    refs: set[str] = set()
    run_root = run_dir.resolve()
    for evidence_item_any in cast(list[object], evidence_any):
        if not isinstance(evidence_item_any, dict):
            continue
        path_any = cast(dict[str, object], evidence_item_any).get("path")
        ref = _normalize_run_relative_ref(path_any)
        if ref is None:
            continue
        candidate = (run_dir / ref).resolve()
        try:
            _ = candidate.relative_to(run_root)
        except ValueError:
            continue
        if candidate.is_file():
            refs.add(ref)
    return sorted(refs)


def _build_finding_verdicts(
    report: dict[str, JsonValue], *, run_dir: Path
) -> list[dict[str, JsonValue]]:
    findings_any = report.get("findings")
    if not isinstance(findings_any, list):
        return []

    try:
        run_state, run_reason_codes, run_verifier_refs = _compute_run_verdict(run_dir)
    except Exception:
        run_state = "NOT_ATTEMPTED"
        run_reason_codes = ["NOT_ATTEMPTED_REQUIRED_VERIFIER_MISSING"]
        run_verifier_refs = []
    out: list[dict[str, JsonValue]] = []
    for finding_any in cast(list[object], findings_any):
        if not isinstance(finding_any, dict):
            continue
        finding = cast(dict[str, object], finding_any)
        finding_id_any = finding.get("id")
        if not isinstance(finding_id_any, str) or not finding_id_any:
            continue
        evidence_refs = _finding_evidence_refs(finding, run_dir=run_dir)
        if not evidence_refs:
            evidence_refs = ["report/report.json"]

        severity_any = finding.get("severity")
        disposition_any = finding.get("disposition")
        if (
            severity_any == "info"
            and isinstance(disposition_any, str)
            and disposition_any != "confirmed"
        ):
            verdict_state = "NOT_APPLICABLE"
            reason_codes = ["NOT_APPLICABLE_NO_RELEVANT_FINDINGS"]
        else:
            verdict_state = run_state
            reason_codes = run_reason_codes

        out.append(
            {
                "finding_id": finding_id_any,
                "verdict": verdict_state,
                "reason_codes": cast(list[JsonValue], cast(list[object], reason_codes)),
                "evidence_refs": cast(
                    list[JsonValue], cast(list[object], sorted(set(evidence_refs)))
                ),
                "verifier_refs": cast(
                    list[JsonValue], cast(list[object], sorted(set(run_verifier_refs)))
                ),
            }
        )

    return sorted(
        out,
        key=lambda item: (
            cast(str, item.get("finding_id", "")),
            cast(list[str], item.get("evidence_refs", [""]))[0],
        ),
    )


def _aggregate_verdict(
    finding_verdicts: list[dict[str, JsonValue]],
) -> dict[str, JsonValue]:
    if not finding_verdicts:
        reason_codes = ["NOT_APPLICABLE_NO_RELEVANT_FINDINGS"]
        return {
            "state": "NOT_APPLICABLE",
            "reason_codes": cast(list[JsonValue], cast(list[object], reason_codes)),
            "aggregation_rule": ANALYST_DIGEST_AGGREGATION_RULE,
        }

    states: list[str] = []
    for verdict in finding_verdicts:
        state_any = verdict.get("verdict")
        if isinstance(state_any, str) and state_any in _ANALYST_DIGEST_STATE_RANK:
            states.append(state_any)
    if not states:
        raise ValueError("invalid analyst digest: finding verdict states unavailable")

    state = min(states, key=lambda candidate: _ANALYST_DIGEST_STATE_RANK[candidate])
    reason_codes_set: set[str] = set()
    for verdict in finding_verdicts:
        verdict_state_any = verdict.get("verdict")
        if verdict_state_any != state:
            continue
        reason_codes_any = verdict.get("reason_codes")
        if not isinstance(reason_codes_any, list):
            continue
        for reason_any in cast(list[object], reason_codes_any):
            if isinstance(reason_any, str):
                reason_codes_set.add(reason_any)

    reason_codes = _sort_reason_codes(reason_codes_set)
    if not reason_codes:
        raise ValueError("invalid analyst digest: aggregated reason_codes unavailable")

    return {
        "state": state,
        "reason_codes": cast(list[JsonValue], cast(list[object], reason_codes)),
        "aggregation_rule": ANALYST_DIGEST_AGGREGATION_RULE,
    }


def _build_evidence_index(
    *, run_dir: Path, evidence_refs: set[str]
) -> list[dict[str, JsonValue]]:
    out: list[dict[str, JsonValue]] = []
    run_root = run_dir.resolve()
    for ref in sorted(evidence_refs):
        if not _is_run_relative_path(ref):
            raise ValueError(
                "invalid analyst digest: evidence ref must be run-relative"
            )
        candidate = (run_dir / ref).resolve()
        try:
            _ = candidate.relative_to(run_root)
        except ValueError as exc:
            raise ValueError(
                "invalid analyst digest: evidence ref escapes run_dir"
            ) from exc
        if not candidate.is_file():
            raise ValueError(
                f"invalid analyst digest: referenced evidence artifact missing ({ref})"
            )
        out.append({"ref": ref, "sha256": _sha256_file(candidate)})
    return out


def _validate_run_relative_artifact_ref(
    *, run_dir: Path, ref: str
) -> tuple[str, Path | None, str | None]:
    """Validate and resolve a run-relative artifact ref.

    Returns (normalized_ref, resolved_path_or_none, invalid_reason_or_none).

    This is stricter than `_is_run_relative_path`: in addition to rejecting
    absolute paths, it fail-closes on any `..` traversal segment and on refs
    that escape `run_dir` after resolution.
    """

    ref_norm, invalid_reason = _normalize_run_relative_ref_with_reason(ref)
    if ref_norm is None:
        return str(ref).replace("\\", "/"), None, invalid_reason

    run_root = run_dir.resolve()
    candidate = (run_dir / ref_norm).resolve()
    try:
        _ = candidate.relative_to(run_root)
    except ValueError:
        return ref_norm, None, "ref escapes run_dir"
    return ref_norm, candidate, None


def collect_overview_artifact_statuses(
    run_dir: Path,
    refs: list[tuple[str, bool]],
) -> list[dict[str, JsonValue]]:
    """Collect deterministic artifact statuses for the overview payload.

    Each input item is (ref, required). Output items are:
      {"ref": str, "required": bool, "status": "present"|"missing"|"invalid",
       "reason"?: str, "sha256"?: str}
    """

    out: list[dict[str, JsonValue]] = []
    for ref, required in refs:
        ref_norm, resolved, invalid_reason = _validate_run_relative_artifact_ref(
            run_dir=run_dir, ref=ref
        )
        if invalid_reason is not None or resolved is None:
            out.append(
                {
                    "ref": ref_norm,
                    "required": bool(required),
                    "status": "invalid",
                    "reason": invalid_reason
                    if invalid_reason is not None
                    else "invalid",
                }
            )
            continue

        if resolved.is_file():
            out.append(
                {
                    "ref": ref_norm,
                    "required": bool(required),
                    "status": "present",
                    "sha256": _sha256_file(resolved),
                }
            )
            continue

        if resolved.exists():
            out.append(
                {
                    "ref": ref_norm,
                    "required": bool(required),
                    "status": "invalid",
                    "reason": "artifact exists but is not a file",
                }
            )
            continue

        out.append({"ref": ref_norm, "required": bool(required), "status": "missing"})

    # Deterministic ordering: always return in normalized ref order.
    return sorted(out, key=lambda item: str(item.get("ref", "")))


def _safe_load_manifest_json(
    run_dir: Path,
) -> tuple[dict[str, JsonValue], str | None]:
    path = run_dir / "manifest.json"
    if not path.is_file():
        return {}, "manifest missing/invalid"
    try:
        obj_any = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return {}, "manifest missing/invalid"
    if not isinstance(obj_any, dict):
        return {}, "manifest missing/invalid"
    return cast(dict[str, JsonValue], obj_any), None


def _overview_artifact_refs() -> list[tuple[str, bool]]:
    # Deterministic ordering is handled by the collector (sorted by ref).
    return [
        ("report/report.json", True),
        (ANALYST_DIGEST_JSON_RELATIVE_PATH, True),
        (ANALYST_REPORT_V2_JSON_RELATIVE_PATH, True),
        (ANALYST_REPORT_V2_VIEWER_RELATIVE_PATH, True),
        ("stages/surfaces/surfaces.json", False),
        ("stages/surfaces/endpoints.json", False),
        ("stages/surfaces/source_sink_graph.json", False),
        ("stages/findings/pattern_scan.json", False),
        ("stages/findings/binary_strings_hits.json", False),
        ("stages/findings/exploit_candidates.json", False),
    ]


def _overview_links() -> dict[str, JsonValue]:
    # Canonical run-relative links for consumers (viewer, CLI).
    return {
        "report_json": "report/report.json",
        "analyst_digest_json": ANALYST_DIGEST_JSON_RELATIVE_PATH,
        "analyst_overview_json": ANALYST_OVERVIEW_JSON_RELATIVE_PATH,
        "analyst_report_v2_json": ANALYST_REPORT_V2_JSON_RELATIVE_PATH,
        "viewer_html": ANALYST_REPORT_V2_VIEWER_RELATIVE_PATH,
        "surfaces_json": "stages/surfaces/surfaces.json",
        "endpoints_json": "stages/surfaces/endpoints.json",
        "source_sink_graph_json": "stages/surfaces/source_sink_graph.json",
        "pattern_scan_json": "stages/findings/pattern_scan.json",
        "binary_strings_hits_json": "stages/findings/binary_strings_hits.json",
        "exploit_candidates_json": "stages/findings/exploit_candidates.json",
    }


def _overview_panes() -> list[dict[str, JsonValue]]:
    panes: list[dict[str, JsonValue]] = []
    for pane_id in ANALYST_OVERVIEW_PANE_ANCHOR_ORDER:
        title = ANALYST_OVERVIEW_PANE_TITLES.get(pane_id, pane_id)
        panes.append({"id": pane_id, "title": title})
    return panes


def _blocked_overview_gates(reason: str) -> list[dict[str, JsonValue]]:
    def gate_item(gate_id: str) -> dict[str, JsonValue]:
        return {
            "id": gate_id,
            "status": ANALYST_OVERVIEW_GATE_STATUS_BLOCKED,
            "reasons": cast(list[JsonValue], cast(list[object], [reason])),
        }

    return [
        gate_item(ANALYST_OVERVIEW_GATE_ID_REPORT_COMPLETENESS),
        gate_item(ANALYST_OVERVIEW_GATE_ID_ANALYST_DIGEST),
        gate_item(ANALYST_OVERVIEW_GATE_ID_ANALYST_REPORT_LINKAGE),
        gate_item(ANALYST_OVERVIEW_GATE_ID_VERIFIED_CHAIN),
        gate_item(ANALYST_OVERVIEW_GATE_ID_FINAL_REPORT_CONTRACT_8MB),
    ]


_OVERVIEW_ABSOLUTE_PATH_REDACTION = "(redacted: absolute path)"


def _looks_like_absolute_path_string(value: str) -> bool:
    if not value:
        return False
    return value.startswith("/") or bool(re.match(r"^[A-Za-z]:[\\/]", value))


def _sanitize_overview_summary_value(value: JsonValue) -> JsonValue:
    if isinstance(value, str):
        if _looks_like_absolute_path_string(value):
            return _OVERVIEW_ABSOLUTE_PATH_REDACTION
        return value
    if isinstance(value, list):
        items = cast(list[JsonValue], value)
        return cast(
            JsonValue,
            [_sanitize_overview_summary_value(item) for item in items],
        )
    if isinstance(value, dict):
        src = cast(dict[str, JsonValue], value)
        out: dict[str, JsonValue] = {}
        for key, item in src.items():
            out[key] = _sanitize_overview_summary_value(item)
        return cast(JsonValue, out)
    return value


def build_analyst_overview(
    report: dict[str, JsonValue],
    *,
    run_dir: Path,
    manifest: dict[str, JsonValue] | None = None,
    digest: dict[str, JsonValue] | None = None,
) -> dict[str, JsonValue]:
    """Build a deterministic single-pane overview payload.

    Input sources:
      - report/report.json (passed as `report`)
      - manifest (passed as `manifest` or loaded from run_dir/manifest.json)
      - report/analyst_digest.json (passed as `digest` or built from `report`)
      - stage artifacts are referenced only (no loading required)
    """

    manifest_obj: dict[str, JsonValue]
    manifest_block_reason: str | None = None
    if manifest is None:
        manifest_obj, manifest_block_reason = _safe_load_manifest_json(run_dir)
    else:
        manifest_obj = dict(manifest)

    if manifest_block_reason is not None:
        gates = _blocked_overview_gates(manifest_block_reason)
    else:
        gates = resolve_overview_gate_applicability(manifest_obj)

    refs = _overview_artifact_refs()
    artifacts = collect_overview_artifact_statuses(run_dir, refs)

    summary: dict[str, JsonValue] = {}

    def add_status_and_summary_only(*, report_key: str, out_key: str) -> None:
        section_any = report.get(report_key)
        if not isinstance(section_any, dict):
            return
        section_obj = cast(dict[str, JsonValue], section_any)
        out: dict[str, JsonValue] = {}
        status_any = section_obj.get("status")
        if isinstance(status_any, str) and status_any:
            out["status"] = status_any
        section_summary_any = section_obj.get("summary")
        if isinstance(section_summary_any, dict):
            out["summary"] = _sanitize_overview_summary_value(
                cast(JsonValue, dict(section_summary_any))
            )
        if out:
            summary[out_key] = cast(JsonValue, out)

    report_completeness_any = report.get("report_completeness")
    if isinstance(report_completeness_any, dict):
        summary["report_completeness"] = cast(JsonValue, dict(report_completeness_any))

    extraction_any = report.get("extraction")
    if isinstance(extraction_any, dict):
        extraction_obj = cast(dict[str, JsonValue], extraction_any)
        extraction_summary: dict[str, JsonValue] = {}
        status_any = extraction_obj.get("status")
        if isinstance(status_any, str) and status_any:
            extraction_summary["status"] = status_any
        confidence_any = extraction_obj.get("confidence")
        if isinstance(confidence_any, (int, float)) and not isinstance(
            confidence_any, bool
        ):
            extraction_summary["confidence"] = float(confidence_any)
        summary_any = extraction_obj.get("summary")
        if isinstance(summary_any, dict):
            extraction_summary["summary"] = _sanitize_overview_summary_value(
                cast(JsonValue, dict(summary_any))
            )
        if extraction_summary:
            summary["extraction_summary"] = cast(JsonValue, extraction_summary)

    inventory_any = report.get("inventory")
    if isinstance(inventory_any, dict):
        inventory_obj = cast(dict[str, JsonValue], inventory_any)
        inventory_summary: dict[str, JsonValue] = {}
        status_any = inventory_obj.get("status")
        if isinstance(status_any, str) and status_any:
            inventory_summary["status"] = status_any
        summary_any = inventory_obj.get("summary")
        if isinstance(summary_any, dict):
            inventory_summary["summary"] = _sanitize_overview_summary_value(
                cast(JsonValue, dict(summary_any))
            )
        if inventory_summary:
            summary["inventory_summary"] = cast(JsonValue, inventory_summary)

    add_status_and_summary_only(report_key="endpoints", out_key="endpoints_summary")
    add_status_and_summary_only(report_key="surfaces", out_key="surfaces_summary")
    add_status_and_summary_only(report_key="graph", out_key="graph_summary")
    add_status_and_summary_only(
        report_key="attack_surface", out_key="attack_surface_summary"
    )

    digest_obj: dict[str, JsonValue] | None = None
    if isinstance(digest, dict):
        digest_obj = dict(digest)
    else:
        try:
            digest_obj = build_analyst_digest(report, run_dir=run_dir)
        except Exception:
            digest_obj = None

    if digest_obj is not None:
        verdict_any = digest_obj.get("exploitability_verdict")
        if isinstance(verdict_any, dict):
            summary["exploitability_verdict"] = cast(JsonValue, dict(verdict_any))
        top_risk_any = digest_obj.get("top_risk_summary")
        if isinstance(top_risk_any, dict):
            summary["top_risk_summary"] = cast(JsonValue, dict(top_risk_any))

    def summary_nested_value(summary_key: str, value_key: str) -> JsonValue | None:
        section_any = summary.get(summary_key)
        if not isinstance(section_any, dict):
            return None
        section_obj = cast(dict[str, JsonValue], section_any)
        section_summary_any = section_obj.get("summary")
        if not isinstance(section_summary_any, dict):
            return None
        section_summary = cast(dict[str, JsonValue], section_summary_any)
        if value_key not in section_summary:
            return None
        return section_summary.get(value_key)

    verdict_state = "unknown"
    reason_codes: list[str] = []
    next_actions: list[str] = []
    if digest_obj is not None:
        verdict_any = digest_obj.get("exploitability_verdict")
        if isinstance(verdict_any, dict):
            verdict_obj = cast(dict[str, JsonValue], verdict_any)
            state_any = verdict_obj.get("state")
            if isinstance(state_any, str) and state_any:
                verdict_state = state_any
            reason_codes_any = verdict_obj.get("reason_codes")
            if isinstance(reason_codes_any, list):
                reason_codes = [
                    reason
                    for reason in cast(list[object], reason_codes_any)
                    if isinstance(reason, str) and reason
                ]
        next_actions_any = digest_obj.get("next_actions")
        if isinstance(next_actions_any, list):
            next_actions = [
                action
                for action in cast(list[object], next_actions_any)
                if isinstance(action, str) and action
            ]

    if verdict_state == "unknown":
        summary_verdict_any = summary.get("exploitability_verdict")
        if isinstance(summary_verdict_any, dict):
            summary_verdict = cast(dict[str, JsonValue], summary_verdict_any)
            state_any = summary_verdict.get("state")
            if isinstance(state_any, str) and state_any:
                verdict_state = state_any
            reason_codes_any = summary_verdict.get("reason_codes")
            if isinstance(reason_codes_any, list) and not reason_codes:
                reason_codes = [
                    reason
                    for reason in cast(list[object], reason_codes_any)
                    if isinstance(reason, str) and reason
                ]

    if not reason_codes:
        reason_codes = ["unknown"]
    if not next_actions:
        next_actions = ["unknown: re-run digest verifier"]

    report_completeness_snapshot: dict[str, JsonValue] | None = None
    report_completeness_any = summary.get("report_completeness")
    if isinstance(report_completeness_any, dict):
        report_completeness_snapshot = cast(
            dict[str, JsonValue],
            _sanitize_overview_summary_value(
                cast(
                    JsonValue, dict(cast(dict[str, JsonValue], report_completeness_any))
                )
            ),
        )
    run_completion_snapshot: dict[str, JsonValue] | None = None
    run_completion_any = report.get("run_completion")
    if isinstance(run_completion_any, dict):
        run_completion_obj = cast(dict[str, JsonValue], run_completion_any)
        run_completion_snapshot = {}
        is_final_any = run_completion_obj.get("is_final")
        if isinstance(is_final_any, bool):
            run_completion_snapshot["is_final"] = is_final_any
        is_partial_any = run_completion_obj.get("is_partial")
        if isinstance(is_partial_any, bool):
            run_completion_snapshot["is_partial"] = is_partial_any
        required_statuses_any = run_completion_obj.get("required_stage_statuses")
        if isinstance(required_statuses_any, dict):
            run_completion_snapshot["required_stage_statuses"] = (
                _sanitize_overview_summary_value(
                    cast(
                        JsonValue,
                        dict(cast(dict[str, JsonValue], required_statuses_any)),
                    )
                )
            )
        if not run_completion_snapshot:
            run_completion_snapshot = None

    executive_status = "ok"
    if verdict_state == "unknown":
        executive_status = "blocked"
    elif reason_codes == ["unknown"] or next_actions == [
        "unknown: re-run digest verifier"
    ]:
        executive_status = "partial"

    endpoints_value = summary_nested_value("attack_surface_summary", "endpoints")
    if endpoints_value is None:
        endpoints_value = summary_nested_value("endpoints_summary", "endpoints")
    surfaces_value = summary_nested_value("attack_surface_summary", "surfaces")
    unknowns_value = summary_nested_value("attack_surface_summary", "unknowns")
    non_promoted_value = summary_nested_value("attack_surface_summary", "non_promoted")

    attack_surface_data: dict[str, JsonValue] = {
        "endpoints": endpoints_value if endpoints_value is not None else "unknown",
        "surfaces": surfaces_value if surfaces_value is not None else "unknown",
        "unknowns": unknowns_value if unknowns_value is not None else "unknown",
        "non_promoted": non_promoted_value
        if non_promoted_value is not None
        else "unknown",
    }
    known_attack_surface_values = sum(
        1
        for key in ("endpoints", "surfaces", "unknowns", "non_promoted")
        if attack_surface_data.get(key) != "unknown"
    )
    if known_attack_surface_values == 4:
        attack_surface_status = "ok"
    elif known_attack_surface_values > 0:
        attack_surface_status = "partial"
    else:
        attack_surface_status = "unknown"

    gates_snapshot = cast(
        list[JsonValue],
        _sanitize_overview_summary_value(
            cast(JsonValue, [dict(gate) for gate in gates])
        ),
    )
    artifacts_snapshot = cast(
        list[JsonValue],
        _sanitize_overview_summary_value(
            cast(JsonValue, [dict(artifact) for artifact in artifacts])
        ),
    )

    artifact_counts: dict[str, JsonValue] = {
        "present": 0,
        "missing": 0,
        "invalid": 0,
        "required_missing": 0,
        "required_invalid": 0,
    }
    has_required_artifact_issue = False
    has_optional_artifact_issue = False
    has_blocked_gate = False
    blockers: list[str] = []

    def _safe_blocker_ref(ref_value: JsonValue) -> str:
        if not isinstance(ref_value, str):
            return "unknown"
        ref_norm = ref_value.replace("\\", "/")
        if _is_run_relative_path(ref_norm):
            return ref_norm
        return "(redacted: non run-relative ref)"

    for artifact_any in artifacts:
        status_any = artifact_any.get("status")
        status = status_any if isinstance(status_any, str) else "unknown"
        required_any = artifact_any.get("required")
        required = bool(required_any) if isinstance(required_any, bool) else False
        artifact_ref = _safe_blocker_ref(artifact_any.get("ref"))
        reason_any = artifact_any.get("reason")
        reason = reason_any if isinstance(reason_any, str) and reason_any else "unknown"

        if status == "present":
            artifact_counts["present"] = cast(int, artifact_counts["present"]) + 1
            continue
        if status == "missing":
            artifact_counts["missing"] = cast(int, artifact_counts["missing"]) + 1
            if required:
                artifact_counts["required_missing"] = (
                    cast(int, artifact_counts["required_missing"]) + 1
                )
                has_required_artifact_issue = True
                blockers.append(f"missing required artifact: {artifact_ref}")
            else:
                has_optional_artifact_issue = True
            continue
        if status == "invalid":
            artifact_counts["invalid"] = cast(int, artifact_counts["invalid"]) + 1
            if required:
                artifact_counts["required_invalid"] = (
                    cast(int, artifact_counts["required_invalid"]) + 1
                )
                has_required_artifact_issue = True
                blockers.append(f"invalid required artifact: {artifact_ref} ({reason})")
            else:
                has_optional_artifact_issue = True
                blockers.append(f"invalid artifact: {artifact_ref} ({reason})")

    for gate_any in gates:
        gate_status_any = gate_any.get("status")
        if gate_status_any != ANALYST_OVERVIEW_GATE_STATUS_BLOCKED:
            continue
        has_blocked_gate = True
        gate_id_any = gate_any.get("id")
        gate_id = (
            gate_id_any if isinstance(gate_id_any, str) and gate_id_any else "unknown"
        )
        reasons_any = gate_any.get("reasons")
        gate_reasons: list[str] = []
        if isinstance(reasons_any, list):
            gate_reasons = [
                reason
                for reason in cast(list[object], reasons_any)
                if isinstance(reason, str) and reason
            ]
        reason_text = ", ".join(gate_reasons) if gate_reasons else "no reason"
        blockers.append(f"blocked gate: {gate_id} ({reason_text})")

    blockers = sorted(set(blockers))

    verification_status = "ok"
    if has_blocked_gate or has_required_artifact_issue:
        verification_status = "blocked"
    elif has_optional_artifact_issue:
        verification_status = "partial"

    verification_data: dict[str, JsonValue] = {
        "gates": gates_snapshot,
        "artifacts": artifacts_snapshot,
        "artifact_counts": cast(JsonValue, artifact_counts),
        "blockers": cast(list[JsonValue], cast(list[object], blockers)),
    }
    if report_completeness_snapshot is not None:
        verification_data["report_completeness"] = cast(
            JsonValue, report_completeness_snapshot
        )

    evidence_link_refs: set[str] = {
        ANALYST_DIGEST_JSON_RELATIVE_PATH,
        ANALYST_DIGEST_MD_RELATIVE_PATH,
        ANALYST_OVERVIEW_JSON_RELATIVE_PATH,
        ANALYST_REPORT_V2_VIEWER_RELATIVE_PATH,
        "report/report.json",
    }
    for link_ref_any in _overview_links().values():
        if isinstance(link_ref_any, str) and _is_run_relative_path(link_ref_any):
            evidence_link_refs.add(link_ref_any.replace("\\", "/"))
    for artifact_any in artifacts:
        artifact_ref_any = artifact_any.get("ref")
        if isinstance(artifact_ref_any, str) and _is_run_relative_path(
            artifact_ref_any
        ):
            evidence_link_refs.add(artifact_ref_any.replace("\\", "/"))
    if digest_obj is not None:
        evidence_index_any = digest_obj.get("evidence_index")
        if isinstance(evidence_index_any, list):
            for item_any in cast(list[object], evidence_index_any):
                if not isinstance(item_any, dict):
                    continue
                ref_any = cast(dict[str, object], item_any).get("ref")
                if isinstance(ref_any, str) and _is_run_relative_path(ref_any):
                    evidence_link_refs.add(ref_any.replace("\\", "/"))
        finding_verdicts_any = digest_obj.get("finding_verdicts")
        if isinstance(finding_verdicts_any, list):
            for finding_any in cast(list[object], finding_verdicts_any):
                if not isinstance(finding_any, dict):
                    continue
                finding_obj = cast(dict[str, object], finding_any)
                for key in ("evidence_refs", "verifier_refs"):
                    refs_any = finding_obj.get(key)
                    if not isinstance(refs_any, list):
                        continue
                    for ref_any in cast(list[object], refs_any):
                        if isinstance(ref_any, str) and _is_run_relative_path(ref_any):
                            evidence_link_refs.add(ref_any.replace("\\", "/"))

    evidence_links = sorted(evidence_link_refs)
    if evidence_links and artifacts:
        evidence_status = "ok"
    elif evidence_links or artifacts:
        evidence_status = "partial"
    else:
        evidence_status = "blocked"

    cockpit: dict[str, JsonValue] = {
        "executive_verdict": {
            "status": executive_status,
            "sources": cast(
                list[JsonValue],
                cast(
                    list[object],
                    [
                        ANALYST_DIGEST_JSON_RELATIVE_PATH,
                        ANALYST_DIGEST_MD_RELATIVE_PATH,
                        ANALYST_OVERVIEW_JSON_RELATIVE_PATH,
                        "report/report.json",
                    ],
                ),
            ),
            "data": {
                "verdict_state": verdict_state,
                "reason_codes": cast(list[JsonValue], cast(list[object], reason_codes)),
                "next_actions": cast(list[JsonValue], cast(list[object], next_actions)),
                "report_completeness": cast(
                    JsonValue,
                    report_completeness_snapshot
                    if report_completeness_snapshot is not None
                    else {"status": "unknown", "gate_passed": "unknown"},
                ),
                "run_completion": cast(
                    JsonValue,
                    run_completion_snapshot
                    if run_completion_snapshot is not None
                    else {"status": "unknown"},
                ),
            },
        },
        "attack_surface_scale": {
            "status": attack_surface_status,
            "sources": cast(
                list[JsonValue],
                cast(
                    list[object],
                    [ANALYST_OVERVIEW_JSON_RELATIVE_PATH, "report/report.json"],
                ),
            ),
            "data": cast(JsonValue, attack_surface_data),
        },
        "verification_status": {
            "status": verification_status,
            "sources": cast(
                list[JsonValue],
                cast(list[object], [ANALYST_OVERVIEW_JSON_RELATIVE_PATH]),
            ),
            "data": cast(JsonValue, verification_data),
        },
        "evidence_navigator": {
            "status": evidence_status,
            "sources": cast(
                list[JsonValue],
                cast(
                    list[object],
                    [
                        ANALYST_OVERVIEW_JSON_RELATIVE_PATH,
                        ANALYST_DIGEST_JSON_RELATIVE_PATH,
                        ANALYST_DIGEST_MD_RELATIVE_PATH,
                    ],
                ),
            ),
            "data": {
                "evidence_links": cast(
                    list[JsonValue], cast(list[object], evidence_links)
                )
            },
        },
    }

    return {
        "schema_version": ANALYST_OVERVIEW_SCHEMA_VERSION,
        "panes": cast(list[JsonValue], cast(list[object], _overview_panes())),
        "gates": cast(list[JsonValue], cast(list[object], gates)),
        "artifacts": cast(list[JsonValue], cast(list[object], artifacts)),
        "links": cast(JsonValue, _overview_links()),
        "summary": cast(JsonValue, summary),
        "cockpit": cast(JsonValue, cockpit),
    }


def write_analyst_overview_json(report_dir: Path, report: dict[str, JsonValue]) -> Path:
    report_path = report_dir.parent / ANALYST_OVERVIEW_JSON_RELATIVE_PATH
    payload = build_analyst_overview(report, run_dir=report_dir.parent)
    _ = report_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return report_path


def _severity_counts_from_findings(
    report: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    counts: dict[str, int] = {severity: 0 for severity in _ANALYST_DIGEST_SEVERITIES}
    findings_any = report.get("findings")
    if not isinstance(findings_any, list):
        return cast(dict[str, JsonValue], counts)
    for finding_any in cast(list[object], findings_any):
        if not isinstance(finding_any, dict):
            continue
        severity_any = cast(dict[str, object], finding_any).get("severity")
        if isinstance(severity_any, str) and severity_any in counts:
            counts[severity_any] += 1
    return cast(dict[str, JsonValue], counts)


def _next_actions_for_state(state: str) -> list[str]:
    if state == "VERIFIED":
        return [
            "Review verified exploit chain artifacts and prepare remediation ticket.",
            "Prioritize patch rollout for VERIFIED findings.",
        ]
    if state == "ATTEMPTED_INCONCLUSIVE":
        return [
            "Inspect verifier outputs for inconclusive attempts and rerun validation.",
            "Regenerate digest after verifier rerun to confirm updated verdict.",
        ]
    if state == "NOT_APPLICABLE":
        return [
            "No relevant findings to verify; monitor new findings in subsequent runs.",
        ]
    return [
        "Run required verifier pipeline to produce verified_chain artifacts.",
        "Regenerate analyst digest after verifier artifacts are available.",
    ]


def _normalize_digest_reason_codes(reason_codes_any: object) -> list[str]:
    if not isinstance(reason_codes_any, list):
        return []
    out: list[str] = []
    for item_any in cast(list[object], reason_codes_any):
        if isinstance(item_any, str) and item_any:
            out.append(item_any)
    return out


def build_exploit_assessment_from_digest_verdict(
    *,
    profile: str,
    stage_statuses: dict[str, JsonValue],
    digest_verdict: dict[str, JsonValue] | None,
) -> dict[str, JsonValue]:
    if profile != "exploit":
        return {
            "profile": profile,
            "stage_statuses": cast(dict[str, JsonValue], dict(stage_statuses)),
            "decision": "not_requested",
            "exploitable": None,
            "reason_codes": cast(
                list[JsonValue], cast(list[object], ["PROFILE_NOT_EXPLOIT"])
            ),
        }

    verdict_state = "NOT_ATTEMPTED"
    reason_codes = ["NOT_ATTEMPTED_REQUIRED_VERIFIER_MISSING"]
    if isinstance(digest_verdict, dict):
        state_any = digest_verdict.get("state")
        if isinstance(state_any, str) and state_any in ANALYST_DIGEST_VERDICTS:
            verdict_state = state_any
        normalized_reason_codes = _normalize_digest_reason_codes(
            digest_verdict.get("reason_codes")
        )
        if normalized_reason_codes:
            reason_codes = normalized_reason_codes

    exploitable: bool | None = None
    if verdict_state == "VERIFIED":
        exploitable = True
    elif verdict_state == "NOT_APPLICABLE":
        exploitable = False

    return {
        "profile": profile,
        "stage_statuses": cast(dict[str, JsonValue], dict(stage_statuses)),
        "decision": verdict_state,
        "exploitable": exploitable,
        "reason_codes": cast(list[JsonValue], cast(list[object], reason_codes)),
    }


def build_analyst_digest(
    report: dict[str, JsonValue], *, run_dir: Path
) -> dict[str, JsonValue]:
    overview_any = report.get("overview")
    overview = (
        cast(dict[str, object], overview_any) if isinstance(overview_any, dict) else {}
    )
    run_id_any = overview.get("run_id")
    firmware_sha_any = overview.get("analyzed_input_sha256")
    if not isinstance(firmware_sha_any, str) or not firmware_sha_any:
        firmware_sha_any = overview.get("input_sha256")
    generated_at_any = overview.get("created_at")

    severity_counts = _severity_counts_from_findings(report)
    finding_verdicts = _build_finding_verdicts(report, run_dir=run_dir)
    exploitability_verdict = _aggregate_verdict(finding_verdicts)

    evidence_refs: set[str] = set()
    for verdict in finding_verdicts:
        refs_any = verdict.get("evidence_refs")
        if not isinstance(refs_any, list):
            continue
        for ref_any in cast(list[object], refs_any):
            if isinstance(ref_any, str):
                if not _is_run_relative_path(ref_any):
                    raise ValueError(
                        "invalid analyst digest: finding evidence ref must be run-relative"
                    )
                evidence_refs.add(ref_any)
        verifier_refs_any = verdict.get("verifier_refs")
        if not isinstance(verifier_refs_any, list):
            raise ValueError("invalid analyst digest: verifier_refs missing")
        for verifier_ref_any in cast(list[object], verifier_refs_any):
            if not isinstance(verifier_ref_any, str) or not _is_run_relative_path(
                verifier_ref_any
            ):
                raise ValueError(
                    "invalid analyst digest: verifier ref must be run-relative"
                )

    evidence_index = _build_evidence_index(run_dir=run_dir, evidence_refs=evidence_refs)
    verdict_state = cast(str, exploitability_verdict.get("state", "NOT_ATTEMPTED"))
    next_actions = _next_actions_for_state(verdict_state)

    digest: dict[str, JsonValue] = {
        "schema_version": ANALYST_DIGEST_SCHEMA_VERSION,
        "run": {
            "run_id": run_id_any
            if isinstance(run_id_any, str) and run_id_any
            else "unknown-run",
            "firmware_sha256": firmware_sha_any
            if isinstance(firmware_sha_any, str) and firmware_sha_any
            else "0" * 64,
            "generated_at": generated_at_any
            if isinstance(generated_at_any, str) and generated_at_any
            else "unknown",
        },
        "top_risk_summary": {
            "total_findings": len(finding_verdicts),
            "severity_counts": severity_counts,
        },
        "finding_verdicts": cast(list[JsonValue], cast(list[object], finding_verdicts)),
        "exploitability_verdict": exploitability_verdict,
        "evidence_index": cast(list[JsonValue], cast(list[object], evidence_index)),
        "next_actions": cast(list[JsonValue], cast(list[object], next_actions)),
    }

    errors = validate_analyst_digest(digest)
    if errors:
        joined = "; ".join(errors)
        raise ValueError(f"invalid analyst digest: {joined}")
    return digest


def write_analyst_digest_json(report_dir: Path, report: dict[str, JsonValue]) -> Path:
    report_path = report_dir / "analyst_digest.json"
    payload = build_analyst_digest(report, run_dir=report_dir.parent)
    _ = report_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return report_path


def write_analyst_digest_md(report_dir: Path, report: dict[str, JsonValue]) -> Path:
    report_path = report_dir / "analyst_digest.md"
    payload = build_analyst_digest(report, run_dir=report_dir.parent)

    run_any = payload.get("run")
    run_obj = cast(dict[str, object], run_any) if isinstance(run_any, dict) else {}
    verdict_any = payload.get("exploitability_verdict")
    verdict_obj = (
        cast(dict[str, object], verdict_any) if isinstance(verdict_any, dict) else {}
    )
    top_risk_any = payload.get("top_risk_summary")
    top_risk_obj = (
        cast(dict[str, object], top_risk_any) if isinstance(top_risk_any, dict) else {}
    )

    lines: list[str] = [
        "# AIEdge Analyst Digest",
        "",
        f"Schema version: `{payload.get('schema_version', '')}`",
        f"Run ID: `{run_obj.get('run_id', '')}`",
        f"Firmware SHA256: `{run_obj.get('firmware_sha256', '')}`",
        f"Generated At: `{run_obj.get('generated_at', '')}`",
        "",
        "## Exploitability Verdict",
        f"- State: `{verdict_obj.get('state', '')}`",
        f"- Aggregation Rule: `{verdict_obj.get('aggregation_rule', '')}`",
        "",
        "## Top Risk Summary",
        f"- Total Findings: {top_risk_obj.get('total_findings', 0)}",
    ]

    severity_counts_any = top_risk_obj.get("severity_counts")
    if isinstance(severity_counts_any, dict):
        for severity in _ANALYST_DIGEST_SEVERITIES:
            lines.append(
                f"- Severity {severity}: {cast(dict[str, object], severity_counts_any).get(severity, 0)}"
            )

    lines.extend(["", "## Finding Verdicts"])
    finding_verdicts_any = payload.get("finding_verdicts")
    finding_verdicts = (
        cast(list[object], finding_verdicts_any)
        if isinstance(finding_verdicts_any, list)
        else []
    )
    if not finding_verdicts:
        lines.append("- (none)")
    else:
        for item_any in finding_verdicts:
            if not isinstance(item_any, dict):
                continue
            item = cast(dict[str, object], item_any)
            lines.append(
                f"- {item.get('finding_id', '')}: verdict={item.get('verdict', '')} evidence={','.join(cast(list[str], item.get('evidence_refs', [])))} verifier={','.join(cast(list[str], item.get('verifier_refs', [])))}"
            )

    lines.extend(["", "## Evidence Index"])
    evidence_index_any = payload.get("evidence_index")
    evidence_index = (
        cast(list[object], evidence_index_any)
        if isinstance(evidence_index_any, list)
        else []
    )
    if not evidence_index:
        lines.append("- (none)")
    else:
        for item_any in evidence_index:
            if not isinstance(item_any, dict):
                continue
            item = cast(dict[str, object], item_any)
            lines.append(f"- {item.get('ref', '')} sha256={item.get('sha256', '')}")

    lines.extend(["", "## Next Actions"])
    next_actions_any = payload.get("next_actions")
    next_actions = (
        cast(list[object], next_actions_any)
        if isinstance(next_actions_any, list)
        else []
    )
    if not next_actions:
        lines.append("- (none)")
    else:
        for action_any in next_actions:
            if isinstance(action_any, str):
                lines.append(f"- {action_any}")

    _ = report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def analyst_report_v2_severity_rank(severity: object) -> int:
    if not isinstance(severity, str):
        return 0
    return ANALYST_REPORT_V2_SEVERITY_RANK.get(severity.lower(), 0)


def analyst_report_v2_first_evidence_ref(claim: dict[str, JsonValue]) -> str:
    refs_any = claim.get("evidence_refs")
    if not isinstance(refs_any, list):
        return ""
    refs = sorted(ref for ref in refs_any if isinstance(ref, str) and ref)
    if not refs:
        return ""
    return refs[0]


def analyst_report_v2_top_risk_sort_key(
    claim: dict[str, JsonValue],
) -> tuple[int, float, str, str]:
    confidence_any = claim.get("confidence")
    confidence = (
        float(confidence_any)
        if isinstance(confidence_any, (int, float))
        and not isinstance(confidence_any, bool)
        else 0.0
    )
    claim_type_any = claim.get("claim_type")
    claim_type = claim_type_any if isinstance(claim_type_any, str) else ""
    return (
        -analyst_report_v2_severity_rank(claim.get("severity")),
        -confidence,
        claim_type,
        analyst_report_v2_first_evidence_ref(claim),
    )


def _parse_utc_iso8601(raw: object) -> datetime | None:
    if not isinstance(raw, str) or not raw:
        return None
    s = raw.strip()
    if not s:
        return None
    # manifest.json uses RFC3339 like 2026-02-15T02:32:08.508226Z
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _format_kst_from_manifest(run_dir: Path) -> str:
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.is_file():
        return "unavailable (missing manifest.json)"
    try:
        obj_any = cast(object, json.loads(manifest_path.read_text(encoding="utf-8")))
    except Exception:
        return "unavailable (unreadable manifest.json)"
    if not isinstance(obj_any, dict):
        return "unavailable (invalid manifest.json)"
    created_at = cast(dict[str, object], obj_any).get("created_at")
    dt = _parse_utc_iso8601(created_at)
    if dt is None:
        return "unavailable (invalid manifest.created_at)"
    try:
        kst = dt.astimezone(ZoneInfo(ANALYST_REPORT_V2_MARKDOWN_TIMEZONE)).replace(
            microsecond=0
        )
    except Exception:
        return "unavailable (tz conversion failed)"
    return f"{kst.isoformat()} ({ANALYST_REPORT_V2_MARKDOWN_TIMEZONE})"


def _normalize_v2_claim_from_claim_like(obj_any: object) -> dict[str, JsonValue] | None:
    if not isinstance(obj_any, dict):
        return None
    obj = cast(dict[str, object], obj_any)

    claim_type_any = obj.get("claim_type")
    if not isinstance(claim_type_any, str) or not claim_type_any:
        return None
    severity_any = obj.get("severity")
    if not isinstance(severity_any, str) or not severity_any:
        return None
    severity = severity_any.lower()
    if severity not in ANALYST_REPORT_V2_SEVERITY_RANK:
        return None

    conf_any = obj.get("confidence")
    if isinstance(conf_any, bool) or not isinstance(conf_any, (int, float)):
        return None
    confidence = _clamp01(float(conf_any))

    refs_any = obj.get("evidence_refs")
    if not isinstance(refs_any, list):
        return None
    refs = sorted(
        {
            x.replace("\\", "/")
            for x in cast(list[object], refs_any)
            if isinstance(x, str) and _is_run_relative_path(x)
        }
    )
    if not refs:
        return None

    out: dict[str, JsonValue] = {
        "claim_type": claim_type_any,
        "severity": severity,
        "confidence": confidence,
        "evidence_refs": cast(list[JsonValue], cast(list[object], refs)),
    }
    tier_any = obj.get("exploitability_tier")
    if is_valid_exploitability_tier(tier_any):
        out["exploitability_tier"] = cast(JsonValue, tier_any)
    value_any = obj.get("value")
    if value_any is not None:
        out["value"] = cast(JsonValue, value_any)
    return out


def _normalize_v2_claim_from_finding(obj_any: object) -> dict[str, JsonValue] | None:
    if not isinstance(obj_any, dict):
        return None
    obj = cast(dict[str, object], obj_any)

    finding_id_any = obj.get("id")
    title_any = obj.get("title")
    claim_type = (
        finding_id_any
        if isinstance(finding_id_any, str) and finding_id_any
        else (title_any if isinstance(title_any, str) and title_any else "")
    )
    if not claim_type:
        return None

    severity_any = obj.get("severity")
    if not isinstance(severity_any, str) or not severity_any:
        return None
    severity = severity_any.lower()
    if severity not in ANALYST_REPORT_V2_SEVERITY_RANK:
        return None

    conf_any = obj.get("confidence")
    if isinstance(conf_any, bool) or not isinstance(conf_any, (int, float)):
        return None
    confidence = _clamp01(float(conf_any))

    evidence_any = obj.get("evidence")
    if not isinstance(evidence_any, list):
        return None
    refs: set[str] = set()
    for ev_any in cast(list[object], evidence_any):
        if not isinstance(ev_any, dict):
            continue
        path_any = cast(dict[str, object], ev_any).get("path")
        if isinstance(path_any, str) and _is_run_relative_path(path_any):
            refs.add(path_any.replace("\\", "/"))
    if not refs:
        return None

    out: dict[str, JsonValue] = {
        "claim_type": claim_type,
        "severity": severity,
        "confidence": confidence,
        "evidence_refs": cast(list[JsonValue], cast(list[object], sorted(refs))),
    }
    tier_any = obj.get("exploitability_tier")
    if is_valid_exploitability_tier(tier_any):
        out["exploitability_tier"] = cast(JsonValue, tier_any)
    return out


def _v2_severity_counts(
    claims: list[dict[str, JsonValue]],
) -> dict[str, JsonValue]:
    counts: dict[str, int] = {
        severity: 0 for severity in ANALYST_REPORT_V2_SEVERITY_ORDER
    }
    for claim in claims:
        severity_any = claim.get("severity")
        if isinstance(severity_any, str) and severity_any in counts:
            counts[severity_any] += 1
    ordered: dict[str, JsonValue] = {}
    for severity in ANALYST_REPORT_V2_SEVERITY_ORDER:
        count = counts.get(severity, 0)
        if count > 0:
            ordered[severity] = count
    return ordered


def _v2_unique_evidence_refs(claims: list[dict[str, JsonValue]]) -> list[str]:
    refs: set[str] = set()
    for claim in claims:
        refs_any = claim.get("evidence_refs")
        if not isinstance(refs_any, list):
            continue
        for ref_any in cast(list[object], refs_any):
            if isinstance(ref_any, str) and ref_any:
                refs.add(ref_any)
    return sorted(refs)


def build_analyst_report_v2(report: dict[str, JsonValue]) -> dict[str, JsonValue]:
    # Preferred source: findings (risk signals) -> fallback: existing claims.
    findings_any = report.get(ANALYST_REPORT_V2_TOP_RISK_SOURCE_FIELD)
    claims_out: list[dict[str, JsonValue]] = []
    source = "claims"

    if isinstance(findings_any, list):
        for item_any in cast(list[object], findings_any):
            norm = _normalize_v2_claim_from_finding(item_any)
            if norm is not None:
                claims_out.append(norm)
    if claims_out:
        source = ANALYST_REPORT_V2_TOP_RISK_SOURCE_FIELD

    if not claims_out:
        claims_any = report.get("claims")
        if isinstance(claims_any, list):
            for item_any in cast(list[object], claims_any):
                norm = _normalize_v2_claim_from_claim_like(item_any)
                if norm is not None:
                    claims_out.append(norm)

    claims_sorted = sorted(claims_out, key=analyst_report_v2_top_risk_sort_key)
    top = claims_sorted[: int(ANALYST_REPORT_V2_TOP_RISK_LIMIT)]
    top_refs = _v2_unique_evidence_refs(top)
    severity_counts = _v2_severity_counts(top)

    return {
        "schema_version": ANALYST_REPORT_V2_SCHEMA_VERSION,
        "source": source,
        "summary": {
            "top_risk_count": len(top),
            "candidate_claim_count": len(claims_sorted),
            "severity_counts": cast(JsonValue, severity_counts),
            "evidence_ref_count": len(top_refs),
        },
        "evidence_index": cast(list[JsonValue], cast(list[object], top_refs)),
        "top_risk_claims": cast(list[JsonValue], cast(list[object], top)),
    }


def write_analyst_report_v2_json(
    report_dir: Path, report: dict[str, JsonValue]
) -> Path:
    report_path = report_dir / "analyst_report_v2.json"
    payload = build_analyst_report_v2(report)
    _ = report_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return report_path


def write_analyst_report_v2_md(report_dir: Path, report: dict[str, JsonValue]) -> Path:
    report_path = report_dir / "analyst_report_v2.md"
    payload = build_analyst_report_v2(report)

    run_dir = report_dir.parent
    run_time_kst = _format_kst_from_manifest(run_dir)

    conclusion = ""
    rc_any = report.get("run_completion")
    if isinstance(rc_any, dict):
        cn_any = cast(dict[str, object], rc_any).get("conclusion_note")
        if isinstance(cn_any, str) and cn_any:
            conclusion = cn_any
    if not conclusion:
        conclusion = (
            "Analysis conclusions are provisional; see report/report.json for details."
        )

    top_any = payload.get("top_risk_claims")
    top = cast(list[object], top_any) if isinstance(top_any, list) else []

    source_any = payload.get("source")
    source = source_any if isinstance(source_any, str) and source_any else "claims"

    summary_any = payload.get("summary")
    summary = (
        cast(dict[str, object], summary_any) if isinstance(summary_any, dict) else {}
    )
    top_count_any = summary.get("top_risk_count")
    top_count = int(top_count_any) if isinstance(top_count_any, int) else len(top)

    lines: list[str] = [
        "# AIEdge Analyst Report v2",
        "",
        "## Executive Summary",
        f"- Conclusion: {conclusion}",
        f"- Run Time (KST): {run_time_kst}",
        f"- Top Risks: {top_count}",
        f"- Source: {source}",
        "",
        "## Top Risks",
    ]
    if not top:
        lines.append("- (none)")
    else:
        for i, item_any in enumerate(
            top[: int(ANALYST_REPORT_V2_TOP_RISK_LIMIT)], start=1
        ):
            if not isinstance(item_any, dict):
                continue
            item = cast(dict[str, object], item_any)
            ct = item.get("claim_type")
            sev = item.get("severity")
            conf = item.get("confidence")
            refs_any = item.get("evidence_refs")
            first_ref = ""
            if isinstance(refs_any, list) and refs_any:
                ref0 = cast(object, refs_any[0])
                if isinstance(ref0, str):
                    first_ref = ref0
            conf_value = (
                f"{float(conf):.2f}"
                if isinstance(conf, (int, float)) and not isinstance(conf, bool)
                else str(conf)
            )
            lines.extend(
                [
                    f"### {i}. [{str(sev).upper()}] {str(ct)}",
                    f"- Confidence: {conf_value}",
                    f"- Primary Evidence: {first_ref if first_ref else '(none)'}",
                    "",
                ]
            )

    evidence_index_any = payload.get("evidence_index")
    evidence_index = (
        [ref for ref in cast(list[object], evidence_index_any) if isinstance(ref, str)]
        if isinstance(evidence_index_any, list)
        else []
    )
    lines.extend(["## Evidence Index", ""])
    if not evidence_index:
        lines.append("- (none)")
    else:
        for ref in evidence_index:
            lines.append(f"- {ref}")

    _ = report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


def write_analyst_report_v2_viewer(
    report_dir: Path, report: dict[str, JsonValue]
) -> Path:
    report_path = report_dir / "viewer.html"
    payload = build_analyst_report_v2(report)
    bootstrap = json.dumps(payload, sort_keys=True, ensure_ascii=True).replace(
        "</", "<\\/"
    )

    try:
        digest_payload: dict[str, JsonValue] = build_analyst_digest(
            report, run_dir=report_dir.parent
        )
    except Exception:
        digest_payload = {}
    digest_bootstrap = json.dumps(
        digest_payload, sort_keys=True, ensure_ascii=True
    ).replace("</", "<\\/")

    overview_payload = build_analyst_overview(
        report,
        run_dir=report_dir.parent,
        digest=digest_payload,
    )
    overview_bootstrap = json.dumps(
        overview_payload, sort_keys=True, ensure_ascii=True
    ).replace("</", "<\\/")
    exploit_candidates_payload: dict[str, JsonValue] = {}
    exploit_candidates_path = (
        report_dir.parent / "stages" / "findings" / "exploit_candidates.json"
    )
    if exploit_candidates_path.is_file():
        try:
            obj_any = cast(
                object, json.loads(exploit_candidates_path.read_text(encoding="utf-8"))
            )
            if isinstance(obj_any, dict):
                exploit_candidates_payload = cast(dict[str, JsonValue], obj_any)
        except Exception:
            exploit_candidates_payload = {}
    exploit_candidates_bootstrap = json.dumps(
        exploit_candidates_payload, sort_keys=True, ensure_ascii=True
    ).replace("</", "<\\/")

    # Graph data bootstrap
    graph_payload: dict[str, JsonValue] = {}
    _GRAPH_NODE_LIMIT = 250
    _GRAPH_EDGE_LIMIT = 400
    for gname in ("comm_graph.json", "reference_graph.json"):
        gpath = report_dir.parent / "stages" / "graph" / gname
        if gpath.is_file():
            try:
                gobj = cast(object, json.loads(gpath.read_text(encoding="utf-8")))
                if isinstance(gobj, dict):
                    gdict = cast(dict[str, object], gobj)
                    # Trim to keep IPC nodes/edges + top N by confidence
                    raw_nodes = gdict.get("nodes")
                    raw_edges = gdict.get("edges")
                    if isinstance(raw_nodes, list) and isinstance(raw_edges, list):
                        # Prioritize IPC nodes, then components, then others
                        ipc_nodes = [n for n in raw_nodes if isinstance(n, dict) and n.get("type") == "ipc_channel"]
                        other_nodes = [n for n in raw_nodes if isinstance(n, dict) and n.get("type") != "ipc_channel"]
                        trimmed_nodes = ipc_nodes + other_nodes[:_GRAPH_NODE_LIMIT - len(ipc_nodes)]
                        # Keep IPC edges + top edges by confidence
                        ipc_edges = [e for e in raw_edges if isinstance(e, dict) and isinstance(e.get("edge_type"), str) and "ipc" in str(e.get("edge_type"))]
                        other_edges = sorted(
                            [e for e in raw_edges if isinstance(e, dict) and not ("ipc" in str(e.get("edge_type", "")))],
                            key=lambda x: -(x.get("confidence", 0) if isinstance(x.get("confidence"), (int, float)) else 0),
                        )
                        trimmed_edges = ipc_edges + other_edges[:_GRAPH_EDGE_LIMIT - len(ipc_edges)]
                        # Keep node IDs referenced by trimmed edges
                        keep_ids: set[str] = set()
                        for e in trimmed_edges:
                            if isinstance(e, dict):
                                s = e.get("src")
                                d = e.get("dst")
                                if isinstance(s, str):
                                    keep_ids.add(s)
                                if isinstance(d, str):
                                    keep_ids.add(d)
                        final_nodes = [n for n in trimmed_nodes if isinstance(n, dict) and n.get("id") in keep_ids]
                        if not final_nodes:
                            final_nodes = trimmed_nodes[:_GRAPH_NODE_LIMIT]
                        gdict_trimmed: dict[str, JsonValue] = {
                            "nodes": cast(JsonValue, final_nodes),
                            "edges": cast(JsonValue, trimmed_edges),
                            "summary": cast(JsonValue, gdict.get("summary", {})),
                            "trimmed": True,
                            "original_nodes": len(raw_nodes),
                            "original_edges": len(raw_edges),
                        }
                        graph_payload[gname.replace(".json", "")] = cast(JsonValue, gdict_trimmed)
                    else:
                        graph_payload[gname.replace(".json", "")] = cast(JsonValue, gdict)
            except Exception:
                pass
    graph_bootstrap = json.dumps(
        graph_payload, sort_keys=True, ensure_ascii=True
    ).replace("</", "<\\/")

    # IPC / binary analysis bootstrap
    ipc_payload: dict[str, JsonValue] = {}
    ba_path = report_dir.parent / "stages" / "inventory" / "binary_analysis.json"
    if ba_path.is_file():
        try:
            ba_obj = cast(object, json.loads(ba_path.read_text(encoding="utf-8")))
            if isinstance(ba_obj, dict):
                ipc_payload = cast(dict[str, JsonValue], ba_obj)
        except Exception:
            pass
    ipc_bootstrap = json.dumps(
        ipc_payload, sort_keys=True, ensure_ascii=True
    ).replace("</", "<\\/")

    # -- heatmap cell builder (safe: only static labels go into textContent) --
    _heatmap_cell_js = (
        "function _hmCell(name,status){"
        "var c=document.createElement('div');c.className='heatmap-cell';"
        "if(status==='ok')c.className+=' low';"
        "else if(status==='partial')c.className+=' medium';"
        "else if(status==='failed')c.className+=' high';"
        "else c.className+=' none';"
        "var t=document.createElement('div');t.style.fontSize='0.72rem';t.style.color='var(--muted)';t.textContent=name;c.appendChild(t);"
        "var v=document.createElement('div');v.textContent=status;c.appendChild(v);"
        "return c;}"
    )

    doc = "\n".join(
        [
            "<!doctype html>",
            '<html lang="en" data-theme="dark">',
            "<head>",
            '  <meta charset="utf-8">',
            '  <meta name="viewport" content="width=device-width, initial-scale=1">',
            "  <title>SCOUT Analyst Report</title>",

            "  <style>",
            "    :root, [data-theme='dark'] {",
            "      --bg: #0c1222;",
            "      --bg-secondary: #111a2e;",
            "      --surface: rgba(255,255,255,0.06);",
            "      --surface-hover: rgba(255,255,255,0.10);",
            "      --glass: rgba(255,255,255,0.07);",
            "      --glass-border: rgba(255,255,255,0.12);",
            "      --ink: #f1f5f9;",
            "      --ink-secondary: #cbd5e1;",
            "      --muted: #94a3b8;",
            "      --accent: #22d3ee;",
            "      --accent-glow: rgba(34,211,238,0.12);",
            "      --success: #4ade80;",
            "      --warning: #fbbf24;",
            "      --danger: #f87171;",
            "      --info: #818cf8;",
            "      --ipc-purple: #c084fc;",
            "      --line: rgba(255,255,255,0.06);",
            "      --radius: 14px;",
            "      --radius-sm: 8px;",
            "    }",
            "    [data-theme='light'] {",
            "      --bg: #f8fafc;",
            "      --bg-secondary: #ffffff;",
            "      --surface: rgba(255,255,255,0.9);",
            "      --surface-hover: #ffffff;",
            "      --glass: rgba(255,255,255,0.75);",
            "      --glass-border: rgba(0,0,0,0.08);",
            "      --ink: #0f172a;",
            "      --ink-secondary: #334155;",
            "      --muted: #64748b;",
            "      --accent: #0891b2;",
            "      --accent-glow: rgba(8,145,178,0.08);",
            "      --line: rgba(0,0,0,0.06);",
            "    }",
            "    html { scroll-behavior: smooth; scroll-padding-top: 74px; }",
            "    * { box-sizing: border-box; margin: 0; padding: 0; }",
            "    body {",
            "      background: linear-gradient(to right, #24243e, #302b63, #0f0c29);",
            "      background-attachment: fixed;",
            "      color: var(--ink);",
            "      font-family: system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif;",
            "      font-size: 14px; line-height: 1.6;",
            "      -webkit-font-smoothing: antialiased;",
            "      min-height: 100vh;",
            "    }",
            "    pre, code, .mono { font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', 'JetBrains Mono', Consolas, monospace; font-size: 0.82rem; }",
            "    body::before {",
            "      content: ''; position: fixed; inset: 0; z-index: -1; pointer-events: none;",
            "      background:",
            "        radial-gradient(800px circle at 10% 20%, rgba(34,211,238,0.25) 0%, transparent 45%),",
            "        radial-gradient(600px circle at 85% 15%, rgba(192,132,252,0.22) 0%, transparent 45%),",
            "        radial-gradient(700px circle at 50% 80%, rgba(74,222,128,0.15) 0%, transparent 45%),",
            "        radial-gradient(500px circle at 95% 70%, rgba(248,113,113,0.12) 0%, transparent 40%);",
            "    }",
            "    [data-theme='light'] body { background: #f0f2f5; }",
            "    [data-theme='light'] body::before { background: radial-gradient(800px circle at 20% 30%, rgba(8,145,178,0.08) 0%, transparent 50%), radial-gradient(600px circle at 75% 15%, rgba(168,85,247,0.06) 0%, transparent 50%); }",
            "    @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }",
            "",
            "    /* --- Top bar --- */",
            "    .top-bar { position: fixed; top: 0; left: 0; right: 0; height: 56px; z-index: 100; display: flex; align-items: center; gap: 16px; padding: 0 32px;",
            "      background: rgba(17,25,40,0.75); backdrop-filter: blur(16px) saturate(180%); -webkit-backdrop-filter: blur(16px) saturate(180%);",
            "      border-bottom: 1px solid rgba(255,255,255,0.125); }",
            "    .top-bar::after { content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 1px;",
            "      background: linear-gradient(90deg, transparent 5%, var(--accent) 30%, var(--ipc-purple) 50%, var(--accent) 70%, transparent 95%); opacity: 0.4; }",
            "    [data-theme='light'] .top-bar { background: rgba(255,255,255,0.8); backdrop-filter: blur(16px); border-bottom: 1px solid rgba(0,0,0,0.06); }",
            "    .logo { font-size: 1.1rem; font-weight: 800; letter-spacing: 0.2em; color: var(--accent); }",
            "    .top-bar .search-bar { flex: 1; max-width: 420px; position: relative; }",
            "    .top-bar .search-bar input { width: 100%; padding: 8px 12px 8px 36px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.15); background: rgba(255,255,255,0.08); backdrop-filter: blur(8px); color: #f1f5f9; font-size: 0.82rem; outline: none; transition: all 0.2s; }",
            "    .top-bar .search-bar input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow), 0 0 20px rgba(34,211,238,0.1); }",
            "    .top-bar .search-bar input::placeholder { color: rgba(255,255,255,0.35); }",
            "    .top-bar .search-bar::before { content: ''; position: absolute; left: 12px; top: 50%; transform: translateY(-50%); width: 14px; height: 14px; border: 2px solid var(--muted); border-radius: 50%; }",
            "    .top-bar .spacer { flex: 1; }",
            "    .theme-toggle { background: var(--surface); border: 1px solid var(--glass-border); border-radius: var(--radius-sm); padding: 6px 12px; color: var(--ink); cursor: pointer; font-size: 0.8rem; transition: all 0.2s ease; }",
            "    .theme-toggle:hover { background: var(--surface-hover); }",
            "",
            "    /* --- Pipeline bar --- */",
            "    .pipeline-bar { position: fixed; top: 56px; left: 0; right: 0; height: 4px; z-index: 99; display: flex; background: var(--bg-secondary); box-shadow: 0 2px 8px rgba(0,0,0,0.2); }",
            "    .pipeline-bar .seg { flex: 1; transition: background 0.3s; position: relative; }",
            "    .pipeline-bar .seg.ok { background: var(--success); box-shadow: 0 0 8px rgba(74,222,128,0.4); }",
            "    .pipeline-bar .seg.partial { background: var(--warning); box-shadow: 0 0 8px rgba(251,191,36,0.4); }",
            "    .pipeline-bar .seg.failed { background: var(--danger); box-shadow: 0 0 8px rgba(248,113,113,0.4); }",
            "    .pipeline-bar .seg.skipped { background: var(--muted); opacity: 0.3; }",
            "    .pipeline-bar .seg.unknown { background: var(--line); }",
            "",
            "    /* --- Page shell (centered flex layout) --- */",
            "    .page-shell { display: flex; max-width: 1800px; margin: 74px auto 0 auto; min-height: calc(100vh - 74px); padding: 0 32px; }",
            "",
            "    /* --- Sidebar --- */",
            "    .sidebar { position: sticky; top: 74px; width: 200px; flex-shrink: 0; height: calc(100vh - 74px); overflow-y: auto; padding: 16px 0;",
            "      background: rgba(255,255,255,0.03);",
            "      border-right: 1px solid rgba(255,255,255,0.06); }",
            "    .sidebar a { display: block; padding: 8px 16px; color: var(--muted); text-decoration: none; font-size: 0.75rem; font-weight: 500;",
            "      transition: all 0.15s; border-left: 2px solid transparent; }",
            "    .sidebar a:hover { color: var(--ink); background: rgba(255,255,255,0.04); }",
            "    .sidebar a.active { color: var(--accent); border-left-color: var(--accent); background: var(--accent-glow); font-weight: 700; }",
            "    .hamburger { display: none; background: none; border: none; color: var(--ink); font-size: 1.3rem; cursor: pointer; }",
            "",
            "    /* --- Main content --- */",
            "    .main-content { flex: 1; min-width: 0; padding: 24px 0 40px 32px; }",
            "",
            "    /* --- Card --- */",
            "    .card { background: rgba(255,255,255,0.10); border: 2px solid rgba(255,255,255,0.20);",
            "      border-radius: 20px; backdrop-filter: blur(40px) saturate(180%); -webkit-backdrop-filter: blur(40px) saturate(180%);",
            "      box-shadow: 0 8px 32px rgba(0,0,0,0.3); overflow: hidden; margin-bottom: 20px;",
            "      transition: all 0.3s ease; position: relative; }",
            "    .card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 1px;",
            "      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent); }",
            "    .card:hover { background: rgba(255,255,255,0.15); box-shadow: 0 12px 48px rgba(0,0,0,0.4); border-color: rgba(255,255,255,0.30); transform: translateY(-2px); }",
            "    [data-theme='light'] .card { background: rgba(255,255,255,0.75); backdrop-filter: blur(20px); box-shadow: 0 4px 16px rgba(0,0,0,0.06); border-color: rgba(0,0,0,0.08); }",
            "    [data-theme='light'] .card:hover { box-shadow: 0 8px 32px rgba(0,0,0,0.1); }",
            "    .card h2 { font-size: 0.75rem; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase;",
            "      padding: 16px 24px; color: #e2e8f0; cursor: pointer; display: flex; align-items: center;",
            "      border-bottom: 1px solid rgba(255,255,255,0.08); transition: all 0.2s; user-select: none;",
            "      background: rgba(255,255,255,0.03); }",
            "    .card h2:hover { color: var(--accent); }",
            "    .card h2::after { content: ''; margin-left: auto; width: 6px; height: 6px;",
            "      border-right: 1.5px solid var(--muted); border-bottom: 1.5px solid var(--muted);",
            "      transform: rotate(45deg); transition: transform 0.2s; }",
            "    .card.collapsed h2::after { transform: rotate(-45deg); }",
            "    .card h2::before { display: none; }",
            "    .card.collapsed .card-body { display: none; }",
            "    .card-body { padding: 20px; color: #f1f5f9; }",
            "    .card h3 { font-size: 0.85rem; font-weight: 600; color: var(--ink); margin: 16px 0 8px 0; }",
            "    .card h3:first-child { margin-top: 0; }",
            "",
            "    /* --- Stat grid --- */",
            "    .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 16px; }",
            "    .stat-card { background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12);",
            "      border-radius: 16px; padding: 20px; text-align: center;",
            "      backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); transition: all 0.2s; }",
            "    .stat-card:hover { background: rgba(255,255,255,0.12); border-color: rgba(255,255,255,0.25); transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,0.2); }",
            "    .stat-card .stat-value { font-size: 2.2rem; font-weight: 800; color: #f1f5f9; line-height: 1.1; }",
            "    .stat-card .stat-value.success { color: var(--success); }",
            "    .stat-card .stat-value.warning { color: var(--warning); }",
            "    .stat-card .stat-value.danger { color: var(--danger); }",
            "    .stat-card .stat-label { font-size: 0.68rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin-top: 4px; }",
            "",
            "    /* --- Badges --- */",
            "    .badge { display: inline-flex; align-items: center; padding: 3px 10px; border-radius: 999px;",
            "      font-size: 0.68rem; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; }",
            "    .badge.pass { background: rgba(74,222,128,0.20); color: #4ade80; border: 1px solid rgba(74,222,128,0.35); }",
            "    .badge.fail { background: rgba(248,113,113,0.20); color: #f87171; border: 1px solid rgba(248,113,113,0.35); }",
            "    .badge.blocked { background: rgba(251,191,36,0.20); color: #fbbf24; border: 1px solid rgba(251,191,36,0.35); }",
            "    .badge.not_applicable, .badge.unknown { background: rgba(148,163,184,0.1); color: var(--muted); border: 1px solid rgba(148,163,184,0.15); }",
            "",
            "    /* --- Shared elements --- */",
            "    .muted { color: var(--muted); }",
            "    .meta { color: var(--ink-secondary); font-size: 0.85rem; }",
            "    p { margin: 0 0 8px 0; }",
            "    .warn { border-left: 3px solid var(--warning); padding: 12px; background: rgba(251,191,36,0.06); color: var(--warning); border-radius: 0 var(--radius-sm) var(--radius-sm) 0; font-size: 0.85rem; }",
            "    .risk { border: 1px solid rgba(255,255,255,0.06); border-left: 3px solid var(--accent); border-radius: 0 var(--radius-sm) var(--radius-sm) 0; padding: 14px 18px; margin-bottom: 10px; background: rgba(255,255,255,0.03); }",
            "    .risk:hover { background: rgba(255,255,255,0.06); }",
            "    .table-wrap { overflow-x: auto; border-radius: var(--radius-sm); border: 1px solid rgba(255,255,255,0.06); margin-top: 8px; }",
            "    table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }",
            "    th { text-align: left; padding: 10px 14px; font-size: 0.68rem; font-weight: 700; text-transform: uppercase;",
            "      letter-spacing: 0.08em; color: var(--muted); background: rgba(255,255,255,0.03); border-bottom: 1px solid rgba(255,255,255,0.06); }",
            "    td { padding: 10px 14px; border-bottom: 1px solid rgba(255,255,255,0.03); color: var(--ink-secondary);",
            "      word-break: break-word; overflow-wrap: break-word; max-width: 300px; }",
            "    tr:hover td { background: rgba(255,255,255,0.03); }",
            "    ul { list-style: none; padding: 0; }",
            "    li { padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.03); font-size: 0.85rem; color: var(--ink-secondary); }",
            "    li:last-child { border-bottom: none; }",
            "",
            "    /* --- Overview grid / gate matrix --- */",
            "    .overview-grid { display: grid; grid-template-columns: 1fr; gap: 12px; }",
            "    .gate-matrix { border: 1px solid rgba(255,255,255,0.06); border-radius: var(--radius-sm); overflow: hidden; }",
            "    .gate-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 10px 16px; border-bottom: 1px solid rgba(255,255,255,0.03); }",
            "    .gate-row:last-child { border-bottom: none; }",
            "    .gate-row:hover { background: var(--surface-hover); }",
            "    .gate-id { font-weight: 600; font-size: 0.82rem; color: var(--ink); }",
            "    .gate-reasons { margin: 6px 0 0 18px; padding: 0; color: var(--muted); }",
            "",
            "    /* --- Evidence --- */",
            "    .evidence-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; }",
            "    .evidence-link { color: var(--accent); text-decoration: none; font-size: 0.82rem; cursor: pointer; }",
            "    .evidence-link:hover { text-decoration: underline; }",
            "    .unsafe-ref { color: var(--danger); font-weight: 500; word-break: break-all; }",
            "    .copy-ref { border: 1px solid var(--glass-border); background: var(--surface); color: var(--muted); border-radius: 6px; padding: 2px 10px; font-size: 0.72rem; cursor: pointer; transition: all 0.15s; }",
            "    .copy-ref:hover { background: var(--accent-glow); border-color: var(--accent); color: var(--accent); }",
            "",
            "    /* --- Candidate bars --- */",
            "    .candidate-bars { display: grid; gap: 8px; margin-top: 10px; }",
            "    .candidate-bar-row { display: grid; grid-template-columns: 80px 1fr 56px; gap: 10px; align-items: center; font-size: 0.85rem; }",
            "    .candidate-bar-track { background: var(--surface); border: 1px solid var(--glass-border); border-radius: 999px; height: 10px; overflow: hidden; }",
            "    .candidate-bar-fill { height: 100%; border-radius: 999px; transition: width 0.6s ease; }",
            "    .candidate-bar-fill.high { background: var(--danger); }",
            "    .candidate-bar-fill.medium { background: var(--warning); }",
            "    .candidate-bar-fill.low { background: var(--info); }",
            "    .candidate-table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.82rem; }",
            "    .candidate-table th, .candidate-table td { border-top: 1px solid var(--line); padding: 8px; text-align: left; vertical-align: top; }",
            "    .candidate-table th { color: var(--muted); font-weight: 600; }",
            "    .candidate-table tr:hover td { background: var(--surface-hover); }",
            "",
            "    /* --- Filter chips --- */",
            "    .filter-chips { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 12px; }",
            "    .filter-chip { display: inline-flex; align-items: center; padding: 4px 14px; border-radius: 999px; font-size: 0.75rem; font-weight: 500;",
            "      border: 1px solid var(--glass-border); background: var(--surface); color: var(--muted); cursor: pointer; transition: all 0.2s ease; margin: 0 4px 4px 0; }",
            "    .filter-chip:hover { border-color: var(--accent); color: var(--accent); }",
            "    .filter-chip.active { background: var(--accent); color: white; border-color: var(--accent); }",
            "",
            "    /* --- Graph --- */",
            "    #graph-svg { width: 100%; border-radius: var(--radius-sm); background: rgba(0,0,0,0.3); border: 1px solid var(--glass-border); }",
            "    .graph-legend { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 12px; padding: 12px; background: var(--surface); border-radius: var(--radius-sm); }",
            "    .graph-legend-item { display: inline-flex; align-items: center; gap: 4px; font-size: 0.72rem; color: var(--muted); margin-right: 12px; }",
            "    .graph-legend-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }",
            "    .graph-controls { display: flex; gap: 8px; margin-bottom: 12px; }",
            "    .graph-controls button { padding: 6px 14px; border-radius: var(--radius-sm); border: 1px solid var(--glass-border); background: var(--surface); color: var(--ink); font-size: 0.8rem; cursor: pointer; transition: all 0.2s ease; }",
            "    .graph-controls button:hover { background: var(--accent-glow); border-color: var(--accent); color: var(--accent); }",
            "    .graph-controls button.active { background: var(--accent); color: white; border-color: var(--accent); }",
            "",
            "    /* --- Heatmap --- */",
            "    .heatmap-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 8px; margin-top: 10px; }",
            "    .heatmap-cell { padding: 12px; border-radius: var(--radius-sm); text-align: center; font-size: 0.78rem; font-weight: 600; border: 1px solid var(--glass-border); transition: transform 0.2s ease; }",
            "    .heatmap-cell:hover { transform: scale(1.04); }",
            "    .heatmap-cell.critical { background: rgba(239,68,68,0.18); color: var(--danger); }",
            "    .heatmap-cell.high { background: rgba(245,158,11,0.18); color: var(--warning); }",
            "    .heatmap-cell.medium { background: rgba(59,130,246,0.18); color: var(--info); }",
            "    .heatmap-cell.low { background: rgba(34,197,94,0.12); color: var(--success); }",
            "    .heatmap-cell.none { background: var(--surface); color: var(--muted); }",
            "",
            "    /* --- IPC map --- */",
            "    .ipc-table { width: 100%; border-collapse: collapse; font-size: 0.82rem; margin-top: 10px; }",
            "    .ipc-table th, .ipc-table td { border-top: 1px solid var(--line); padding: 8px; text-align: left; vertical-align: top; }",
            "    .ipc-table th { color: var(--muted); font-weight: 600; }",
            "    .ipc-table tr:hover td { background: var(--surface-hover); }",
            "    .ipc-badge { background: rgba(168,85,247,0.12); border-color: rgba(168,85,247,0.3); color: var(--ipc-purple); }",
            "",
            "    /* --- Modal --- */",
            "    .modal-overlay { position: fixed; inset: 0; z-index: 200; background: rgba(0,0,0,0.7); backdrop-filter: blur(8px); display: none; align-items: center; justify-content: center; }",
            "    .modal-overlay.visible { display: flex; }",
            "    .modal-card { background: var(--bg-secondary); border: 1px solid var(--glass-border); border-radius: var(--radius); padding: 24px;",
            "      max-width: 720px; width: 92%; max-height: 82vh; overflow-y: auto; animation: fadeIn 0.3s ease; box-shadow: 0 24px 80px rgba(0,0,0,0.4); }",
            "    .modal-card h3 { margin-bottom: 12px; }",
            "    .modal-close { position: absolute; top: 12px; right: 16px; background: none; border: none; color: var(--muted); font-size: 1.5rem; cursor: pointer; padding: 4px 8px; border-radius: var(--radius-sm); transition: all 0.2s; }",
            "    .modal-close:hover { background: var(--surface); color: var(--ink); }",
            "    pre { background: rgba(6,8,14,0.6); border: 1px solid var(--glass-border); border-radius: var(--radius-sm); padding: 20px; overflow-x: auto; font-size: 0.78rem; line-height: 1.7; color: var(--ink-secondary); backdrop-filter: blur(8px); }",
            "",
            "    /* --- Binary hardening bar --- */",
            "    .hardening-bars { display: grid; gap: 6px; margin-top: 10px; }",
            "    .hardening-row { display: grid; grid-template-columns: 100px 1fr 50px; gap: 8px; align-items: center; font-size: 0.82rem; }",
            "    .hardening-track { height: 8px; border-radius: 999px; background: var(--surface); border: 1px solid var(--glass-border); overflow: hidden; }",
            "    .hardening-fill { height: 100%; border-radius: 999px; background: var(--accent); transition: width 0.6s ease; }",
            "",
            "    /* --- Responsive --- */",
            "    @media (max-width: 1200px) { .page-shell { padding: 0 16px; } .sidebar { width: 180px; } }",
            "    @media (max-width: 768px) {",
            "      .sidebar { position: fixed; top: 60px; left: 0; bottom: 0; width: 260px; transform: translateX(-100%);",
            "        transition: transform 0.3s; background: var(--bg-secondary); z-index: 90; box-shadow: 4px 0 24px rgba(0,0,0,0.4); height: auto; border-radius: 0; }",
            "      .sidebar.open { transform: translateX(0); }",
            "      .hamburger { display: block; }",
            "      .main-content { padding: 16px 0 32px 0; }",
            "      .page-shell { margin-top: 66px; }",
            "      .stat-grid { grid-template-columns: repeat(2, 1fr); }",
            "      .top-bar { padding: 0 16px; }",
            "      .top-bar .search-bar { max-width: none; }",
            "      #graph-svg { height: 300px; }",
            "      .modal-card { width: 96%; max-height: 90vh; padding: 16px; }",
            "    }",
            "    @media (max-width: 480px) {",
            "      .stat-grid { grid-template-columns: 1fr; }",
            "      .top-bar { padding: 0 12px; }",
            "    }",
            "  </style>",
            "</head>",
            "<body>",
            "  <!-- Top Bar -->",
            '  <header class="top-bar">',
            '    <button class="hamburger" id="hamburger-btn" aria-label="Menu">&#9776;</button>',
            '    <span class="logo">SCOUT</span>',
            '    <div class="search-bar">',
            '      <input type="text" id="global-search" placeholder="Search panes..." aria-label="Search">',
            "    </div>",
            '    <div class="spacer"></div>',
            '    <button class="theme-toggle" id="theme-toggle">Light</button>',
            "  </header>",
            "",
            "  <!-- Pipeline Progress Bar -->",
            '  <div class="pipeline-bar" id="pipeline-bar"></div>',
            "",
            '  <div class="page-shell">',
            '  <nav class="sidebar" id="sidebar">',
            '    <a href="#pane-overview-gates">Overview & Gates</a>',
            '    <a href="#pane-vulnerabilities-verdicts">Vulnerabilities</a>',
            '    <a href="#pane-structure-binaries">Structure & Binaries</a>',
            '    <a href="#pane-protocols-attack-surface">Protocols & Surface</a>',
            '    <a href="#pane-graph">Graph Visualization</a>',
            '    <a href="#pane-ipc-map">IPC Map</a>',
            '    <a href="#pane-risk-heatmap">Risk Heatmap</a>',
            '    <a href="#pane-exploit-candidate-map">Exploit Candidates</a>',
            '    <a href="#pane-evidence-next-actions">Evidence & Actions</a>',
            '    <a href="#pane-executive-verdict">Executive Verdict</a>',
            '    <a href="#pane-attack-surface-scale">Attack Surface Scale</a>',
            '    <a href="#pane-verification-status">Verification Status</a>',
            '    <a href="#pane-evidence-navigator">Evidence Navigator</a>',
            '    <a href="#pane-summary">Summary</a>',
            "  </nav>",
            '  <main class="main-content">',
            '    <section class="card" id="pane-header">',
            "      <h2>SCOUT Analyst Report</h2>",
            '      <div class="card-body">',
            '        <div id="meta" class="meta"></div>',
            '        <div id="file-warning" class="warn" hidden>Tip: Local file mode can block fetch(). Run a local server (python3 -m http.server) from this report directory.</div>',
            "      </div>",
            "    </section>",
            "",
            '    <section class="card" id="pane-overview-gates">',
            "      <h2>Overview & Gates</h2>",
            '      <div class="card-body" id="overview-gates"></div>',
            "    </section>",
            "",
            '    <section class="card" id="pane-vulnerabilities-verdicts">',
            "      <h2>Vulnerabilities & Verdicts</h2>",
            '      <div class="card-body" id="vulnerabilities-verdicts"></div>',
            "    </section>",
            "",
            '    <section class="card" id="pane-structure-binaries">',
            "      <h2>Structure & Binaries</h2>",
            '      <div class="card-body" id="structure-binaries"></div>',
            "    </section>",
            "",
            '    <section class="card" id="pane-protocols-attack-surface">',
            "      <h2>Protocols & Attack Surface</h2>",
            '      <div class="card-body" id="protocols-attack-surface"></div>',
            "    </section>",
            "",
            '    <section class="card" id="pane-graph">',
            "      <h2>Graph Visualization</h2>",
            '      <div class="card-body" id="graph-vis"></div>',
            "    </section>",
            "",
            '    <section class="card" id="pane-ipc-map">',
            "      <h2>IPC Map</h2>",
            '      <div class="card-body" id="ipc-map"></div>',
            "    </section>",
            "",
            '    <section class="card" id="pane-risk-heatmap">',
            "      <h2>Risk Heatmap</h2>",
            '      <div class="card-body" id="risk-heatmap"></div>',
            "    </section>",
            "",
            '    <section class="card" id="pane-exploit-candidate-map">',
            "      <h2>Exploit Candidate Map</h2>",
            '      <div class="card-body" id="exploit-candidate-map"></div>',
            "    </section>",
            "",
            '    <section class="card" id="pane-evidence-next-actions">',
            "      <h2>Evidence & Next Actions</h2>",
            '      <div class="card-body" id="evidence-next-actions"></div>',
            "    </section>",
            "",
            '    <section class="card" id="pane-executive-verdict">',
            "      <h2>Executive Verdict</h2>",
            '      <div class="card-body" id="executive-verdict"></div>',
            "    </section>",
            "",
            '    <section class="card" id="pane-attack-surface-scale">',
            "      <h2>Attack Surface Scale</h2>",
            '      <div class="card-body" id="attack-surface-scale"></div>',
            "    </section>",
            "",
            '    <section class="card" id="pane-verification-status">',
            "      <h2>Verification Status</h2>",
            '      <div class="card-body" id="verification-status"></div>',
            "    </section>",
            "",
            '    <section class="card" id="pane-evidence-navigator">',
            "      <h2>Evidence Navigator</h2>",
            '      <div class="card-body" id="evidence-navigator"></div>',
            "    </section>",
            "",
            '    <section class="card" id="pane-summary">',
            "      <h2>Summary</h2>",
            '      <div class="card-body">',
            '        <ul id="summary"></ul>',
            '        <h3 style="margin-top:12px">Top Risks</h3>',
            '        <div id="risks"></div>',
            '        <h3 style="margin-top:12px">Evidence Index</h3>',
            '        <ul id="evidence"></ul>',
            "      </div>",
            "    </section>",
            "  </main>",
            "  </div>",
            "",
            "  <!-- Evidence modal -->",
            '  <div class="modal-overlay" id="evidence-modal" hidden>',
            '    <div class="modal-card" style="position:relative">',
            '      <button class="modal-close" id="modal-close-btn">&times;</button>',
            '      <h3 id="modal-title">Evidence Detail</h3>',
            '      <pre id="modal-content"></pre>',
            "    </div>",
            "  </div>",
            "",
            "  <!-- Bootstrap data -->",
            '  <script id="bootstrap-data" type="application/json">',
            f"  {bootstrap}",
            "  </script>",
            '  <script id="bootstrap-overview-data" type="application/json">',
            f"  {overview_bootstrap}",
            "  </script>",
            '  <script id="bootstrap-digest-data" type="application/json">',
            f"  {digest_bootstrap}",
            "  </script>",
            '  <script id="bootstrap-exploit-candidates-data" type="application/json">',
            f"  {exploit_candidates_bootstrap}",
            "  </script>",
            '  <script id="bootstrap-graph-data" type="application/json">',
            f"  {graph_bootstrap}",
            "  </script>",
            '  <script id="bootstrap-ipc-data" type="application/json">',
            f"  {ipc_bootstrap}",
            "  </script>",
            "",
            "  <script>",
            "  /* ===== Utilities ===== */",
            "  function asText(v) {",
            "    if (typeof v === 'string' || typeof v === 'number') return String(v);",
            "    return '';",
            "  }",
            "  function asTextOr(v, fallback) { var t = asText(v); return t ? t : fallback; }",
            "  function clearNode(n) { if (!n) return; while (n.firstChild) n.removeChild(n.firstChild); }",
            "  function addListItem(list, text) { var li = document.createElement('li'); li.textContent = text; list.appendChild(li); }",
            "",
            "  function badgeClassForStatus(status) {",
            "    var s = asText(status);",
            "    if (s === 'pass') return 'pass';",
            "    if (s === 'fail') return 'fail';",
            "    if (s === 'blocked') return 'blocked';",
            "    if (s === 'not_applicable') return 'not_applicable';",
            "    return 'unknown';",
            "  }",
            "  function badgeClassForVerdictState(state) {",
            "    var s = asText(state);",
            "    if (s === 'VERIFIED') return 'pass';",
            "    if (s === 'ATTEMPTED_INCONCLUSIVE') return 'blocked';",
            "    if (s === 'NOT_ATTEMPTED') return 'blocked';",
            "    if (s === 'NOT_APPLICABLE') return 'not_applicable';",
            "    return 'unknown';",
            "  }",
            "  function formatArrayInline(arrAny) {",
            "    if (!Array.isArray(arrAny)) return '(unavailable)';",
            "    var parts = arrAny.map(asText).filter(function(x) { return x !== ''; });",
            "    if (parts.length === 0) return '(none)';",
            "    return parts.join(', ');",
            "  }",
            "",
            "  function isSafeRunRelativeRef(ref) {",
            "    if (typeof ref !== 'string') return false;",
            "    var trimmed = ref.trim();",
            "    if (!trimmed) return false;",
            "    if (trimmed.startsWith('/')) return false;",
            "    if (/^[A-Za-z]:[\\\\/]/.test(trimmed)) return false;",
            "    if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(trimmed)) return false;",
            "    var normalized = trimmed.replace(/\\\\\\\\/g, '/');",
            "    var segments = normalized.split('/');",
            "    for (var i = 0; i < segments.length; i += 1) {",
            "      if (segments[i] === '..') return false;",
            "    }",
            "    return true;",
            "  }",
            "",
            "  function copyText(ref) {",
            "    var text = asText(ref);",
            "    if (!text) return Promise.resolve(false);",
            "    function fallbackCopy() {",
            "      try {",
            "        var ta = document.createElement('textarea');",
            "        ta.value = text; ta.setAttribute('readonly', 'readonly');",
            "        ta.style.position = 'fixed'; ta.style.top = '-1000px'; ta.style.left = '-1000px';",
            "        document.body.appendChild(ta); ta.focus(); ta.select();",
            "        var ok = document.execCommand('copy');",
            "        document.body.removeChild(ta); return ok;",
            "      } catch (_) { return false; }",
            "    }",
            "    if (navigator && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {",
            "      return navigator.clipboard.writeText(text).then(function() { return true; }).catch(function() { return fallbackCopy(); });",
            "    }",
            "    return Promise.resolve(fallbackCopy());",
            "  }",
            "",
            "  function hrefForEvidenceRef(ref) {",
            "    var normalized = ref.replace(/\\\\\\\\/g, '/');",
            "    if (normalized.startsWith('report/')) return './' + normalized.slice('report/'.length);",
            "    return '../' + normalized;",
            "  }",
            "",
            "  /* ===== Theme toggle ===== */",
            "  function toggleTheme() {",
            "    var html = document.documentElement;",
            "    var current = html.getAttribute('data-theme') || 'dark';",
            "    var next = current === 'dark' ? 'light' : 'dark';",
            "    html.setAttribute('data-theme', next);",
            "    document.getElementById('theme-toggle').textContent = next === 'dark' ? 'Light' : 'Dark';",
            "    try { localStorage.setItem('scout-theme', next); } catch(_) {}",
            "  }",
            "  (function() {",
            "    try {",
            "      var saved = localStorage.getItem('scout-theme');",
            "      if (saved === 'light' || saved === 'dark') {",
            "        document.documentElement.setAttribute('data-theme', saved);",
            "        var btn = document.getElementById('theme-toggle');",
            "        if (btn) btn.textContent = saved === 'dark' ? 'Light' : 'Dark';",
            "      }",
            "    } catch(_) {}",
            "  })();",
            "  document.getElementById('theme-toggle').addEventListener('click', toggleTheme);",
            "",
            "  /* ===== Card collapse ===== */",
            "  function toggleCard(el) {",
            "    var card = el.closest('.card');",
            "    if (!card) return;",
            "    card.classList.toggle('collapsed');",
            "    var id = card.id || '';",
            "    try { sessionStorage.setItem('scout-card-' + id, card.classList.contains('collapsed') ? '1' : '0'); } catch(_) {}",
            "  }",
            "  document.querySelectorAll('.card h2').forEach(function(h2) {",
            "    h2.addEventListener('click', function() { toggleCard(h2); });",
            "    var card = h2.closest('.card');",
            "    if (card && card.id) {",
            "      try {",
            "        var saved = sessionStorage.getItem('scout-card-' + card.id);",
            "        if (saved === '1') card.classList.add('collapsed');",
            "      } catch(_) {}",
            "    }",
            "  });",
            "",
            "  /* ===== Global search ===== */",
            "  function globalSearch(query) {",
            "    var q = (query || '').toLowerCase().trim();",
            "    document.querySelectorAll('.card[id^=\"pane-\"]').forEach(function(card) {",
            "      if (!q) { card.style.display = ''; return; }",
            "      var text = (card.textContent || '').toLowerCase();",
            "      card.style.display = text.indexOf(q) >= 0 ? '' : 'none';",
            "    });",
            "  }",
            "  document.getElementById('global-search').addEventListener('input', function(e) { globalSearch(e.target.value); });",
            "",
            "  /* ===== Sidebar hamburger ===== */",
            "  document.getElementById('hamburger-btn').addEventListener('click', function() {",
            "    document.getElementById('sidebar').classList.toggle('open');",
            "  });",
            "  document.querySelectorAll('.sidebar a').forEach(function(a) {",
            "    a.addEventListener('click', function(e) {",
            "      e.preventDefault();",
            "      var target = document.querySelector(this.getAttribute('href'));",
            "      if (target) {",
            "        target.scrollIntoView({ behavior: 'smooth', block: 'start' });",
            "        if (target.classList.contains('collapsed')) { target.classList.remove('collapsed'); }",
            "      }",
            "      document.getElementById('sidebar').classList.remove('open');",
            "      document.querySelectorAll('.sidebar a').forEach(function(l) { l.classList.remove('active'); });",
            "      this.classList.add('active');",
            "    });",
            "  });",
            "",
            "  /* ===== Intersection observer for active sidebar tracking ===== */",
            "  var observer = new IntersectionObserver(function(entries) {",
            "    entries.forEach(function(entry) {",
            "      if (entry.isIntersecting) {",
            "        var id = entry.target.id;",
            "        document.querySelectorAll('.sidebar a').forEach(function(a) {",
            "          a.classList.toggle('active', a.getAttribute('href') === '#' + id);",
            "        });",
            "      }",
            "    });",
            "  }, { rootMargin: '-80px 0px -60% 0px' });",
            "  document.querySelectorAll('.card[id^=\"pane-\"]').forEach(function(el) { observer.observe(el); });",
            "",
            "  /* ===== Evidence modal ===== */",
            "  function showEvidenceModal(ref) {",
            "    var modal = document.getElementById('evidence-modal');",
            "    var title = document.getElementById('modal-title');",
            "    var content = document.getElementById('modal-content');",
            "    if (!modal || !title || !content) return;",
            "    title.textContent = ref;",
            "    content.textContent = 'Loading...';",
            "    modal.classList.add('visible');",
            "    if (isSafeRunRelativeRef(ref)) {",
            "      var href = hrefForEvidenceRef(ref);",
            "      fetch(href, { cache: 'no-store' }).then(function(r) {",
            "        if (!r.ok) throw new Error('HTTP ' + r.status);",
            "        return r.text();",
            "      }).then(function(text) {",
            "        try { content.textContent = JSON.stringify(JSON.parse(text), null, 2); }",
            "        catch(_) { content.textContent = text; }",
            "      }).catch(function(err) { content.textContent = 'Could not load: ' + err.message; });",
            "    } else {",
            "      content.textContent = 'Unsafe reference - cannot load.';",
            "    }",
            "  }",
            "  document.getElementById('modal-close-btn').addEventListener('click', function() {",
            "    document.getElementById('evidence-modal').classList.remove('visible');",
            "  });",
            "  document.getElementById('evidence-modal').addEventListener('click', function(e) {",
            "    if (e.target === this) this.classList.remove('visible');",
            "  });",
            "",
            "  /* ===== Pipeline Progress ===== */",
            "  function renderPipelineProgress(overview) {",
            "    var bar = document.getElementById('pipeline-bar');",
            "    if (!bar) return;",
            "    clearNode(bar);",
            "    var summary = (overview && typeof overview.summary === 'object' && overview.summary) ? overview.summary : {};",
            "    var stageKeys = ['tooling_summary','extraction_summary','structure_summary','carving_summary','firmware_profile_summary',",
            "      'inventory_summary','endpoints_summary','surfaces_summary','web_ui_summary','graph_summary',",
            "      'attack_surface_summary','functional_spec_summary','threat_model_summary','findings_summary',",
            "      'llm_triage_summary','llm_synthesis_summary','attribution_summary','dynamic_validation_summary',",
            "      'emulation_summary','exploit_gate_summary','exploit_chain_summary','exploit_autopoc_summary',",
            "      'poc_validation_summary','exploit_policy_summary'];",
            "    stageKeys.forEach(function(key) {",
            "      var stageAny = summary[key];",
            "      var stage = (stageAny && typeof stageAny === 'object') ? stageAny : null;",
            "      var seg = document.createElement('div');",
            "      seg.className = 'seg';",
            "      if (stage) {",
            "        var st = asText(stage.status);",
            "        if (st === 'ok') seg.className += ' ok';",
            "        else if (st === 'partial') seg.className += ' partial';",
            "        else if (st === 'failed') seg.className += ' failed';",
            "        else if (st === 'skipped') seg.className += ' skipped';",
            "        else seg.className += ' unknown';",
            "      } else { seg.className += ' unknown'; }",
            "      seg.title = key.replace('_summary', '');",
            "      bar.appendChild(seg);",
            "    });",
            "  }",
            "",
            "  /* ===== renderOverview ===== */",
            "  function renderOverview(overview) {",
            "    var mount = document.getElementById('overview-gates');",
            "    if (!mount) return;",
            "    mount.innerHTML = '';",
            "    var s = (overview && overview.summary) ? overview.summary : {};",
            "    var grid = document.createElement('div');",
            "    grid.className = 'stat-grid';",
            "    var stats = [",
            "      { label: 'Files', value: s.inventory_summary && s.inventory_summary.summary ? (s.inventory_summary.summary.files || 0) : 0 },",
            "      { label: 'Binaries', value: s.inventory_summary && s.inventory_summary.summary ? (s.inventory_summary.summary.binaries || 0) : 0 },",
            "      { label: 'Endpoints', value: s.endpoints_summary && s.endpoints_summary.summary ? (s.endpoints_summary.summary.endpoints || 0) : 0 },",
            "      { label: 'Surfaces', value: s.surfaces_summary && s.surfaces_summary.summary ? (s.surfaces_summary.summary.surfaces || 0) : 0 },",
            "      { label: 'Attack Surface', value: s.attack_surface_summary && s.attack_surface_summary.summary ? (s.attack_surface_summary.summary.attack_surface_items || 0) : 0 },",
            "      { label: 'Findings', value: s.top_risk_summary ? (s.top_risk_summary.total_findings || 0) : 0 }",
            "    ];",
            "    stats.forEach(function(st) {",
            "      var card = document.createElement('div');",
            "      card.className = 'stat-card';",
            "      var val = document.createElement('div');",
            "      val.className = 'stat-value';",
            "      val.textContent = String(st.value);",
            "      var lbl = document.createElement('div');",
            "      lbl.className = 'stat-label';",
            "      lbl.textContent = st.label;",
            "      card.appendChild(val);",
            "      card.appendChild(lbl);",
            "      grid.appendChild(card);",
            "    });",
            "    mount.appendChild(grid);",
            "",
            "    var rc = s.report_completeness || {};",
            "    var rcDiv = document.createElement('div');",
            "    rcDiv.style.marginTop = '16px';",
            "    var rcTitle = document.createElement('h3');",
            "    rcTitle.textContent = 'Report Completeness';",
            "    rcDiv.appendChild(rcTitle);",
            "    var rcBadge = document.createElement('span');",
            "    rcBadge.className = 'badge ' + (rc.gate_passed ? 'pass' : rc.status === 'incomplete' ? 'fail' : 'blocked');",
            "    rcBadge.textContent = rc.status || 'unknown';",
            "    rcDiv.appendChild(rcBadge);",
            "    if (rc.reasons && rc.reasons.length) {",
            "      var ul = document.createElement('ul');",
            "      ul.style.marginTop = '8px';",
            "      rc.reasons.forEach(function(r) { var li = document.createElement('li'); li.textContent = r; ul.appendChild(li); });",
            "      rcDiv.appendChild(ul);",
            "    }",
            "    mount.appendChild(rcDiv);",
            "",
            "    var gates = (overview && overview.gates) ? overview.gates : [];",
            "    if (gates.length) {",
            "      var gTitle = document.createElement('h3');",
            "      gTitle.textContent = 'Gate Matrix';",
            "      mount.appendChild(gTitle);",
            "      var gDiv = document.createElement('div');",
            "      gDiv.className = 'gate-matrix';",
            "      gates.forEach(function(g) {",
            "        var row = document.createElement('div');",
            "        row.className = 'gate-row';",
            "        row.innerHTML = '<span class=\"gate-id\">' + asText(g.id) + '</span>';",
            "        var reasons = (g.reasons || []).join(', ') || '';",
            "        var statusSpan = document.createElement('span');",
            "        statusSpan.className = 'badge ' + badgeClassForStatus(g.status);",
            "        statusSpan.textContent = asText(g.status);",
            "        row.appendChild(document.createTextNode(' '));",
            "        if (reasons) { var rSpan = document.createElement('span'); rSpan.className = 'muted'; rSpan.style.fontSize = '0.8rem'; rSpan.textContent = reasons; row.appendChild(rSpan); }",
            "        row.appendChild(statusSpan);",
            "        gDiv.appendChild(row);",
            "      });",
            "      mount.appendChild(gDiv);",
            "    }",
            "  }",
            "",
            "  /* ===== renderVulnerabilities ===== */",
            "  function renderVulnerabilities(digest) {",
            "    var mount = document.getElementById('vulnerabilities-verdicts');",
            "    if (!mount) return;",
            "    clearNode(mount);",
            "    var digestObj = (digest && typeof digest === 'object') ? digest : {};",
            "    var evAny = digestObj.exploitability_verdict;",
            "    var ev = (evAny && typeof evAny === 'object') ? evAny : null;",
            "    var findingVerdicts = Array.isArray(digestObj.finding_verdicts) ? digestObj.finding_verdicts : null;",
            "    if (!ev && !findingVerdicts) {",
            "      var degraded = document.createElement('p'); degraded.className = 'muted';",
            "      degraded.textContent = 'Digest unavailable or invalid (degraded). Expected ./analyst_digest.json or embedded bootstrap.';",
            "      mount.appendChild(degraded); return;",
            "    }",
            "    var overallBox = document.createElement('div');",
            "    mount.appendChild(overallBox);",
            "    var overallTitle = document.createElement('h3'); overallTitle.textContent = 'Overall Exploitability Verdict';",
            "    overallBox.appendChild(overallTitle);",
            "    if (!ev) {",
            "      var missing = document.createElement('p'); missing.className = 'muted'; missing.textContent = '(missing exploitability_verdict)';",
            "      overallBox.appendChild(missing);",
            "    } else {",
            "      var state = asText(ev.state);",
            "      var line = document.createElement('p');",
            "      var badge = document.createElement('span'); badge.className = 'badge ' + badgeClassForVerdictState(state); badge.textContent = state || 'unknown';",
            "      line.appendChild(badge); overallBox.appendChild(line);",
            "      var rcLine = document.createElement('p'); rcLine.className = 'muted';",
            "      rcLine.textContent = 'reason_codes: ' + formatArrayInline(ev.reason_codes);",
            "      overallBox.appendChild(rcLine);",
            "    }",
            "",
            "    /* severity filter chips */",
            "    var filterBox = document.createElement('div'); filterBox.className = 'filter-chips';",
            "    var severities = ['all','critical','high','medium','low','info'];",
            "    var activeSev = 'all';",
            "    severities.forEach(function(sev) {",
            "      var chip = document.createElement('button'); chip.className = 'filter-chip' + (sev === 'all' ? ' active' : '');",
            "      chip.textContent = sev; chip.dataset.sev = sev;",
            "      chip.addEventListener('click', function() {",
            "        activeSev = sev;",
            "        filterBox.querySelectorAll('.filter-chip').forEach(function(c) { c.classList.remove('active'); });",
            "        chip.classList.add('active');",
            "        mount.querySelectorAll('.finding-item').forEach(function(fi) {",
            "          if (sev === 'all') { fi.style.display = ''; return; }",
            "          fi.style.display = (fi.dataset.severity === sev) ? '' : 'none';",
            "        });",
            "      });",
            "      filterBox.appendChild(chip);",
            "    });",
            "    mount.appendChild(filterBox);",
            "",
            "    var listBox = document.createElement('div');",
            "    mount.appendChild(listBox);",
            "    var listTitle = document.createElement('h3'); listTitle.textContent = 'Finding Verdicts';",
            "    listBox.appendChild(listTitle);",
            "    if (!Array.isArray(findingVerdicts)) {",
            "      var ml = document.createElement('p'); ml.className = 'muted'; ml.textContent = '(missing finding_verdicts)';",
            "      listBox.appendChild(ml); return;",
            "    }",
            "    var items = findingVerdicts;",
            "    var total = items.length;",
            "    var maxShow = 100;",
            "    if (total === 0) { var em = document.createElement('p'); em.className = 'muted'; em.textContent = '(none)'; listBox.appendChild(em); return; }",
            "    var note = document.createElement('p'); note.className = 'muted';",
            "    note.textContent = (total > maxShow) ? ('Showing first ' + maxShow + ' of ' + total + ' findings (deterministic order).') : ('Showing ' + total + ' findings.');",
            "    listBox.appendChild(note);",
            "    items.slice(0, maxShow).forEach(function(itemAny) {",
            "      if (!itemAny || typeof itemAny !== 'object') return;",
            "      var item = itemAny;",
            "      var box = document.createElement('article'); box.className = 'risk finding-item';",
            "      var sev = asText(item.severity).toLowerCase() || 'unknown';",
            "      box.dataset.severity = sev;",
            "      var h = document.createElement('h3'); h.textContent = asText(item.finding_id) || '(missing finding_id)';",
            "      box.appendChild(h);",
            "      var verdictLine = document.createElement('p');",
            "      var verdictKey = document.createElement('span'); verdictKey.className = 'muted'; verdictKey.textContent = 'verdict: ';",
            "      verdictLine.appendChild(verdictKey);",
            "      var st = asText(item.verdict);",
            "      var vBadge = document.createElement('span'); vBadge.className = 'badge ' + badgeClassForVerdictState(st); vBadge.textContent = st || 'unknown';",
            "      verdictLine.appendChild(vBadge); box.appendChild(verdictLine);",
            "      var rc = document.createElement('p'); rc.className = 'muted'; rc.textContent = 'reason_codes: ' + formatArrayInline(item.reason_codes); box.appendChild(rc);",
            "      var evrefs = document.createElement('p'); evrefs.className = 'muted'; evrefs.textContent = 'evidence_refs: ' + formatArrayInline(item.evidence_refs); box.appendChild(evrefs);",
            "      var vrefs = document.createElement('p'); vrefs.className = 'muted'; vrefs.textContent = 'verifier_refs: ' + formatArrayInline(item.verifier_refs); box.appendChild(vrefs);",
            "      listBox.appendChild(box);",
            "    });",
            "  }",
            "",
            "  /* ===== renderStructure ===== */",
            "  function renderStructure(overview) {",
            "    var mount = document.getElementById('structure-binaries');",
            "    if (!mount) return;",
            "    clearNode(mount);",
            "    var summary = (overview && typeof overview.summary === 'object' && overview.summary) ? overview.summary : {};",
            "    var exAny = summary.extraction_summary;",
            "    var invAny = summary.inventory_summary;",
            "    var ex = (exAny && typeof exAny === 'object') ? exAny : null;",
            "    var inv = (invAny && typeof invAny === 'object') ? invAny : null;",
            "",
            "    /* Extraction stat grid */",
            "    var exTitle = document.createElement('h3'); exTitle.textContent = 'Extraction'; mount.appendChild(exTitle);",
            "    if (!ex) {",
            "      var m = document.createElement('p'); m.className = 'muted'; m.textContent = '(missing extraction summary)'; mount.appendChild(m);",
            "    } else {",
            "      var exS = (ex.summary && typeof ex.summary === 'object') ? ex.summary : {};",
            "      var exGrid = document.createElement('div'); exGrid.className = 'stat-grid';",
            "      var exStats = [",
            "        { label: 'Status', value: asTextOr(ex.status, '-') },",
            "        { label: 'Confidence', value: asTextOr(ex.confidence, '-') },",
            "        { label: 'Tool', value: asTextOr(exS.tool, '-') },",
            "        { label: 'Files Extracted', value: asTextOr(exS.extracted_file_count, '0') }",
            "      ];",
            "      exStats.forEach(function(st) {",
            "        var card = document.createElement('div'); card.className = 'stat-card';",
            "        var val = document.createElement('div'); val.className = 'stat-value'; val.textContent = String(st.value);",
            "        var lbl = document.createElement('div'); lbl.className = 'stat-label'; lbl.textContent = st.label;",
            "        card.appendChild(val); card.appendChild(lbl); exGrid.appendChild(card);",
            "      });",
            "      mount.appendChild(exGrid);",
            "      if (exS.extracted_dir) {",
            "        var dirP = document.createElement('p'); dirP.className = 'meta'; dirP.textContent = 'extracted_dir: ' + asText(exS.extracted_dir); mount.appendChild(dirP);",
            "      }",
            "    }",
            "",
            "    /* Inventory stat grid */",
            "    var invTitle = document.createElement('h3'); invTitle.textContent = 'Inventory'; mount.appendChild(invTitle);",
            "    if (!inv) {",
            "      var m2 = document.createElement('p'); m2.className = 'muted'; m2.textContent = '(missing inventory summary)'; mount.appendChild(m2);",
            "    } else {",
            "      var invS = (inv.summary && typeof inv.summary === 'object') ? inv.summary : {};",
            "      var invGrid = document.createElement('div'); invGrid.className = 'stat-grid';",
            "      var invStats = [",
            "        { label: 'Status', value: asTextOr(inv.status, '-') },",
            "        { label: 'Roots Scanned', value: asTextOr(invS.roots_scanned, '0') },",
            "        { label: 'Files', value: asTextOr(invS.files, '0') },",
            "        { label: 'Binaries', value: asTextOr(invS.binaries, '0') },",
            "        { label: 'Configs', value: asTextOr(invS.configs, '0') },",
            "        { label: 'String Hits', value: asTextOr(invS.string_hits, '0') }",
            "      ];",
            "      invStats.forEach(function(st) {",
            "        var card = document.createElement('div'); card.className = 'stat-card';",
            "        var val = document.createElement('div'); val.className = 'stat-value'; val.textContent = String(st.value);",
            "        var lbl = document.createElement('div'); lbl.className = 'stat-label'; lbl.textContent = st.label;",
            "        card.appendChild(val); card.appendChild(lbl); invGrid.appendChild(card);",
            "      });",
            "      mount.appendChild(invGrid);",
            "    }",
            "",
            "    /* Binary hardening bars (from IPC data if available) */",
            "    var ipcNode = document.getElementById('bootstrap-ipc-data');",
            "    var ipcData = {};",
            "    try { ipcData = JSON.parse((ipcNode && ipcNode.textContent) || '{}'); } catch(_) {}",
            "    var binaries = (ipcData && typeof ipcData === 'object' && Array.isArray(ipcData.binaries)) ? ipcData.binaries : [];",
            "    if (binaries.length > 0) {",
            "      var hTitle = document.createElement('h3'); hTitle.textContent = 'Binary Hardening'; hTitle.style.marginTop = '12px';",
            "      mount.appendChild(hTitle);",
            "      var hardeningKeys = ['nx','pie','relro','canary','stripped'];",
            "      var hWrap = document.createElement('div'); hWrap.className = 'hardening-bars';",
            "      hardeningKeys.forEach(function(key) {",
            "        var count = 0;",
            "        binaries.forEach(function(bin) {",
            "          if (bin && typeof bin === 'object' && bin.hardening && typeof bin.hardening === 'object') {",
            "            if (bin.hardening[key]) count++;",
            "          }",
            "        });",
            "        var pct = binaries.length > 0 ? Math.round(count / binaries.length * 100) : 0;",
            "        var row = document.createElement('div'); row.className = 'hardening-row';",
            "        var lbl = document.createElement('span'); lbl.textContent = key.toUpperCase();",
            "        var track = document.createElement('div'); track.className = 'hardening-track';",
            "        var fill = document.createElement('div'); fill.className = 'hardening-fill'; fill.style.width = pct + '%';",
            "        track.appendChild(fill);",
            "        var val = document.createElement('span'); val.className = 'muted'; val.textContent = pct + '%';",
            "        row.appendChild(lbl); row.appendChild(track); row.appendChild(val);",
            "        hWrap.appendChild(row);",
            "      });",
            "      mount.appendChild(hWrap);",
            "    }",
            "  }",
            "",
            "  /* ===== renderProtocols ===== */",
            "  function renderProtocols(overview) {",
            "    var mount = document.getElementById('protocols-attack-surface');",
            "    if (!mount) return;",
            "    clearNode(mount);",
            "    var summary = (overview && typeof overview.summary === 'object' && overview.summary) ? overview.summary : {};",
            "    var links = (overview && typeof overview.links === 'object' && overview.links) ? overview.links : {};",
            "    var epAny = summary.endpoints_summary; var sfAny = summary.surfaces_summary;",
            "    var grAny = summary.graph_summary; var asAny = summary.attack_surface_summary;",
            "    var ep = (epAny && typeof epAny === 'object') ? epAny : null;",
            "    var sf = (sfAny && typeof sfAny === 'object') ? sfAny : null;",
            "    var gr = (grAny && typeof grAny === 'object') ? grAny : null;",
            "    var asf = (asAny && typeof asAny === 'object') ? asAny : null;",
            "",
            "    /* Endpoints stat grid */",
            "    var epTitle = document.createElement('h3'); epTitle.textContent = 'Endpoints'; mount.appendChild(epTitle);",
            "    if (!ep) { var m = document.createElement('p'); m.className = 'muted'; m.textContent = '(missing endpoints summary)'; mount.appendChild(m); }",
            "    else {",
            "      var epS = (ep.summary && typeof ep.summary === 'object') ? ep.summary : {};",
            "      var epGrid = document.createElement('div'); epGrid.className = 'stat-grid';",
            "      var epStats = [",
            "        { label: 'Status', value: asTextOr(ep.status, '-') },",
            "        { label: 'Endpoints', value: asTextOr(epS.endpoints, '0') },",
            "        { label: 'Roots Scanned', value: asTextOr(epS.roots_scanned, '0') },",
            "        { label: 'Files Scanned', value: asTextOr(epS.files_scanned, '0') }",
            "      ];",
            "      epStats.forEach(function(st) {",
            "        var card = document.createElement('div'); card.className = 'stat-card';",
            "        var val = document.createElement('div'); val.className = 'stat-value'; val.textContent = String(st.value);",
            "        var lbl = document.createElement('div'); lbl.className = 'stat-label'; lbl.textContent = st.label;",
            "        card.appendChild(val); card.appendChild(lbl); epGrid.appendChild(card);",
            "      });",
            "      mount.appendChild(epGrid);",
            "      var cls = asText(epS.classification); if (cls) { var clsP = document.createElement('p'); clsP.className = 'meta'; clsP.textContent = 'Classification: ' + cls; mount.appendChild(clsP); }",
            "      var obs = asText(epS.observation); if (obs) { var obsP = document.createElement('p'); obsP.className = 'meta'; obsP.textContent = 'Observation: ' + obs; mount.appendChild(obsP); }",
            "    }",
            "",
            "    /* Surfaces stat grid */",
            "    var sfTitle = document.createElement('h3'); sfTitle.textContent = 'Surfaces'; mount.appendChild(sfTitle);",
            "    if (!sf) { var m2 = document.createElement('p'); m2.className = 'muted'; m2.textContent = '(missing surfaces summary)'; mount.appendChild(m2); }",
            "    else {",
            "      var sfS = (sf.summary && typeof sf.summary === 'object') ? sf.summary : {};",
            "      var sfGrid = document.createElement('div'); sfGrid.className = 'stat-grid';",
            "      var sfStats = [",
            "        { label: 'Status', value: asTextOr(sf.status, '-') },",
            "        { label: 'Surfaces', value: asTextOr(sfS.surfaces, '0') },",
            "        { label: 'Unknowns', value: asTextOr(sfS.unknowns, '0') }",
            "      ];",
            "      sfStats.forEach(function(st) {",
            "        var card = document.createElement('div'); card.className = 'stat-card';",
            "        var val = document.createElement('div'); val.className = 'stat-value'; val.textContent = String(st.value);",
            "        var lbl = document.createElement('div'); lbl.className = 'stat-label'; lbl.textContent = st.label;",
            "        card.appendChild(val); card.appendChild(lbl); sfGrid.appendChild(card);",
            "      });",
            "      mount.appendChild(sfGrid);",
            "      var cls2 = asText(sfS.classification); if (cls2) { var clsP2 = document.createElement('p'); clsP2.className = 'meta'; clsP2.textContent = 'Classification: ' + cls2; mount.appendChild(clsP2); }",
            "      var obs2 = asText(sfS.observation); if (obs2) { var obsP2 = document.createElement('p'); obsP2.className = 'meta'; obsP2.textContent = 'Observation: ' + obs2; mount.appendChild(obsP2); }",
            "    }",
            "",
            "    /* Graph stat grid */",
            "    var grTitle = document.createElement('h3'); grTitle.textContent = 'Source/Sink Graph'; mount.appendChild(grTitle);",
            "    if (!gr) { var m3 = document.createElement('p'); m3.className = 'muted'; m3.textContent = '(missing graph summary)'; mount.appendChild(m3); }",
            "    else {",
            "      var grS = (gr.summary && typeof gr.summary === 'object') ? gr.summary : {};",
            "      var grGrid = document.createElement('div'); grGrid.className = 'stat-grid';",
            "      var grStats = [",
            "        { label: 'Status', value: asTextOr(gr.status, '-') },",
            "        { label: 'Nodes', value: asTextOr(grS.nodes, '0') },",
            "        { label: 'Edges', value: asTextOr(grS.edges, '0') },",
            "        { label: 'Components', value: asTextOr(grS.components, '0') },",
            "        { label: 'Endpoints', value: asTextOr(grS.endpoints, '0') },",
            "        { label: 'Surfaces', value: asTextOr(grS.surfaces, '0') }",
            "      ];",
            "      grStats.forEach(function(st) {",
            "        var card = document.createElement('div'); card.className = 'stat-card';",
            "        var val = document.createElement('div'); val.className = 'stat-value'; val.textContent = String(st.value);",
            "        var lbl = document.createElement('div'); lbl.className = 'stat-label'; lbl.textContent = st.label;",
            "        card.appendChild(val); card.appendChild(lbl); grGrid.appendChild(card);",
            "      });",
            "      mount.appendChild(grGrid);",
            "    }",
            "",
            "    /* Attack Surface stat grid */",
            "    var asTitle = document.createElement('h3'); asTitle.textContent = 'Attack Surface'; mount.appendChild(asTitle);",
            "    if (!asf) { var m4 = document.createElement('p'); m4.className = 'muted'; m4.textContent = '(missing attack_surface summary)'; mount.appendChild(m4); }",
            "    else {",
            "      var asS = (asf.summary && typeof asf.summary === 'object') ? asf.summary : {};",
            "      var asGrid = document.createElement('div'); asGrid.className = 'stat-grid';",
            "      var asStats = [",
            "        { label: 'Status', value: asTextOr(asf.status, '-') },",
            "        { label: 'Surfaces', value: asTextOr(asS.surfaces, '0') },",
            "        { label: 'Endpoints', value: asTextOr(asS.endpoints, '0') },",
            "        { label: 'Graph Nodes', value: asTextOr(asS.graph_nodes, '0') },",
            "        { label: 'Graph Edges', value: asTextOr(asS.graph_edges, '0') },",
            "        { label: 'Attack Items', value: asTextOr(asS.attack_surface_items, '0') }",
            "      ];",
            "      asStats.forEach(function(st) {",
            "        var card = document.createElement('div'); card.className = 'stat-card';",
            "        var val = document.createElement('div'); val.className = 'stat-value'; val.textContent = String(st.value);",
            "        var lbl = document.createElement('div'); lbl.className = 'stat-label'; lbl.textContent = st.label;",
            "        card.appendChild(val); card.appendChild(lbl); asGrid.appendChild(card);",
            "      });",
            "      mount.appendChild(asGrid);",
            "    }",
            "",
            "    var artifactBox = document.createElement('div'); mount.appendChild(artifactBox);",
            "    var artifactTitle = document.createElement('h3'); artifactTitle.textContent = 'Artifacts (run-relative paths)'; artifactBox.appendChild(artifactTitle);",
            "    var alist = document.createElement('ul');",
            "    addListItem(alist, 'surfaces_json: ' + asTextOr(links.surfaces_json, '(missing)'));",
            "    addListItem(alist, 'endpoints_json: ' + asTextOr(links.endpoints_json, '(missing)'));",
            "    addListItem(alist, 'source_sink_graph_json: ' + asTextOr(links.source_sink_graph_json, '(missing)'));",
            "    artifactBox.appendChild(alist);",
            "  }",
            "",
            "  /* ===== renderExploitCandidateMap ===== */",
            "  function renderExploitCandidateMap(candidatesPayload) {",
            "    var mount = document.getElementById('exploit-candidate-map');",
            "    if (!mount) return;",
            "    clearNode(mount);",
            "    var payload = (candidatesPayload && typeof candidatesPayload === 'object') ? candidatesPayload : {};",
            "    var summaryAny = payload.summary;",
            "    var summary = (summaryAny && typeof summaryAny === 'object') ? summaryAny : {};",
            "    var candidates = Array.isArray(payload.candidates) ? payload.candidates : [];",
            "    var summaryList = document.createElement('ul');",
            "    addListItem(summaryList, 'schema_version: ' + asTextOr(payload.schema_version, '(missing)'));",
            "    addListItem(summaryList, 'candidate_count: ' + asTextOr(summary.candidate_count, '0'));",
            "    addListItem(summaryList, 'chain_backed: ' + asTextOr(summary.chain_backed, '0'));",
            "    mount.appendChild(summaryList);",
            "    var bars = [['high', Number(summary.high || 0)], ['medium', Number(summary.medium || 0)], ['low', Number(summary.low || 0)]];",
            "    var maxCount = Math.max(1, bars[0][1], bars[1][1], bars[2][1]);",
            "    var barsWrap = document.createElement('div'); barsWrap.className = 'candidate-bars';",
            "    bars.forEach(function(rowAny) {",
            "      var label = asText(rowAny[0]);",
            "      var count = Number.isFinite(rowAny[1]) ? rowAny[1] : 0;",
            "      var row = document.createElement('div'); row.className = 'candidate-bar-row';",
            "      var left = document.createElement('span'); left.textContent = label.toUpperCase();",
            "      var track = document.createElement('div'); track.className = 'candidate-bar-track';",
            "      var fill = document.createElement('div'); fill.className = 'candidate-bar-fill ' + label;",
            "      fill.style.width = (Math.max(0, count) / maxCount * 100) + '%';",
            "      track.appendChild(fill);",
            "      var right = document.createElement('span'); right.textContent = String(count);",
            "      row.appendChild(left); row.appendChild(track); row.appendChild(right);",
            "      barsWrap.appendChild(row);",
            "    });",
            "    mount.appendChild(barsWrap);",
            "    if (!candidates || candidates.length === 0) {",
            "      var none = document.createElement('p'); none.className = 'muted'; none.textContent = 'No exploit candidates met current promotion criteria.';",
            "      mount.appendChild(none); return;",
            "    }",
            "    var nt = document.createElement('p'); nt.className = 'muted';",
            "    nt.textContent = 'Showing ' + Math.min(20, candidates.length) + ' candidate(s).';",
            "    mount.appendChild(nt);",
            "    candidates.slice(0, 20).forEach(function(itemAny) {",
            "      var item = (itemAny && typeof itemAny === 'object') ? itemAny : {};",
            "      var card = document.createElement('div'); card.className = 'risk';",
            "      var hdr = document.createElement('div'); hdr.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap';",
            "      var priority = asText(item.priority) || 'unknown';",
            "      var pb = document.createElement('span');",
            "      pb.className = 'badge ' + (priority === 'high' ? 'fail' : (priority === 'medium' ? 'blocked' : 'unknown'));",
            "      pb.textContent = priority; hdr.appendChild(pb);",
            "      var sn = Number(item.score);",
            "      var ss = document.createElement('span'); ss.style.cssText = 'font-weight:700;font-size:0.9rem;color:var(--ink)';",
            "      ss.textContent = Number.isFinite(sn) ? sn.toFixed(3) : '?'; hdr.appendChild(ss);",
            "      var sb = document.createElement('span'); sb.className = 'badge'; sb.textContent = asText(item.source) || '?'; hdr.appendChild(sb);",
            "      card.appendChild(hdr);",
            "      var fams = Array.isArray(item.families) ? item.families.map(asText).filter(Boolean) : [];",
            "      if (fams.length) { var fd = document.createElement('div'); fd.style.cssText = 'display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px';",
            "        fams.forEach(function(f) { var fb = document.createElement('span'); fb.className = 'filter-chip'; fb.style.cssText = 'font-size:0.68rem;padding:2px 8px;cursor:default'; fb.textContent = f; fd.appendChild(fb); });",
            "        card.appendChild(fd); }",
            "      var path = asText(item.path);",
            "      if (path && path !== '(none)') { var pd = document.createElement('div'); pd.style.cssText = 'font-size:0.78rem;color:var(--accent);word-break:break-all;margin-bottom:6px';",
            "        pd.textContent = path.split('/').slice(-3).join('/'); card.appendChild(pd); }",
            "      var attack = asText(item.attack_hypothesis);",
            "      if (attack) { var ad = document.createElement('p'); ad.style.cssText = 'font-size:0.82rem;color:var(--ink-secondary);margin-bottom:4px';",
            "        ad.textContent = attack; card.appendChild(ad); }",
            "      var impacts = Array.isArray(item.expected_impact) ? item.expected_impact.map(asText).filter(Boolean) : [];",
            "      if (impacts.length) { var id = document.createElement('p'); id.style.cssText = 'font-size:0.82rem;color:var(--warning);margin-bottom:4px';",
            "        id.textContent = 'Impact: ' + impacts[0]; card.appendChild(id); }",
            "      var steps = Array.isArray(item.validation_plan) ? item.validation_plan.map(asText).filter(Boolean)",
            "        : (Array.isArray(item.analyst_next_steps) ? item.analyst_next_steps.map(asText).filter(Boolean) : []);",
            "      if (steps.length) { var sd = document.createElement('p'); sd.style.cssText = 'font-size:0.78rem;color:var(--muted)';",
            "        sd.textContent = 'Next: ' + steps[0]; card.appendChild(sd); }",
            "      mount.appendChild(card);",
            "    });",
            "  }",
            "",
            "  /* ===== renderEvidenceNextActions ===== */",
            "  function renderEvidenceNextActions(digest) {",
            "    var mount = document.getElementById('evidence-next-actions');",
            "    if (!mount) return;",
            "    clearNode(mount);",
            "    var digestObj = (digest && typeof digest === 'object') ? digest : null;",
            "    var nextActions = digestObj && Array.isArray(digestObj.next_actions) ? digestObj.next_actions : null;",
            "    var evidenceIndex = digestObj && Array.isArray(digestObj.evidence_index) ? digestObj.evidence_index : null;",
            "    if (!nextActions && !evidenceIndex) {",
            "      var degraded = document.createElement('p'); degraded.className = 'muted';",
            "      degraded.textContent = 'Digest unavailable or invalid (degraded). Expected ./analyst_digest.json or embedded bootstrap.';",
            "      mount.appendChild(degraded); return;",
            "    }",
            "    var actionsTitle = document.createElement('h3'); actionsTitle.textContent = 'Next Actions'; mount.appendChild(actionsTitle);",
            "    var actionsList = document.createElement('ul'); mount.appendChild(actionsList);",
            "    if (!nextActions || nextActions.length === 0) { addListItem(actionsList, '(none)'); }",
            "    else { nextActions.forEach(function(action) { addListItem(actionsList, asText(action)); }); }",
            "    if (evidenceIndex) {",
            "      var evidenceTitle = document.createElement('h3'); evidenceTitle.textContent = 'Evidence Index'; mount.appendChild(evidenceTitle);",
            "      var evidenceList = document.createElement('ul'); mount.appendChild(evidenceList);",
            "      if (evidenceIndex.length === 0) { addListItem(evidenceList, '(none)'); }",
            "      else { evidenceIndex.forEach(function(ref) { addListItem(evidenceList, asText(ref)); }); }",
            "    }",
            "  }",
            "",
            "  /* ===== renderExecutiveVerdict ===== */",
            "  function renderExecutiveVerdict(overview, digest) {",
            "    var mount = document.getElementById('executive-verdict');",
            "    if (!mount) return;",
            "    clearNode(mount);",
            "    var digestObj = (digest && typeof digest === 'object') ? digest : {};",
            "    var digestVerdictAny = digestObj.exploitability_verdict;",
            "    var digestVerdict = (digestVerdictAny && typeof digestVerdictAny === 'object') ? digestVerdictAny : null;",
            "    var digestNextActionsAny = digestObj.next_actions;",
            "    var digestNextActions = Array.isArray(digestNextActionsAny) ? digestNextActionsAny.map(asText).filter(Boolean) : [];",
            "    var overviewObj = (overview && typeof overview === 'object') ? overview : {};",
            "    var cockpitAny = overviewObj.cockpit;",
            "    var cockpit = (cockpitAny && typeof cockpitAny === 'object') ? cockpitAny : {};",
            "    var executiveAny = cockpit.executive_verdict;",
            "    var executive = (executiveAny && typeof executiveAny === 'object') ? executiveAny : null;",
            "    var executiveDataAny = executive && executive.data;",
            "    var executiveData = (executiveDataAny && typeof executiveDataAny === 'object') ? executiveDataAny : {};",
            "    var digestState = digestVerdict ? asText(digestVerdict.state) : '';",
            "    var overviewState = asText(executiveData.verdict_state);",
            "    var verdictState = digestState || overviewState || 'unknown';",
            "    var digestReasonCodes = digestVerdict && Array.isArray(digestVerdict.reason_codes) ? digestVerdict.reason_codes.map(asText).filter(Boolean) : [];",
            "    var overviewReasonCodes = Array.isArray(executiveData.reason_codes) ? executiveData.reason_codes.map(asText).filter(Boolean) : [];",
            "    var reasonCodes = digestReasonCodes.length > 0 ? digestReasonCodes : (overviewReasonCodes.length > 0 ? overviewReasonCodes : ['unknown']);",
            "    var overviewNextActions = Array.isArray(executiveData.next_actions) ? executiveData.next_actions.map(asText).filter(Boolean) : [];",
            "    var nextActions = digestNextActions.length > 0 ? digestNextActions : (overviewNextActions.length > 0 ? overviewNextActions : ['unknown: re-run digest verifier']);",
            "    var statusLabel = 'unknown';",
            "    if (digestVerdict || executive) {",
            "      var explicitStatus = executive ? asText(executive.status) : '';",
            "      if (explicitStatus) statusLabel = explicitStatus;",
            "      else if (verdictState === 'unknown') statusLabel = 'blocked';",
            "      else statusLabel = 'unknown';",
            "    } else { statusLabel = 'blocked'; }",
            "    var header = document.createElement('p');",
            "    var badge = document.createElement('span'); badge.className = 'badge ' + badgeClassForStatus(statusLabel);",
            "    badge.textContent = statusLabel || 'unknown'; header.appendChild(badge); mount.appendChild(header);",
            "    var verdictLine = document.createElement('p'); verdictLine.textContent = 'verdict_state: ' + (verdictState || 'unknown'); mount.appendChild(verdictLine);",
            "    var rTitle = document.createElement('p'); rTitle.className = 'muted'; rTitle.textContent = 'reason_codes:'; mount.appendChild(rTitle);",
            "    var reasonList = document.createElement('ul'); reasonCodes.forEach(function(code) { addListItem(reasonList, code); }); mount.appendChild(reasonList);",
            "    var naTitle = document.createElement('p'); naTitle.className = 'muted'; naTitle.textContent = 'next_actions:'; mount.appendChild(naTitle);",
            "    var nextActionsList = document.createElement('ul'); nextActionsList.className = 'next-actions';",
            "    nextActions.forEach(function(action) { addListItem(nextActionsList, action); }); mount.appendChild(nextActionsList);",
            "    var trustBoundary = document.createElement('p'); trustBoundary.className = 'muted';",
            "    trustBoundary.textContent = 'Trust boundary: viewer.html is a convenience aid only and not a verifier; verifier scripts remain authoritative.';",
            "    mount.appendChild(trustBoundary);",
            "  }",
            "",
            "  /* ===== renderAttackSurfaceScale ===== */",
            "  function renderAttackSurfaceScale(overview) {",
            "    var mount = document.getElementById('attack-surface-scale');",
            "    if (!mount) return;",
            "    clearNode(mount);",
            "    var overviewObj = (overview && typeof overview === 'object') ? overview : {};",
            "    var cockpitAny = overviewObj.cockpit;",
            "    var cockpit = (cockpitAny && typeof cockpitAny === 'object') ? cockpitAny : {};",
            "    var scaleAny = cockpit.attack_surface_scale;",
            "    var scale = (scaleAny && typeof scaleAny === 'object') ? scaleAny : null;",
            "    var scaleDataAny = scale && scale.data;",
            "    var scaleData = (scaleDataAny && typeof scaleDataAny === 'object') ? scaleDataAny : null;",
            "    var statusLabel = 'blocked';",
            "    if (scale) { var es = asText(scale.status); statusLabel = es || 'unknown'; }",
            "    var header = document.createElement('p');",
            "    var badge = document.createElement('span'); badge.className = 'badge ' + badgeClassForStatus(statusLabel);",
            "    badge.textContent = statusLabel || 'unknown'; header.appendChild(badge); mount.appendChild(header);",
            "    if (!scaleData) {",
            "      var m = document.createElement('p'); m.className = 'muted'; m.textContent = 'missing source: overview.cockpit.attack_surface_scale.data'; mount.appendChild(m);",
            "    }",
            "    var rows = document.createElement('ul');",
            "    ['endpoints','surfaces','unknowns','non_promoted'].forEach(function(label) {",
            "      var rawValue = scaleData ? scaleData[label] : undefined;",
            "      var rawText = asText(rawValue);",
            "      addListItem(rows, label + ': ' + (rawText ? rawText : 'unknown'));",
            "    });",
            "    mount.appendChild(rows);",
            "  }",
            "",
            "  /* ===== renderVerificationStatus ===== */",
            "  function renderVerificationStatus(overview) {",
            "    var mount = document.getElementById('verification-status');",
            "    if (!mount) return;",
            "    clearNode(mount);",
            "    var overviewObj = (overview && typeof overview === 'object') ? overview : {};",
            "    var cockpitAny = overviewObj.cockpit;",
            "    var cockpit = (cockpitAny && typeof cockpitAny === 'object') ? cockpitAny : {};",
            "    var verificationAny = cockpit.verification_status;",
            "    var verification = (verificationAny && typeof verificationAny === 'object') ? verificationAny : null;",
            "    var verificationDataAny = verification && verification.data;",
            "    var verificationData = (verificationDataAny && typeof verificationDataAny === 'object') ? verificationDataAny : null;",
            "    var statusLabel = 'blocked';",
            "    if (verification) { var es = asText(verification.status); statusLabel = es || 'unknown'; }",
            "    var header = document.createElement('p');",
            "    var badge = document.createElement('span'); badge.className = 'badge ' + badgeClassForStatus(statusLabel);",
            "    badge.textContent = statusLabel || 'unknown'; header.appendChild(badge); mount.appendChild(header);",
            "    var disclaimer = document.createElement('p'); disclaimer.className = 'muted';",
            "    disclaimer.textContent = 'Not a verifier; see verifier scripts for authoritative results.'; mount.appendChild(disclaimer);",
            "    if (!verificationData) {",
            "      var m = document.createElement('p'); m.className = 'muted'; m.textContent = 'missing source: overview.cockpit.verification_status.data'; mount.appendChild(m);",
            "    }",
            "    var countsTitle = document.createElement('h3'); countsTitle.textContent = 'Artifact Counts'; mount.appendChild(countsTitle);",
            "    var countsList = document.createElement('ul'); mount.appendChild(countsList);",
            "    var countsAny = verificationData ? verificationData.artifact_counts : null;",
            "    var counts = (countsAny && typeof countsAny === 'object') ? countsAny : null;",
            "    ['present','missing','invalid','required_missing','required_invalid'].forEach(function(key) {",
            "      var valueAny = counts ? counts[key] : undefined;",
            "      var valueText = (typeof valueAny === 'number') ? String(valueAny) : 'unknown';",
            "      addListItem(countsList, key + ': ' + valueText);",
            "    });",
            "    var blockersTitle = document.createElement('h3'); blockersTitle.textContent = 'Blockers'; mount.appendChild(blockersTitle);",
            "    var blockersList = document.createElement('ul'); mount.appendChild(blockersList);",
            "    var blockersAny = verificationData ? verificationData.blockers : null;",
            "    var blockers = Array.isArray(blockersAny) ? blockersAny.map(asText).filter(Boolean) : null;",
            "    if (!blockers) { addListItem(blockersList, 'unknown (missing overview.cockpit.verification_status.data.blockers)'); }",
            "    else if (blockers.length === 0) { addListItem(blockersList, '(none)'); }",
            "    else { blockers.forEach(function(blocker) { addListItem(blockersList, blocker); }); }",
            "    var gatesTitle = document.createElement('h3'); gatesTitle.textContent = 'Gate Applicability/Presence (not verifier pass/fail)'; mount.appendChild(gatesTitle);",
            "    var gatesAny = verificationData ? verificationData.gates : null;",
            "    var gates = Array.isArray(gatesAny) ? gatesAny : null;",
            "    if (!gates) {",
            "      var ug = document.createElement('p'); ug.className = 'muted'; ug.textContent = 'unknown (missing overview.cockpit.verification_status.data.gates)'; mount.appendChild(ug); return;",
            "    }",
            "    if (gates.length === 0) {",
            "      var em = document.createElement('p'); em.className = 'muted'; em.textContent = '(none)'; mount.appendChild(em); return;",
            "    }",
            "    var matrix = document.createElement('div'); matrix.className = 'gate-matrix'; mount.appendChild(matrix);",
            "    gates.forEach(function(gateAny) {",
            "      if (!gateAny || typeof gateAny !== 'object') return;",
            "      var gate = gateAny;",
            "      var gateId = asText(gate.id) || '(missing id)';",
            "      var gateStatus = asText(gate.status) || 'unknown';",
            "      var row = document.createElement('div'); row.className = 'gate-row';",
            "      var left = document.createElement('div');",
            "      var idNode = document.createElement('div'); idNode.className = 'gate-id'; idNode.textContent = gateId;",
            "      left.appendChild(idNode);",
            "      var vBadge = document.createElement('span'); vBadge.className = 'badge ' + badgeClassForStatus(gateStatus); vBadge.textContent = gateStatus;",
            "      row.appendChild(left); row.appendChild(vBadge); matrix.appendChild(row);",
            "    });",
            "  }",
            "",
            "  /* ===== collectEvidenceNavigatorRefs ===== */",
            "  function collectEvidenceNavigatorRefs(overview) {",
            "    var refs = []; var seen = new Set();",
            "    function addRef(ref) {",
            "      if (typeof ref !== 'string') return;",
            "      var cleaned = ref.trim();",
            "      if (!cleaned || seen.has(cleaned)) return;",
            "      seen.add(cleaned); refs.push(cleaned);",
            "    }",
            "    var overviewObj = (overview && typeof overview === 'object') ? overview : {};",
            "    var cockpitAny = overviewObj.cockpit;",
            "    var cockpit = (cockpitAny && typeof cockpitAny === 'object') ? cockpitAny : {};",
            "    var navAny = cockpit.evidence_navigator;",
            "    var nav = (navAny && typeof navAny === 'object') ? navAny : {};",
            "    var navDataAny = nav.data;",
            "    var navData = (navDataAny && typeof navDataAny === 'object') ? navDataAny : {};",
            "    var preferredAny = navData.evidence_links;",
            "    if (Array.isArray(preferredAny) && preferredAny.length > 0) {",
            "      preferredAny.forEach(addRef);",
            "    } else {",
            "      var linksAny = overviewObj.links;",
            "      var links = (linksAny && typeof linksAny === 'object') ? linksAny : {};",
            "      Object.keys(links).sort().forEach(function(key) { addRef(links[key]); });",
            "      var artifactsAny = overviewObj.artifacts;",
            "      var artifacts = Array.isArray(artifactsAny) ? artifactsAny : [];",
            "      artifacts.forEach(function(a) { if (a && typeof a === 'object') addRef(a.ref); });",
            "    }",
            "    var canonicalOrder = ['report/analyst_digest.md','report/analyst_digest.json','report/analyst_overview.json','report/report.json','report/viewer.html'];",
            "    var canonicalSet = new Set(canonicalOrder);",
            "    var ordered = [];",
            "    canonicalOrder.forEach(function(ref) { if (seen.has(ref)) ordered.push(ref); });",
            "    refs.filter(function(ref) { return !canonicalSet.has(ref); }).sort().forEach(function(ref) { ordered.push(ref); });",
            "    return ordered;",
            "  }",
            "",
            "  /* ===== renderEvidenceNavigator ===== */",
            "  function renderEvidenceNavigator(overview) {",
            "    var mount = document.getElementById('evidence-navigator');",
            "    if (!mount) return;",
            "    clearNode(mount);",
            "    var overviewObj = (overview && typeof overview === 'object') ? overview : {};",
            "    var cockpitAny = overviewObj.cockpit;",
            "    var cockpit = (cockpitAny && typeof cockpitAny === 'object') ? cockpitAny : {};",
            "    var navAny = cockpit.evidence_navigator;",
            "    var nav = (navAny && typeof navAny === 'object') ? navAny : null;",
            "    var statusLine = document.createElement('p');",
            "    var badge = document.createElement('span');",
            "    var statusLabel = nav ? (asText(nav.status) || 'unknown') : 'blocked';",
            "    badge.className = 'badge ' + badgeClassForStatus(statusLabel);",
            "    badge.textContent = statusLabel;",
            "    statusLine.appendChild(badge); mount.appendChild(statusLine);",
            "    var refs = collectEvidenceNavigatorRefs(overviewObj);",
            "    var list = document.createElement('ul'); mount.appendChild(list);",
            "    if (refs.length === 0) { addListItem(list, '(none)'); return; }",
            "    refs.forEach(function(ref) {",
            "      var li = document.createElement('li');",
            "      var row = document.createElement('div'); row.className = 'evidence-row';",
            "      if (isSafeRunRelativeRef(ref)) {",
            "        var link = document.createElement('a'); link.className = 'evidence-link';",
            "        link.href = hrefForEvidenceRef(ref); link.textContent = ref;",
            "        link.addEventListener('click', function(e) { e.preventDefault(); showEvidenceModal(ref); });",
            "        row.appendChild(link);",
            "      } else {",
            "        var unsafe = document.createElement('span'); unsafe.className = 'unsafe-ref'; unsafe.textContent = ref;",
            "        row.appendChild(unsafe);",
            "      }",
            "      var copy = document.createElement('button'); copy.className = 'copy-ref'; copy.type = 'button'; copy.textContent = 'copy';",
            "      copy.addEventListener('click', function() {",
            "        copyText(ref).then(function(ok) { copy.textContent = ok ? 'copied' : 'copy failed'; window.setTimeout(function() { copy.textContent = 'copy'; }, 900); });",
            "      });",
            "      row.appendChild(copy);",
            "      li.appendChild(row); list.appendChild(li);",
            "    });",
            "  }",
            "",
            "  /* ===== renderGraph (Pure JS force-directed, no D3) ===== */",
            "  function renderGraph(graphData) {",
            "    var mount = document.getElementById('graph-vis');",
            "    if (!mount) return;",
            "    mount.innerHTML = '';",
            "",
            "    var gd = (graphData && typeof graphData === 'object') ? graphData : {};",
            "    var cg = gd.comm_graph || gd.reference_graph || gd;",
            "    var rawNodes = Array.isArray(cg.nodes) ? cg.nodes : [];",
            "    var rawEdges = Array.isArray(cg.edges) ? cg.edges : [];",
            "",
            "    if (rawNodes.length === 0) {",
            "      mount.innerHTML = '<p class=\"muted\">No graph data available.</p>';",
            "      return;",
            "    }",
            "",
            "    /* Build node/edge data */",
            "    var nodeMap = {};",
            "    var nodes = [];",
            "    rawNodes.forEach(function(n, i) {",
            "      if (!n || !n.id) return;",
            "      var node = {",
            "        id: n.id,",
            "        label: n.label || n.id.split(':').pop() || '?',",
            "        type: n.type || 'unknown',",
            "        x: Math.random() * 800 + 100,",
            "        y: Math.random() * 500 + 50,",
            "        vx: 0, vy: 0,",
            "        pinned: false",
            "      };",
            "      nodeMap[n.id] = node;",
            "      nodes.push(node);",
            "    });",
            "",
            "    var edges = [];",
            "    rawEdges.forEach(function(e) {",
            "      if (!e || !e.src || !e.dst) return;",
            "      if (nodeMap[e.src] && nodeMap[e.dst]) {",
            "        edges.push({",
            "          source: nodeMap[e.src],",
            "          target: nodeMap[e.dst],",
            "          type: e.edge_type || 'references',",
            "          confidence: e.confidence || 0.5",
            "        });",
            "      }",
            "    });",
            "",
            "    /* Info bar */",
            "    var info = document.createElement('div');",
            "    info.style.cssText = 'display:flex;gap:16px;align-items:center;margin-bottom:12px;flex-wrap:wrap;';",
            "    info.innerHTML = '<span style=\"color:var(--ink-secondary);font-size:0.82rem\">' + nodes.length + ' nodes, ' + edges.length + ' edges</span>';",
            "",
            "    /* Filter buttons */",
            "    var filters = [",
            "      {label: 'All', filter: null},",
            "      {label: 'IPC Only', filter: 'ipc'},",
            "      {label: 'Components', filter: 'component'}",
            "    ];",
            "    var activeFilter = null;",
            "    filters.forEach(function(f) {",
            "      var btn = document.createElement('button');",
            "      btn.className = 'filter-chip' + (f.filter === null ? ' active' : '');",
            "      btn.textContent = f.label;",
            "      btn.onclick = function() {",
            "        activeFilter = f.filter;",
            "        info.querySelectorAll('.filter-chip').forEach(function(b) { b.classList.remove('active'); });",
            "        btn.classList.add('active');",
            "        drawFrame();",
            "      };",
            "      info.appendChild(btn);",
            "    });",
            "    mount.appendChild(info);",
            "",
            "    /* Canvas */",
            "    var canvas = document.createElement('canvas');",
            "    canvas.style.cssText = 'width:100%;border-radius:12px;background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.08);cursor:grab;';",
            "    var dpr = window.devicePixelRatio || 1;",
            "    mount.appendChild(canvas);",
            "",
            "    function resizeCanvas() {",
            "      var rect = canvas.getBoundingClientRect();",
            "      canvas.width = rect.width * dpr;",
            "      canvas.height = 500 * dpr;",
            "      canvas.style.height = '500px';",
            "    }",
            "    resizeCanvas();",
            "    window.addEventListener('resize', resizeCanvas);",
            "",
            "    var ctx = canvas.getContext('2d');",
            "",
            "    /* Color map */",
            "    var colorMap = {",
            "      component: '#22d3ee',",
            "      surface: '#4ade80',",
            "      endpoint: '#fbbf24',",
            "      ipc_channel: '#c084fc',",
            "      vendor: '#94a3b8',",
            "      host: '#38bdf8',",
            "      service: '#fb923c'",
            "    };",
            "",
            "    /* Transform state (zoom/pan) */",
            "    var transform = { x: 0, y: 0, scale: 1 };",
            "    var dragging = null;",
            "    var panning = false;",
            "    var panStart = { x: 0, y: 0 };",
            "    var hovered = null;",
            "",
            "    /* Tooltip div */",
            "    var tooltip = document.createElement('div');",
            "    tooltip.style.cssText = 'position:absolute;pointer-events:none;background:rgba(17,25,40,0.95);backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,0.15);border-radius:8px;padding:8px 12px;font-size:0.75rem;color:#f1f5f9;display:none;z-index:10;max-width:300px;word-break:break-all;';",
            "    mount.style.position = 'relative';",
            "    mount.appendChild(tooltip);",
            "",
            "    /* Screen to world coordinates */",
            "    function screenToWorld(sx, sy) {",
            "      var rect = canvas.getBoundingClientRect();",
            "      return {",
            "        x: (sx - rect.left - transform.x) / transform.scale,",
            "        y: (sy - rect.top - transform.y) / transform.scale",
            "      };",
            "    }",
            "",
            "    function findNodeAt(wx, wy) {",
            "      var best = null, bestDist = 20 / transform.scale;",
            "      for (var i = nodes.length - 1; i >= 0; i--) {",
            "        var n = nodes[i];",
            "        var dx = n.x - wx, dy = n.y - wy;",
            "        var dist = Math.sqrt(dx*dx + dy*dy);",
            "        var r = n.type === 'endpoint' ? 3 : (n.type === 'ipc_channel' ? 8 : 6);",
            "        if (dist < r + bestDist) { best = n; bestDist = dist; }",
            "      }",
            "      return best;",
            "    }",
            "",
            "    /* Mouse events */",
            "    canvas.addEventListener('mousedown', function(e) {",
            "      var w = screenToWorld(e.clientX, e.clientY);",
            "      var node = findNodeAt(w.x, w.y);",
            "      if (node) {",
            "        dragging = node;",
            "        node.pinned = true;",
            "        canvas.style.cursor = 'grabbing';",
            "      } else {",
            "        panning = true;",
            "        panStart = { x: e.clientX - transform.x, y: e.clientY - transform.y };",
            "        canvas.style.cursor = 'grabbing';",
            "      }",
            "    });",
            "",
            "    canvas.addEventListener('mousemove', function(e) {",
            "      if (dragging) {",
            "        var w = screenToWorld(e.clientX, e.clientY);",
            "        dragging.x = w.x;",
            "        dragging.y = w.y;",
            "      } else if (panning) {",
            "        transform.x = e.clientX - panStart.x;",
            "        transform.y = e.clientY - panStart.y;",
            "      } else {",
            "        var w = screenToWorld(e.clientX, e.clientY);",
            "        var node = findNodeAt(w.x, w.y);",
            "        hovered = node;",
            "        canvas.style.cursor = node ? 'pointer' : 'grab';",
            "        if (node) {",
            "          var rect = canvas.getBoundingClientRect();",
            "          tooltip.style.display = 'block';",
            "          tooltip.style.left = (e.clientX - rect.left + 12) + 'px';",
            "          tooltip.style.top = (e.clientY - rect.top - 10) + 'px';",
            "          var connCount = edges.filter(function(ed) { return ed.source === node || ed.target === node; }).length;",
            "          tooltip.innerHTML = '<div style=\"font-weight:700;margin-bottom:2px\">' + node.label + '</div><div style=\"color:' + (colorMap[node.type]||'#94a3b8') + '\">' + node.type + '</div><div style=\"color:#94a3b8\">' + connCount + ' connections</div>';",
            "        } else {",
            "          tooltip.style.display = 'none';",
            "        }",
            "      }",
            "    });",
            "",
            "    canvas.addEventListener('mouseup', function() {",
            "      if (dragging) dragging.pinned = false;",
            "      dragging = null;",
            "      panning = false;",
            "      canvas.style.cursor = 'grab';",
            "    });",
            "",
            "    canvas.addEventListener('mouseleave', function() {",
            "      dragging = null;",
            "      panning = false;",
            "      tooltip.style.display = 'none';",
            "    });",
            "",
            "    canvas.addEventListener('wheel', function(e) {",
            "      e.preventDefault();",
            "      var rect = canvas.getBoundingClientRect();",
            "      var mx = e.clientX - rect.left;",
            "      var my = e.clientY - rect.top;",
            "      var delta = e.deltaY > 0 ? 0.9 : 1.1;",
            "      var newScale = Math.max(0.1, Math.min(5, transform.scale * delta));",
            "      transform.x = mx - (mx - transform.x) * (newScale / transform.scale);",
            "      transform.y = my - (my - transform.y) * (newScale / transform.scale);",
            "      transform.scale = newScale;",
            "    }, { passive: false });",
            "",
            "    /* Force simulation */",
            "    var alpha = 1.0;",
            "    var running = true;",
            "",
            "    function simulate() {",
            "      if (alpha < 0.001) { alpha = 0; return; }",
            "      alpha *= 0.99;",
            "      var k = alpha;",
            "",
            "      /* Repulsion (charge) */",
            "      for (var i = 0; i < nodes.length; i++) {",
            "        for (var j = i + 1; j < nodes.length; j++) {",
            "          var a = nodes[i], b = nodes[j];",
            "          var dx = b.x - a.x, dy = b.y - a.y;",
            "          var dist = Math.sqrt(dx*dx + dy*dy) || 1;",
            "          var force = -300 * k / (dist * dist);",
            "          var fx = dx / dist * force, fy = dy / dist * force;",
            "          if (!a.pinned) { a.vx -= fx; a.vy -= fy; }",
            "          if (!b.pinned) { b.vx += fx; b.vy += fy; }",
            "        }",
            "      }",
            "",
            "      /* Attraction (links) */",
            "      edges.forEach(function(e) {",
            "        var dx = e.target.x - e.source.x, dy = e.target.y - e.source.y;",
            "        var dist = Math.sqrt(dx*dx + dy*dy) || 1;",
            "        var force = (dist - 80) * 0.01 * k;",
            "        var fx = dx / dist * force, fy = dy / dist * force;",
            "        if (!e.source.pinned) { e.source.vx += fx; e.source.vy += fy; }",
            "        if (!e.target.pinned) { e.target.vx -= fx; e.target.vy -= fy; }",
            "      });",
            "",
            "      /* Center gravity */",
            "      var cx = canvas.width / dpr / 2, cy = canvas.height / dpr / 2;",
            "      nodes.forEach(function(n) {",
            "        if (!n.pinned) {",
            "          n.vx += (cx - n.x) * 0.001 * k;",
            "          n.vy += (cy - n.y) * 0.001 * k;",
            "        }",
            "      });",
            "",
            "      /* Apply velocity with damping */",
            "      nodes.forEach(function(n) {",
            "        if (!n.pinned) {",
            "          n.vx *= 0.6;",
            "          n.vy *= 0.6;",
            "          n.x += n.vx;",
            "          n.y += n.vy;",
            "        }",
            "      });",
            "    }",
            "",
            "    /* Visibility check for filter */",
            "    function isVisible(node) {",
            "      if (!activeFilter) return true;",
            "      if (activeFilter === 'ipc') return node.type === 'ipc_channel' || edges.some(function(e) {",
            "        return (e.type.indexOf('ipc') >= 0) && (e.source === node || e.target === node);",
            "      });",
            "      if (activeFilter === 'component') return node.type === 'component' || node.type === 'ipc_channel';",
            "      return true;",
            "    }",
            "",
            "    function drawFrame() {",
            "      simulate();",
            "      var w = canvas.width, h = canvas.height;",
            "      ctx.setTransform(1,0,0,1,0,0);",
            "      ctx.clearRect(0, 0, w, h);",
            "      ctx.setTransform(dpr * transform.scale, 0, 0, dpr * transform.scale, dpr * transform.x, dpr * transform.y);",
            "",
            "      /* Draw edges */",
            "      edges.forEach(function(e) {",
            "        if (!isVisible(e.source) && !isVisible(e.target)) return;",
            "        var isIpc = e.type.indexOf('ipc') >= 0;",
            "        ctx.beginPath();",
            "        ctx.moveTo(e.source.x, e.source.y);",
            "        ctx.lineTo(e.target.x, e.target.y);",
            "        ctx.strokeStyle = isIpc ? 'rgba(192,132,252,0.6)' : 'rgba(255,255,255,0.08)';",
            "        ctx.lineWidth = isIpc ? 1.5 : 0.5;",
            "        if (isIpc) { ctx.setLineDash([4, 3]); } else { ctx.setLineDash([]); }",
            "        /* Highlight edges of hovered node */",
            "        if (hovered && (e.source === hovered || e.target === hovered)) {",
            "          ctx.strokeStyle = isIpc ? 'rgba(192,132,252,0.9)' : 'rgba(34,211,238,0.5)';",
            "          ctx.lineWidth = 2;",
            "        }",
            "        ctx.stroke();",
            "        ctx.setLineDash([]);",
            "      });",
            "",
            "      /* Draw nodes */",
            "      nodes.forEach(function(n) {",
            "        if (!isVisible(n)) return;",
            "        var color = colorMap[n.type] || '#94a3b8';",
            "        var isHovered = hovered === n;",
            "        var isConnected = hovered && edges.some(function(e) { return (e.source === hovered && e.target === n) || (e.target === hovered && e.source === n); });",
            "        var nodeAlpha = hovered ? (isHovered || isConnected ? 1.0 : 0.15) : 0.85;",
            "",
            "        ctx.globalAlpha = nodeAlpha;",
            "        ctx.beginPath();",
            "",
            "        if (n.type === 'ipc_channel') {",
            "          /* Diamond shape */",
            "          var s = isHovered ? 10 : 7;",
            "          ctx.moveTo(n.x, n.y - s);",
            "          ctx.lineTo(n.x + s, n.y);",
            "          ctx.lineTo(n.x, n.y + s);",
            "          ctx.lineTo(n.x - s, n.y);",
            "          ctx.closePath();",
            "        } else if (n.type === 'endpoint') {",
            "          ctx.arc(n.x, n.y, isHovered ? 4 : 2.5, 0, Math.PI * 2);",
            "        } else {",
            "          ctx.arc(n.x, n.y, isHovered ? 9 : 6, 0, Math.PI * 2);",
            "        }",
            "",
            "        /* Glow for hovered */",
            "        if (isHovered) {",
            "          ctx.shadowColor = color;",
            "          ctx.shadowBlur = 16;",
            "        }",
            "        ctx.fillStyle = color;",
            "        ctx.fill();",
            "        ctx.shadowBlur = 0;",
            "",
            "        /* Label for components and IPC (not endpoints - too many) */",
            "        if ((n.type === 'component' || n.type === 'ipc_channel') && transform.scale > 0.5) {",
            "          ctx.font = (n.type === 'ipc_channel' ? 'bold ' : '') + '9px system-ui';",
            "          ctx.fillStyle = isHovered ? '#ffffff' : 'rgba(255,255,255,0.6)';",
            "          ctx.textAlign = 'center';",
            "          ctx.fillText(n.label.length > 20 ? n.label.substring(0,18) + '..' : n.label, n.x, n.y + (n.type === 'ipc_channel' ? 16 : 14));",
            "        }",
            "        ctx.globalAlpha = 1;",
            "      });",
            "",
            "      if (running) requestAnimationFrame(drawFrame);",
            "    }",
            "",
            "    /* Legend */",
            "    var legend = document.createElement('div');",
            "    legend.style.cssText = 'display:flex;flex-wrap:wrap;gap:12px;margin-top:10px;';",
            "    Object.entries(colorMap).forEach(function(entry) {",
            "      var type = entry[0], color = entry[1];",
            "      var item = document.createElement('span');",
            "      item.style.cssText = 'display:inline-flex;align-items:center;gap:4px;font-size:0.72rem;color:var(--muted)';",
            "      var dot = document.createElement('span');",
            "      dot.style.cssText = 'width:8px;height:8px;border-radius:' + (type === 'ipc_channel' ? '2px' : '50%') + ';background:' + color;",
            "      item.appendChild(dot);",
            "      item.appendChild(document.createTextNode(type));",
            "      legend.appendChild(item);",
            "    });",
            "    mount.appendChild(legend);",
            "",
            "    /* Trimmed note */",
            "    if (cg.trimmed) {",
            "      var trimNote = document.createElement('p');",
            "      trimNote.className = 'muted';",
            "      trimNote.style.fontSize = '0.75rem';",
            "      trimNote.style.marginTop = '8px';",
            "      trimNote.textContent = 'Showing trimmed view (' + nodes.length + '/' + (cg.original_nodes||'?') + ' nodes, ' + edges.length + '/' + (cg.original_edges||'?') + ' edges). Full data available via fetch.';",
            "      mount.appendChild(trimNote);",
            "    }",
            "",
            "    drawFrame();",
            "  }",
            "",
            "  /* ===== renderIpcMap ===== */",
            "  function renderIpcMap(ipcData, graphData) {",
            "    var mount = document.getElementById('ipc-map');",
            "    if (!mount) return;",
            "    clearNode(mount);",
            "    var data = (ipcData && typeof ipcData === 'object') ? ipcData : {};",
            "    var binaries = Array.isArray(data.binaries) ? data.binaries : [];",
            "    var ipcBins = binaries.filter(function(b) { return b && (b.ipc_indicators || (Array.isArray(b.ipc_symbols) && b.ipc_symbols.length > 0)); });",
            "    var gd = (graphData && typeof graphData === 'object') ? graphData : {};",
            "    var cg = gd.comm_graph || gd.reference_graph || gd;",
            "    var gNodes = Array.isArray(cg.nodes) ? cg.nodes : [];",
            "    var gEdges = Array.isArray(cg.edges) ? cg.edges : [];",
            "    var ipcNodes = gNodes.filter(function(n) { return n && n.type === 'ipc_channel'; });",
            "    var ipcEdges = gEdges.filter(function(e) { return e && e.edge_type && e.edge_type.indexOf('ipc') >= 0; });",
            "    if (ipcBins.length === 0 && ipcNodes.length === 0) {",
            "      mount.innerHTML = '<p class=\"muted\">No IPC mechanisms detected.</p>'; return;",
            "    }",
            "    var grid = document.createElement('div'); grid.className = 'stat-grid';",
            "    [{l:'IPC Channels',v:ipcNodes.length},{l:'IPC Connections',v:ipcEdges.length},{l:'IPC Binaries',v:ipcBins.length}].forEach(function(s) {",
            "      var c = document.createElement('div'); c.className = 'stat-card';",
            "      var val = document.createElement('div'); val.className = 'stat-value'; val.textContent = String(s.v);",
            "      if (s.v > 0) val.style.color = '#c084fc';",
            "      var lbl = document.createElement('div'); lbl.className = 'stat-label'; lbl.textContent = s.l;",
            "      c.appendChild(val); c.appendChild(lbl); grid.appendChild(c);",
            "    });",
            "    mount.appendChild(grid);",
            "    if (ipcNodes.length > 0) {",
            "      var h3 = document.createElement('h3'); h3.textContent = 'IPC Channels'; mount.appendChild(h3);",
            "      var wrap = document.createElement('div'); wrap.className = 'table-wrap';",
            "      var tbl = document.createElement('table');",
            "      var th = document.createElement('thead'); var hr = document.createElement('tr');",
            "      ['Channel','Type','Connected Components','Evidence'].forEach(function(l) { var t = document.createElement('th'); t.textContent = l; hr.appendChild(t); });",
            "      th.appendChild(hr); tbl.appendChild(th);",
            "      var tb = document.createElement('tbody');",
            "      ipcNodes.forEach(function(node) {",
            "        var tr = document.createElement('tr');",
            "        var td1 = document.createElement('td');",
            "        var badge = document.createElement('span'); badge.className = 'badge';",
            "        badge.style.cssText = 'background:rgba(192,132,252,0.15);color:#c084fc;border:1px solid rgba(192,132,252,0.3)';",
            "        badge.textContent = node.label || '?'; td1.appendChild(badge); tr.appendChild(td1);",
            "        var chEdges = ipcEdges.filter(function(e) { return e.dst === node.id || e.src === node.id; });",
            "        var types = {}; chEdges.forEach(function(e) { types[e.edge_type] = true; });",
            "        var td2 = document.createElement('td'); td2.textContent = Object.keys(types).join(', ') || 'ipc'; tr.appendChild(td2);",
            "        var comps = {}; chEdges.forEach(function(e) { var o = e.src === node.id ? e.dst : e.src; if (o.indexOf('component:') === 0) comps[o.replace('component:','')] = true; });",
            "        var td3 = document.createElement('td'); td3.textContent = Object.keys(comps).join(', ') || '-'; tr.appendChild(td3);",
            "        var td4 = document.createElement('td'); var refs = Array.isArray(node.evidence_refs) ? node.evidence_refs : [];",
            "        td4.textContent = refs.length > 0 ? refs[0].split('/').pop() + (refs.length > 1 ? ' (+' + (refs.length-1) + ')' : '') : '-';",
            "        tr.appendChild(td4); tb.appendChild(tr);",
            "      });",
            "      tbl.appendChild(tb); wrap.appendChild(tbl); mount.appendChild(wrap);",
            "    }",
            "    if (ipcBins.length > 0) {",
            "      var h3b = document.createElement('h3'); h3b.textContent = 'Binary IPC Indicators'; mount.appendChild(h3b);",
            "      var wrap2 = document.createElement('div'); wrap2.className = 'table-wrap';",
            "      var tbl2 = document.createElement('table');",
            "      var th2 = document.createElement('thead'); var hr2 = document.createElement('tr');",
            "      ['Binary','IPC Symbols','Socket Paths','D-Bus'].forEach(function(l) { var t = document.createElement('th'); t.textContent = l; hr2.appendChild(t); });",
            "      th2.appendChild(hr2); tbl2.appendChild(th2);",
            "      var tb2 = document.createElement('tbody');",
            "      ipcBins.slice(0,50).forEach(function(bin) {",
            "        var tr = document.createElement('tr'); var ind = bin.ipc_indicators || {};",
            "        var td1 = document.createElement('td'); td1.textContent = (asText(bin.path)||'?').split('/').pop(); tr.appendChild(td1);",
            "        var td2 = document.createElement('td'); var sy = Array.isArray(ind.ipc_symbols) ? ind.ipc_symbols : []; td2.textContent = sy.slice(0,5).join(', ') || '-'; tr.appendChild(td2);",
            "        var td3 = document.createElement('td'); var sk = Array.isArray(ind.unix_socket_paths) ? ind.unix_socket_paths : []; td3.textContent = sk.slice(0,3).join(', ') || '-'; tr.appendChild(td3);",
            "        var td4 = document.createElement('td'); var db = Array.isArray(ind.dbus_interfaces) ? ind.dbus_interfaces : []; td4.textContent = db.slice(0,3).join(', ') || '-'; tr.appendChild(td4);",
            "        tb2.appendChild(tr);",
            "      });",
            "      tbl2.appendChild(tb2); wrap2.appendChild(tbl2); mount.appendChild(wrap2);",
            "    }",
            "  }",
            "",
            "  /* ===== renderRiskHeatmap ===== */",
            f"  {_heatmap_cell_js}",
            "  function renderRiskHeatmap(overview, exploitCandidates) {",
            "    var mount = document.getElementById('risk-heatmap');",
            "    if (!mount) return;",
            "    clearNode(mount);",
            "    var ov = (overview && typeof overview === 'object') ? overview : {};",
            "    var ec = (exploitCandidates && typeof exploitCandidates === 'object') ? exploitCandidates : {};",
            "    var summary = (ov.summary && typeof ov.summary === 'object') ? ov.summary : {};",
            "",
            "    /* Build risk cells from stages */",
            "    var stageNames = ['extraction','inventory','endpoints','surfaces','graph','attack_surface','findings','emulation','exploit_chain'];",
            "    var grid = document.createElement('div'); grid.className = 'heatmap-grid';",
            "",
            "    stageNames.forEach(function(name) {",
            "      var sKey = name + '_summary';",
            "      var stageAny = summary[sKey];",
            "      var stage = (stageAny && typeof stageAny === 'object') ? stageAny : null;",
            "      var status = stage ? asText(stage.status) : 'unknown';",
            "      grid.appendChild(_hmCell(name, status));",
            "    });",
            "",
            "    /* Add candidate counts as heatmap cells */",
            "    var ecSummary = (ec.summary && typeof ec.summary === 'object') ? ec.summary : {};",
            "    ['high','medium','low'].forEach(function(level) {",
            "      var count = Number(ecSummary[level] || 0);",
            "      var cell = document.createElement('div'); cell.className = 'heatmap-cell';",
            "      if (level === 'high' && count > 0) cell.className += ' critical';",
            "      else if (level === 'medium' && count > 0) cell.className += ' high';",
            "      else if (count > 0) cell.className += ' medium';",
            "      else cell.className += ' none';",
            "      var t = document.createElement('div'); t.style.fontSize = '0.72rem'; t.style.color = 'var(--muted)'; t.textContent = 'exploit:' + level; cell.appendChild(t);",
            "      var v = document.createElement('div'); v.textContent = String(count); cell.appendChild(v);",
            "      grid.appendChild(cell);",
            "    });",
            "",
            "    mount.appendChild(grid);",
            "  }",
            "",
            "  /* ===== render (legacy summary) ===== */",
            "  function render(data) {",
            "    var meta = document.getElementById('meta');",
            "    var summary = document.getElementById('summary');",
            "    var risks = document.getElementById('risks');",
            "    var evidence = document.getElementById('evidence');",
            "    var schema = asText(data && data.schema_version ? data.schema_version : '');",
            "    var source = asText(data && data.source ? data.source : '');",
            "    if (meta) meta.textContent = 'schema=' + (schema || 'n/a') + (source ? ' | source=' + source : '');",
            "    if (summary) {",
            "      var summaryObj = data && typeof data.summary === 'object' && data.summary ? data.summary : {};",
            "      addListItem(summary, 'Top Risk Count: ' + asText(summaryObj.top_risk_count));",
            "      addListItem(summary, 'Candidate Claim Count: ' + asText(summaryObj.candidate_claim_count));",
            "      addListItem(summary, 'Evidence Ref Count: ' + asText(summaryObj.evidence_ref_count));",
            "    }",
            "    var top = Array.isArray(data && data.top_risk_claims) ? data.top_risk_claims : [];",
            "    if (risks) {",
            "      if (top.length === 0) {",
            "        var empty = document.createElement('p'); empty.className = 'muted'; empty.textContent = '(none)'; risks.appendChild(empty);",
            "      } else {",
            "        top.forEach(function(item, idx) {",
            "          var box = document.createElement('article'); box.className = 'risk';",
            "          var h = document.createElement('h3');",
            "          var sev = asText(item && item.severity ? item.severity : '').toUpperCase();",
            "          h.textContent = (idx + 1) + '. [' + (sev || 'N/A') + '] ' + asText(item && item.claim_type ? item.claim_type : '');",
            "          box.appendChild(h);",
            "          var conf = document.createElement('p'); conf.className = 'muted';",
            "          conf.textContent = 'Confidence: ' + asText(item && item.confidence !== undefined ? item.confidence : '');",
            "          box.appendChild(conf);",
            "          var refs = Array.isArray(item && item.evidence_refs) ? item.evidence_refs : [];",
            "          var refsList = document.createElement('ul');",
            "          if (refs.length === 0) { addListItem(refsList, '(none)'); }",
            "          else { refs.forEach(function(ref) { addListItem(refsList, asText(ref)); }); }",
            "          box.appendChild(refsList); risks.appendChild(box);",
            "        });",
            "      }",
            "    }",
            "    if (evidence) {",
            "      var idxRefs = Array.isArray(data && data.evidence_index) ? data.evidence_index : [];",
            "      if (idxRefs.length === 0) { addListItem(evidence, '(none)'); }",
            "      else { idxRefs.forEach(function(ref) { addListItem(evidence, asText(ref)); }); }",
            "    }",
            "  }",
            "",
            "  /* ===== Data Loaders ===== */",
            "  async function loadData() {",
            "    if (window.location && window.location.protocol === 'file:') {",
            "      var warn = document.getElementById('file-warning'); if (warn) warn.hidden = false;",
            "    }",
            "    try { var res = await fetch('./analyst_report_v2.json', { cache: 'no-store' }); if (res.ok) return await res.json(); } catch (_) {}",
            "    var bn = document.getElementById('bootstrap-data'); if (!bn) return {};",
            "    try { return JSON.parse(bn.textContent || '{}'); } catch (_) { return {}; }",
            "  }",
            "  async function loadOverview() {",
            "    try { var r = await fetch('./analyst_overview.json', { cache: 'no-store' }); if (r.ok) { try { var d = await r.json(); if (d && typeof d === 'object') return d; } catch(_) {} } } catch(_) {}",
            "    var bn = document.getElementById('bootstrap-overview-data'); if (!bn) return {};",
            "    try { var d2 = JSON.parse(bn.textContent || '{}'); return (d2 && typeof d2 === 'object') ? d2 : {}; } catch(_) { return {}; }",
            "  }",
            "  async function loadDigest() {",
            "    try { var r = await fetch('./analyst_digest.json', { cache: 'no-store' }); if (r.ok) { try { var d = await r.json(); return (d && typeof d === 'object') ? d : {}; } catch(_) {} } } catch(_) {}",
            "    var bn = document.getElementById('bootstrap-digest-data'); if (!bn) return {};",
            "    try { var d2 = JSON.parse(bn.textContent || '{}'); return (d2 && typeof d2 === 'object') ? d2 : {}; } catch(_) { return {}; }",
            "  }",
            "  async function loadExploitCandidates() {",
            "    try { var r = await fetch('../stages/findings/exploit_candidates.json', { cache: 'no-store' }); if (r.ok) { try { var d = await r.json(); return (d && typeof d === 'object') ? d : {}; } catch(_) {} } } catch(_) {}",
            "    var bn = document.getElementById('bootstrap-exploit-candidates-data'); if (!bn) return {};",
            "    try { var d2 = JSON.parse(bn.textContent || '{}'); return (d2 && typeof d2 === 'object') ? d2 : {}; } catch(_) { return {}; }",
            "  }",
            "  async function loadGraph() {",
            "    try { var r = await fetch('../stages/graph/comm_graph.json', { cache: 'no-store' }); if (r.ok) { try { var d = await r.json(); if (d && typeof d === 'object') return { comm_graph: d }; } catch(_) {} } } catch(_) {}",
            "    var bn = document.getElementById('bootstrap-graph-data'); if (!bn) return {};",
            "    try { var d2 = JSON.parse(bn.textContent || '{}'); return (d2 && typeof d2 === 'object') ? d2 : {}; } catch(_) { return {}; }",
            "  }",
            "  async function loadIPC() {",
            "    try { var r = await fetch('../stages/inventory/binary_analysis.json', { cache: 'no-store' }); if (r.ok) { try { var d = await r.json(); return (d && typeof d === 'object') ? d : {}; } catch(_) {} } } catch(_) {}",
            "    var bn = document.getElementById('bootstrap-ipc-data'); if (!bn) return {};",
            "    try { var d2 = JSON.parse(bn.textContent || '{}'); return (d2 && typeof d2 === 'object') ? d2 : {}; } catch(_) { return {}; }",
            "  }",
            "",
            "  /* ===== Render All Panes ===== */",
            "  function renderAllPanes(overview, digest, data, exploitCandidates, graphData, ipcData) {",
            "    var safeOverview = (overview && typeof overview === 'object') ? overview : {};",
            "    var safeDigest = (digest && typeof digest === 'object') ? digest : {};",
            "    var safeData = (data && typeof data === 'object') ? data : {};",
            "    var safeExploitCandidates = (exploitCandidates && typeof exploitCandidates === 'object') ? exploitCandidates : {};",
            "    var safeGraph = (graphData && typeof graphData === 'object') ? graphData : {};",
            "    var safeIpc = (ipcData && typeof ipcData === 'object') ? ipcData : {};",
            "    window.__aiedge_overview = safeOverview;",
            "    window.__aiedge_digest = safeDigest;",
            "    function safeRender(fn) { try { fn(); } catch (_) {} }",
            "    safeRender(function() { renderPipelineProgress(safeOverview); });",
            "    safeRender(function() { renderOverview(window.__aiedge_overview); });",
            "    safeRender(function() { renderVulnerabilities(window.__aiedge_digest); });",
            "    safeRender(function() { renderStructure(safeOverview); });",
            "    safeRender(function() { renderProtocols(safeOverview); });",
            "    safeRender(function() { renderGraph(safeGraph); });",
            "    safeRender(function() { renderIpcMap(safeIpc, safeGraph); });",
            "    safeRender(function() { renderRiskHeatmap(safeOverview, safeExploitCandidates); });",
            "    safeRender(function() { renderExploitCandidateMap(safeExploitCandidates); });",
            "    safeRender(function() { renderEvidenceNextActions(safeDigest); });",
            "    safeRender(function() { renderExecutiveVerdict(safeOverview, safeDigest); });",
            "    safeRender(function() { renderAttackSurfaceScale(safeOverview); });",
            "    safeRender(function() { renderVerificationStatus(safeOverview); });",
            "    safeRender(function() { renderEvidenceNavigator(safeOverview); });",
            "    safeRender(function() { render(safeData); });",
            "  }",
            "",
            "  /* ===== Main dispatch ===== */",
            "  // legacy: loadData().then(render)",
            "  // legacy: render({});",
            "  Promise.all([loadData(), loadOverview(), loadDigest(), loadExploitCandidates(), loadGraph(), loadIPC()])",
            "    .then(function(results) {",
            "      renderAllPanes(results[1], results[2], results[0], results[3], results[4], results[5]);",
            "    }).catch(() => {",
            "      renderAllPanes({}, {}, {}, {}, {}, {});",
            "    });",
            "  </script>",
            "</body>",
            "</html>",
            "",
        ]
    )

    _ = report_path.write_text(doc, encoding="utf-8")
    return report_path


def build_minimal_report(
    *,
    overview: dict[str, JsonValue] | None = None,
    extraction: dict[str, JsonValue] | None = None,
    inventory: dict[str, JsonValue] | None = None,
    limitations: list[str] | None = None,
) -> dict[str, JsonValue]:
    rep = empty_report()
    if overview is not None:
        rep["overview"] = dict(overview)
    if extraction is not None:
        rep["extraction"] = dict(extraction)
    if inventory is not None:
        rep["inventory"] = dict(inventory)
    if limitations:
        rep["limitations"] = list(limitations)
    return rep


def write_report_json(report_dir: Path, report: dict[str, JsonValue]) -> Path:
    report_path = report_dir / "report.json"
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    _ = report_path.write_text(payload, encoding="utf-8")
    return report_path


def write_report_html(report_dir: Path, report: dict[str, JsonValue]) -> Path:
    report_path = report_dir / "report.html"
    report_json = json.dumps(report, indent=2, sort_keys=True)

    safe_pre = html.escape(report_json, quote=True)
    doc = "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '  <meta charset="utf-8">',
            '  <meta name="viewport" content="width=device-width, initial-scale=1">',
            "  <title>aiedge report</title>",
            "  <style>",
            "    :root { color-scheme: light; }",
            "    body { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace; margin: 24px; }",
            "    h1 { font-size: 18px; margin: 0 0 12px 0; }",
            "    pre { background: #f6f8fa; padding: 16px; border-radius: 8px; overflow: auto; }",
            "  </style>",
            "</head>",
            "<body>",
            "  <h1>aiedge report</h1>",
            "  <pre>",
            safe_pre,
            "  </pre>",
            "</body>",
            "</html>",
            "",
        ]
    )

    _ = report_path.write_text(doc, encoding="utf-8")
    return report_path


def build_analyst_report(report: dict[str, JsonValue]) -> dict[str, JsonValue]:
    section_objs: dict[str, dict[str, JsonValue]] = {}
    for section in ANALYST_REPORT_REQUIRED_SECTIONS:
        section_any = report.get(section)
        if isinstance(section_any, dict):
            section_objs[section] = dict(section_any)
        else:
            section_objs[section] = {}

    section_evidence_paths: dict[str, list[str]] = {}
    limitations_accum: list[str] = []
    all_claims: list[dict[str, JsonValue]] = []
    for section in ANALYST_REPORT_REQUIRED_SECTIONS:
        section_obj = section_objs[section]
        section_paths = _extract_evidence_paths(section_obj)
        section_evidence_paths[section] = section_paths
        limitations_accum.extend(_extract_limitations(section_obj))
        all_claims.extend(_extract_claims(section_obj, fallback_refs=section_paths))

    top_level_limitations = report.get("limitations")
    if isinstance(top_level_limitations, list):
        for item in cast(list[object], top_level_limitations):
            if isinstance(item, str) and item:
                limitations_accum.append(item)

    analyst_report: dict[str, JsonValue] = {
        "schema_version": ANALYST_REPORT_SCHEMA_VERSION,
        "claims": cast(
            list[JsonValue],
            cast(list[object], _dedupe_and_sort_claims(all_claims)),
        ),
        "limitations": cast(
            list[JsonValue],
            cast(list[object], sorted(set(limitations_accum))),
        ),
        "artifacts": cast(
            JsonValue, {"section_evidence_paths": section_evidence_paths}
        ),
    }
    for section, section_obj in section_objs.items():
        analyst_report[section] = cast(JsonValue, section_obj)
    return analyst_report


def _is_run_relative_path(path: object) -> bool:
    return _normalize_run_relative_ref(path) is not None


def _normalize_run_relative_ref(path: object) -> str | None:
    normalized, _ = _normalize_run_relative_ref_with_reason(path)
    return normalized


def _normalize_run_relative_ref_with_reason(
    path: object,
) -> tuple[str | None, str | None]:
    if not isinstance(path, str) or not path:
        return None, "ref must be a non-empty string"

    ref = path.replace("\\", "/")
    if ref.startswith("/"):
        return None, "ref must be run-relative"
    if re.match(r"^[A-Za-z]:[\\/]", ref):
        return None, "ref must not be an absolute drive path"
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", ref):
        return None, "ref must not include a URI scheme"

    parts: list[str] = []
    for part in ref.split("/"):
        if not part or part == ".":
            continue
        if part == "..":
            return None, "ref must not contain '..'"
        parts.append(part)

    if not parts:
        return None, "ref must resolve to a non-empty run-relative path"
    return "/".join(parts), None


def _iter_object_items(value: object) -> list[tuple[str, object]]:
    if not isinstance(value, dict):
        return []
    src = cast(dict[object, object], value)
    out: list[tuple[str, object]] = []
    for key, item in src.items():
        out.append((str(key), item))
    return out


def _iter_object_list(value: object) -> list[object]:
    if not isinstance(value, list):
        return []
    return list(cast(list[object], value))


def _extract_evidence_paths(obj: object) -> list[str]:
    paths: set[str] = set()
    for key, value in _iter_object_items(obj):
        if key == "evidence":
            for ev_any in _iter_object_list(value):
                if not isinstance(ev_any, dict):
                    continue
                ev_obj = cast(dict[str, object], ev_any)
                path_any = ev_obj.get("path")
                if _is_run_relative_path(path_any):
                    paths.add(cast(str, path_any))
        for nested_key, nested_value in _iter_object_items(value):
            _ = nested_key
            for nested_path in _extract_evidence_paths(nested_value):
                paths.add(nested_path)
        for nested_item in _iter_object_list(value):
            for nested_path in _extract_evidence_paths(nested_item):
                paths.add(nested_path)
    for item in _iter_object_list(obj):
        for nested_path in _extract_evidence_paths(item):
            paths.add(nested_path)
    return sorted(paths)


def _extract_limitations(obj: object) -> list[str]:
    limitations: set[str] = set()
    for key, value in _iter_object_items(obj):
        if key == "limitations":
            for item in _iter_object_list(value):
                if isinstance(item, str) and item:
                    limitations.add(item)
        for nested in _extract_limitations(value):
            limitations.add(nested)
    for item in _iter_object_list(obj):
        for nested in _extract_limitations(item):
            limitations.add(nested)
    return sorted(limitations)


def _extract_claims(
    obj: object, *, fallback_refs: list[str]
) -> list[dict[str, JsonValue]]:
    claims: list[dict[str, JsonValue]] = []
    if not isinstance(obj, dict):
        return claims
    obj_dict = cast(dict[str, object], obj)
    claims_any = obj_dict.get("claims")
    if isinstance(claims_any, list):
        for claim_any in cast(list[object], claims_any):
            claim = _normalize_claim(claim_any, fallback_refs=fallback_refs)
            if claim is not None:
                claims.append(claim)
    return claims


def _normalize_claim(
    claim_any: object, *, fallback_refs: list[str]
) -> dict[str, JsonValue] | None:
    if not isinstance(claim_any, dict):
        return None
    claim_obj = cast(dict[str, object], claim_any)

    claim_type_any = claim_obj.get("claim_type")
    if not isinstance(claim_type_any, str) or not claim_type_any:
        return None
    if "value" not in claim_obj:
        return None

    confidence_any = claim_obj.get("confidence")
    if isinstance(confidence_any, bool) or not isinstance(confidence_any, (int, float)):
        return None
    confidence = float(confidence_any)
    if confidence < 0.0 or confidence > 1.0:
        return None

    refs_any = claim_obj.get("evidence_refs")
    refs: set[str] = set()
    if isinstance(refs_any, list):
        for ref in cast(list[object], refs_any):
            if _is_run_relative_path(ref):
                refs.add(cast(str, ref))
    if not refs:
        refs.update(fallback_refs)
    if not refs:
        return None

    claim: dict[str, JsonValue] = {
        "claim_type": claim_type_any,
        "value": cast(JsonValue, claim_obj.get("value")),
        "confidence": confidence,
        "evidence_refs": cast(list[JsonValue], cast(list[object], sorted(refs))),
    }

    alternatives_any = claim_obj.get("alternatives_considered")
    if isinstance(alternatives_any, list):
        alternatives = sorted(
            {
                item
                for item in cast(list[object], alternatives_any)
                if isinstance(item, str) and item
            }
        )
        if alternatives:
            claim["alternatives_considered"] = cast(
                list[JsonValue], cast(list[object], alternatives)
            )

    unknowns_any = claim_obj.get("unknowns")
    if isinstance(unknowns_any, list):
        unknowns = sorted(
            {
                item
                for item in cast(list[object], unknowns_any)
                if isinstance(item, str) and item
            }
        )
        if unknowns:
            claim["unknowns"] = cast(list[JsonValue], cast(list[object], unknowns))

    return claim


def _claim_sort_key(claim: dict[str, JsonValue]) -> tuple[str, str, str, str, str, str]:
    claim_type = str(claim.get("claim_type", ""))
    value_s = json.dumps(claim.get("value"), sort_keys=True, ensure_ascii=True)
    confidence_s = f"{float(cast(float, claim.get('confidence', 0.0))):.6f}"
    refs = ",".join(cast(list[str], claim.get("evidence_refs", [])))
    alternatives = ",".join(cast(list[str], claim.get("alternatives_considered", [])))
    unknowns = ",".join(cast(list[str], claim.get("unknowns", [])))
    return (claim_type, value_s, confidence_s, refs, alternatives, unknowns)


def _dedupe_and_sort_claims(
    claims: list[dict[str, JsonValue]],
) -> list[dict[str, JsonValue]]:
    out: list[dict[str, JsonValue]] = []
    seen: set[tuple[str, str, str, str, str, str]] = set()
    for claim in sorted(claims, key=_claim_sort_key):
        key = _claim_sort_key(claim)
        if key in seen:
            continue
        seen.add(key)
        out.append(claim)
    return out


def write_analyst_report_json(report_dir: Path, report: dict[str, JsonValue]) -> Path:
    report_path = report_dir / "analyst_report.json"
    payload = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    _ = report_path.write_text(payload, encoding="utf-8")
    return report_path


def write_analyst_report_md(report_dir: Path, report: dict[str, JsonValue]) -> Path:
    report_path = report_dir / "analyst_report.md"
    lines: list[str] = [
        "# AIEdge Analyst Report",
        "",
        f"Schema version: `{report.get('schema_version', '')}`",
        "",
    ]
    for section in ANALYST_REPORT_REQUIRED_SECTIONS:
        lines.extend(
            [
                f"## {section}",
                "",
                "```json",
                json.dumps(
                    report.get(section, {}), indent=2, sort_keys=True, ensure_ascii=True
                ),
                "```",
                "",
            ]
        )
    _ = report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def write_stub_log(logs_dir: Path, *, filename: str = "aiedge.log") -> Path:
    log_path = logs_dir / filename
    _ = log_path.write_text("aiedge: no extraction stages executed\n", encoding="utf-8")
    return log_path


def ensure_artifacts_dir(run_dir: Path) -> Path:
    artifacts_dir = run_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    readme = artifacts_dir / "README.txt"
    if not readme.exists():
        _ = readme.write_text(
            "No extracted artifacts yet. Extraction is not implemented in this scaffold.\n",
            encoding="utf-8",
        )
    return artifacts_dir
