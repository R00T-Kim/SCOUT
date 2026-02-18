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

    try:
        evidence_fn(run_dir)
    except Exception as exc:
        reason = _extract_reason_code(exc)
        if reason == "missing_required_artifact":
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

    doc = "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '  <meta charset="utf-8">',
            '  <meta name="viewport" content="width=device-width, initial-scale=1">',
            "  <title>AIEdge Analyst Report v2 Viewer</title>",
            "  <style>",
            "    :root { color-scheme: light; --bg:#f3f4f6; --surface:#ffffff; --ink:#101828; --muted:#475467; --line:#d0d5dd; --accent:#0f766e; }",
            "    * { box-sizing: border-box; }",
            "    body { margin: 0; background: var(--bg); color: var(--ink); font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Helvetica, Arial, sans-serif; }",
            "    .wrap { max-width: 1080px; margin: 0 auto; padding: 24px; }",
            "    .card { background: var(--surface); border: 1px solid var(--line); border-radius: 12px; padding: 16px; margin-bottom: 14px; }",
            "    h1 { margin: 0; font-size: 1.55rem; }",
            "    h2 { margin: 0 0 10px 0; font-size: 1.1rem; }",
            "    h3 { margin: 0 0 8px 0; font-size: 1rem; }",
            "    .meta { margin-top: 10px; color: var(--muted); font-size: 0.92rem; }",
            "    .warn { border-left: 4px solid #f59e0b; padding: 10px 12px; background: #fff7ed; color: #7c2d12; margin-top: 12px; }",
            "    .risk { border: 1px solid var(--line); border-radius: 10px; padding: 12px; margin-bottom: 10px; }",
            "    .muted { color: var(--muted); }",
            "    .badge { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 999px; font-size: 0.78rem; font-weight: 600; border: 1px solid var(--line); background: #f9fafb; color: var(--ink); }",
            "    .badge.pass { background: #ecfdf3; border-color: #a6f4c5; color: #027a48; }",
            "    .badge.fail { background: #fef3f2; border-color: #fecdca; color: #b42318; }",
            "    .badge.blocked { background: #fffaeb; border-color: #fedf89; color: #b54708; }",
            "    .badge.not_applicable { background: #f2f4f7; border-color: #e4e7ec; color: #344054; }",
            "    .badge.unknown { background: #f2f4f7; border-color: #e4e7ec; color: #344054; }",
            "    .overview-grid { display: grid; grid-template-columns: 1fr; gap: 12px; }",
            "    .gate-matrix { border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }",
            "    .gate-row { display: flex; gap: 12px; justify-content: space-between; padding: 10px 12px; border-top: 1px solid var(--line); }",
            "    .gate-row:first-child { border-top: none; }",
            "    .gate-id { font-weight: 600; }",
            "    .gate-reasons { margin: 6px 0 0 18px; padding: 0; color: var(--muted); }",
            "    .evidence-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; }",
            "    .evidence-link { color: var(--accent); text-decoration: none; font-weight: 600; word-break: break-all; }",
            "    .evidence-link:hover { text-decoration: underline; }",
            "    .unsafe-ref { color: #b42318; font-weight: 600; word-break: break-all; }",
            "    .copy-ref { border: 1px solid var(--line); background: #f9fafb; color: var(--ink); border-radius: 8px; padding: 2px 8px; font-size: 0.78rem; cursor: pointer; }",
            "    .copy-ref:hover { background: #f2f4f7; }",
            "    .candidate-bars { display: grid; gap: 8px; margin-top: 10px; }",
            "    .candidate-bar-row { display: grid; grid-template-columns: 80px 1fr 56px; gap: 10px; align-items: center; }",
            "    .candidate-bar-track { background: #f2f4f7; border: 1px solid var(--line); border-radius: 999px; height: 10px; overflow: hidden; }",
            "    .candidate-bar-fill { height: 100%; background: #1570ef; }",
            "    .candidate-bar-fill.high { background: #b42318; }",
            "    .candidate-bar-fill.medium { background: #b54708; }",
            "    .candidate-bar-fill.low { background: #1570ef; }",
            "    .candidate-table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.9rem; }",
            "    .candidate-table th, .candidate-table td { border-top: 1px solid var(--line); padding: 8px; text-align: left; vertical-align: top; }",
            "    .candidate-table th { color: var(--muted); font-weight: 600; }",
            "    ul { margin: 8px 0 0 18px; padding: 0; }",
            "    li { margin: 4px 0; }",
            "  </style>",
            "</head>",
            "<body>",
            '  <div class="wrap">',
            '    <section class="card">',
            "      <h1>AIEdge Analyst Report v2 Viewer</h1>",
            '      <div id="meta" class="meta"></div>',
            '      <div id="file-warning" class="warn" hidden>Tip: Local file mode can block fetch(). Run a local server (for example: python3 -m http.server) from this report directory.</div>',
            "    </section>",
            '    <section class="card" id="pane-overview-gates">',
            "      <h2>Overview & Gates</h2>",
            '      <div id="overview-gates"></div>',
            "    </section>",
            '    <section class="card" id="pane-vulnerabilities-verdicts">',
            "      <h2>Vulnerabilities & Verdicts</h2>",
            '      <div id="vulnerabilities-verdicts"></div>',
            "    </section>",
            '    <section class="card" id="pane-structure-binaries">',
            "      <h2>Structure & Binaries</h2>",
            '      <div id="structure-binaries"></div>',
            "    </section>",
            '    <section class="card" id="pane-protocols-attack-surface">',
            "      <h2>Protocols & Attack Surface</h2>",
            '      <div id="protocols-attack-surface"></div>',
            "    </section>",
            '    <section class="card" id="pane-exploit-candidate-map">',
            "      <h2>Exploit Candidate Map</h2>",
            '      <div id="exploit-candidate-map"></div>',
            "    </section>",
            '    <section class="card" id="pane-evidence-next-actions">',
            "      <h2>Evidence & Next Actions</h2>",
            '      <div id="evidence-next-actions"></div>',
            "    </section>",
            '    <section class="card" id="pane-executive-verdict">',
            "      <h2>Executive Verdict</h2>",
            '      <div id="executive-verdict"></div>',
            "    </section>",
            '    <section class="card" id="pane-attack-surface-scale">',
            "      <h2>Attack Surface Scale</h2>",
            '      <div id="attack-surface-scale"></div>',
            "    </section>",
            '    <section class="card" id="pane-verification-status">',
            "      <h2>Verification Status</h2>",
            '      <div id="verification-status"></div>',
            "    </section>",
            '    <section class="card" id="pane-evidence-navigator">',
            "      <h2>Evidence Navigator</h2>",
            '      <div id="evidence-navigator"></div>',
            "    </section>",
            '    <section class="card">',
            "      <h2>Executive Summary</h2>",
            '      <ul id="summary"></ul>',
            "    </section>",
            '    <section class="card">',
            "      <h2>Top Risks</h2>",
            '      <div id="risks"></div>',
            "    </section>",
            '    <section class="card">',
            "      <h2>Evidence Index</h2>",
            '      <ul id="evidence"></ul>',
            "    </section>",
            "  </div>",
            '  <script id="bootstrap-data" type="application/json">',
            bootstrap,
            "  </script>",
            '  <script id="bootstrap-overview-data" type="application/json">',
            overview_bootstrap,
            "  </script>",
            '  <script id="bootstrap-digest-data" type="application/json">',
            digest_bootstrap,
            "  </script>",
            '  <script id="bootstrap-exploit-candidates-data" type="application/json">',
            exploit_candidates_bootstrap,
            "  </script>",
            "  <script>",
            "    function asText(v) {",
            "      if (typeof v === 'string' || typeof v === 'number') return String(v);",
            "      return '';",
            "    }",
            "",
            "    function addListItem(list, text) {",
            "      const li = document.createElement('li');",
            "      li.textContent = text;",
            "      list.appendChild(li);",
            "    }",
            "",
            "    function badgeClassForStatus(status) {",
            "      const s = asText(status);",
            "      if (s === 'pass') return 'pass';",
            "      if (s === 'fail') return 'fail';",
            "      if (s === 'blocked') return 'blocked';",
            "      if (s === 'not_applicable') return 'not_applicable';",
            "      return 'unknown';",
            "    }",
            "",
            "    function clearNode(node) {",
            "      if (!node) return;",
            "      while (node.firstChild) node.removeChild(node.firstChild);",
            "    }",
            "",
            "    function badgeClassForVerdictState(state) {",
            "      const s = asText(state);",
            "      if (s === 'VERIFIED') return 'pass';",
            "      if (s === 'ATTEMPTED_INCONCLUSIVE') return 'blocked';",
            "      if (s === 'NOT_ATTEMPTED') return 'blocked';",
            "      if (s === 'NOT_APPLICABLE') return 'not_applicable';",
            "      return 'unknown';",
            "    }",
            "",
            "    function formatArrayInline(arrAny) {",
            "      if (!Array.isArray(arrAny)) return '(unavailable)';",
            "      const parts = arrAny.map(asText).filter(function(x) { return x !== ''; });",
            "      if (parts.length === 0) return '(none)';",
            "      return parts.join(', ');",
            "    }",
            "",
            "    function asTextOr(v, fallback) {",
            "      const t = asText(v);",
            "      return t ? t : fallback;",
            "    }",
            "",
            "    function renderVulnerabilities(digest) {",
            "      const mount = document.getElementById('vulnerabilities-verdicts');",
            "      if (!mount) return;",
            "      clearNode(mount);",
            "",
            "      const digestObj = (digest && typeof digest === 'object') ? digest : {};",
            "      const evAny = digestObj.exploitability_verdict;",
            "      const ev = (evAny && typeof evAny === 'object') ? evAny : null;",
            "      const findingVerdicts = Array.isArray(digestObj.finding_verdicts) ? digestObj.finding_verdicts : null;",
            "",
            "      if (!ev && !findingVerdicts) {",
            "        const degraded = document.createElement('p');",
            "        degraded.className = 'muted';",
            "        degraded.textContent = 'Digest unavailable or invalid (degraded). Expected ./analyst_digest.json or embedded bootstrap.';",
            "        mount.appendChild(degraded);",
            "        return;",
            "      }",
            "",
            "      const overallBox = document.createElement('div');",
            "      mount.appendChild(overallBox);",
            "      const overallTitle = document.createElement('h3');",
            "      overallTitle.textContent = 'Overall Exploitability Verdict';",
            "      overallBox.appendChild(overallTitle);",
            "",
            "      if (!ev) {",
            "        const missing = document.createElement('p');",
            "        missing.className = 'muted';",
            "        missing.textContent = '(missing exploitability_verdict)';",
            "        overallBox.appendChild(missing);",
            "      } else {",
            "        const state = asText(ev.state);",
            "        const line = document.createElement('p');",
            "        const badge = document.createElement('span');",
            "        badge.className = 'badge ' + badgeClassForVerdictState(state);",
            "        badge.textContent = state || 'unknown';",
            "        line.appendChild(badge);",
            "        overallBox.appendChild(line);",
            "",
            "        const rcLine = document.createElement('p');",
            "        rcLine.className = 'muted';",
            "        rcLine.textContent = 'reason_codes: ' + formatArrayInline(ev.reason_codes);",
            "        overallBox.appendChild(rcLine);",
            "      }",
            "",
            "      const listBox = document.createElement('div');",
            "      mount.appendChild(listBox);",
            "      const listTitle = document.createElement('h3');",
            "      listTitle.textContent = 'Finding Verdicts';",
            "      listBox.appendChild(listTitle);",
            "",
            "      if (!Array.isArray(findingVerdicts)) {",
            "        const missingList = document.createElement('p');",
            "        missingList.className = 'muted';",
            "        missingList.textContent = '(missing finding_verdicts)';",
            "        listBox.appendChild(missingList);",
            "        return;",
            "      }",
            "",
            "      const items = findingVerdicts;",
            "      const total = items.length;",
            "      const maxShow = 100;",
            "      if (total === 0) {",
            "        const empty = document.createElement('p');",
            "        empty.className = 'muted';",
            "        empty.textContent = '(none)';",
            "        listBox.appendChild(empty);",
            "        return;",
            "      }",
            "",
            "      const note = document.createElement('p');",
            "      note.className = 'muted';",
            "      note.textContent = (total > maxShow) ? ('Showing first ' + maxShow + ' of ' + total + ' findings (deterministic order).') : ('Showing ' + total + ' findings.');",
            "      listBox.appendChild(note);",
            "",
            "      items.slice(0, maxShow).forEach(function(itemAny) {",
            "        if (!itemAny || typeof itemAny !== 'object') return;",
            "        const item = itemAny;",
            "",
            "        const box = document.createElement('article');",
            "        box.className = 'risk';",
            "",
            "        const h = document.createElement('h3');",
            "        h.textContent = asText(item.finding_id) || '(missing finding_id)';",
            "        box.appendChild(h);",
            "",
            "        const verdictLine = document.createElement('p');",
            "        const verdictKey = document.createElement('span');",
            "        verdictKey.className = 'muted';",
            "        verdictKey.textContent = 'verdict: ';",
            "        verdictLine.appendChild(verdictKey);",
            "        const st = asText(item.verdict);",
            "        const badge = document.createElement('span');",
            "        badge.className = 'badge ' + badgeClassForVerdictState(st);",
            "        badge.textContent = st || 'unknown';",
            "        verdictLine.appendChild(badge);",
            "        box.appendChild(verdictLine);",
            "",
            "        const rc = document.createElement('p');",
            "        rc.className = 'muted';",
            "        rc.textContent = 'reason_codes: ' + formatArrayInline(item.reason_codes);",
            "        box.appendChild(rc);",
            "",
            "        const evrefs = document.createElement('p');",
            "        evrefs.className = 'muted';",
            "        evrefs.textContent = 'evidence_refs: ' + formatArrayInline(item.evidence_refs);",
            "        box.appendChild(evrefs);",
            "",
            "        const vrefs = document.createElement('p');",
            "        vrefs.className = 'muted';",
            "        vrefs.textContent = 'verifier_refs: ' + formatArrayInline(item.verifier_refs);",
            "        box.appendChild(vrefs);",
            "",
            "        listBox.appendChild(box);",
            "      });",
            "    }",
            "",
            "    function renderStructure(overview) {",
            "      const mount = document.getElementById('structure-binaries');",
            "      if (!mount) return;",
            "      clearNode(mount);",
            "",
            "      const summary = (overview && typeof overview.summary === 'object' && overview.summary) ? overview.summary : {};",
            "      const exAny = summary.extraction_summary;",
            "      const invAny = summary.inventory_summary;",
            "      const ex = (exAny && typeof exAny === 'object') ? exAny : null;",
            "      const inv = (invAny && typeof invAny === 'object') ? invAny : null;",
            "",
            "      const exBox = document.createElement('div');",
            "      mount.appendChild(exBox);",
            "      const exTitle = document.createElement('h3');",
            "      exTitle.textContent = 'Extraction';",
            "      exBox.appendChild(exTitle);",
            "      if (!ex) {",
            "        const missing = document.createElement('p');",
            "        missing.className = 'muted';",
            "        missing.textContent = '(missing extraction summary)';",
            "        exBox.appendChild(missing);",
            "      } else {",
            "        const exSummaryAny = ex.summary;",
            "        const exSummary = (exSummaryAny && typeof exSummaryAny === 'object') ? exSummaryAny : {};",
            "        const list = document.createElement('ul');",
            "        addListItem(list, 'status: ' + asTextOr(ex.status, '(missing)'));",
            "        addListItem(list, 'confidence: ' + asTextOr(ex.confidence, '(missing)'));",
            "        addListItem(list, 'tool: ' + asTextOr(exSummary.tool, '(missing)'));",
            "        addListItem(list, 'extracted_dir: ' + asTextOr(exSummary.extracted_dir, '(missing)'));",
            "        addListItem(list, 'extracted_file_count: ' + asTextOr(exSummary.extracted_file_count, '(missing)'));",
            "        exBox.appendChild(list);",
            "      }",
            "",
            "      const invBox = document.createElement('div');",
            "      mount.appendChild(invBox);",
            "      const invTitle = document.createElement('h3');",
            "      invTitle.textContent = 'Inventory';",
            "      invBox.appendChild(invTitle);",
            "      if (!inv) {",
            "        const missing = document.createElement('p');",
            "        missing.className = 'muted';",
            "        missing.textContent = '(missing inventory summary)';",
            "        invBox.appendChild(missing);",
            "      } else {",
            "        const invSummaryAny = inv.summary;",
            "        const invSummary = (invSummaryAny && typeof invSummaryAny === 'object') ? invSummaryAny : {};",
            "        const list = document.createElement('ul');",
            "        addListItem(list, 'status: ' + asTextOr(inv.status, '(missing)'));",
            "        addListItem(list, 'roots_scanned: ' + asTextOr(invSummary.roots_scanned, '(missing)'));",
            "        addListItem(list, 'files: ' + asTextOr(invSummary.files, '(missing)'));",
            "        addListItem(list, 'binaries: ' + asTextOr(invSummary.binaries, '(missing)'));",
            "        addListItem(list, 'configs: ' + asTextOr(invSummary.configs, '(missing)'));",
            "        addListItem(list, 'string_hits: ' + asTextOr(invSummary.string_hits, '(missing)'));",
            "        invBox.appendChild(list);",
            "      }",
            "    }",
            "",
            "    function renderProtocols(overview) {",
            "      const mount = document.getElementById('protocols-attack-surface');",
            "      if (!mount) return;",
            "      clearNode(mount);",
            "",
            "      const summary = (overview && typeof overview.summary === 'object' && overview.summary) ? overview.summary : {};",
            "      const links = (overview && typeof overview.links === 'object' && overview.links) ? overview.links : {};",
            "",
            "      const epAny = summary.endpoints_summary;",
            "      const sfAny = summary.surfaces_summary;",
            "      const grAny = summary.graph_summary;",
            "      const asAny = summary.attack_surface_summary;",
            "      const ep = (epAny && typeof epAny === 'object') ? epAny : null;",
            "      const sf = (sfAny && typeof sfAny === 'object') ? sfAny : null;",
            "      const gr = (grAny && typeof grAny === 'object') ? grAny : null;",
            "      const asf = (asAny && typeof asAny === 'object') ? asAny : null;",
            "",
            "      const epBox = document.createElement('div');",
            "      mount.appendChild(epBox);",
            "      const epTitle = document.createElement('h3');",
            "      epTitle.textContent = 'Endpoints';",
            "      epBox.appendChild(epTitle);",
            "      if (!ep) {",
            "        const missing = document.createElement('p');",
            "        missing.className = 'muted';",
            "        missing.textContent = '(missing endpoints summary)';",
            "        epBox.appendChild(missing);",
            "      } else {",
            "        const epSummaryAny = ep.summary;",
            "        const epSummary = (epSummaryAny && typeof epSummaryAny === 'object') ? epSummaryAny : {};",
            "        const list = document.createElement('ul');",
            "        addListItem(list, 'status: ' + asTextOr(ep.status, '(missing)'));",
            "        addListItem(list, 'endpoints: ' + asTextOr(epSummary.endpoints, '(missing)'));",
            "        addListItem(list, 'roots_scanned: ' + asTextOr(epSummary.roots_scanned, '(missing)'));",
            "        addListItem(list, 'files_scanned: ' + asTextOr(epSummary.files_scanned, '(missing)'));",
            "        const cls = asText(epSummary.classification);",
            "        if (cls) addListItem(list, 'classification: ' + cls);",
            "        const obs = asText(epSummary.observation);",
            "        if (obs) addListItem(list, 'observation: ' + obs);",
            "        epBox.appendChild(list);",
            "      }",
            "",
            "      const sfBox = document.createElement('div');",
            "      mount.appendChild(sfBox);",
            "      const sfTitle = document.createElement('h3');",
            "      sfTitle.textContent = 'Surfaces';",
            "      sfBox.appendChild(sfTitle);",
            "      if (!sf) {",
            "        const missing = document.createElement('p');",
            "        missing.className = 'muted';",
            "        missing.textContent = '(missing surfaces summary)';",
            "        sfBox.appendChild(missing);",
            "      } else {",
            "        const sfSummaryAny = sf.summary;",
            "        const sfSummary = (sfSummaryAny && typeof sfSummaryAny === 'object') ? sfSummaryAny : {};",
            "        const list = document.createElement('ul');",
            "        addListItem(list, 'status: ' + asTextOr(sf.status, '(missing)'));",
            "        addListItem(list, 'surfaces: ' + asTextOr(sfSummary.surfaces, '(missing)'));",
            "        addListItem(list, 'unknowns: ' + asTextOr(sfSummary.unknowns, '(missing)'));",
            "        const cls = asText(sfSummary.classification);",
            "        if (cls) addListItem(list, 'classification: ' + cls);",
            "        const obs = asText(sfSummary.observation);",
            "        if (obs) addListItem(list, 'observation: ' + obs);",
            "        sfBox.appendChild(list);",
            "      }",
            "",
            "      const grBox = document.createElement('div');",
            "      mount.appendChild(grBox);",
            "      const grTitle = document.createElement('h3');",
            "      grTitle.textContent = 'Source/Sink Graph';",
            "      grBox.appendChild(grTitle);",
            "      if (!gr) {",
            "        const missing = document.createElement('p');",
            "        missing.className = 'muted';",
            "        missing.textContent = '(missing graph summary)';",
            "        grBox.appendChild(missing);",
            "      } else {",
            "        const grSummaryAny = gr.summary;",
            "        const grSummary = (grSummaryAny && typeof grSummaryAny === 'object') ? grSummaryAny : {};",
            "        const list = document.createElement('ul');",
            "        addListItem(list, 'status: ' + asTextOr(gr.status, '(missing)'));",
            "        const nodes = asText(grSummary.nodes);",
            "        if (nodes) addListItem(list, 'nodes: ' + nodes);",
            "        const edges = asText(grSummary.edges);",
            "        if (edges) addListItem(list, 'edges: ' + edges);",
            "        const comps = asText(grSummary.components);",
            "        if (comps) addListItem(list, 'components: ' + comps);",
            "        const epc = asText(grSummary.endpoints);",
            "        if (epc) addListItem(list, 'endpoints: ' + epc);",
            "        const sfc = asText(grSummary.surfaces);",
            "        if (sfc) addListItem(list, 'surfaces: ' + sfc);",
            "        const vendors = asText(grSummary.vendors);",
            "        if (vendors) addListItem(list, 'vendors: ' + vendors);",
            "        grBox.appendChild(list);",
            "      }",
            "",
            "      const asBox = document.createElement('div');",
            "      mount.appendChild(asBox);",
            "      const asTitle = document.createElement('h3');",
            "      asTitle.textContent = 'Attack Surface';",
            "      asBox.appendChild(asTitle);",
            "      if (!asf) {",
            "        const missing = document.createElement('p');",
            "        missing.className = 'muted';",
            "        missing.textContent = '(missing attack_surface summary)';",
            "        asBox.appendChild(missing);",
            "      } else {",
            "        const asSummaryAny = asf.summary;",
            "        const asSummary = (asSummaryAny && typeof asSummaryAny === 'object') ? asSummaryAny : {};",
            "        const list = document.createElement('ul');",
            "        addListItem(list, 'status: ' + asTextOr(asf.status, '(missing)'));",
            "        const surfaces = asText(asSummary.surfaces);",
            "        if (surfaces) addListItem(list, 'surfaces: ' + surfaces);",
            "        const endpoints = asText(asSummary.endpoints);",
            "        if (endpoints) addListItem(list, 'endpoints: ' + endpoints);",
            "        const graphNodes = asText(asSummary.graph_nodes);",
            "        if (graphNodes) addListItem(list, 'graph_nodes: ' + graphNodes);",
            "        const graphEdges = asText(asSummary.graph_edges);",
            "        if (graphEdges) addListItem(list, 'graph_edges: ' + graphEdges);",
            "        const items = asText(asSummary.attack_surface_items);",
            "        if (items) addListItem(list, 'attack_surface_items: ' + items);",
            "        const unknowns = asText(asSummary.unknowns);",
            "        if (unknowns) addListItem(list, 'unknowns: ' + unknowns);",
            "        asBox.appendChild(list);",
            "      }",
            "",
            "      const artifactBox = document.createElement('div');",
            "      mount.appendChild(artifactBox);",
            "      const artifactTitle = document.createElement('h3');",
            "      artifactTitle.textContent = 'Artifacts (run-relative paths)';",
            "      artifactBox.appendChild(artifactTitle);",
            "      const list = document.createElement('ul');",
            "      addListItem(list, 'surfaces_json: ' + asTextOr(links.surfaces_json, '(missing)'));",
            "      addListItem(list, 'endpoints_json: ' + asTextOr(links.endpoints_json, '(missing)'));",
            "      addListItem(list, 'source_sink_graph_json: ' + asTextOr(links.source_sink_graph_json, '(missing)'));",
            "      artifactBox.appendChild(list);",
            "    }",
            "",
            "    function renderExploitCandidateMap(candidatesPayload) {",
            "      const mount = document.getElementById('exploit-candidate-map');",
            "      if (!mount) return;",
            "      clearNode(mount);",
            "",
            "      const payload = (candidatesPayload && typeof candidatesPayload === 'object') ? candidatesPayload : {};",
            "      const summaryAny = payload.summary;",
            "      const summary = (summaryAny && typeof summaryAny === 'object') ? summaryAny : {};",
            "      const candidates = Array.isArray(payload.candidates) ? payload.candidates : [];",
            "",
            "      const summaryList = document.createElement('ul');",
            "      addListItem(summaryList, 'schema_version: ' + asTextOr(payload.schema_version, '(missing)'));",
            "      addListItem(summaryList, 'candidate_count: ' + asTextOr(summary.candidate_count, '0'));",
            "      addListItem(summaryList, 'chain_backed: ' + asTextOr(summary.chain_backed, '0'));",
            "      mount.appendChild(summaryList);",
            "",
            "      const bars = [",
            "        ['high', Number(summary.high || 0)],",
            "        ['medium', Number(summary.medium || 0)],",
            "        ['low', Number(summary.low || 0)]",
            "      ];",
            "      const maxCount = Math.max(1, ...bars.map(function(x) { return Number.isFinite(x[1]) ? x[1] : 0; }));",
            "",
            "      const barsWrap = document.createElement('div');",
            "      barsWrap.className = 'candidate-bars';",
            "      bars.forEach(function(rowAny) {",
            "        const label = asText(rowAny[0]);",
            "        const count = Number.isFinite(rowAny[1]) ? rowAny[1] : 0;",
            "        const row = document.createElement('div');",
            "        row.className = 'candidate-bar-row';",
            "",
            "        const left = document.createElement('span');",
            "        left.textContent = label.toUpperCase();",
            "",
            "        const track = document.createElement('div');",
            "        track.className = 'candidate-bar-track';",
            "        const fill = document.createElement('div');",
            "        fill.className = 'candidate-bar-fill ' + label;",
            "        fill.style.width = (Math.max(0, count) / maxCount * 100) + '%';",
            "        track.appendChild(fill);",
            "",
            "        const right = document.createElement('span');",
            "        right.textContent = String(count);",
            "",
            "        row.appendChild(left);",
            "        row.appendChild(track);",
            "        row.appendChild(right);",
            "        barsWrap.appendChild(row);",
            "      });",
            "      mount.appendChild(barsWrap);",
            "",
            "      if (!candidates || candidates.length === 0) {",
            "        const none = document.createElement('p');",
            "        none.className = 'muted';",
            "        none.textContent = 'No exploit candidates met current promotion criteria.';",
            "        mount.appendChild(none);",
            "        return;",
            "      }",
            "",
            "      const note = document.createElement('p');",
            "      note.className = 'muted';",
            "      note.textContent = 'Showing first ' + Math.min(20, candidates.length) + ' candidate(s) in deterministic order.';",
            "      mount.appendChild(note);",
            "",
            "      const table = document.createElement('table');",
            "      table.className = 'candidate-table';",
            "      const thead = document.createElement('thead');",
            "      const headRow = document.createElement('tr');",
            "      ['priority', 'score', 'source', 'path', 'families'].forEach(function(label) {",
            "        const th = document.createElement('th');",
            "        th.textContent = label;",
            "        headRow.appendChild(th);",
            "      });",
            "      thead.appendChild(headRow);",
            "      table.appendChild(thead);",
            "",
            "      const tbody = document.createElement('tbody');",
            "      candidates.slice(0, 20).forEach(function(itemAny) {",
            "        const item = (itemAny && typeof itemAny === 'object') ? itemAny : {};",
            "        const tr = document.createElement('tr');",
            "",
            "        const tdPriority = document.createElement('td');",
            "        const priority = asText(item.priority) || 'unknown';",
            "        const prBadge = document.createElement('span');",
            "        prBadge.className = 'badge ' + (priority === 'high' ? 'fail' : (priority === 'medium' ? 'blocked' : 'unknown'));",
            "        prBadge.textContent = priority;",
            "        tdPriority.appendChild(prBadge);",
            "        tr.appendChild(tdPriority);",
            "",
            "        const tdScore = document.createElement('td');",
            "        const scoreNum = Number(item.score);",
            "        tdScore.textContent = Number.isFinite(scoreNum) ? scoreNum.toFixed(3) : asText(item.score);",
            "        tr.appendChild(tdScore);",
            "",
            "        const tdSource = document.createElement('td');",
            "        tdSource.textContent = asText(item.source) || 'unknown';",
            "        tr.appendChild(tdSource);",
            "",
            "        const tdPath = document.createElement('td');",
            "        tdPath.textContent = asText(item.path) || '(none)';",
            "        tr.appendChild(tdPath);",
            "",
            "        const tdFamilies = document.createElement('td');",
            "        const fams = Array.isArray(item.families) ? item.families.map(asText).filter(Boolean) : [];",
            "        tdFamilies.textContent = fams.length ? fams.join(', ') : '(none)';",
            "        tr.appendChild(tdFamilies);",
            "",
            "        tbody.appendChild(tr);",
            "      });",
            "      table.appendChild(tbody);",
            "      mount.appendChild(table);",
            "    }",
            "",
            "    function renderEvidenceNextActions(digest) {",
            "      const mount = document.getElementById('evidence-next-actions');",
            "      if (!mount) return;",
            "      clearNode(mount);",
            "",
            "      const digestObj = (digest && typeof digest === 'object') ? digest : null;",
            "      const nextActions = digestObj && Array.isArray(digestObj.next_actions) ? digestObj.next_actions : null;",
            "      const evidenceIndex = digestObj && Array.isArray(digestObj.evidence_index) ? digestObj.evidence_index : null;",
            "",
            "      if (!nextActions && !evidenceIndex) {",
            "        const degraded = document.createElement('p');",
            "        degraded.className = 'muted';",
            "        degraded.textContent = 'Digest unavailable or invalid (degraded). Expected ./analyst_digest.json or embedded bootstrap.';",
            "        mount.appendChild(degraded);",
            "        return;",
            "      }",
            "",
            "      const actionsTitle = document.createElement('h3');",
            "      actionsTitle.textContent = 'Next Actions';",
            "      mount.appendChild(actionsTitle);",
            "",
            "      const actionsList = document.createElement('ul');",
            "      mount.appendChild(actionsList);",
            "      if (!nextActions || nextActions.length === 0) {",
            "        addListItem(actionsList, '(none)');",
            "      } else {",
            "        nextActions.forEach(function(action) {",
            "          addListItem(actionsList, asText(action));",
            "        });",
            "      }",
            "",
            "      if (evidenceIndex) {",
            "        const evidenceTitle = document.createElement('h3');",
            "        evidenceTitle.textContent = 'Evidence Index';",
            "        mount.appendChild(evidenceTitle);",
            "",
            "        const evidenceList = document.createElement('ul');",
            "        mount.appendChild(evidenceList);",
            "        if (evidenceIndex.length === 0) {",
            "          addListItem(evidenceList, '(none)');",
            "        } else {",
            "          evidenceIndex.forEach(function(ref) {",
            "            addListItem(evidenceList, asText(ref));",
            "          });",
            "        }",
            "      }",
            "    }",
            "",
            "    function renderExecutiveVerdict(overview, digest) {",
            "      const mount = document.getElementById('executive-verdict');",
            "      if (!mount) return;",
            "      clearNode(mount);",
            "",
            "      const digestObj = (digest && typeof digest === 'object') ? digest : {};",
            "      const digestVerdictAny = digestObj.exploitability_verdict;",
            "      const digestVerdict = (digestVerdictAny && typeof digestVerdictAny === 'object') ? digestVerdictAny : null;",
            "      const digestNextActionsAny = digestObj.next_actions;",
            "      const digestNextActions = Array.isArray(digestNextActionsAny) ? digestNextActionsAny.map(asText).filter(Boolean) : [];",
            "",
            "      const overviewObj = (overview && typeof overview === 'object') ? overview : {};",
            "      const cockpitAny = overviewObj.cockpit;",
            "      const cockpit = (cockpitAny && typeof cockpitAny === 'object') ? cockpitAny : {};",
            "      const executiveAny = cockpit.executive_verdict;",
            "      const executive = (executiveAny && typeof executiveAny === 'object') ? executiveAny : null;",
            "      const executiveDataAny = executive && executive.data;",
            "      const executiveData = (executiveDataAny && typeof executiveDataAny === 'object') ? executiveDataAny : {};",
            "",
            "      const digestState = digestVerdict ? asText(digestVerdict.state) : '';",
            "      const overviewState = asText(executiveData.verdict_state);",
            "      const verdictState = digestState || overviewState || 'unknown';",
            "",
            "      const digestReasonCodes = digestVerdict && Array.isArray(digestVerdict.reason_codes)",
            "        ? digestVerdict.reason_codes.map(asText).filter(Boolean)",
            "        : [];",
            "      const overviewReasonCodes = Array.isArray(executiveData.reason_codes)",
            "        ? executiveData.reason_codes.map(asText).filter(Boolean)",
            "        : [];",
            "      const reasonCodes = digestReasonCodes.length > 0 ? digestReasonCodes : (overviewReasonCodes.length > 0 ? overviewReasonCodes : ['unknown']);",
            "",
            "      const overviewNextActions = Array.isArray(executiveData.next_actions)",
            "        ? executiveData.next_actions.map(asText).filter(Boolean)",
            "        : [];",
            "      const nextActions = digestNextActions.length > 0 ? digestNextActions : (overviewNextActions.length > 0 ? overviewNextActions : ['unknown: re-run digest verifier']);",
            "",
            "      let statusLabel = 'unknown';",
            "      if (digestVerdict || executive) {",
            "        const explicitStatus = executive ? asText(executive.status) : '';",
            "        if (explicitStatus) {",
            "          statusLabel = explicitStatus;",
            "        } else if (verdictState === 'unknown') {",
            "          statusLabel = 'blocked';",
            "        } else {",
            "          statusLabel = 'unknown';",
            "        }",
            "      } else {",
            "        statusLabel = 'blocked';",
            "      }",
            "",
            "      const header = document.createElement('p');",
            "      const badge = document.createElement('span');",
            "      badge.className = 'badge ' + badgeClassForStatus(statusLabel);",
            "      badge.textContent = statusLabel || 'unknown';",
            "      header.appendChild(badge);",
            "      mount.appendChild(header);",
            "",
            "      const verdictLine = document.createElement('p');",
            "      verdictLine.textContent = 'verdict_state: ' + (verdictState || 'unknown');",
            "      mount.appendChild(verdictLine);",
            "",
            "      const reasonsTitle = document.createElement('p');",
            "      reasonsTitle.className = 'muted';",
            "      reasonsTitle.textContent = 'reason_codes:';",
            "      mount.appendChild(reasonsTitle);",
            "      const reasonList = document.createElement('ul');",
            "      reasonCodes.forEach(function(code) { addListItem(reasonList, code); });",
            "      mount.appendChild(reasonList);",
            "",
            "      const nextActionsTitle = document.createElement('p');",
            "      nextActionsTitle.className = 'muted';",
            "      nextActionsTitle.textContent = 'next_actions:';",
            "      mount.appendChild(nextActionsTitle);",
            "      const nextActionsList = document.createElement('ul');",
            "      nextActionsList.className = 'next-actions';",
            "      nextActions.forEach(function(action) { addListItem(nextActionsList, action); });",
            "      mount.appendChild(nextActionsList);",
            "",
            "      const trustBoundary = document.createElement('p');",
            "      trustBoundary.className = 'muted';",
            "      trustBoundary.textContent = 'Trust boundary: viewer.html is a convenience aid only and not a verifier; verifier scripts remain authoritative.';",
            "      mount.appendChild(trustBoundary);",
            "    }",
            "",
            "    function renderAttackSurfaceScale(overview) {",
            "      const mount = document.getElementById('attack-surface-scale');",
            "      if (!mount) return;",
            "      clearNode(mount);",
            "",
            "      const overviewObj = (overview && typeof overview === 'object') ? overview : {};",
            "      const cockpitAny = overviewObj.cockpit;",
            "      const cockpit = (cockpitAny && typeof cockpitAny === 'object') ? cockpitAny : {};",
            "      const scaleAny = cockpit.attack_surface_scale;",
            "      const scale = (scaleAny && typeof scaleAny === 'object') ? scaleAny : null;",
            "      const scaleDataAny = scale && scale.data;",
            "      const scaleData = (scaleDataAny && typeof scaleDataAny === 'object') ? scaleDataAny : null;",
            "",
            "      let statusLabel = 'blocked';",
            "      if (scale) {",
            "        const explicitStatus = asText(scale.status);",
            "        statusLabel = explicitStatus || 'unknown';",
            "      }",
            "",
            "      const header = document.createElement('p');",
            "      const badge = document.createElement('span');",
            "      badge.className = 'badge ' + badgeClassForStatus(statusLabel);",
            "      badge.textContent = statusLabel || 'unknown';",
            "      header.appendChild(badge);",
            "      mount.appendChild(header);",
            "",
            "      if (!scaleData) {",
            "        const missing = document.createElement('p');",
            "        missing.className = 'muted';",
            "        missing.textContent = 'missing source: overview.cockpit.attack_surface_scale.data';",
            "        mount.appendChild(missing);",
            "      }",
            "",
            "      const rows = document.createElement('ul');",
            "      ['endpoints', 'surfaces', 'unknowns', 'non_promoted'].forEach(function(label) {",
            "        const rawValue = scaleData ? scaleData[label] : undefined;",
            "        const rawText = asText(rawValue);",
            "        const valueText = rawText ? rawText : 'unknown';",
            "        addListItem(rows, label + ': ' + valueText);",
            "      });",
            "      mount.appendChild(rows);",
            "    }",
            "",
            "    function renderVerificationStatus(overview) {",
            "      const mount = document.getElementById('verification-status');",
            "      if (!mount) return;",
            "      clearNode(mount);",
            "",
            "      const overviewObj = (overview && typeof overview === 'object') ? overview : {};",
            "      const cockpitAny = overviewObj.cockpit;",
            "      const cockpit = (cockpitAny && typeof cockpitAny === 'object') ? cockpitAny : {};",
            "      const verificationAny = cockpit.verification_status;",
            "      const verification = (verificationAny && typeof verificationAny === 'object') ? verificationAny : null;",
            "      const verificationDataAny = verification && verification.data;",
            "      const verificationData = (verificationDataAny && typeof verificationDataAny === 'object') ? verificationDataAny : null;",
            "",
            "      let statusLabel = 'blocked';",
            "      if (verification) {",
            "        const explicitStatus = asText(verification.status);",
            "        statusLabel = explicitStatus || 'unknown';",
            "      }",
            "",
            "      const header = document.createElement('p');",
            "      const badge = document.createElement('span');",
            "      badge.className = 'badge ' + badgeClassForStatus(statusLabel);",
            "      badge.textContent = statusLabel || 'unknown';",
            "      header.appendChild(badge);",
            "      mount.appendChild(header);",
            "",
            "      const disclaimer = document.createElement('p');",
            "      disclaimer.className = 'muted';",
            "      disclaimer.textContent = 'Not a verifier; see verifier scripts for authoritative results.';",
            "      mount.appendChild(disclaimer);",
            "",
            "      if (!verificationData) {",
            "        const missing = document.createElement('p');",
            "        missing.className = 'muted';",
            "        missing.textContent = 'missing source: overview.cockpit.verification_status.data';",
            "        mount.appendChild(missing);",
            "      }",
            "",
            "      const countsTitle = document.createElement('h3');",
            "      countsTitle.textContent = 'Artifact Counts';",
            "      mount.appendChild(countsTitle);",
            "      const countsList = document.createElement('ul');",
            "      mount.appendChild(countsList);",
            "      const countsAny = verificationData ? verificationData.artifact_counts : null;",
            "      const counts = (countsAny && typeof countsAny === 'object') ? countsAny : null;",
            "      ['present', 'missing', 'invalid', 'required_missing', 'required_invalid'].forEach(function(key) {",
            "        const valueAny = counts ? counts[key] : undefined;",
            "        const valueText = (typeof valueAny === 'number') ? String(valueAny) : 'unknown';",
            "        addListItem(countsList, key + ': ' + valueText);",
            "      });",
            "",
            "      const blockersTitle = document.createElement('h3');",
            "      blockersTitle.textContent = 'Blockers';",
            "      mount.appendChild(blockersTitle);",
            "      const blockersList = document.createElement('ul');",
            "      mount.appendChild(blockersList);",
            "      const blockersAny = verificationData ? verificationData.blockers : null;",
            "      const blockers = Array.isArray(blockersAny) ? blockersAny.map(asText).filter(Boolean) : null;",
            "      if (!blockers) {",
            "        addListItem(blockersList, 'unknown (missing overview.cockpit.verification_status.data.blockers)');",
            "      } else if (blockers.length === 0) {",
            "        addListItem(blockersList, '(none)');",
            "      } else {",
            "        blockers.forEach(function(blocker) { addListItem(blockersList, blocker); });",
            "      }",
            "",
            "      const gatesTitle = document.createElement('h3');",
            "      gatesTitle.textContent = 'Gate Applicability/Presence (not verifier pass/fail)';",
            "      mount.appendChild(gatesTitle);",
            "      const gatesAny = verificationData ? verificationData.gates : null;",
            "      const gates = Array.isArray(gatesAny) ? gatesAny : null;",
            "      if (!gates) {",
            "        const unknownGates = document.createElement('p');",
            "        unknownGates.className = 'muted';",
            "        unknownGates.textContent = 'unknown (missing overview.cockpit.verification_status.data.gates)';",
            "        mount.appendChild(unknownGates);",
            "        return;",
            "      }",
            "",
            "      if (gates.length === 0) {",
            "        const empty = document.createElement('p');",
            "        empty.className = 'muted';",
            "        empty.textContent = '(none)';",
            "        mount.appendChild(empty);",
            "        return;",
            "      }",
            "",
            "      const matrix = document.createElement('div');",
            "      matrix.className = 'gate-matrix';",
            "      mount.appendChild(matrix);",
            "",
            "      gates.forEach(function(gateAny) {",
            "        if (!gateAny || typeof gateAny !== 'object') return;",
            "        const gate = gateAny;",
            "        const gateId = asText(gate.id) || '(missing id)';",
            "        const gateStatus = asText(gate.status) || 'unknown';",
            "",
            "        const row = document.createElement('div');",
            "        row.className = 'gate-row';",
            "",
            "        const left = document.createElement('div');",
            "        const idNode = document.createElement('div');",
            "        idNode.className = 'gate-id';",
            "        idNode.textContent = gateId;",
            "        left.appendChild(idNode);",
            "",
            "        const badge = document.createElement('span');",
            "        badge.className = 'badge ' + badgeClassForStatus(gateStatus);",
            "        badge.textContent = gateStatus;",
            "",
            "        row.appendChild(left);",
            "        row.appendChild(badge);",
            "        matrix.appendChild(row);",
            "      });",
            "    }",
            "",
            "    function isSafeRunRelativeRef(ref) {",
            "      if (typeof ref !== 'string') return false;",
            "      const trimmed = ref.trim();",
            "      if (!trimmed) return false;",
            "      if (trimmed.startsWith('/')) return false;",
            "      if (/^[A-Za-z]:[\\/]/.test(trimmed)) return false;",
            "      if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(trimmed)) return false;",
            "      const normalized = trimmed.replace(/\\\\/g, '/');",
            "      const segments = normalized.split('/');",
            "      for (let i = 0; i < segments.length; i += 1) {",
            "        if (segments[i] === '..') return false;",
            "      }",
            "      return true;",
            "    }",
            "",
            "    function copyText(ref) {",
            "      const text = asText(ref);",
            "      if (!text) return Promise.resolve(false);",
            "",
            "      function fallbackCopy() {",
            "        try {",
            "          const ta = document.createElement('textarea');",
            "          ta.value = text;",
            "          ta.setAttribute('readonly', 'readonly');",
            "          ta.style.position = 'fixed';",
            "          ta.style.top = '-1000px';",
            "          ta.style.left = '-1000px';",
            "          document.body.appendChild(ta);",
            "          ta.focus();",
            "          ta.select();",
            "          const ok = document.execCommand('copy');",
            "          document.body.removeChild(ta);",
            "          return ok;",
            "        } catch (_) {",
            "          return false;",
            "        }",
            "      }",
            "",
            "      if (navigator && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {",
            "        return navigator.clipboard.writeText(text).then(function() { return true; }).catch(function() { return fallbackCopy(); });",
            "      }",
            "      return Promise.resolve(fallbackCopy());",
            "    }",
            "",
            "    function hrefForEvidenceRef(ref) {",
            "      const normalized = ref.replace(/\\\\/g, '/');",
            "      if (normalized.startsWith('report/')) {",
            "        return './' + normalized.slice('report/'.length);",
            "      }",
            "      return '../' + normalized;",
            "    }",
            "",
            "    function collectEvidenceNavigatorRefs(overview) {",
            "      const refs = [];",
            "      const seen = new Set();",
            "",
            "      function addRef(ref) {",
            "        if (typeof ref !== 'string') return;",
            "        const cleaned = ref.trim();",
            "        if (!cleaned || seen.has(cleaned)) return;",
            "        seen.add(cleaned);",
            "        refs.push(cleaned);",
            "      }",
            "",
            "      const overviewObj = (overview && typeof overview === 'object') ? overview : {};",
            "      const cockpitAny = overviewObj.cockpit;",
            "      const cockpit = (cockpitAny && typeof cockpitAny === 'object') ? cockpitAny : {};",
            "      const navAny = cockpit.evidence_navigator;",
            "      const nav = (navAny && typeof navAny === 'object') ? navAny : {};",
            "      const navDataAny = nav.data;",
            "      const navData = (navDataAny && typeof navDataAny === 'object') ? navDataAny : {};",
            "      const preferredAny = navData.evidence_links;",
            "      if (Array.isArray(preferredAny) && preferredAny.length > 0) {",
            "        preferredAny.forEach(addRef);",
            "      } else {",
            "        const linksAny = overviewObj.links;",
            "        const links = (linksAny && typeof linksAny === 'object') ? linksAny : {};",
            "        Object.keys(links).sort().forEach(function(key) {",
            "          addRef(links[key]);",
            "        });",
            "",
            "        const artifactsAny = overviewObj.artifacts;",
            "        const artifacts = Array.isArray(artifactsAny) ? artifactsAny : [];",
            "        artifacts.forEach(function(artifactAny) {",
            "          if (!artifactAny || typeof artifactAny !== 'object') return;",
            "          addRef(artifactAny.ref);",
            "        });",
            "      }",
            "",
            "      const canonicalOrder = [",
            "        'report/analyst_digest.md',",
            "        'report/analyst_digest.json',",
            "        'report/analyst_overview.json',",
            "        'report/report.json',",
            "        'report/viewer.html'",
            "      ];",
            "      const canonicalSet = new Set(canonicalOrder);",
            "      const ordered = [];",
            "      canonicalOrder.forEach(function(ref) {",
            "        if (seen.has(ref)) ordered.push(ref);",
            "      });",
            "      refs.filter(function(ref) { return !canonicalSet.has(ref); }).sort().forEach(function(ref) {",
            "        ordered.push(ref);",
            "      });",
            "      return ordered;",
            "    }",
            "",
            "    function renderEvidenceNavigator(overview) {",
            "      const mount = document.getElementById('evidence-navigator');",
            "      if (!mount) return;",
            "      clearNode(mount);",
            "",
            "      const overviewObj = (overview && typeof overview === 'object') ? overview : {};",
            "      const cockpitAny = overviewObj.cockpit;",
            "      const cockpit = (cockpitAny && typeof cockpitAny === 'object') ? cockpitAny : {};",
            "      const navAny = cockpit.evidence_navigator;",
            "      const nav = (navAny && typeof navAny === 'object') ? navAny : null;",
            "",
            "      const statusLine = document.createElement('p');",
            "      const badge = document.createElement('span');",
            "      const statusLabel = nav ? (asText(nav.status) || 'unknown') : 'blocked';",
            "      badge.className = 'badge ' + badgeClassForStatus(statusLabel);",
            "      badge.textContent = statusLabel;",
            "      statusLine.appendChild(badge);",
            "      mount.appendChild(statusLine);",
            "",
            "      const refs = collectEvidenceNavigatorRefs(overviewObj);",
            "      const list = document.createElement('ul');",
            "      mount.appendChild(list);",
            "      if (refs.length === 0) {",
            "        addListItem(list, '(none)');",
            "        return;",
            "      }",
            "",
            "      refs.forEach(function(ref) {",
            "        const li = document.createElement('li');",
            "        const row = document.createElement('div');",
            "        row.className = 'evidence-row';",
            "",
            "        if (isSafeRunRelativeRef(ref)) {",
            "          const link = document.createElement('a');",
            "          link.className = 'evidence-link';",
            "          link.href = hrefForEvidenceRef(ref);",
            "          link.textContent = ref;",
            "          row.appendChild(link);",
            "        } else {",
            "          const unsafe = document.createElement('span');",
            "          unsafe.className = 'unsafe-ref';",
            "          unsafe.textContent = ref;",
            "          row.appendChild(unsafe);",
            "        }",
            "",
            "        const copy = document.createElement('button');",
            "        copy.className = 'copy-ref';",
            "        copy.type = 'button';",
            "        copy.textContent = 'copy';",
            "        copy.addEventListener('click', function() {",
            "          copyText(ref).then(function(ok) {",
            "            copy.textContent = ok ? 'copied' : 'copy failed';",
            "            window.setTimeout(function() { copy.textContent = 'copy'; }, 900);",
            "          });",
            "        });",
            "        row.appendChild(copy);",
            "",
            "        li.appendChild(row);",
            "        list.appendChild(li);",
            "      });",
            "    }",
            "",
            "    function renderOverview(overview) {",
            "      const mount = document.getElementById('overview-gates');",
            "      if (!mount) return;",
            "      clearNode(mount);",
            "",
            "      const grid = document.createElement('div');",
            "      grid.className = 'overview-grid';",
            "      mount.appendChild(grid);",
            "",
            "      const summary = (overview && typeof overview.summary === 'object' && overview.summary) ? overview.summary : {};",
            "      const rc = (summary && typeof summary.report_completeness === 'object' && summary.report_completeness) ? summary.report_completeness : null;",
            "",
            "      const completenessBox = document.createElement('div');",
            "      grid.appendChild(completenessBox);",
            "      const completenessTitle = document.createElement('h3');",
            "      completenessTitle.textContent = 'Report Completeness';",
            "      completenessBox.appendChild(completenessTitle);",
            "",
            "      let completenessState = 'UNKNOWN';",
            "      let completenessBadgeClass = 'unknown';",
            "      if (rc && typeof rc.gate_passed === 'boolean') {",
            "        if (rc.gate_passed) {",
            "          completenessState = 'COMPLETE';",
            "          completenessBadgeClass = 'pass';",
            "        } else {",
            "          completenessState = 'INCOMPLETE';",
            "          completenessBadgeClass = 'fail';",
            "        }",
            "      }",
            "",
            "      const completenessLine = document.createElement('p');",
            "      const b = document.createElement('span');",
            "      b.className = 'badge ' + completenessBadgeClass;",
            "      b.textContent = completenessState;",
            "      completenessLine.appendChild(b);",
            "      completenessBox.appendChild(completenessLine);",
            "",
            "      if (rc) {",
            "        const details = document.createElement('ul');",
            "        addListItem(details, 'gate_passed: ' + (typeof rc.gate_passed === 'boolean' ? String(rc.gate_passed) : 'unknown'));",
            "        addListItem(details, 'status: ' + asText(rc.status));",
            "        const reasonsAny = rc.reasons;",
            "        const reasons = Array.isArray(reasonsAny) ? reasonsAny.map(asText).filter(Boolean) : [];",
            "        completenessBox.appendChild(details);",
            "        if (reasons.length > 0) {",
            "          const reasonsTitle = document.createElement('p');",
            "          reasonsTitle.className = 'muted';",
            "          reasonsTitle.textContent = 'reasons:';",
            "          completenessBox.appendChild(reasonsTitle);",
            "          const reasonsList = document.createElement('ul');",
            "          reasons.forEach(function(r) { addListItem(reasonsList, r); });",
            "          completenessBox.appendChild(reasonsList);",
            "        }",
            "      }",
            "",
            "      const gatesBox = document.createElement('div');",
            "      grid.appendChild(gatesBox);",
            "      const gatesTitle = document.createElement('h3');",
            "      gatesTitle.textContent = 'Gate Matrix';",
            "      gatesBox.appendChild(gatesTitle);",
            "",
            "      const gates = Array.isArray(overview && overview.gates) ? overview.gates : [];",
            "      if (gates.length === 0) {",
            "        const empty = document.createElement('p');",
            "        empty.className = 'muted';",
            "        empty.textContent = '(none)';",
            "        gatesBox.appendChild(empty);",
            "        return;",
            "      }",
            "",
            "      const matrix = document.createElement('div');",
            "      matrix.className = 'gate-matrix';",
            "      gatesBox.appendChild(matrix);",
            "",
            "      gates.forEach(function(itemAny) {",
            "        if (!itemAny || typeof itemAny !== 'object') return;",
            "        const item = itemAny;",
            "        const gateId = asText(item.id);",
            "        const gateStatus = asText(item.status);",
            "        const reasonsAny = item.reasons;",
            "        const reasons = Array.isArray(reasonsAny) ? reasonsAny.map(asText).filter(Boolean) : [];",
            "",
            "        const row = document.createElement('div');",
            "        row.className = 'gate-row';",
            "",
            "        const left = document.createElement('div');",
            "        const idNode = document.createElement('div');",
            "        idNode.className = 'gate-id';",
            "        idNode.textContent = gateId || '(missing id)';",
            "        left.appendChild(idNode);",
            "",
            "        const reasonsList = document.createElement('ul');",
            "        reasonsList.className = 'gate-reasons';",
            "        if (reasons.length === 0) {",
            "          addListItem(reasonsList, '(none)');",
            "        } else {",
            "          reasons.forEach(function(r) { addListItem(reasonsList, r); });",
            "        }",
            "        left.appendChild(reasonsList);",
            "",
            "        const badge = document.createElement('span');",
            "        badge.className = 'badge ' + badgeClassForStatus(gateStatus);",
            "        badge.textContent = gateStatus || 'unknown';",
            "",
            "        row.appendChild(left);",
            "        row.appendChild(badge);",
            "        matrix.appendChild(row);",
            "      });",
            "    }",
            "",
            "    function render(data) {",
            "      const meta = document.getElementById('meta');",
            "      const summary = document.getElementById('summary');",
            "      const risks = document.getElementById('risks');",
            "      const evidence = document.getElementById('evidence');",
            "",
            "      const schema = asText(data && data.schema_version ? data.schema_version : '');",
            "      const source = asText(data && data.source ? data.source : '');",
            "      meta.textContent = 'schema=' + (schema || 'n/a') + (source ? ' | source=' + source : '');",
            "",
            "      const summaryObj = data && typeof data.summary === 'object' && data.summary ? data.summary : {};",
            "      addListItem(summary, 'Top Risk Count: ' + asText(summaryObj.top_risk_count));",
            "      addListItem(summary, 'Candidate Claim Count: ' + asText(summaryObj.candidate_claim_count));",
            "      addListItem(summary, 'Evidence Ref Count: ' + asText(summaryObj.evidence_ref_count));",
            "",
            "      const top = Array.isArray(data && data.top_risk_claims) ? data.top_risk_claims : [];",
            "      if (top.length === 0) {",
            "        const empty = document.createElement('p');",
            "        empty.className = 'muted';",
            "        empty.textContent = '(none)';",
            "        risks.appendChild(empty);",
            "      } else {",
            "        top.forEach(function(item, idx) {",
            "          const box = document.createElement('article');",
            "          box.className = 'risk';",
            "          const h = document.createElement('h3');",
            "          const sev = asText(item && item.severity ? item.severity : '').toUpperCase();",
            "          h.textContent = (idx + 1) + '. [' + (sev || 'N/A') + '] ' + asText(item && item.claim_type ? item.claim_type : '');",
            "          box.appendChild(h);",
            "",
            "          const conf = document.createElement('p');",
            "          conf.className = 'muted';",
            "          conf.textContent = 'Confidence: ' + asText(item && item.confidence !== undefined ? item.confidence : '');",
            "          box.appendChild(conf);",
            "",
            "          const refs = Array.isArray(item && item.evidence_refs) ? item.evidence_refs : [];",
            "          const refsList = document.createElement('ul');",
            "          if (refs.length === 0) {",
            "            addListItem(refsList, '(none)');",
            "          } else {",
            "            refs.forEach(function(ref) { addListItem(refsList, asText(ref)); });",
            "          }",
            "          box.appendChild(refsList);",
            "          risks.appendChild(box);",
            "        });",
            "      }",
            "",
            "      const idxRefs = Array.isArray(data && data.evidence_index) ? data.evidence_index : [];",
            "      if (idxRefs.length === 0) {",
            "        addListItem(evidence, '(none)');",
            "      } else {",
            "        idxRefs.forEach(function(ref) { addListItem(evidence, asText(ref)); });",
            "      }",
            "    }",
            "",
            "    async function loadData() {",
            "      if (window.location && window.location.protocol === 'file:') {",
            "        const warn = document.getElementById('file-warning');",
            "        if (warn) warn.hidden = false;",
            "      }",
            "",
            "      try {",
            "        const res = await fetch('./analyst_report_v2.json', { cache: 'no-store' });",
            "        if (res.ok) return await res.json();",
            "      } catch (_) {}",
            "",
            "      const bootstrapNode = document.getElementById('bootstrap-data');",
            "      if (!bootstrapNode) return {};",
            "      try {",
            "        return JSON.parse(bootstrapNode.textContent || '{}');",
            "      } catch (_) {",
            "        return {};",
            "      }",
            "    }",
            "",
            "    async function loadOverview() {",
            "      try {",
            "        const res = await fetch('./analyst_overview.json', { cache: 'no-store' });",
            "        if (res.ok) {",
            "          try {",
            "            const data = await res.json();",
            "            if (data && typeof data === 'object') return data;",
            "          } catch (_) {}",
            "        }",
            "      } catch (_) {}",
            "",
            "      const bootstrapNode = document.getElementById('bootstrap-overview-data');",
            "      if (!bootstrapNode) return {};",
            "      try {",
            "        const data = JSON.parse(bootstrapNode.textContent || '{}');",
            "        return (data && typeof data === 'object') ? data : {};",
            "      } catch (_) {",
            "        return {};",
            "      }",
            "    }",
            "",
            "    async function loadDigest() {",
            "      try {",
            "        const res = await fetch('./analyst_digest.json', { cache: 'no-store' });",
            "        if (res.ok) {",
            "          try {",
            "            const data = await res.json();",
            "            return (data && typeof data === 'object') ? data : {};",
            "          } catch (_) {}",
            "        }",
            "      } catch (_) {}",
            "",
            "      const bootstrapNode = document.getElementById('bootstrap-digest-data');",
            "      if (!bootstrapNode) return {};",
            "      try {",
            "        const data = JSON.parse(bootstrapNode.textContent || '{}');",
            "        return (data && typeof data === 'object') ? data : {};",
            "      } catch (_) {",
            "        return {};",
            "      }",
            "    }",
            "",
            "    async function loadExploitCandidates() {",
            "      try {",
            "        const res = await fetch('../stages/findings/exploit_candidates.json', { cache: 'no-store' });",
            "        if (res.ok) {",
            "          try {",
            "            const data = await res.json();",
            "            return (data && typeof data === 'object') ? data : {};",
            "          } catch (_) {}",
            "        }",
            "      } catch (_) {}",
            "",
            "      const bootstrapNode = document.getElementById('bootstrap-exploit-candidates-data');",
            "      if (!bootstrapNode) return {};",
            "      try {",
            "        const data = JSON.parse(bootstrapNode.textContent || '{}');",
            "        return (data && typeof data === 'object') ? data : {};",
            "      } catch (_) {",
            "        return {};",
            "      }",
            "    }",
            "",
            "    function renderAllPanes(overview, digest, data, exploitCandidates) {",
            "      const safeOverview = (overview && typeof overview === 'object') ? overview : {};",
            "      const safeDigest = (digest && typeof digest === 'object') ? digest : {};",
            "      const safeData = (data && typeof data === 'object') ? data : {};",
            "      const safeExploitCandidates = (exploitCandidates && typeof exploitCandidates === 'object') ? exploitCandidates : {};",
            "",
            "      window.__aiedge_overview = safeOverview;",
            "      window.__aiedge_digest = safeDigest;",
            "",
            "      function safeRender(fn) {",
            "        try { fn(); } catch (_) {}",
            "      }",
            "",
            "      safeRender(function() { renderOverview(window.__aiedge_overview); });",
            "      safeRender(function() { renderVulnerabilities(window.__aiedge_digest); });",
            "      safeRender(function() { renderStructure(window.__aiedge_overview); });",
            "      safeRender(function() { renderProtocols(window.__aiedge_overview); });",
            "      safeRender(function() { renderExploitCandidateMap(safeExploitCandidates); });",
            "      safeRender(function() { renderEvidenceNextActions(window.__aiedge_digest); });",
            "      safeRender(function() { renderExecutiveVerdict(window.__aiedge_overview, window.__aiedge_digest); });",
            "      safeRender(function() { renderAttackSurfaceScale(window.__aiedge_overview); });",
            "      safeRender(function() { renderVerificationStatus(window.__aiedge_overview); });",
            "      safeRender(function() { renderEvidenceNavigator(window.__aiedge_overview); });",
            "      safeRender(function() { render(safeData); });",
            "    }",
            "",
            "    // legacy: loadData().then(render)",
            "    Promise.all([loadData(), loadOverview(), loadDigest(), loadExploitCandidates()]).then(([data, overview, digest, exploitCandidates]) => {",
            "      renderAllPanes(overview, digest, data, exploitCandidates);",
            "    }).catch(() => {",
            "      // legacy catch fallback: render({});",
            "      renderAllPanes({}, {}, {}, {});",
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
