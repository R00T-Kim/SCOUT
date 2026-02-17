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
        if not isinstance(path_any, str) or not _is_run_relative_path(path_any):
            continue
        ref = path_any.replace("\\", "/")
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
            "    loadData().then(render).catch(function() { render({}); });",
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
    if not isinstance(path, str) or not path:
        return False
    if path.startswith("/"):
        return False
    if re.match(r"^[A-Za-z]:\\", path):
        return False
    return True


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
