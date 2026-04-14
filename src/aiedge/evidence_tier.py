from __future__ import annotations

from enum import Enum
from typing import Any, Iterable


class EvidenceTier(str, Enum):
    SYMBOL_ONLY = "symbol_only"
    STATIC_COLOCATED = "static_colocated"
    STATIC_INTERPROC = "static_interproc"
    PCODE_VERIFIED = "pcode_verified"
    DYNAMIC_VERIFIED = "dynamic_verified"
    UNKNOWN = "unknown"


EVIDENCE_TIERS: tuple[str, ...] = tuple(t.value for t in EvidenceTier)

_METHOD_TIER_MAP: dict[str, EvidenceTier] = {
    "symbol_cooccurrence": EvidenceTier.SYMBOL_ONLY,
    "static_inference": EvidenceTier.SYMBOL_ONLY,
    "static_inference_ba": EvidenceTier.SYMBOL_ONLY,
    "source_sink_graph": EvidenceTier.SYMBOL_ONLY,
    "attack_surface_fallback": EvidenceTier.SYMBOL_ONLY,
    "decompiled_colocated": EvidenceTier.STATIC_COLOCATED,
    "decompiled_interprocedural": EvidenceTier.STATIC_INTERPROC,
    "llm_taint_trace": EvidenceTier.STATIC_INTERPROC,
    "pcode_verified": EvidenceTier.PCODE_VERIFIED,
    "pcode_dataflow": EvidenceTier.PCODE_VERIFIED,
    "pcode_colocated": EvidenceTier.PCODE_VERIFIED,
    "dynamic_validation": EvidenceTier.DYNAMIC_VERIFIED,
    "poc_validation": EvidenceTier.DYNAMIC_VERIFIED,
    "exploit_chain": EvidenceTier.DYNAMIC_VERIFIED,
}

_FINDING_ID_TIER_MAP: dict[str, EvidenceTier] = {
    "aiedge.findings.web.exec_sink_overlap": EvidenceTier.SYMBOL_ONLY,
}


def is_valid_evidence_tier(value: object) -> bool:
    return isinstance(value, str) and value in EVIDENCE_TIERS


def tier_from_method(method: object) -> EvidenceTier | None:
    if not isinstance(method, str):
        return None
    return _METHOD_TIER_MAP.get(method)


def _has_family(value: object, name: str) -> bool:
    if not isinstance(value, list):
        return False
    return any(item == name for item in value if isinstance(item, str))


def _has_dynamic_exploitability_tier(value: object) -> bool:
    return value in {"dynamic_repro", "exploitability_assessed"}


def classify_finding_evidence_tier(finding: dict[str, Any]) -> EvidenceTier:
    if not isinstance(finding, dict):
        return EvidenceTier.UNKNOWN

    existing = finding.get("evidence_tier")
    if is_valid_evidence_tier(existing):
        return EvidenceTier(str(existing))

    if _has_dynamic_exploitability_tier(finding.get("exploitability_tier")):
        return EvidenceTier.DYNAMIC_VERIFIED

    method_tier = tier_from_method(finding.get("method"))
    if method_tier is not None:
        return method_tier

    source_type_tier = tier_from_method(finding.get("source_type"))
    if source_type_tier is not None:
        return source_type_tier

    finding_id = finding.get("id")
    if isinstance(finding_id, str) and finding_id in _FINDING_ID_TIER_MAP:
        return _FINDING_ID_TIER_MAP[finding_id]

    if finding.get("cve_id") or _has_family(finding.get("families"), "cve_match"):
        return EvidenceTier.STATIC_COLOCATED

    return EvidenceTier.UNKNOWN


def annotate_findings_with_evidence_tiers(
    findings: Iterable[dict[str, Any]],
) -> dict[str, int]:
    counts: dict[str, int] = {tier.value: 0 for tier in EvidenceTier}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        tier = classify_finding_evidence_tier(finding)
        finding["evidence_tier"] = tier.value
        counts[tier.value] = counts.get(tier.value, 0) + 1
    return counts


def annotate_findings_with_tier(
    findings: Iterable[dict[str, Any]],
) -> dict[str, int]:
    return annotate_findings_with_evidence_tiers(findings)
