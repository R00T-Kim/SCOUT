from __future__ import annotations

from copy import deepcopy
from typing import cast

from aiedge.schema import ANALYST_DIGEST_SCHEMA_VERSION, validate_analyst_digest


_SHA256 = "a" * 64
_SHA256_B = "b" * 64


def _base_digest() -> dict[str, object]:
    return {
        "schema_version": ANALYST_DIGEST_SCHEMA_VERSION,
        "run": {
            "run_id": "2026-02-17_sha256-deadbeef",
            "firmware_sha256": _SHA256,
            "generated_at": "2026-02-17T00:00:00Z",
        },
        "top_risk_summary": {
            "total_findings": 1,
            "severity_counts": {
                "critical": 1,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
        },
        "finding_verdicts": [
            {
                "finding_id": "F-001",
                "verdict": "VERIFIED",
                "reason_codes": [
                    "VERIFIED_ALL_GATES_PASSED",
                    "VERIFIED_REPRO_3_OF_3",
                ],
                "evidence_refs": ["stages/findings/pattern_scan.json"],
                "verifier_refs": ["report/verified_chain.json"],
            }
        ],
        "exploitability_verdict": {
            "state": "VERIFIED",
            "reason_codes": [
                "VERIFIED_ALL_GATES_PASSED",
                "VERIFIED_REPRO_3_OF_3",
            ],
            "aggregation_rule": "worst_state_precedence_v1",
        },
        "evidence_index": [
            {"ref": "stages/findings/pattern_scan.json", "sha256": _SHA256_B}
        ],
        "next_actions": ["Review verified chain evidence."],
    }


def test_validate_analyst_digest_accepts_verified_fixture() -> None:
    digest = _base_digest()
    assert validate_analyst_digest(digest) == []


def test_validate_analyst_digest_accepts_attempted_inconclusive_fixture() -> None:
    digest = _base_digest()
    findings = cast(list[object], digest["finding_verdicts"])
    finding = cast(dict[str, object], findings[0])
    finding["verdict"] = "ATTEMPTED_INCONCLUSIVE"
    finding["reason_codes"] = ["ATTEMPTED_REPRO_INSUFFICIENT"]

    verdict = cast(dict[str, object], digest["exploitability_verdict"])
    verdict["state"] = "ATTEMPTED_INCONCLUSIVE"
    verdict["reason_codes"] = ["ATTEMPTED_REPRO_INSUFFICIENT"]

    assert validate_analyst_digest(digest) == []


def test_validate_analyst_digest_accepts_not_attempted_fixture() -> None:
    digest = _base_digest()
    findings = cast(list[object], digest["finding_verdicts"])
    finding = cast(dict[str, object], findings[0])
    finding["verdict"] = "NOT_ATTEMPTED"
    finding["reason_codes"] = ["NOT_ATTEMPTED_REQUIRED_VERIFIER_MISSING"]
    finding["verifier_refs"] = []

    verdict = cast(dict[str, object], digest["exploitability_verdict"])
    verdict["state"] = "NOT_ATTEMPTED"
    verdict["reason_codes"] = ["NOT_ATTEMPTED_REQUIRED_VERIFIER_MISSING"]

    assert validate_analyst_digest(digest) == []


def test_validate_analyst_digest_rejects_missing_required_field() -> None:
    digest = _base_digest()
    del digest["evidence_index"]
    errors = validate_analyst_digest(digest)
    assert "missing top-level key: evidence_index" in errors


def test_validate_analyst_digest_rejects_absolute_evidence_ref_path() -> None:
    digest = _base_digest()
    findings = cast(list[object], digest["finding_verdicts"])
    finding = cast(dict[str, object], findings[0])
    finding["evidence_refs"] = ["/tmp/evidence.json"]

    errors = validate_analyst_digest(digest)
    assert "finding_verdicts[0].evidence_refs[0] must be run-relative path" in errors


def test_validate_analyst_digest_applies_worst_state_precedence() -> None:
    digest = _base_digest()
    findings = cast(list[object], digest["finding_verdicts"])
    second = deepcopy(cast(dict[str, object], findings[0]))
    second["finding_id"] = "F-002"
    second["verdict"] = "ATTEMPTED_INCONCLUSIVE"
    second["reason_codes"] = ["ATTEMPTED_VERIFIER_FAILED"]
    findings.append(second)
    top_risk_summary = cast(dict[str, object], digest["top_risk_summary"])
    top_risk_summary["total_findings"] = 2

    verdict = cast(dict[str, object], digest["exploitability_verdict"])
    verdict["state"] = "ATTEMPTED_INCONCLUSIVE"
    verdict["reason_codes"] = ["ATTEMPTED_VERIFIER_FAILED"]

    assert validate_analyst_digest(digest) == []
