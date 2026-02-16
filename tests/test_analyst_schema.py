from __future__ import annotations


from aiedge.schema import (
    ANALYST_REPORT_SCHEMA_VERSION,
    empty_analyst_report,
    validate_analyst_report,
)


def test_empty_analyst_report_is_schema_valid() -> None:
    rep = empty_analyst_report()
    assert rep["schema_version"] == ANALYST_REPORT_SCHEMA_VERSION
    assert validate_analyst_report(rep) == []


def test_validate_analyst_report_rejects_claim_without_evidence_refs() -> None:
    rep = empty_analyst_report()
    rep["claims"] = [
        {
            "claim_type": "attribution.vendor",
            "value": "Acme",
            "confidence": 0.5,
            "evidence_refs": [],
        }
    ]
    errors = validate_analyst_report(rep)
    assert "claims[0].evidence_refs must be non-empty list" in errors
