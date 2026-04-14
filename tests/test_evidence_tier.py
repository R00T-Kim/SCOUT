from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from aiedge import mcp_server
from aiedge.evidence_tier import (
    EvidenceTier,
    annotate_findings_with_tier,
    classify_finding_evidence_tier,
)
from aiedge.findings import run_findings
from aiedge.sarif_export import findings_to_sarif
from aiedge.schema import empty_report, validate_report
from aiedge.stage import StageContext


def _extract_json_payload(content: list[dict[str, str]]) -> Any:
    assert content and content[0]["type"] == "text"
    return json.loads(content[0]["text"])


def _write_findings(run_dir: Path, findings: list[dict[str, Any]]) -> Path:
    findings_dir = run_dir / "stages" / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    findings_path = findings_dir / "findings.json"
    findings_path.write_text(
        json.dumps({"findings": findings}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return findings_path


@pytest.fixture
def fake_run_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    runs_root = tmp_path / "aiedge-runs"
    run_id = "20260414_run_evidence_tier"
    run_dir = runs_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(mcp_server, "_RUNS_DIR", runs_root)
    return run_dir


def test_helper_annotates_expected_tiers() -> None:
    findings: list[dict[str, Any]] = [
        {
            "id": "f-symbol",
            "method": "static_inference",
        },
        {
            "id": "f-pcode",
            "method": "pcode_verified",
        },
        {
            "id": "f-cve",
            "cve_id": "CVE-2026-0001",
        },
        {
            "id": "f-dynamic",
            "exploitability_tier": "dynamic_repro",
        },
    ]
    counts = annotate_findings_with_tier(findings)
    assert findings[0]["evidence_tier"] == EvidenceTier.SYMBOL_ONLY.value
    assert findings[1]["evidence_tier"] == EvidenceTier.PCODE_VERIFIED.value
    assert findings[2]["evidence_tier"] == EvidenceTier.STATIC_COLOCATED.value
    assert findings[3]["evidence_tier"] == EvidenceTier.DYNAMIC_VERIFIED.value
    assert counts[EvidenceTier.SYMBOL_ONLY.value] == 1
    assert counts[EvidenceTier.PCODE_VERIFIED.value] == 1
    assert counts[EvidenceTier.STATIC_COLOCATED.value] == 1
    assert counts[EvidenceTier.DYNAMIC_VERIFIED.value] == 1


def test_classify_unknown_when_no_signal() -> None:
    finding = {"id": "f-unknown", "severity": "info"}
    assert classify_finding_evidence_tier(finding) == EvidenceTier.UNKNOWN


def test_run_findings_payload_includes_tier_counts_and_field(
    scout_stage_ctx: StageContext,
) -> None:
    result = run_findings(scout_stage_ctx)
    assert result.status in {"ok", "partial"}

    payload = json.loads(
        (
            scout_stage_ctx.run_dir / "stages" / "findings" / "findings.json"
        ).read_text(encoding="utf-8")
    )
    assert "tier_counts" in payload
    tier_counts = cast(dict[str, int], payload["tier_counts"])
    assert EvidenceTier.UNKNOWN.value in tier_counts

    findings = cast(list[dict[str, Any]], payload["findings"])
    assert findings
    assert all("evidence_tier" in finding for finding in findings)


def test_sarif_includes_evidence_tier_property(tmp_path: Path) -> None:
    findings = [
        {
            "id": "finding-1",
            "title": "Example finding",
            "severity": "high",
            "confidence": 0.8,
            "disposition": "suspected",
            "evidence_tier": EvidenceTier.STATIC_INTERPROC.value,
            "evidence": [{"path": "stages/findings/findings.json"}],
        }
    ]
    payload = findings_to_sarif(findings, tmp_path)
    props = payload["runs"][0]["results"][0]["properties"]
    assert props["scout_evidence_tier"] == EvidenceTier.STATIC_INTERPROC.value


def test_mcp_list_findings_filters_by_evidence_tier(fake_run_dir: Path) -> None:
    _write_findings(
        fake_run_dir,
        [
            {
                "id": "v1",
                "category": "vulnerability",
                "severity": "high",
                "confidence": 0.8,
                "evidence_tier": "symbol_only",
            },
            {
                "id": "v2",
                "category": "vulnerability",
                "severity": "high",
                "confidence": 0.9,
                "evidence_tier": "pcode_verified",
            },
        ],
    )
    payload = _extract_json_payload(
        mcp_server._tool_list_findings(
            {"run_id": fake_run_dir.name, "evidence_tier": "pcode_verified"}
        )
    )
    assert payload["total"] == 1
    assert payload["filters_applied"]["evidence_tier"] == "pcode_verified"
    assert payload["findings"][0]["id"] == "v2"


def test_mcp_filter_by_category_returns_evidence_tier(fake_run_dir: Path) -> None:
    _write_findings(
        fake_run_dir,
        [
            {
                "id": "v1",
                "category": "vulnerability",
                "severity": "high",
                "confidence": 0.8,
                "evidence_tier": "symbol_only",
            }
        ],
    )
    payload = _extract_json_payload(
        mcp_server._tool_filter_by_category(
            {"run_id": fake_run_dir.name, "category": "vulnerability"}
        )
    )
    assert payload["total"] == 1
    assert payload["findings"][0]["evidence_tier"] == "symbol_only"


def test_mcp_filter_by_evidence_tier_returns_matches(fake_run_dir: Path) -> None:
    _write_findings(
        fake_run_dir,
        [
            {
                "id": "v1",
                "category": "vulnerability",
                "severity": "high",
                "confidence": 0.8,
                "evidence_tier": "symbol_only",
            },
            {
                "id": "v2",
                "category": "vulnerability",
                "severity": "high",
                "confidence": 0.9,
                "evidence_tier": "pcode_verified",
            },
        ],
    )
    payload = _extract_json_payload(
        mcp_server._tool_filter_by_evidence_tier(
            {"run_id": fake_run_dir.name, "evidence_tier": "pcode_verified"}
        )
    )
    assert payload["evidence_tier"] == "pcode_verified"
    assert payload["total"] == 1
    assert payload["findings"][0]["id"] == "v2"


def test_validate_report_rejects_invalid_evidence_tier() -> None:
    report = cast(dict[str, object], empty_report())
    report["findings"] = [
        {
            "id": "aiedge.findings.invalid-evidence-tier",
            "title": "invalid evidence tier",
            "severity": "info",
            "confidence": 0.5,
            "disposition": "suspected",
            "evidence_tier": "bogus",
            "evidence": [{"path": "stages/findings/findings.json"}],
        }
    ]
    errors = validate_report(report)
    assert any("evidence_tier must be one of" in err for err in errors)
