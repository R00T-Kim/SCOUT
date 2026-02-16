from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from aiedge.run import analyze_run, create_run, run_subset
from aiedge.schema import empty_report, validate_report


def _load_report(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def test_e2e_full_run_report_contract_fields_and_invariants(tmp_path: Path) -> None:
    firmware = tmp_path / "tiny.bin"
    _ = firmware.write_bytes(b"TINY-FW-CONTRACT")

    info = create_run(
        str(firmware),
        case_id="case-e2e-contract-full",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _ = analyze_run(info, time_budget_s=1, no_llm=True)

    report = _load_report(info.report_json_path)
    assert validate_report(report) == []

    completion = cast(dict[str, object], report["run_completion"])
    assert completion["is_final"] is True
    assert completion["is_partial"] is False

    required = cast(dict[str, str], completion["required_stage_statuses"])
    assert set(required.keys()) == {"tooling", "extraction", "inventory", "findings"}
    assert all(v in {"ok", "partial", "failed", "skipped"} for v in required.values())
    assert all(v != "pending" for v in required.values())

    integrity = cast(dict[str, object], report["ingestion_integrity"])
    overview_link = cast(dict[str, object], integrity["overview_link"])
    assert overview_link["input_sha256_matches_analyzed"] is True
    assert overview_link["input_size_bytes_matches_analyzed"] is True

    completeness = cast(dict[str, object], report["report_completeness"])
    assert completeness["gate_passed"] is True
    assert completion.get("conclusion_ready") is True

    findings = cast(list[dict[str, object]], report["findings"])
    assert findings
    for finding in findings:
        evidence = cast(list[dict[str, object]], finding["evidence"])
        assert evidence
        for ev in evidence:
            assert isinstance(ev.get("path"), str) and not cast(
                str, ev["path"]
            ).startswith("/")
            if "snippet" in ev:
                assert "snippet_sha256" in ev


def test_e2e_subset_run_is_non_final_and_gate_fails(tmp_path: Path) -> None:
    firmware = tmp_path / "tiny.bin"
    _ = firmware.write_bytes(b"TINY-FW-CONTRACT")

    info = create_run(
        str(firmware),
        case_id="case-e2e-contract-subset",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _ = run_subset(info, ["tooling"], time_budget_s=5, no_llm=True)

    report = _load_report(info.report_json_path)
    assert validate_report(report) == []

    completion = cast(dict[str, object], report["run_completion"])
    assert completion["is_final"] is False
    assert completion["is_partial"] is True

    completeness = cast(dict[str, object], report["report_completeness"])
    assert completeness["gate_passed"] is False
    reasons = cast(list[object], completeness["reasons"])
    assert any(
        isinstance(reason, str) and "required stage pending" in reason
        for reason in reasons
    )


def test_validate_report_enforces_strict_finding_evidence_contract() -> None:
    report = cast(dict[str, object], empty_report())
    report["findings"] = [
        {
            "id": "aiedge.findings.contract.invalid",
            "title": "Invalid finding evidence",
            "severity": "info",
            "confidence": 0.5,
            "disposition": "suspected",
            "evidence": [
                {
                    "path": "stages/findings/findings.json",
                    "snippet": "ascii-snippet",
                    "note": "ok",
                    "extra": "forbidden",
                },
                {
                    "path": "stages/findings/findings.json",
                    "snippet": "non-ascii:\u2603",
                    "snippet_sha256": "deadbeef",
                },
            ],
        }
    ]

    errors = validate_report(report)
    assert any("contains unsupported field: extra" in err for err in errors)
    assert any(
        "snippet_sha256 must be non-empty printable ASCII string when snippet is present"
        in err
        for err in errors
    )
    assert any(
        "snippet must be non-empty printable ASCII string" in err for err in errors
    )
