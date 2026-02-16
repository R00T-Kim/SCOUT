from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aiedge.run import analyze_run, create_run
from aiedge.policy import AIEdgePolicyViolation
from aiedge.schema import REPORT_SCHEMA_VERSION, empty_report, validate_report


def test_empty_report_has_stable_top_level_keys() -> None:
    report = empty_report()

    required_keys = {
        "schema_version",
        "overview",
        "extraction",
        "inventory",
        "findings",
        "limitations",
        "llm",
    }

    assert required_keys.issubset(report.keys())


def test_empty_report_required_types_and_json_serializable() -> None:
    report = empty_report()

    assert report["schema_version"] == REPORT_SCHEMA_VERSION
    assert isinstance(report["schema_version"], str)

    assert isinstance(report["overview"], dict)
    assert isinstance(report["extraction"], dict)
    assert isinstance(report["inventory"], dict)
    assert isinstance(report["llm"], dict)

    assert isinstance(report["findings"], list)
    assert isinstance(report["limitations"], list)
    assert isinstance(report["ingestion_integrity"], dict)
    assert isinstance(report["report_completeness"], dict)

    _ = json.dumps(report)


def test_empty_report_is_schema_valid() -> None:
    assert validate_report(empty_report()) == []


def test_create_run_report_json_is_schema_valid(tmp_path: Path) -> None:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")

    info = create_run(
        str(fw),
        case_id="case-1",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    rep = cast(
        dict[str, object],
        json.loads(info.report_json_path.read_text(encoding="utf-8")),
    )
    assert validate_report(rep) == []


def test_create_run_manifest_includes_default_network_policy(tmp_path: Path) -> None:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")

    info = create_run(
        str(fw),
        case_id="case-1",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    manifest = cast(
        dict[str, object],
        json.loads(info.manifest_path.read_text(encoding="utf-8")),
    )
    policy = cast(dict[str, object], manifest["network_policy"])

    assert policy["internal_comms"] == {"allowed": True}
    assert policy["internet_egress"] == {
        "mode": "allowlist",
        "allowlist": ["pypi.org", "files.pythonhosted.org", "github.com"],
    }
    assert policy["override_open_egress"] is False
    assert policy["warnings"] == []


def test_create_run_manifest_includes_open_egress_override_warning(
    tmp_path: Path,
) -> None:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")

    info = create_run(
        str(fw),
        case_id="case-1",
        ack_authorization=True,
        open_egress=True,
        egress_allowlist=["example.com"],
        runs_root=tmp_path / "runs",
    )

    manifest = cast(
        dict[str, object],
        json.loads(info.manifest_path.read_text(encoding="utf-8")),
    )
    policy = cast(dict[str, object], manifest["network_policy"])

    assert policy["internet_egress"] == {
        "mode": "open",
        "allowlist": ["example.com"],
    }
    assert policy["override_open_egress"] is True
    assert policy["warnings"] == ["open_egress enabled"]
    assert manifest["warnings"] == ["open_egress enabled"]


def test_create_run_rejects_input_inside_runs_root(tmp_path: Path) -> None:
    runs_root = tmp_path / "runs"
    fw = runs_root / "2026-02-13_0000_sha256-deadbeef" / "input" / "firmware.bin"
    _ = fw.parent.mkdir(parents=True)
    _ = fw.write_bytes(b"firmware")

    with pytest.raises(AIEdgePolicyViolation):
        _ = create_run(
            str(fw),
            case_id="case-guardrail",
            ack_authorization=True,
            runs_root=runs_root,
        )


def test_analyze_run_budget_exhausted_report_is_schema_valid(tmp_path: Path) -> None:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")

    info = create_run(
        str(fw),
        case_id="case-1",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    _ = analyze_run(info, time_budget_s=0, no_llm=True)
    rep = cast(
        dict[str, object],
        json.loads(info.report_json_path.read_text(encoding="utf-8")),
    )
    assert validate_report(rep) == []

    assert isinstance(rep.get("extraction"), dict)
    assert isinstance(rep.get("inventory"), dict)
    assert isinstance(rep.get("findings"), list)

    findings = rep.get("findings")
    assert isinstance(findings, list)
    for f_any in cast(list[object], findings):
        assert isinstance(f_any, dict)
        f = cast(dict[str, object], f_any)
        assert f.get("severity")
        assert f.get("disposition") in ("confirmed", "suspected")
        conf = f.get("confidence")
        assert isinstance(conf, (int, float))
        assert 0.0 <= float(conf) <= 1.0
        ev = f.get("evidence")
        assert isinstance(ev, list) and ev


def test_analyze_run_without_binwalk_is_schema_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", "")

    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")

    info = create_run(
        str(fw),
        case_id="case-1",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    _ = analyze_run(info, time_budget_s=5, no_llm=True)
    rep = cast(
        dict[str, object],
        json.loads(info.report_json_path.read_text(encoding="utf-8")),
    )
    assert validate_report(rep) == []


def test_validate_report_rejects_invalid_completeness_shape() -> None:
    report = cast(dict[str, object], empty_report())
    report["report_completeness"] = {"gate_passed": "yes"}
    errors = validate_report(report)
    assert "report_completeness.gate_passed must be bool" in errors


def test_validate_report_rejects_invalid_tier_and_missing_t2_evidence() -> None:
    report = cast(dict[str, object], empty_report())
    report["findings"] = [
        {
            "id": "aiedge.findings.invalid-tier",
            "title": "invalid tier",
            "severity": "info",
            "confidence": 0.5,
            "disposition": "suspected",
            "exploitability_tier": "invalid-tier",
            "evidence": [{"path": "stages/findings/findings.json"}],
        },
        {
            "id": "aiedge.findings.high-without-t2",
            "title": "high severity requires t2",
            "severity": "high",
            "confidence": 0.9,
            "disposition": "confirmed",
            "exploitability_tier": "strong_static",
            "evidence": [{"path": "stages/findings/findings.json"}],
        },
        {
            "id": "aiedge.findings.t2-without-exploit-evidence",
            "title": "tier2 missing exploit evidence",
            "severity": "medium",
            "confidence": 0.8,
            "disposition": "suspected",
            "exploitability_tier": "dynamic_repro",
            "evidence": [{"path": "stages/findings/findings.json"}],
        },
    ]

    errors = validate_report(report)
    assert any(err.startswith("TIER_INVALID_VALUE:") for err in errors)
    assert any(err.startswith("TIER_HIGH_SEVERITY_REQUIRES_T2:") for err in errors)
    assert any(err.startswith("TIER_EVIDENCE_MISSING:") for err in errors)


def test_validate_report_accepts_t2_with_exploit_stage_evidence_dict_path() -> None:
    report = cast(dict[str, object], empty_report())
    report["findings"] = [
        {
            "id": "aiedge.findings.t2-with-exploit-evidence",
            "title": "tier2 has exploit-stage evidence",
            "severity": "medium",
            "confidence": 0.8,
            "disposition": "suspected",
            "exploitability_tier": "dynamic_repro",
            "evidence": [
                {
                    "path": "stages/poc_validation/poc_validation.json",
                    "note": "reproduction artifact",
                }
            ],
        }
    ]

    errors = validate_report(report)
    assert not any(err.startswith("TIER_EVIDENCE_MISSING:") for err in errors)
    assert errors == []
