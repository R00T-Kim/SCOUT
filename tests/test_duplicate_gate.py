from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aiedge.duplicate_gate import DUPLICATE_GATE_ANALYSIS_FAIL_OPEN
from aiedge.duplicate_gate import apply_duplicate_gate
from aiedge.fingerprinting import claim_fingerprint_sha256
from aiedge.run import RunInfo, analyze_run, create_run
from aiedge.schema import JsonValue


def _make_firmware(path: Path, payload: bytes = b"dup-gate-fw") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_bytes(payload)
    return path


def _make_run(tmp_path: Path, *, firmware_payload: bytes = b"dup-gate-fw") -> RunInfo:
    fw = _make_firmware(tmp_path / "fw.bin", payload=firmware_payload)
    return create_run(
        str(fw),
        case_id="case-duplicate-gate",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )


def _load_report(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def test_analyze_run_suppresses_exact_duplicates_across_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry_path = (
        tmp_path / ".sisyphus" / "state" / "aiedge" / "duplicate_registry.json"
    )
    monkeypatch.setenv("AIEDGE_DUPLICATE_REGISTRY_PATH", str(registry_path))

    info_first = _make_run(tmp_path / "first")
    _ = analyze_run(info_first, time_budget_s=0, no_llm=True)
    report_first = _load_report(info_first.report_json_path)
    findings_first = cast(list[object], report_first.get("findings", []))
    assert findings_first

    info_second = _make_run(tmp_path / "second")
    _ = analyze_run(info_second, time_budget_s=0, no_llm=True)
    report_second = _load_report(info_second.report_json_path)

    gate = cast(dict[str, object], report_second.get("duplicate_gate", {}))
    exact_duplicates = cast(int, gate.get("exact_duplicate_count", 0))
    findings_second = cast(list[object], report_second.get("findings", []))

    assert exact_duplicates >= 1
    assert len(findings_second) + exact_duplicates == len(findings_first)

    artifact_path = info_second.run_dir / "report" / "duplicate_gate.json"
    artifact = cast(
        dict[str, object], json.loads(artifact_path.read_text(encoding="utf-8"))
    )
    suppressed = cast(list[object], artifact.get("suppressed", []))
    reopened = cast(list[object], artifact.get("reopened", []))
    assert len(suppressed) == exact_duplicates
    assert reopened == []


def test_analyze_run_fails_explicitly_on_corrupt_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry_path = (
        tmp_path / ".sisyphus" / "state" / "aiedge" / "duplicate_registry.json"
    )
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    _ = registry_path.write_text("{not-json", encoding="utf-8")
    monkeypatch.setenv("AIEDGE_DUPLICATE_REGISTRY_PATH", str(registry_path))

    info = _make_run(tmp_path / "corrupt")
    with pytest.raises(ValueError, match="DUPLICATE_REGISTRY_LOAD_ERROR"):
        _ = analyze_run(info, time_budget_s=0, no_llm=True)


def test_analyze_run_duplicate_gate_analysis_fail_open_records_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry_path = (
        tmp_path / ".sisyphus" / "state" / "aiedge" / "duplicate_registry.json"
    )
    monkeypatch.setenv("AIEDGE_DUPLICATE_REGISTRY_PATH", str(registry_path))

    from aiedge import duplicate_gate as duplicate_gate_mod

    original = cast(object, getattr(duplicate_gate_mod, "claim_fingerprint_sha256"))

    def _boom_once(claim: object, *, fingerprint_version: str = "claim-fp-v1") -> str:
        _ = fingerprint_version
        raise RuntimeError(f"boom for {type(claim).__name__}")

    monkeypatch.setattr(duplicate_gate_mod, "claim_fingerprint_sha256", _boom_once)
    info = _make_run(tmp_path / "fail-open")
    _ = analyze_run(info, time_budget_s=0, no_llm=True)
    monkeypatch.setattr(duplicate_gate_mod, "claim_fingerprint_sha256", original)

    report = _load_report(info.report_json_path)
    gate = cast(dict[str, object], report.get("duplicate_gate", {}))
    assert gate.get("warning_token") == DUPLICATE_GATE_ANALYSIS_FAIL_OPEN

    warning_reasons = cast(list[object], gate.get("warning_reasons", []))
    assert warning_reasons
    assert any(
        isinstance(reason, str) and DUPLICATE_GATE_ANALYSIS_FAIL_OPEN in reason
        for reason in warning_reasons
    )

    artifact = cast(
        dict[str, object],
        json.loads(
            (info.run_dir / "report" / "duplicate_gate.json").read_text("utf-8")
        ),
    )
    artifact_warnings = cast(list[object], artifact.get("warnings", []))
    assert artifact_warnings


def test_duplicate_gate_auto_reopens_on_evidence_hash_delta(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run-auto-reopen"
    run_dir.mkdir(parents=True, exist_ok=True)
    finding_base: dict[str, JsonValue] = {
        "id": "aiedge.findings.dup-test",
        "title": "Duplicate claim",
        "severity": "medium",
        "confidence": 0.5,
        "description": "deterministic duplicate gate test",
        "evidence": [{"path": "stages/findings/findings.json"}],
        "evidence_refs": [{"artifact_sha256": "a" * 64}],
    }
    fp_before = claim_fingerprint_sha256(finding_base)

    first = apply_duplicate_gate(
        findings=[finding_base],
        run_id="run-1",
        run_dir=run_dir,
        seen_at="2026-02-15T00:00:00Z",
    )
    assert len(first.findings) == 1

    finding_with_evidence_delta = dict(finding_base)
    finding_with_evidence_delta["evidence_refs"] = [{"artifact_sha256": "b" * 64}]
    fp_after = claim_fingerprint_sha256(finding_with_evidence_delta)
    assert fp_before == fp_after

    second = apply_duplicate_gate(
        findings=[finding_with_evidence_delta],
        run_id="run-2",
        run_dir=run_dir,
        seen_at="2026-02-15T00:00:00Z",
    )
    assert len(second.findings) == 1
    assert cast(int, second.report_section.get("exact_duplicate_count", 0)) == 0
    assert cast(int, second.report_section.get("context_reopen_count", 0)) == 1

    artifact = cast(
        dict[str, object],
        json.loads((run_dir / "report" / "duplicate_gate.json").read_text("utf-8")),
    )
    suppressed = cast(list[object], artifact.get("suppressed", []))
    reopened = cast(list[object], artifact.get("reopened", []))
    novelty = cast(list[object], artifact.get("novelty", []))
    assert suppressed == []
    assert len(reopened) == 1
    reopened_item = cast(dict[str, object], reopened[0])
    reason_codes = cast(list[object], reopened_item.get("trigger_reason_codes", []))
    assert "evidence_hash_delta" in reason_codes
    assert "novelty_threshold_met" in reason_codes
    assert cast(float, reopened_item.get("novelty_after", 0.0)) >= 0.70
    assert novelty
    top_novelty = cast(dict[str, object], novelty[0])
    assert top_novelty.get("status") == "reopened"


def test_duplicate_gate_force_retriage_reopens_without_evidence_delta(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run-force-retriage"
    run_dir.mkdir(parents=True, exist_ok=True)
    finding: dict[str, JsonValue] = {
        "id": "aiedge.findings.force-retriage",
        "title": "Force retriage duplicate",
        "severity": "low",
        "confidence": 0.4,
        "description": "manual override path test",
        "evidence": [{"path": "stages/findings/findings.json"}],
        "evidence_refs": [{"artifact_sha256": "c" * 64}],
    }

    _ = apply_duplicate_gate(
        findings=[finding],
        run_id="run-1",
        run_dir=run_dir,
        seen_at="2026-02-15T00:00:00Z",
    )

    second = apply_duplicate_gate(
        findings=[finding],
        run_id="run-2",
        run_dir=run_dir,
        seen_at="2026-02-15T00:00:00Z",
        force_retriage=True,
    )
    assert len(second.findings) == 1
    assert cast(int, second.report_section.get("exact_duplicate_count", 0)) == 0
    assert cast(int, second.report_section.get("context_reopen_count", 0)) == 1

    artifact = cast(
        dict[str, object],
        json.loads((run_dir / "report" / "duplicate_gate.json").read_text("utf-8")),
    )
    suppressed = cast(list[object], artifact.get("suppressed", []))
    reopened = cast(list[object], artifact.get("reopened", []))
    assert suppressed == []
    assert len(reopened) == 1
    reopened_item = cast(dict[str, object], reopened[0])
    reason_codes = cast(list[object], reopened_item.get("trigger_reason_codes", []))
    assert "manual_override" in reason_codes
    assert "force_retriage_override" in reason_codes
