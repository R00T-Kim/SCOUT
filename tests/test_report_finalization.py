from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from aiedge.run import RunInfo, analyze_run, create_run, run_subset


def _make_run(tmp_path: Path) -> RunInfo:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")
    return create_run(
        str(fw),
        case_id="case-finalization",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )


def _load_report(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def test_analyze_run_marks_report_final_with_terminal_required_stage_statuses(
    tmp_path: Path,
) -> None:
    info = _make_run(tmp_path)
    _ = analyze_run(info, time_budget_s=0, no_llm=True)

    report = _load_report(info.report_json_path)
    completion = cast(dict[str, object], report.get("run_completion"))

    assert completion["is_final"] is True
    assert completion["is_partial"] is False

    required = cast(dict[str, str], completion.get("required_stage_statuses"))
    assert set(required.keys()) == {"tooling", "extraction", "inventory", "findings"}
    assert all(
        status in {"ok", "partial", "failed", "skipped"} for status in required.values()
    )
    assert all(status != "pending" for status in required.values())


def test_run_subset_marks_report_non_final_when_required_stages_not_executed(
    tmp_path: Path,
) -> None:
    info = _make_run(tmp_path)
    _ = run_subset(info, ["tooling"], time_budget_s=5, no_llm=True)

    report = _load_report(info.report_json_path)
    completion = cast(dict[str, object], report.get("run_completion"))

    assert completion["is_final"] is False
    assert completion["is_partial"] is True
    assert isinstance(completion.get("reason"), str) and cast(str, completion["reason"])


def test_analyze_run_emits_ingestion_integrity_chain_and_stage_references(
    tmp_path: Path,
) -> None:
    info = _make_run(tmp_path)
    _ = analyze_run(info, time_budget_s=0, no_llm=True)

    report = _load_report(info.report_json_path)

    integrity = cast(dict[str, object], report.get("ingestion_integrity"))
    source_input = cast(dict[str, object], integrity.get("source_input"))
    analyzed_input = cast(dict[str, object], integrity.get("analyzed_input"))
    overview_link = cast(dict[str, object], integrity.get("overview_link"))
    stage_consumption = cast(dict[str, object], integrity.get("stage_consumption"))

    assert source_input.get("sha256")
    assert source_input.get("size_bytes")
    assert analyzed_input.get("path") == "input/firmware.bin"
    assert isinstance(analyzed_input.get("sha256"), str)
    assert isinstance(analyzed_input.get("size_bytes"), int)
    assert overview_link["input_sha256_matches_analyzed"] is True
    assert overview_link["input_size_bytes_matches_analyzed"] is True

    manifest_paths = cast(
        dict[str, object], stage_consumption.get("required_stage_manifest_paths")
    )
    assert manifest_paths["tooling"] == "stages/tooling/stage.json"
    assert manifest_paths["extraction"] == "stages/extraction/stage.json"
    assert manifest_paths["inventory"] == "stages/inventory/stage.json"
    assert manifest_paths["findings"] is None

    evidence_paths = cast(
        dict[str, object], stage_consumption.get("required_stage_evidence_paths")
    )
    extraction_evidence = cast(list[object], evidence_paths["extraction"])
    assert extraction_evidence
    assert all(isinstance(x, str) and x for x in extraction_evidence)


def test_completeness_gate_marks_missing_required_inputs_and_blocks_clean_conclusion(
    tmp_path: Path,
) -> None:
    info = _make_run(tmp_path)
    _ = (info.run_dir / "input" / "firmware.bin").unlink()

    _ = analyze_run(info, time_budget_s=0, no_llm=True)
    report = _load_report(info.report_json_path)

    completeness = cast(dict[str, object], report.get("report_completeness"))
    assert completeness["gate_passed"] is False
    missing_inputs = cast(
        list[object], completeness.get("missing_required_stage_inputs")
    )
    assert "tooling" in missing_inputs

    reasons = cast(list[object], completeness.get("reasons"))
    assert any(
        isinstance(x, str) and "required stage inputs missing" in x for x in reasons
    )

    findings = cast(list[object], report.get("findings"))
    finding_ids = {
        cast(str, cast(dict[str, object], item).get("id"))
        for item in findings
        if isinstance(item, dict)
    }
    assert "aiedge.findings.no_signals" not in finding_ids
    assert "aiedge.findings.analysis_incomplete" in finding_ids

    completion = cast(dict[str, object], report.get("run_completion"))
    assert completion["conclusion_ready"] is False
