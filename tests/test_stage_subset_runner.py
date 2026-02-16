from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aiedge.run import RunInfo, create_run, run_subset


def _make_run(tmp_path: Path) -> RunInfo:
    firmware = tmp_path / "firmware.bin"
    _ = firmware.write_bytes(b"fake firmware for subset runner")
    return create_run(
        str(firmware),
        case_id="case-subset",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )


def test_run_subset_runs_selected_stages_only(tmp_path: Path) -> None:
    run_info = _make_run(tmp_path)
    initial_report = cast(
        dict[str, object],
        json.loads(run_info.report_json_path.read_text(encoding="utf-8")),
    )

    rep = run_subset(run_info, ["tooling", "structure"], time_budget_s=30, no_llm=True)

    assert [r.stage for r in rep.stage_results] == ["tooling", "structure"]
    assert (run_info.run_dir / "stages" / "tooling").is_dir()
    assert (run_info.run_dir / "stages" / "structure").is_dir()
    tooling_manifest_path = run_info.run_dir / "stages" / "tooling" / "stage.json"
    tooling_attempt_manifest_path = (
        run_info.run_dir
        / "stages"
        / "tooling"
        / "attempts"
        / "attempt-1"
        / "stage.json"
    )
    assert tooling_manifest_path.is_file()
    assert tooling_attempt_manifest_path.is_file()

    tooling_manifest = cast(
        dict[str, object],
        json.loads(tooling_manifest_path.read_text(encoding="utf-8")),
    )
    assert str(tooling_manifest.get("contract_version", "")).startswith("1")
    assert tooling_manifest.get("stage_name") == "tooling"
    assert tooling_manifest.get("attempt") == 1
    assert tooling_manifest.get("status") == rep.stage_results[0].status

    stage_key = tooling_manifest.get("stage_key")
    assert isinstance(stage_key, str)
    assert len(stage_key) == 64
    assert all(ch in "0123456789abcdef" for ch in stage_key)

    inputs = cast(list[object], tooling_manifest.get("inputs"))
    assert inputs
    first_input = cast(dict[str, object], inputs[0])
    input_path = cast(str, first_input["path"])
    assert not input_path.startswith("/")
    assert cast(str, first_input["sha256"])

    artifacts = cast(list[object], tooling_manifest.get("artifacts"))
    assert artifacts
    first_artifact = cast(dict[str, object], artifacts[0])
    artifact_path = cast(str, first_artifact["path"])
    assert not artifact_path.startswith("/")

    assert not (run_info.run_dir / "stages" / "inventory").exists()
    assert not (run_info.run_dir / "stages" / "emulation").exists()

    report = cast(
        dict[str, object],
        json.loads(run_info.report_json_path.read_text(encoding="utf-8")),
    )
    assert "tooling" in report
    assert "structure" in report
    assert report.get("inventory") == initial_report.get("inventory")
    assert report.get("emulation") == initial_report.get("emulation")


def test_run_subset_rejects_unknown_stage_name(tmp_path: Path) -> None:
    info = _make_run(tmp_path)
    with pytest.raises(ValueError, match="Unknown stage 'does_not_exist'") as exc:
        _ = run_subset(info, ["tooling", "does_not_exist"], no_llm=True)
    assert "Valid stage names:" in str(exc.value)


def test_stage_manifest_attempt_history_is_append_only(tmp_path: Path) -> None:
    info = _make_run(tmp_path)

    _ = run_subset(info, ["tooling"], time_budget_s=30, no_llm=True)
    _ = run_subset(info, ["tooling"], time_budget_s=30, no_llm=True)

    stage_dir = info.run_dir / "stages" / "tooling"
    assert (stage_dir / "attempts" / "attempt-1" / "stage.json").is_file()
    assert (stage_dir / "attempts" / "attempt-2" / "stage.json").is_file()

    latest_manifest = cast(
        dict[str, object],
        json.loads((stage_dir / "stage.json").read_text(encoding="utf-8")),
    )
    assert latest_manifest.get("attempt") == 2


def test_run_subset_rejects_blank_stage_name(tmp_path: Path) -> None:
    info = _make_run(tmp_path)
    with pytest.raises(ValueError, match="non-empty"):
        _ = run_subset(info, ["   "], no_llm=True)
