import json
from pathlib import Path

import pytest

import aiedge.fuzz_campaign as fuzz_campaign
import aiedge.fuzz_target as fuzz_target
from aiedge.fuzz_campaign import (
    FuzzCampaignStage,
    _append_campaign_execution_limitations,
    _campaign_completed,
)
from aiedge.stage import StageContext


def test_campaign_with_no_executions_records_partial_limitations() -> None:
    limitations: list[str] = []

    _append_campaign_execution_limitations(
        limitations,
        docker_rc=1,
        docker_err="[-] PROGRAM ABORT : Fork server handshake failed",
        stats={"execs_done": 0},
    )

    assert "docker_exit_1" in limitations
    assert "forkserver_handshake_failed" in limitations
    assert "no_fuzzer_executions" in limitations


def test_campaign_with_arch_mismatch_records_target_arch_limitation() -> None:
    limitations: list[str] = []

    _append_campaign_execution_limitations(
        limitations,
        docker_rc=1,
        docker_err="afl-qemu-trace: target: Invalid ELF image for this architecture",
        stats={"execs_done": 0},
    )

    assert "target_arch_mismatch" in limitations
    assert "no_fuzzer_executions" in limitations


def test_campaign_completed_requires_fuzzer_executions() -> None:
    assert not _campaign_completed({"skipped": False, "stats": {"execs_done": 0}})
    assert not _campaign_completed({"skipped": True, "stats": {"execs_done": 10}})
    assert _campaign_completed({"skipped": False, "stats": {"execs_done": 10}})


def test_stage_marks_attempt_with_no_execs_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "run"
    ctx = StageContext(
        run_dir=run_dir,
        logs_dir=run_dir / "logs",
        report_dir=run_dir / "report",
    )

    monkeypatch.setattr(fuzz_campaign, "_docker_available", lambda: True)
    monkeypatch.setattr(
        fuzz_target,
        "select_fuzz_targets",
        lambda _run_dir, max_targets=None: [{"path": "bin/busybox"}],
    )
    monkeypatch.setattr(
        fuzz_campaign,
        "_run_campaign",
        lambda *args, **kwargs: {
            "target": "bin/busybox",
            "basename": "busybox",
            "skipped": False,
            "stats": {"execs_done": 0},
            "crashes_dir": None,
            "limitations": ["no_fuzzer_executions"],
        },
    )

    stage = FuzzCampaignStage(
        run_dir=run_dir,
        case_id=None,
        remaining_budget_s=lambda: 120.0,
        no_llm=True,
    )

    outcome = stage.run(ctx)

    assert outcome.status == "partial"
    assert outcome.details["targets_attempted"] == 1
    assert outcome.details["targets_completed"] == 0
    assert "no_fuzzer_executions" in outcome.limitations

    results = json.loads(
        (run_dir / "stages" / "fuzzing" / "campaign_results.json").read_text(
            encoding="utf-8"
        )
    )
    assert results["targets_attempted"] == 1
    assert results["targets_completed"] == 0
    assert results["limitations"] == ["no_fuzzer_executions"]
