from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from aiedge.stage import StageContext, StageOutcome, SubprocessStage, run_stages


def _ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    logs_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


@dataclass(frozen=True)
class _OkStage:
    name: str = "ok"

    def run(self, ctx: StageContext) -> StageOutcome:
        _ = ctx
        return StageOutcome(status="ok", details={"value": 1})


@dataclass(frozen=True)
class _ExplodeStage:
    name: str = "explode"

    def run(self, ctx: StageContext) -> StageOutcome:
        _ = ctx
        raise RuntimeError("boom")


def test_stage_runner_ok_to_ok(tmp_path: Path) -> None:
    rep = run_stages([_OkStage()], _ctx(tmp_path))
    assert rep.status == "ok"
    assert [r.status for r in rep.stage_results] == ["ok"]
    assert rep.limitations == []


def test_stage_runner_exception_becomes_failed(tmp_path: Path) -> None:
    rep = run_stages([_ExplodeStage()], _ctx(tmp_path))
    assert rep.status == "partial"
    assert rep.stage_results[0].status == "failed"
    assert "boom" in (rep.stage_results[0].error or "")
    assert rep.limitations


def test_stage_runner_timeout_is_failed(tmp_path: Path) -> None:
    stage = SubprocessStage(
        name="sleep",
        argv=[sys.executable, "-c", "import time; time.sleep(2)"],
        timeout_s=0.1,
    )

    rep = run_stages([stage], _ctx(tmp_path))
    assert rep.status == "partial"
    assert rep.stage_results[0].status == "failed"
    assert rep.stage_results[0].timed_out is True
    assert any("timed out" in lim for lim in rep.limitations)


def test_stage_runner_continues_after_failure(tmp_path: Path) -> None:
    rep = run_stages(
        [_OkStage("first"), _ExplodeStage(), _OkStage("last")], _ctx(tmp_path)
    )
    assert [r.stage for r in rep.stage_results] == ["first", "explode", "last"]
    assert [r.status for r in rep.stage_results] == ["ok", "failed", "ok"]
    assert rep.status == "partial"
