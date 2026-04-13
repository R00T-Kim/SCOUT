"""Unit tests for stage_executor.execute_single_stage."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from aiedge.stage import StageContext, StageOutcome, StageResult
from aiedge.stage_executor import execute_single_stage

# ---------------------------------------------------------------------------
# Minimal stage implementations
# ---------------------------------------------------------------------------


class _OkStage:
    name = "ok_stage"

    def run(self, ctx: StageContext) -> StageOutcome:
        return StageOutcome(status="ok", details={"k": "v"}, limitations=[])


class _PartialStage:
    name = "partial_stage"

    def run(self, ctx: StageContext) -> StageOutcome:
        return StageOutcome(
            status="partial", details={}, limitations=["something missing"]
        )


class _SkippedStage:
    name = "skipped_stage"

    def run(self, ctx: StageContext) -> StageOutcome:
        return StageOutcome(status="skipped", details={}, limitations=[])


class _CrashStage:
    name = "crash_stage"

    def run(self, ctx: StageContext) -> StageOutcome:
        raise RuntimeError("boom")


class _TimeoutStage:
    name = "timeout_stage"

    def run(self, ctx: StageContext) -> StageOutcome:
        raise subprocess.TimeoutExpired(cmd="fakecmd", timeout=1.0)


# ---------------------------------------------------------------------------
# Progress observer
# ---------------------------------------------------------------------------


class _ProgressRecorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, Any]] = []

    def on_start(self, idx: int, total: int, stage_name: str) -> None:
        self.events.append(("on_start", (idx, total, stage_name)))

    def on_end(self, idx: int, total: int, stage_name: str, res: StageResult) -> None:
        self.events.append(("on_end", (idx, total, stage_name, res.status)))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = tmp_path / "logs"
    report_dir = tmp_path / "report"
    for d in (run_dir, logs_dir, report_dir):
        d.mkdir(parents=True, exist_ok=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_ok_stage_returns_correct_result(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    res = execute_single_stage(_OkStage(), ctx)
    assert res.stage == "ok_stage"
    assert res.status == "ok"
    assert res.details == {"k": "v"}
    assert res.limitations == []
    assert res.error is None
    assert res.timed_out is False
    assert res.duration_s >= 0.0
    assert res.started_at
    assert res.finished_at


def test_partial_stage(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    res = execute_single_stage(_PartialStage(), ctx)
    assert res.stage == "partial_stage"
    assert res.status == "partial"
    assert res.limitations == ["something missing"]
    assert res.error is None
    assert res.timed_out is False


def test_skipped_stage(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    res = execute_single_stage(_SkippedStage(), ctx)
    assert res.status == "skipped"
    assert res.timed_out is False


def test_crash_does_not_propagate(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    res = execute_single_stage(_CrashStage(), ctx)
    assert res.stage == "crash_stage"
    assert res.status == "failed"
    assert res.error is not None
    assert "RuntimeError" in res.error
    assert any("RuntimeError" in lim for lim in res.limitations)
    assert res.timed_out is False


def test_timeout_exception_sets_timed_out(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    res = execute_single_stage(_TimeoutStage(), ctx)
    assert res.stage == "timeout_stage"
    assert res.status == "failed"
    assert res.timed_out is True
    assert res.details.get("timeout") is True


def test_progress_callbacks_called_on_success(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    rec = _ProgressRecorder()
    execute_single_stage(_OkStage(), ctx, idx=2, total=5, on_progress=rec)
    assert ("on_start", (2, 5, "ok_stage")) in rec.events
    assert ("on_end", (2, 5, "ok_stage", "ok")) in rec.events


def test_progress_callbacks_called_on_failure(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    rec = _ProgressRecorder()
    execute_single_stage(_CrashStage(), ctx, idx=0, total=1, on_progress=rec)
    assert ("on_start", (0, 1, "crash_stage")) in rec.events
    assert ("on_end", (0, 1, "crash_stage", "failed")) in rec.events


def test_no_progress_observer_ok(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    # must not raise even without on_progress
    res = execute_single_stage(_OkStage(), ctx)
    assert res.status == "ok"


def test_progress_observer_without_on_start(tmp_path: Path) -> None:
    """Observer missing on_start/on_end attributes must not crash."""

    class _Bare:
        pass

    ctx = _make_ctx(tmp_path)
    res = execute_single_stage(_OkStage(), ctx, on_progress=_Bare())
    assert res.status == "ok"


def test_default_idx_total_values(tmp_path: Path) -> None:
    """Default idx=0, total=1 are passed to on_progress when not specified."""
    ctx = _make_ctx(tmp_path)
    rec = _ProgressRecorder()
    execute_single_stage(_OkStage(), ctx, on_progress=rec)
    assert ("on_start", (0, 1, "ok_stage")) in rec.events
    assert ("on_end", (0, 1, "ok_stage", "ok")) in rec.events
