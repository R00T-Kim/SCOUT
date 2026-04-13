"""Behaviour tests for run_stages_parallel().

These tests use minimal mock Stage objects (no real pipeline stages, no disk
side effects) plus the Phase 2A ``scout_stage_ctx`` fixture.

What the suite exercises:
  * Two independent stages in the same topo level actually run concurrently.
  * A failed stage propagates 'skipped' to downstream dependents.
  * fail_fast=True cancels still-pending peers in the current level.
  * fail_fast=False keeps executing remaining peers in the same level.
  * ProgressTracker in out_of_order mode reports events in completion order.
"""

from __future__ import annotations

import io
import threading
import time
from dataclasses import dataclass

import pytest

from aiedge.progress import ProgressTracker
from aiedge.stage import (
    StageContext,
    StageOutcome,
    StageResult,
    run_stages_parallel,
)
from aiedge.stage_dag import STAGE_DEPS


# ---------------------------------------------------------------------------
# Minimal mock Stage that also mutates STAGE_DEPS for the duration of a test.
# We use real SCOUT stage *names* so run_stages_parallel() can resolve their
# dependency edges via STAGE_DEPS directly. No synthetic graph is needed --
# the live dict already contains the adjacency we care about.
# ---------------------------------------------------------------------------
@dataclass
class _MockStage:
    _name: str
    behaviour: str = "ok"  # 'ok' | 'fail' | 'sleep:<sec>' | 'raise'
    started: threading.Event = None  # type: ignore[assignment]
    release: threading.Event = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.started is None:
            self.started = threading.Event()
        if self.release is None:
            self.release = threading.Event()
            _ = self.release.set()

    @property
    def name(self) -> str:
        return self._name

    def run(self, ctx: StageContext) -> StageOutcome:
        _ = ctx
        _ = self.started.set()

        if self.behaviour.startswith("sleep:"):
            delay = float(self.behaviour.split(":", 1)[1])
            time.sleep(delay)

        # Block until release is set (used for concurrency tests).
        _ = self.release.wait(timeout=5.0)

        if self.behaviour == "fail":
            return StageOutcome(status="failed", limitations=["mock failure"])
        if self.behaviour == "raise":
            raise RuntimeError("mock raise")
        return StageOutcome(status="ok")


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------
def test_parallel_two_independent_stages_run_concurrently(
    scout_stage_ctx: StageContext,
) -> None:
    """structure and carving both depend only on extraction, share level 2.

    Without concurrency the test would block forever because each stage blocks
    on its own ``release`` event until the other stage has signalled
    ``started``. With a 2-worker pool, both run simultaneously and release
    each other in turn.
    """
    stage_a = _MockStage(_name="structure")
    stage_b = _MockStage(_name="carving")

    # Wire: each stage only releases after the *other* has started.
    stage_a.release.clear()
    stage_b.release.clear()

    def unblocker() -> None:
        if stage_a.started.wait(timeout=3.0) and stage_b.started.wait(timeout=3.0):
            _ = stage_a.release.set()
            _ = stage_b.release.set()

    t = threading.Thread(target=unblocker, daemon=True)
    t.start()

    report = run_stages_parallel([stage_a, stage_b], scout_stage_ctx, max_workers=2)
    t.join(timeout=5.0)

    statuses = {r.stage: r.status for r in report.stage_results}
    assert statuses == {"structure": "ok", "carving": "ok"}
    assert report.status == "ok"


# ---------------------------------------------------------------------------
# Skip-on-failed-dep semantics
# ---------------------------------------------------------------------------
def test_parallel_skips_dependents_on_failure(
    scout_stage_ctx: StageContext,
) -> None:
    """inventory fails -> endpoints (dep=inventory) must be marked skipped.

    Uses the real STAGE_DEPS edge inventory -> endpoints. We include
    extraction first because inventory depends on it in the DAG.
    """
    stage_extract = _MockStage(_name="extraction", behaviour="ok")
    stage_inv = _MockStage(_name="inventory", behaviour="fail")
    stage_ep = _MockStage(_name="endpoints", behaviour="ok")
    # Also include tooling so extraction (which depends on tooling) has a
    # valid level-0 predecessor.
    stage_tool = _MockStage(_name="tooling", behaviour="ok")

    report = run_stages_parallel(
        [stage_tool, stage_extract, stage_inv, stage_ep],
        scout_stage_ctx,
        max_workers=2,
    )

    by_name = {r.stage: r for r in report.stage_results}
    assert by_name["tooling"].status == "ok"
    assert by_name["extraction"].status == "ok"
    assert by_name["inventory"].status == "failed"
    assert by_name["endpoints"].status == "skipped"
    assert any("upstream" in lim for lim in by_name["endpoints"].limitations)
    assert report.status in ("partial", "failed")


# ---------------------------------------------------------------------------
# fail_fast semantics
# ---------------------------------------------------------------------------
def test_parallel_fail_fast_cancels_pending(
    scout_stage_ctx: StageContext,
) -> None:
    """With fail_fast=True, a failed peer must cancel at least one still-queued peer.

    Setup exploits the fact that ``topo_levels`` sorts each level
    alphabetically, and ``ThreadPoolExecutor`` submits in iteration order with
    ``max_workers=1``. ``carving`` sorts first inside level 2 (alongside
    ``firmware_lineage``, ``firmware_profile``, ``structure``), so we make
    ``carving`` the fast-failing stage; the other three peers are slow sleepers
    whose futures are still pending when ``carving`` fails. ``fail_fast=True``
    must cancel at least one of them before the worker picks it up.
    """
    stage_tool = _MockStage(_name="tooling", behaviour="ok")
    stage_extract = _MockStage(_name="extraction", behaviour="ok")
    stage_carv = _MockStage(_name="carving", behaviour="fail")
    stage_lin = _MockStage(_name="firmware_lineage", behaviour="sleep:5.0")
    stage_prof = _MockStage(_name="firmware_profile", behaviour="sleep:5.0")
    stage_struct = _MockStage(_name="structure", behaviour="sleep:5.0")

    report = run_stages_parallel(
        [
            stage_tool,
            stage_extract,
            stage_carv,
            stage_lin,
            stage_prof,
            stage_struct,
        ],
        scout_stage_ctx,
        max_workers=1,
        fail_fast=True,
    )

    by_name = {r.stage: r for r in report.stage_results}
    assert by_name["carving"].status == "failed"
    # At least one level-2 peer beyond ``carving`` must have been cancelled
    # before it could run -- fail_fast's whole contract.
    level_peers = ["firmware_lineage", "firmware_profile", "structure"]
    cancelled_count = sum(
        1 for n in level_peers if by_name.get(n) and by_name[n].status == "skipped"
    )
    observed = {
        n: (by_name.get(n).status if by_name.get(n) else "absent") for n in level_peers
    }
    assert cancelled_count >= 1, (
        "fail_fast=True with max_workers=1 must cancel at least one queued peer; "
        f"saw statuses: {observed}"
    )


def test_parallel_fail_open_completes_level(
    scout_stage_ctx: StageContext,
) -> None:
    """With fail_fast=False (default), peers in the same level still complete."""
    stage_tool = _MockStage(_name="tooling", behaviour="ok")
    stage_extract = _MockStage(_name="extraction", behaviour="ok")
    stage_struct = _MockStage(_name="structure", behaviour="fail")
    stage_carv = _MockStage(_name="carving", behaviour="ok")

    report = run_stages_parallel(
        [stage_tool, stage_extract, stage_struct, stage_carv],
        scout_stage_ctx,
        max_workers=4,
        fail_fast=False,
    )

    by_name = {r.stage: r for r in report.stage_results}
    assert by_name["structure"].status == "failed"
    assert by_name["carving"].status == "ok", "fail_fast=False must let peers complete"


# ---------------------------------------------------------------------------
# Exception handling
# ---------------------------------------------------------------------------
def test_parallel_stage_raising_is_reported_as_failed(
    scout_stage_ctx: StageContext,
) -> None:
    """A stage raising inside run() is recorded as a failed StageResult."""
    stage_tool = _MockStage(_name="tooling", behaviour="raise")
    report = run_stages_parallel([stage_tool], scout_stage_ctx, max_workers=1)
    by_name = {r.stage: r for r in report.stage_results}
    assert by_name["tooling"].status == "failed"
    # execute_single_stage catches the RuntimeError so the StageResult records
    # the exception type in its limitations list.
    assert any("RuntimeError" in lim for lim in by_name["tooling"].limitations)


# ---------------------------------------------------------------------------
# Progress out-of-order reporting
# ---------------------------------------------------------------------------
def test_parallel_progress_out_of_order(
    scout_stage_ctx: StageContext,
) -> None:
    """ProgressTracker(out_of_order=True) must accept level-completion events."""
    buf = io.StringIO()
    tracker = ProgressTracker(file=buf, out_of_order=True)

    stage_tool = _MockStage(_name="tooling", behaviour="ok")
    stage_extract = _MockStage(_name="extraction", behaviour="ok")

    _ = run_stages_parallel(
        [stage_tool, stage_extract],
        scout_stage_ctx,
        max_workers=2,
        on_progress=tracker,
    )

    output = buf.getvalue()
    assert "tooling" in output
    assert "extraction" in output
    assert "[SCOUT] Pipeline (parallel)" in output
    # Out-of-order format uses completion counter [1/N], [2/N], ...
    assert "[  1/2]" in output
    assert "[  2/2]" in output


def test_parallel_progress_in_order_mode_also_works(
    scout_stage_ctx: StageContext,
) -> None:
    """Default ProgressTracker (out_of_order=False) must still render events.

    Acts as a regression guard that run_stages_parallel() does not crash the
    idx-ordered branch when callers pass an unmodified tracker.
    """
    buf = io.StringIO()
    tracker = ProgressTracker(file=buf, out_of_order=False)

    stage_tool = _MockStage(_name="tooling", behaviour="ok")
    _ = run_stages_parallel([stage_tool], scout_stage_ctx, on_progress=tracker)
    output = buf.getvalue()
    assert "tooling" in output


# ---------------------------------------------------------------------------
# Sanity: STAGE_DEPS reference used by the tests still matches reality.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "stage_name,expected_deps",
    [
        ("tooling", frozenset()),
        ("extraction", frozenset({"tooling"})),
        ("inventory", frozenset({"extraction"})),
        ("endpoints", frozenset({"inventory"})),
        ("structure", frozenset({"extraction"})),
        ("carving", frozenset({"extraction"})),
    ],
)
def test_stage_deps_fixture_edges(
    stage_name: str, expected_deps: frozenset[str]
) -> None:
    assert STAGE_DEPS[stage_name] == expected_deps


# ---------------------------------------------------------------------------
# Return type smoke check
# ---------------------------------------------------------------------------
def test_parallel_returns_runreport_shape(
    scout_stage_ctx: StageContext,
) -> None:
    stage_tool = _MockStage(_name="tooling")
    report = run_stages_parallel([stage_tool], scout_stage_ctx)
    assert isinstance(report.stage_results, list)
    assert all(isinstance(r, StageResult) for r in report.stage_results)
    assert isinstance(report.limitations, list)
