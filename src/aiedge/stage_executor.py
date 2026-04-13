from __future__ import annotations

"""Single-stage execution helper.

Extracted from stage.py:run_stages() to enable reuse by both sequential
(run_stages) and future parallel (run_stages_parallel) execution modes.

Behaviour is identical to the inline code that previously lived inside the
run_stages() for-loop.
"""

import subprocess
import time
from typing import Any, cast

from .schema import JsonValue
from .stage import (
    Stage,
    StageContext,
    StageResult,
    _iso_utc_now,
)


def execute_single_stage(
    stage: Stage,
    ctx: StageContext,
    *,
    idx: int = 0,
    total: int = 1,
    on_progress: object | None = None,
) -> StageResult:
    """Execute a single stage, capturing exceptions and emitting progress events.

    Preserves the exact behaviour of the inline stage execution block that
    previously lived in run_stages().  Errors are caught and returned as a
    failed StageResult; the caller decides whether to continue.

    Args:
        stage:       The stage to execute.
        ctx:         Shared StageContext (run_dir, logs_dir, report_dir).
        idx:         0-based position of this stage in the batch (passed to
                     on_progress.on_start / on_end).
        total:       Total number of stages in the batch (same callbacks).
        on_progress: Optional progress observer.  Must expose on_start and
                     on_end if present (checked with hasattr, same as
                     run_stages()).
    """
    stage_name = getattr(stage, "name", stage.__class__.__name__)

    if on_progress is not None and hasattr(on_progress, "on_start"):
        cast(Any, on_progress).on_start(idx, total, stage_name)

    started_at = _iso_utc_now()
    t0 = time.monotonic()
    timed_out = False
    error: str | None = None

    try:
        outcome = stage.run(ctx)
        status = outcome.status
        details = dict(outcome.details)
        stage_limits = list(outcome.limitations)
    except subprocess.TimeoutExpired as e:
        timed_out = True
        status = "failed"
        details = cast(dict[str, JsonValue], {"timeout": True})
        stage_limits = [f"Stage '{getattr(stage, 'name', '<unknown>')}' timed out"]
        error = str(e)
    except Exception as e:
        status = "failed"
        details = {}
        stage_limits = [
            f"Stage '{getattr(stage, 'name', '<unknown>')}' raised: {type(e).__name__}: {e}"
        ]
        error = f"{type(e).__name__}: {e}"

    finished_at = _iso_utc_now()
    duration_s = max(0.0, time.monotonic() - t0)

    if bool(details.get("timeout")) or any("timed out" in lim for lim in stage_limits):
        timed_out = True

    res = StageResult(
        stage=stage_name,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        duration_s=duration_s,
        details=details,
        limitations=stage_limits,
        error=error,
        timed_out=timed_out,
    )

    if on_progress is not None and hasattr(on_progress, "on_end"):
        cast(Any, on_progress).on_end(idx, total, stage_name, res)

    return res
