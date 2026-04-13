from __future__ import annotations

"""Stage runner primitives.

Timeouts are treated as `failed`.
"""

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from .schema import JsonValue

StageStatus = Literal["ok", "partial", "failed", "skipped"]


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class StageContext:
    run_dir: Path
    logs_dir: Path
    report_dir: Path


@dataclass(frozen=True)
class StageOutcome:
    status: StageStatus
    details: dict[str, JsonValue] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class StageResult:
    stage: str
    status: StageStatus
    started_at: str
    finished_at: str
    duration_s: float
    details: dict[str, JsonValue]
    limitations: list[str]
    error: str | None
    timed_out: bool


@dataclass(frozen=True)
class RunReport:
    status: StageStatus
    stage_results: list[StageResult]
    limitations: list[str]


class Stage(Protocol):
    @property
    def name(self) -> str: ...

    def run(self, ctx: StageContext) -> StageOutcome: ...


@dataclass(frozen=True)
class SubprocessStage:
    name: str
    argv: Sequence[str]
    timeout_s: float | None = None
    cwd: Path | None = None

    def run(self, ctx: StageContext) -> StageOutcome:
        _ = ctx
        try:
            res = subprocess.run(
                list(self.argv),
                cwd=str(self.cwd) if self.cwd is not None else None,
                text=True,
                capture_output=True,
                check=False,
                timeout=self.timeout_s,
            )
        except subprocess.TimeoutExpired:
            return StageOutcome(
                status="failed",
                details=cast(dict[str, JsonValue], {"timeout": True}),
                limitations=[f"Stage '{self.name}' timed out after {self.timeout_s}s"],
            )

        details: dict[str, JsonValue] = {
            "returncode": res.returncode,
            "stdout": res.stdout or "",
            "stderr": res.stderr or "",
        }

        if res.returncode == 0:
            return StageOutcome(status="ok", details=details)

        return StageOutcome(
            status="failed",
            details=details,
            limitations=[
                f"Stage '{self.name}' failed with return code {res.returncode}"
            ],
        )


def _combine_status(statuses: Sequence[StageStatus]) -> StageStatus:
    if not statuses:
        return "skipped"
    if all(s == "skipped" for s in statuses):
        return "skipped"
    if any(s in ("failed", "partial") for s in statuses):
        return "partial"
    return "ok"


def run_stages(
    stages: Sequence[Stage],
    ctx: StageContext,
    *,
    on_progress: object | None = None,
) -> RunReport:
    from .stage_executor import execute_single_stage

    results: list[StageResult] = []
    limitations: list[str] = []
    total = len(stages)

    for idx, stage in enumerate(stages):
        res = execute_single_stage(
            stage, ctx, idx=idx, total=total, on_progress=on_progress
        )
        results.append(res)
        limitations.extend(res.limitations)

    overall = _combine_status([r.status for r in results])
    return RunReport(status=overall, stage_results=results, limitations=limitations)


def run_stages_parallel(
    stages: Sequence[Stage],
    ctx: StageContext,
    *,
    max_workers: int = 4,
    fail_fast: bool = False,
    on_progress: object | None = None,
) -> RunReport:
    """Execute stages in DAG-derived levels using a thread pool.

    Each topological level runs its stages concurrently through a
    :class:`concurrent.futures.ThreadPoolExecutor`; levels themselves run
    sequentially. A stage is marked ``skipped`` if any of its ``STAGE_DEPS``
    dependencies already failed in an earlier level (fail-open semantics).

    Args:
        stages: Stage instances to execute. Order does not matter -- the DAG
            rebuilds level ordering from :data:`stage_dag.STAGE_DEPS`.
        ctx: Shared :class:`StageContext`. The dataclass is frozen and its
            ``Path`` attributes are immutable, so it is safe to share across
            threads without synchronisation.
        max_workers: Thread pool size (default 4).
        fail_fast: When True, cancel any still-pending futures inside the
            current level on the first failure. Stages already running are not
            interrupted; subsequent levels are still processed so that skipped
            dependents are recorded deterministically.
        on_progress: Optional observer exposing ``register_batch`` /
            ``on_start`` / ``on_end`` methods. Progress events are emitted in
            completion order, so the observer must tolerate out-of-order
            reporting (see :class:`progress.ProgressTracker` ``out_of_order``).

    Returns:
        :class:`RunReport` with one :class:`StageResult` per input stage.

    Notes:
        * ``run_stages()`` is unmodified; sequential behaviour stays
          bit-for-bit identical for callers that do not opt in.
        * ``findings`` is not in ``STAGE_DEPS`` and must be executed outside
          this function via the regular ``run_findings(ctx)`` integrated step.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from .stage_dag import STAGE_DEPS, topo_levels
    from .stage_executor import execute_single_stage

    stage_map: dict[str, Stage] = {s.name: s for s in stages}
    requested: set[str] = set(stage_map.keys())

    if on_progress is not None and hasattr(on_progress, "register_batch"):
        cast(Any, on_progress).register_batch("Pipeline (parallel)", len(stages))

    # Preserve caller order for any stage missing from STAGE_DEPS (should be
    # empty in practice, but keep fail-open behaviour just in case).
    missing_from_dag: list[str] = [s.name for s in stages if s.name not in STAGE_DEPS]
    dag_requested: set[str] = requested - set(missing_from_dag)

    levels: list[list[str]]
    try:
        levels = topo_levels(STAGE_DEPS, dag_requested)
    except ValueError:
        # On a broken graph fall back to caller order as a single level so we
        # still produce a deterministic RunReport instead of crashing.
        levels = [[s.name for s in stages]]
        missing_from_dag = []

    # Append any DAG-unknown stages as a final serial level so they still run.
    if missing_from_dag:
        levels.append(list(missing_from_dag))

    results: list[StageResult] = []
    limitations: list[str] = []
    failed_stages: set[str] = set()

    total = len(stages)
    idx_counter = 0

    for level in levels:
        runnable: list[str] = [
            name
            for name in level
            if not (STAGE_DEPS.get(name, frozenset()) & failed_stages)
        ]
        skipped: list[str] = [name for name in level if name not in runnable]

        for name in skipped:
            skipped_limit = f"Stage '{name}' skipped: upstream dependency failed"
            now_iso = _iso_utc_now()
            res = StageResult(
                stage=name,
                status="skipped",
                started_at=now_iso,
                finished_at=now_iso,
                duration_s=0.0,
                details=cast(dict[str, JsonValue], {}),
                limitations=[skipped_limit],
                error=None,
                timed_out=False,
            )
            results.append(res)
            limitations.append(skipped_limit)
            failed_stages.add(name)
            if on_progress is not None and hasattr(on_progress, "on_end"):
                cast(Any, on_progress).on_end(idx_counter, total, name, res)
            idx_counter += 1

        if not runnable:
            continue

        level_aborted = False
        recorded_names: set[str] = set()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_name: dict[Any, str] = {
                executor.submit(
                    execute_single_stage,
                    stage_map[name],
                    ctx,
                    idx=0,
                    total=total,
                    on_progress=None,
                ): name
                for name in runnable
            }
            for future in as_completed(future_to_name):
                name = future_to_name[future]
                now_iso = _iso_utc_now()
                cancelled = future.cancelled()
                if cancelled:
                    cancel_limit = (
                        f"Stage '{name}' cancelled by fail_fast after peer failure"
                    )
                    res = StageResult(
                        stage=name,
                        status="skipped",
                        started_at=now_iso,
                        finished_at=now_iso,
                        duration_s=0.0,
                        details=cast(dict[str, JsonValue], {}),
                        limitations=[cancel_limit],
                        error=None,
                        timed_out=False,
                    )
                    failed_stages.add(name)
                else:
                    try:
                        res = future.result()
                    except Exception as exc:
                        err_msg = f"{type(exc).__name__}: {exc}"
                        res = StageResult(
                            stage=name,
                            status="failed",
                            started_at=now_iso,
                            finished_at=now_iso,
                            duration_s=0.0,
                            details=cast(dict[str, JsonValue], {}),
                            limitations=[
                                f"Stage '{name}' raised during parallel execution: {err_msg}"
                            ],
                            error=err_msg,
                            timed_out=False,
                        )
                results.append(res)
                recorded_names.add(name)
                limitations.extend(res.limitations)
                if res.status in ("failed", "partial"):
                    failed_stages.add(name)
                    if fail_fast and not level_aborted:
                        level_aborted = True
                        for pending in future_to_name:
                            if not pending.done():
                                _ = pending.cancel()
                if on_progress is not None and hasattr(on_progress, "on_end"):
                    cast(Any, on_progress).on_end(idx_counter, total, name, res)
                idx_counter += 1

        # After the pool drains, any runnable stage that was cancelled but
        # ``as_completed`` did not yield (e.g. because the cancel happened
        # before the future was ever materialised) must still produce a
        # StageResult so the RunReport shape is stable.
        if level_aborted and fail_fast:
            for fut, name in future_to_name.items():
                if name in recorded_names:
                    continue
                cancel_limit = (
                    f"Stage '{name}' cancelled by fail_fast after peer failure"
                )
                now_iso = _iso_utc_now()
                res = StageResult(
                    stage=name,
                    status="skipped",
                    started_at=now_iso,
                    finished_at=now_iso,
                    duration_s=0.0,
                    details=cast(dict[str, JsonValue], {}),
                    limitations=[cancel_limit],
                    error=None,
                    timed_out=False,
                )
                results.append(res)
                recorded_names.add(name)
                limitations.append(cancel_limit)
                failed_stages.add(name)
                if on_progress is not None and hasattr(on_progress, "on_end"):
                    cast(Any, on_progress).on_end(idx_counter, total, name, res)
                idx_counter += 1

    overall = _combine_status([r.status for r in results])
    return RunReport(status=overall, stage_results=results, limitations=limitations)
