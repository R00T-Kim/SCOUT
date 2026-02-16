from __future__ import annotations

"""Stage runner primitives.

Timeouts are treated as `failed`.
"""

import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Protocol, cast

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


def run_stages(stages: Sequence[Stage], ctx: StageContext) -> RunReport:
    results: list[StageResult] = []
    limitations: list[str] = []

    for stage in stages:
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

        if bool(details.get("timeout")) or any(
            "timed out" in lim for lim in stage_limits
        ):
            timed_out = True

        stage_name = getattr(stage, "name", stage.__class__.__name__)
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
        results.append(res)
        limitations.extend(stage_limits)

    overall = _combine_status([r.status for r in results])
    return RunReport(status=overall, stage_results=results, limitations=limitations)
