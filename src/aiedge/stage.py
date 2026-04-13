from __future__ import annotations

"""Stage runner primitives.

Timeouts are treated as `failed`.
"""

import subprocess
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
