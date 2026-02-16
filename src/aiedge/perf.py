from __future__ import annotations

import json
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import cast


@dataclass(frozen=True)
class RunPerf:
    run_dir: Path
    stage_durations_s: dict[str, float]
    total_stage_time_s: float


def load_stage_durations(run_dir: Path) -> dict[str, float]:
    stages_dir = run_dir / "stages"
    if not stages_dir.is_dir():
        return {}
    out: dict[str, float] = {}
    for stage_dir in sorted(p for p in stages_dir.iterdir() if p.is_dir()):
        stage_json = stage_dir / "stage.json"
        if not stage_json.is_file():
            continue
        raw = json.loads(stage_json.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            continue
        obj = cast(dict[str, object], raw)
        name_any = obj.get("stage_name")
        dur_any = obj.get("duration_s")
        if not (isinstance(name_any, str) and name_any):
            continue
        if isinstance(dur_any, (int, float)):
            out[name_any] = float(max(0.0, float(dur_any)))
    return out


def collect_run_perf(run_dir: Path) -> RunPerf:
    durs = load_stage_durations(run_dir)
    total = float(sum(durs.values()))
    return RunPerf(run_dir=run_dir, stage_durations_s=durs, total_stage_time_s=total)


@dataclass(frozen=True)
class PerfSummary:
    stage_p50_s: dict[str, float]
    stage_p95_s: dict[str, float]
    total_p50_s: float
    total_p95_s: float


def summarize_runs(runs: list[RunPerf]) -> PerfSummary:
    totals = [r.total_stage_time_s for r in runs]
    if not totals:
        return PerfSummary(
            stage_p50_s={}, stage_p95_s={}, total_p50_s=0.0, total_p95_s=0.0
        )

    stages: set[str] = set()
    for r in runs:
        stages.update(r.stage_durations_s.keys())

    stage_p50: dict[str, float] = {}
    stage_p95: dict[str, float] = {}
    for s in sorted(stages):
        vals = [r.stage_durations_s.get(s, 0.0) for r in runs]
        vals_sorted = sorted(vals)
        stage_p50[s] = float(statistics.median(vals_sorted))
        stage_p95[s] = float(vals_sorted[int(0.95 * (len(vals_sorted) - 1))])

    totals_sorted = sorted(totals)
    total_p50 = float(statistics.median(totals_sorted))
    total_p95 = float(totals_sorted[int(0.95 * (len(totals_sorted) - 1))])
    return PerfSummary(
        stage_p50_s=stage_p50,
        stage_p95_s=stage_p95,
        total_p50_s=total_p50,
        total_p95_s=total_p95,
    )


@dataclass(frozen=True)
class PerfThresholds:
    total_p95_s_max: float
    per_stage_p95_s_max: dict[str, float]


def check_thresholds(summary: PerfSummary, thresholds: PerfThresholds) -> list[str]:
    reasons: list[str] = []
    if summary.total_p95_s > thresholds.total_p95_s_max:
        reasons.append(
            f"total_p95_s {summary.total_p95_s:.3f} exceeds max {thresholds.total_p95_s_max:.3f}"
        )
    for stage, max_s in thresholds.per_stage_p95_s_max.items():
        val = summary.stage_p95_s.get(stage)
        if val is None:
            continue
        if val > max_s:
            reasons.append(
                f"stage {stage} p95 {val:.3f} exceeds max {float(max_s):.3f}"
            )
    return reasons
