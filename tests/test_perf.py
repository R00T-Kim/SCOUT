from __future__ import annotations

import json
from pathlib import Path

from aiedge.perf import (
    PerfThresholds,
    check_thresholds,
    collect_run_perf,
    summarize_runs,
)


def _write_stage(run_dir: Path, stage: str, duration_s: float) -> None:
    d = run_dir / "stages" / stage
    d.mkdir(parents=True, exist_ok=True)
    (d / "stage.json").write_text(
        json.dumps(
            {"stage_name": stage, "duration_s": float(duration_s)},
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        )
        + "\n",
        encoding="utf-8",
    )


def test_collect_run_perf_reads_stage_durations(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_stage(run_dir, "tooling", 1.25)
    _write_stage(run_dir, "extraction", 3.5)

    perf = collect_run_perf(run_dir)
    assert perf.stage_durations_s["tooling"] == 1.25
    assert perf.stage_durations_s["extraction"] == 3.5
    assert perf.total_stage_time_s == 4.75


def test_summarize_runs_and_threshold_check(tmp_path: Path) -> None:
    r1 = tmp_path / "r1"
    _write_stage(r1, "tooling", 1.0)
    _write_stage(r1, "extraction", 2.0)
    r2 = tmp_path / "r2"
    _write_stage(r2, "tooling", 1.5)
    _write_stage(r2, "extraction", 4.0)
    r3 = tmp_path / "r3"
    _write_stage(r3, "tooling", 2.0)
    _write_stage(r3, "extraction", 6.0)

    runs = [collect_run_perf(r) for r in (r1, r2, r3)]
    summary = summarize_runs(runs)
    assert summary.total_p50_s > 0.0
    assert summary.stage_p95_s["extraction"] >= summary.stage_p50_s["extraction"]

    thresholds = PerfThresholds(
        total_p95_s_max=3.0, per_stage_p95_s_max={"extraction": 3.0}
    )
    reasons = check_thresholds(summary, thresholds)
    assert any("extraction" in r for r in reasons)
