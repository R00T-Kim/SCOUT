"""Generalized StageContext factory for tests.

Based on _make_ctx() pattern in test_llm_failure_observability.py and test_llm_triage.py.
"""

from __future__ import annotations

from pathlib import Path

from aiedge.stage import StageContext


def make_stage_ctx(tmp_path: Path) -> StageContext:
    """Create a StageContext with run_dir, logs_dir, report_dir under tmp_path."""
    run_dir = tmp_path / "run"
    logs_dir = tmp_path / "logs"
    report_dir = tmp_path / "report"
    run_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)
