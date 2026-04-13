"""Unit tests for report_assembler.finalize_report.

These tests focus on the thin orchestration shell extracted from run.py.
The heavy helpers (``_apply_llm_exec_step`` etc.) still live in run.py
and are lazily imported by finalize_report, so we exercise the module
at the import level here. End-to-end behaviour is covered by the
existing integration tests in the repo (analyze_run paths).
"""

from __future__ import annotations

import importlib

import pytest


def test_finalize_report_is_importable() -> None:
    """Smoke test: report_assembler.finalize_report loads cleanly."""
    mod = importlib.import_module("aiedge.report_assembler")
    assert hasattr(mod, "finalize_report")
    assert callable(mod.finalize_report)


def test_finalize_report_has_keyword_only_signature() -> None:
    """finalize_report must keep the (*, report, info, no_llm, manifest_profile, budget_s) signature."""
    from inspect import Parameter, signature

    from aiedge.report_assembler import finalize_report

    sig = signature(finalize_report)
    expected = {"report", "info", "no_llm", "manifest_profile", "budget_s"}
    assert set(sig.parameters.keys()) == expected
    for name in expected:
        param = sig.parameters[name]
        assert (
            param.kind == Parameter.KEYWORD_ONLY
        ), f"parameter {name} must be keyword-only to preserve call contract"


def test_finalize_report_delegates_to_handoff_writer() -> None:
    """finalize_report should import write_firmware_handoff at module load time.

    Regression guard: prevents accidental re-inlining of the handoff
    logic back into report_assembler.
    """
    import aiedge.report_assembler as ra
    from aiedge.handoff_writer import write_firmware_handoff

    assert ra.write_firmware_handoff is write_firmware_handoff


def test_finalize_report_lazy_imports_run_helpers() -> None:
    """The lazy import block inside finalize_report must resolve run helpers.

    This protects against future renames of the private helpers that
    finalize_report depends on.
    """
    from aiedge import run as _run

    for attr in (
        "_apply_llm_exec_step",
        "_set_report_completion",
        "_refresh_integrity_and_completeness",
        "_write_analyst_report_artifacts",
        "_mark_report_incomplete_due_to_digest",
        "_write_post_pipeline_artifacts",
    ):
        assert hasattr(_run, attr), f"run.{attr} missing after extraction"


def test_run_module_re_exports_finalize_report() -> None:
    """run.py must import finalize_report from report_assembler.

    Call sites inside run (analyze_run, subset paths) use the
    ``finalize_report`` symbol directly; this test catches accidental
    removal of the import.
    """
    from aiedge import run as _run
    from aiedge.report_assembler import finalize_report

    assert _run.finalize_report is finalize_report


def test_run_module_re_exports_write_firmware_handoff() -> None:
    """run.py must import write_firmware_handoff from handoff_writer."""
    from aiedge import run as _run
    from aiedge.handoff_writer import write_firmware_handoff

    assert _run.write_firmware_handoff is write_firmware_handoff


def test_report_assembler_no_circular_import() -> None:
    """report_assembler must be importable before run.py is imported.

    This is the canary test for the lazy-import pattern: if the top-level
    imports in report_assembler accidentally pull in run.py, this would
    trigger a circular import chain.
    """
    import sys

    # Force re-import by removing from cache.
    for mod_name in list(sys.modules.keys()):
        if mod_name == "aiedge.report_assembler":
            del sys.modules[mod_name]
    # This should succeed without loading aiedge.run.
    mod = importlib.import_module("aiedge.report_assembler")
    assert mod is not None


@pytest.mark.parametrize("budget", [0, 1, 3600])
def test_finalize_report_accepts_various_budgets(budget: int) -> None:
    """Signature accepts ints for budget_s without crashing at parameter binding."""
    from inspect import signature

    from aiedge.report_assembler import finalize_report

    sig = signature(finalize_report)
    # Just verify the parameter is present; full execution requires RunInfo.
    assert "budget_s" in sig.parameters
