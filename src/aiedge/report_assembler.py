"""Report finalization and assembly.

Extracted from run.py to reduce the size of the main orchestration
module. Behaviour is identical to the inline ``_finalize_report`` that
previously lived in run.py: LLM execution, completion metadata,
integrity/completeness refresh, JSON/HTML report emission, analyst
artifacts, firmware handoff, and post-pipeline artifacts.

The bulk of the heavy lifting still happens inside the private helpers
that remain in ``run.py`` (they carry a deep web of cross-references
that would require moving dozens of functions). This module contains
only the thin orchestration shell plus a delegation to
``handoff_writer.write_firmware_handoff`` for the handoff payload.

To avoid a circular import between ``run`` and ``report_assembler``,
the helpers from ``run`` are imported lazily inside :func:`finalize_report`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from . import reporting
from .handoff_writer import write_firmware_handoff
from .normalize import normalize_limitations_list
from .schema import JsonValue

if TYPE_CHECKING:
    from .run import RunInfo


def finalize_report(
    *,
    report: dict[str, JsonValue],
    info: "RunInfo",
    no_llm: bool,
    manifest_profile: str,
    budget_s: float,
) -> None:
    """Shared finalization: LLM exec, completion, integrity, reports, handoff.

    Matches the previous ``run._finalize_report`` behaviour exactly. The
    call order and fail-open semantics (handoff write failure appends a
    limitation but does not abort) are preserved verbatim.
    """
    # Lazy imports to avoid circular dependency with run.py.
    from .run import (
        _apply_llm_exec_step,
        _mark_report_incomplete_due_to_digest,
        _refresh_integrity_and_completeness,
        _set_report_completion,
        _write_analyst_report_artifacts,
        _write_post_pipeline_artifacts,
    )

    report["llm"] = _apply_llm_exec_step(info=info, report=report, no_llm=no_llm)
    _set_report_completion(
        report,
        is_final=True,
        reason="full analyze_run completed",
        findings_executed=True,
    )
    _refresh_integrity_and_completeness(report, info, findings_executed=True)

    report_dir = info.run_dir / "report"
    _ = reporting.write_report_json(report_dir, report)
    _ = reporting.write_report_html(report_dir, report)
    try:
        _write_analyst_report_artifacts(report_dir, report)
    except Exception as exc:
        _mark_report_incomplete_due_to_digest(report=report, info=info, err=exc)
        _ = reporting.write_report_json(report_dir, report)
        _ = reporting.write_report_html(report_dir, report)
        raise
    try:
        write_firmware_handoff(
            info=info,
            profile=manifest_profile,
            max_wallclock_per_run=int(max(1, budget_s)),
        )
    except Exception as exc:
        limits = normalize_limitations_list(report.get("limitations"))
        tag = f"firmware_handoff_write_failed:{type(exc).__name__}"
        if tag not in limits:
            limits.append(tag)
            report["limitations"] = cast(list[JsonValue], cast(list[object], limits))
            _ = reporting.write_report_json(report_dir, report)
            _ = reporting.write_report_html(report_dir, report)
    _write_post_pipeline_artifacts(info.run_dir, report)
