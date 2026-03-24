"""Ghidra headless analysis stage for SCOUT firmware pipeline.

Runs Ghidra headless against priority ELF binaries selected from the inventory
stage output.  Binaries are ranked by risky-symbol density (execve, system,
popen, strcpy, sprintf) so the most exploitation-relevant targets are analysed
first within the time budget.

Inputs:
    stages/inventory/binary_analysis.json  — binary list with matched symbols

Outputs:
    stages/ghidra_analysis/ghidra_analysis.json  — per-binary analysis summary
    stages/ghidra_analysis/results/<sha256>/      — per-binary Ghidra artefacts
    stages/ghidra_analysis/stage.json             — standard stage metadata

Environment variables:
    AIEDGE_GHIDRA_MAX_BINARIES   — max binaries to analyse (default 10, 1–50)
    AIEDGE_GHIDRA_TIMEOUT_S      — per-binary Ghidra timeout in seconds
                                   (default 300, 30–1800)
"""
from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .ghidra_bridge import analyze_binary, ghidra_available
from .path_safety import assert_under_dir, env_int, rel_to_run_dir, sha256_text
from .policy import AIEdgePolicyViolation
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_STAGE_NAME = "ghidra_analysis"

# Symbols that raise exploitation interest and drive binary prioritisation
_RISKY_SYMBOLS: frozenset[str] = frozenset(
    {"system", "popen", "execve", "execvp", "execl", "execle",
     "execlp", "strcpy", "strcat", "sprintf", "vsprintf", "gets"}
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_json(run_dir: Path, dest: Path, data: object) -> None:
    """Serialise *data* to *dest*, enforcing run-dir path containment."""
    assert_under_dir(run_dir, dest)
    dest.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_stage_json(
    run_dir: Path,
    stage_dir: Path,
    status: str,
    details: dict[str, JsonValue],
    limitations: list[str],
) -> None:
    """Write the standard stage.json metadata file."""
    stage_json: dict[str, JsonValue] = {
        "details": cast(JsonValue, details),
        "limitations": cast(JsonValue, limitations),
        "stage": _STAGE_NAME,
        "status": status,
    }
    stage_json_path = stage_dir / "stage.json"
    try:
        assert_under_dir(run_dir, stage_json_path)
        stage_json_path.write_text(
            json.dumps(stage_json, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    except (OSError, AIEdgePolicyViolation):
        pass  # non-fatal


def _binary_priority(hit: dict[str, object]) -> tuple[int, int]:
    """Compute sort key for a binary_analysis hit.

    Returns (-risky_symbol_count, 0) so higher-risk binaries sort first.
    """
    syms: object = hit.get("matched_symbols", [])
    if not isinstance(syms, list):
        syms = []
    risky_count = sum(1 for s in syms if s in _RISKY_SYMBOLS)
    return (-risky_count, 0)


def _resolve_binary_path(hit: dict[str, object], run_dir: Path) -> Path | None:
    """Attempt to resolve the absolute path for a binary_analysis hit.

    Tries in order:
    1. run_dir / hit["path"]  (path relative to run dir)
    2. Any rootfs* directory under stages/extraction/
    3. Strips leading "/" and searches under stages/extraction/rootfs*
    """
    raw_path: object = hit.get("path", "")
    if not isinstance(raw_path, str) or not raw_path:
        return None

    # Strategy 1: direct relative path from run_dir
    candidate = run_dir / raw_path
    if candidate.is_file():
        return candidate

    # Strategy 2 & 3: search under extracted rootfs directories
    extraction_dir = run_dir / "stages" / "extraction"
    stripped = raw_path.lstrip("/")

    if extraction_dir.is_dir():
        for rootfs in extraction_dir.iterdir():
            if not rootfs.is_dir():
                continue
            # Direct relative join
            c = rootfs / stripped
            if c.is_file():
                return c

    return None


# ---------------------------------------------------------------------------
# Stage
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GhidraAnalysisStage:
    """Ghidra headless analysis stage.

    Implements the Stage protocol (structural typing — no ABC required).
    """

    run_dir: Path
    case_id: str | None
    remaining_budget_s: Callable[[], float]
    no_llm: bool

    @property
    def name(self) -> str:
        return _STAGE_NAME

    def run(self, ctx: StageContext) -> StageOutcome:  # noqa: C901
        run_dir = ctx.run_dir
        t0 = time.monotonic()
        limitations: list[str] = []

        # ------------------------------------------------------------------
        # 1. Availability check — skip gracefully when Ghidra is absent
        # ------------------------------------------------------------------
        if not ghidra_available():
            return StageOutcome(
                status="skipped",
                details={"reason": "analyzeHeadless not found; set AIEDGE_GHIDRA_HOME"},
                limitations=["ghidra_not_installed"],
            )

        # ------------------------------------------------------------------
        # 2. Load inventory binary_analysis.json
        # ------------------------------------------------------------------
        inv_path = run_dir / "stages" / "inventory" / "binary_analysis.json"
        if not inv_path.is_file():
            return StageOutcome(
                status="skipped",
                details={"reason": "binary_analysis.json missing; inventory stage required"},
                limitations=["no_inventory"],
            )

        try:
            inv_raw: object = json.loads(inv_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return StageOutcome(
                status="skipped",
                details={"reason": f"binary_analysis.json parse error: {exc}"},
                limitations=["inventory_parse_error"],
            )

        if not isinstance(inv_raw, dict):
            return StageOutcome(
                status="skipped",
                details={"reason": "binary_analysis.json: unexpected top-level type"},
                limitations=["inventory_format_error"],
            )

        hits_raw: object = inv_raw.get("hits", [])
        hits: list[dict[str, object]] = [
            h for h in (hits_raw if isinstance(hits_raw, list) else [])
            if isinstance(h, dict) and h.get("path")
        ]

        # ------------------------------------------------------------------
        # 3. Select and prioritise binaries
        # ------------------------------------------------------------------
        max_binaries = env_int(
            "AIEDGE_GHIDRA_MAX_BINARIES", default=10, min_value=1, max_value=50
        )
        timeout_per = float(
            env_int("AIEDGE_GHIDRA_TIMEOUT_S", default=300, min_value=30, max_value=1800)
        )

        selected = sorted(hits, key=_binary_priority)[:max_binaries]

        if not selected:
            return StageOutcome(
                status="skipped",
                details={"reason": "no eligible binaries in inventory"},
                limitations=["no_eligible_binaries"],
            )

        # ------------------------------------------------------------------
        # 4. Set up output directories
        # ------------------------------------------------------------------
        stage_dir = run_dir / "stages" / _STAGE_NAME
        try:
            stage_dir.mkdir(parents=True, exist_ok=True)
            assert_under_dir(run_dir, stage_dir)
        except (OSError, AIEdgePolicyViolation) as exc:
            return StageOutcome(
                status="failed",
                details={"error": str(exc)},
                limitations=[f"stage directory creation failed: {exc}"],
            )

        results_dir = stage_dir / "results"
        try:
            results_dir.mkdir(exist_ok=True)
            assert_under_dir(run_dir, results_dir)
        except (OSError, AIEdgePolicyViolation) as exc:
            return StageOutcome(
                status="failed",
                details={"error": str(exc)},
                limitations=[f"results directory creation failed: {exc}"],
            )

        # ------------------------------------------------------------------
        # 5. Analyse each binary within the time budget
        # ------------------------------------------------------------------
        analysis_results: list[dict[str, object]] = []

        for hit in selected:
            # Respect overall run time budget (leave ≥60 s headroom)
            if self.remaining_budget_s() < 60.0:
                limitations.append("time_budget_exhausted_before_all_binaries_analysed")
                break

            bin_path = _resolve_binary_path(hit, run_dir)
            if bin_path is None:
                limitations.append(
                    f"binary not found on disk: {hit.get('path', '<unknown>')}"
                )
                continue

            result = analyze_binary(
                binary_path=bin_path,
                output_dir=results_dir,
                run_dir=run_dir,
                timeout_s=timeout_per,
            )

            analysis_results.append(
                {
                    "binary": str(hit.get("path", "")),
                    "status": result.get("status", "failed"),
                    "binary_hash": result.get("binary_hash", ""),
                    "result_files": result.get("result_files", {}),
                    "duration_s": result.get("duration_s", 0.0),
                    "error": result.get("error"),
                }
            )

        # ------------------------------------------------------------------
        # 6. Compute aggregate statistics
        # ------------------------------------------------------------------
        binaries_succeeded = sum(
            1 for r in analysis_results if r.get("status") == "ok"
        )
        binaries_partial = sum(
            1 for r in analysis_results if r.get("status") == "partial"
        )

        if binaries_succeeded > 0:
            agg_status: StageStatus = "ok"
        elif binaries_partial > 0 or analysis_results:
            agg_status = "partial"
        else:
            agg_status = "skipped"

        # ------------------------------------------------------------------
        # 7. Write ghidra_analysis.json summary
        # ------------------------------------------------------------------
        duration = time.monotonic() - t0
        summary: dict[str, object] = {
            "schema_version": "ghidra-analysis-v1",
            "binaries_selected": len(selected),
            "binaries_analysed": len(analysis_results),
            "binaries_succeeded": binaries_succeeded,
            "binaries_partial": binaries_partial,
            "results": analysis_results,
            "limitations": limitations,
            "duration_s": round(duration, 2),
        }

        summary_path = stage_dir / "ghidra_analysis.json"
        summary_written = False
        try:
            _write_json(run_dir, summary_path, summary)
            summary_written = True
        except (OSError, AIEdgePolicyViolation) as exc:
            limitations.append(f"ghidra_analysis.json write failed: {exc}")
            agg_status = "partial"

        # ------------------------------------------------------------------
        # 8. Build StageOutcome details (JSON-serialisable)
        # ------------------------------------------------------------------
        artifact_hash: str | None = None
        if summary_written and summary_path.is_file():
            try:
                artifact_hash = sha256_text(
                    summary_path.read_text(encoding="utf-8", errors="replace")
                )
            except OSError:
                pass

        details_out: dict[str, JsonValue] = {
            "binaries_selected": len(selected),
            "binaries_analysed": len(analysis_results),
            "binaries_succeeded": binaries_succeeded,
            "binaries_partial": binaries_partial,
            "ghidra_analysis_path": rel_to_run_dir(run_dir, summary_path),
            "duration_s": round(duration, 2),
        }
        if artifact_hash is not None:
            details_out["ghidra_analysis_sha256"] = artifact_hash

        # ------------------------------------------------------------------
        # 9. Write stage.json
        # ------------------------------------------------------------------
        _write_stage_json(run_dir, stage_dir, agg_status, details_out, limitations)

        return StageOutcome(
            status=agg_status,
            details=details_out,
            limitations=limitations,
        )


# ---------------------------------------------------------------------------
# Factory (matches StageFactory signature in stage_registry.py)
# ---------------------------------------------------------------------------


def make_ghidra_analysis_stage(
    info: object,
    case_id: str | None,
    remaining_budget_s: Callable[[], float],
    no_llm: bool,
) -> GhidraAnalysisStage:
    """Factory function for registration in _STAGE_FACTORIES."""
    firmware_dest_any = getattr(info, "firmware_dest", None)
    run_dir = (
        firmware_dest_any.parent
        if isinstance(firmware_dest_any, Path)
        else Path(".")
    )
    return GhidraAnalysisStage(
        run_dir=run_dir,
        case_id=case_id,
        remaining_budget_s=remaining_budget_s,
        no_llm=no_llm,
    )
