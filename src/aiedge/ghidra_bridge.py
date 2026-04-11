"""Ghidra headless analysis bridge for SCOUT.

Detects, launches, and caches Ghidra headless analysis results for individual
ELF binaries.  All file writes are path-safety validated against the run
directory.

Environment variables:
    AIEDGE_GHIDRA_HOME  — path to Ghidra installation root (contains
                          support/analyzeHeadless).  Falls back to PATH lookup.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from .path_safety import assert_under_dir, sha256_file
from .policy import AIEdgePolicyViolation

# ---------------------------------------------------------------------------
# Public availability check
# ---------------------------------------------------------------------------


def ghidra_available() -> bool:
    """Return True if Ghidra analyzeHeadless is reachable.

    Checks AIEDGE_GHIDRA_HOME first, then PATH.
    """
    return _find_analyze_headless() is not None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _find_analyze_headless() -> str | None:
    """Return the absolute path to analyzeHeadless, or None if not found."""
    ghidra_home = os.environ.get("AIEDGE_GHIDRA_HOME", "")
    if ghidra_home:
        candidate = Path(ghidra_home) / "support" / "analyzeHeadless"
        if candidate.is_file():
            return str(candidate)
    which = shutil.which("analyzeHeadless")
    if which:
        return which
    # Auto-detect from common install paths
    for pattern in ("/opt/ghidra_*", "/usr/local/ghidra*", "/usr/share/ghidra*"):
        import glob as _glob
        for d in sorted(_glob.glob(pattern), reverse=True):
            candidate = Path(d) / "support" / "analyzeHeadless"
            if candidate.is_file():
                os.environ["AIEDGE_GHIDRA_HOME"] = d
                return str(candidate)
    return None


def _scripts_dir() -> Path:
    """Return the bundled Ghidra scripts directory."""
    return Path(__file__).parent / "ghidra_scripts"


def _run_script(
    headless: str,
    binary_path: Path,
    project_dir: Path,
    script_path: Path,
    out_path: Path,
    scripts_dir: Path,
    timeout_s: float,
    *,
    no_analysis: bool = False,
) -> bool:
    """Run analyzeHeadless with a single postScript and return success.

    Returns True when out_path was produced by the script.
    """
    argv: list[str] = [
        headless,
        str(project_dir),
        "ScoutProject",
        "-import", str(binary_path),
        "-postScript", str(script_path), str(out_path),
        "-scriptPath", str(scripts_dir),
        "-deleteProject",
    ]
    if no_analysis:
        argv.append("-noanalysis")

    try:
        subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

    return out_path.is_file()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_binary(
    binary_path: Path,
    output_dir: Path,
    run_dir: Path,
    *,
    timeout_s: float = 300.0,
    scripts: list[str] | None = None,
) -> dict[str, object]:
    """Run Ghidra headless analysis on a single ELF binary.

    Results are cached under ``output_dir/<sha256-of-binary>/``.  If a
    completed cache entry is found the function returns immediately without
    launching Ghidra.

    Args:
        binary_path: Absolute path to the ELF binary to analyse.
        output_dir:  Directory inside *run_dir* where per-binary results are
                     stored (e.g. ``stage_dir / "results"``).
        run_dir:     Root of the current SCOUT run; used for path containment
                     checks and relative-path construction.
        timeout_s:   Maximum wall-clock seconds for a single Ghidra invocation.
        scripts:     List of script basenames to run.  Defaults to the full
                     set: decompile_all, xref_graph, dataflow_trace, string_refs.

    Returns:
        dict with keys:
            status        — "ok" | "failed" | "skipped" | "partial"
            binary_hash   — SHA-256 hex digest of *binary_path*
            binary_path   — str of *binary_path*
            result_files  — mapping of output filename → run-dir-relative path
            duration_s    — wall-clock seconds consumed
            error         — error string or None
    """
    # ------------------------------------------------------------------
    # 1. Cache lookup
    # ------------------------------------------------------------------
    binary_hash = sha256_file(binary_path)
    cache_dir = output_dir / binary_hash
    results_marker = cache_dir / "_analysis_complete.json"

    if results_marker.is_file():
        try:
            cached: dict[str, object] = json.loads(
                results_marker.read_text(encoding="utf-8")
            )
            return cached
        except Exception:
            # Corrupt marker — fall through to re-analyse
            pass

    # ------------------------------------------------------------------
    # 2. Locate analyzeHeadless
    # ------------------------------------------------------------------
    headless = _find_analyze_headless()
    if headless is None:
        return {
            "status": "skipped",
            "binary_hash": binary_hash,
            "binary_path": str(binary_path),
            "result_files": {},
            "duration_s": 0.0,
            "error": "analyzeHeadless_not_found",
        }

    # ------------------------------------------------------------------
    # 3. Create cache directory and temp project dir
    # ------------------------------------------------------------------
    try:
        assert_under_dir(run_dir, cache_dir)
    except AIEdgePolicyViolation as exc:
        return {
            "status": "failed",
            "binary_hash": binary_hash,
            "binary_path": str(binary_path),
            "result_files": {},
            "duration_s": 0.0,
            "error": f"path_containment_violation: {exc}",
        }

    cache_dir.mkdir(parents=True, exist_ok=True)
    project_dir = cache_dir / "ghidra_project"
    project_dir.mkdir(exist_ok=True)

    # ------------------------------------------------------------------
    # 4. Resolve scripts to run
    # ------------------------------------------------------------------
    scripts_dir = _scripts_dir()

    # Default script set: (basename, no_analysis flag)
    _DEFAULT_SCRIPTS: list[tuple[str, bool]] = [
        ("decompile_all.py", False),
        ("xref_graph.py", False),
        ("dataflow_trace.py", False),
        ("pcode_taint.py", False),  # P-code SSA forward taint analysis
        ("string_refs.py", True),   # -noanalysis for string extraction only
    ]

    if scripts is not None:
        script_specs: list[tuple[str, bool]] = [(s, False) for s in scripts]
    else:
        script_specs = _DEFAULT_SCRIPTS

    # ------------------------------------------------------------------
    # 5. Run each script
    # ------------------------------------------------------------------
    t0 = time.monotonic()
    result_files: dict[str, str | None] = {}

    for script_basename, no_analysis in script_specs:
        script_path = scripts_dir / script_basename
        if not script_path.is_file():
            # Script not bundled — skip silently
            continue

        out_name = script_basename.replace(".py", ".json")
        out_path = cache_dir / out_name

        succeeded = _run_script(
            headless=headless,
            binary_path=binary_path,
            project_dir=project_dir,
            script_path=script_path,
            out_path=out_path,
            scripts_dir=scripts_dir,
            timeout_s=timeout_s,
            no_analysis=no_analysis,
        )

        if succeeded:
            # Store run-dir-relative path for portability
            try:
                rel = str(out_path.relative_to(run_dir))
            except ValueError:
                rel = str(out_path)
            result_files[out_name] = rel
        else:
            result_files[out_name] = None

    duration = time.monotonic() - t0

    # ------------------------------------------------------------------
    # 6. Determine overall status
    # ------------------------------------------------------------------
    succeeded_count = sum(1 for v in result_files.values() if v is not None)
    if succeeded_count == len(result_files) and succeeded_count > 0:
        status = "ok"
    elif succeeded_count > 0:
        status = "partial"
    else:
        status = "failed"

    result: dict[str, object] = {
        "status": status,
        "binary_hash": binary_hash,
        "binary_path": str(binary_path),
        "result_files": result_files,
        "duration_s": round(duration, 2),
        "error": None,
    }

    # ------------------------------------------------------------------
    # 7. Write cache marker
    # ------------------------------------------------------------------
    try:
        assert_under_dir(run_dir, results_marker)
        results_marker.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, AIEdgePolicyViolation):
        # Non-fatal: cache miss on next run, but analysis completed
        pass

    # ------------------------------------------------------------------
    # 8. Cleanup ephemeral project directory
    # ------------------------------------------------------------------
    try:
        shutil.rmtree(project_dir, ignore_errors=True)
    except Exception:
        pass

    return result
