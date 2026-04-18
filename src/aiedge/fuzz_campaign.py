"""fuzz_campaign.py — AFL++ Docker campaign execution stage for SCOUT.

Implements the ``fuzzing`` pipeline stage.  For each selected target the
stage:

1. Selects targets via :func:`fuzz_target.select_fuzz_targets`.
2. Generates dictionary, seed corpus, and harness config via
   :mod:`fuzz_harness`.
3. Runs AFL++ inside a Docker container (``--network none``) for up to
   ``AIEDGE_FUZZ_BUDGET_S`` seconds per target.
4. Monitors campaign progress by parsing ``fuzzer_stats``.
5. Collects crashes and hands them to :mod:`fuzz_triage`.
6. Writes ``stages/fuzzing/campaign_results.json``.

The stage skips gracefully when Docker is unavailable, no suitable targets
are found, or the remaining time budget is exhausted.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .path_safety import assert_under_dir, env_int, rel_to_run_dir, sha256_file
from .policy import AIEdgePolicyViolation
from .stage import StageContext, StageOutcome

# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------


def _afl_image() -> str:
    return os.environ.get("AIEDGE_AFLPP_IMAGE", "aflplusplus/aflplusplus")


def _fuzz_budget_s() -> int:
    return env_int("AIEDGE_FUZZ_BUDGET_S", default=300, min_value=30, max_value=86400)


def _max_targets() -> int:
    return env_int("AIEDGE_FUZZ_MAX_TARGETS", default=3, min_value=1, max_value=20)


# ---------------------------------------------------------------------------
# AFL++ performance environment variables
# ---------------------------------------------------------------------------


def _build_afl_perf_env(target: dict) -> dict[str, str]:
    """Build AFL++ environment variables for performance optimisation.

    Returns a dict of ``AFL_*`` variables that improve throughput in
    Docker/QEMU mode.  These are additive — they do not conflict with
    the harness ``env`` dict.

    Optimisations (per Airbus AFL++ research — potential 10-100x speedup):

    * ``AFL_SKIP_CPUFREQ``   — bypass CPU governor check inside containers.
    * ``AFL_NO_AFFINITY``    — do not pin to CPUs (containers may have none).
    * ``AFL_AUTORESUME``     — resume interrupted campaigns automatically.
    * ``AFL_FAST_CAL``       — faster initial seed calibration pass.

    Optional target-specific knobs:

    * ``AFL_ENTRYPOINT``           — skip process init, jump to main logic.
    * ``AFL_QEMU_INST_RANGES``     — limit QEMU instrumentation to code ranges.
    """
    env: dict[str, str] = {
        "AFL_SKIP_CPUFREQ": "1",
        "AFL_NO_AFFINITY": "1",
        "AFL_AUTORESUME": "1",
        "AFL_FAST_CAL": "1",
    }

    # If target has a known entrypoint offset (e.g. from Ghidra analysis),
    # AFL++ will skip process initialisation and start fuzzing from that
    # address.  This avoids expensive libc/firmware init on every exec.
    entrypoint = target.get("entrypoint_offset")
    if entrypoint:
        env["AFL_ENTRYPOINT"] = str(entrypoint)

    # If target has known code ranges (from Ghidra), limit QEMU
    # instrumentation to only those ranges.  Reduces overhead from
    # instrumenting library code that is not interesting.
    code_ranges = target.get("code_ranges")
    if code_ranges:
        env["AFL_QEMU_INST_RANGES"] = str(code_ranges)

    return env


# ---------------------------------------------------------------------------
# Multi-instance campaign configuration
# ---------------------------------------------------------------------------

_MULTI_INSTANCE_MIN_BUDGET_S = 600  # require >= 10 minutes for multi-instance


def _build_multi_instance_configs(
    target: dict,
    budget_s: int,
    run_dir: Path,
) -> list[dict]:
    """Generate configs for master + worker AFL++ instances.

    Multi-instance fuzzing uses AFL++'s ``-M`` / ``-S`` flags to run
    cooperative instances sharing a single output directory.  Each instance
    uses a different strategy for broader coverage:

    * **main**    — master instance with ``AFL_FINAL_SYNC=1``.
    * **qasan**   — worker with ``AFL_USE_QASAN=1`` (memory safety checks).
    * **worker1** — standard worker for extra throughput.

    Only enabled when *budget_s* >= 600 (10 minutes).  For shorter budgets
    a single instance is more efficient.

    Args:
        target: Target descriptor dict.
        budget_s: Available time budget in seconds.
        run_dir: Root run directory (unused for now, reserved for future
            per-instance output separation).

    Returns:
        List of config dicts, each with ``instance_name``, ``afl_flags``,
        and ``extra_env``.  Empty list if budget is insufficient.
    """
    if budget_s < _MULTI_INSTANCE_MIN_BUDGET_S:
        return []

    return [
        {
            "instance_name": "main",
            "afl_flags": ["-M", "main"],
            "extra_env": {"AFL_FINAL_SYNC": "1"},
        },
        {
            "instance_name": "qasan",
            "afl_flags": ["-S", "qasan"],
            "extra_env": {"AFL_USE_QASAN": "1"},
        },
        {
            "instance_name": "worker1",
            "afl_flags": ["-S", "worker1"],
            "extra_env": {},
        },
    ]


# ---------------------------------------------------------------------------
# Docker availability check
# ---------------------------------------------------------------------------


def _docker_available() -> bool:
    """Return True if docker is on PATH and the daemon is responsive."""
    if not shutil.which("docker"):
        return False
    try:
        cp = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        return cp.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# fuzzer_stats parsing
# ---------------------------------------------------------------------------


def _parse_fuzzer_stats(stats_path: Path) -> dict[str, str]:
    """Parse an AFL++ ``fuzzer_stats`` file into a key→value dict."""
    result: dict[str, str] = {}
    if not stats_path.is_file():
        return result
    try:
        for line in stats_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                result[k.strip()] = v.strip()
    except Exception:
        pass
    return result


def _collect_stats(output_dir: Path) -> dict[str, Any]:
    """Read fuzzer_stats from a completed (or mid-run) AFL++ output directory."""
    stats = _parse_fuzzer_stats(output_dir / "default" / "fuzzer_stats")
    return {
        "execs_done": int(stats.get("execs_done", 0)),
        "paths_found": int(stats.get("paths_total", 0)),
        "crashes_found": int(
            stats.get("saved_crashes", stats.get("unique_crashes", 0))
        ),
        "hangs_found": int(stats.get("saved_hangs", stats.get("unique_hangs", 0))),
        "execs_per_sec": float(stats.get("execs_per_sec", 0.0)),
        "afl_banner": stats.get("afl_banner", ""),
    }


def _append_campaign_execution_limitations(
    limitations: list[str],
    *,
    docker_rc: int | None,
    docker_err: str,
    stats: dict[str, Any],
) -> None:
    """Record AFL++ startup/execution failures that make a campaign incomplete."""
    if docker_rc not in (None, 0):
        limitations.append(f"docker_exit_{docker_rc}")

    err_lc = docker_err.lower()
    if "fork server handshake failed" in err_lc:
        limitations.append("forkserver_handshake_failed")
    if "invalid elf image" in err_lc:
        limitations.append("target_arch_mismatch")

    try:
        execs_done = int(stats.get("execs_done", 0))
    except (TypeError, ValueError):
        execs_done = 0
    if execs_done <= 0:
        limitations.append("no_fuzzer_executions")


def _campaign_completed(result: dict[str, Any]) -> bool:
    """Return True only when AFL++ actually executed the target at least once."""
    if result.get("skipped"):
        return False
    stats = result.get("stats", {})
    if not isinstance(stats, dict):
        return False
    try:
        return int(stats.get("execs_done", 0)) > 0
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Campaign execution for a single target
# ---------------------------------------------------------------------------


def _run_campaign(
    target: dict,
    stage_dir: Path,
    run_dir: Path,
    budget_s: int,
    remaining_budget_fn: Callable[[], float],
) -> dict:
    """Run one AFL++ campaign in Docker against *target*.

    Args:
        target: Target descriptor from :func:`fuzz_target.select_fuzz_targets`.
        stage_dir: ``stages/fuzzing/`` directory (must be inside *run_dir*).
        run_dir: Root of the current analysis run.
        budget_s: Maximum seconds to fuzz this target.
        remaining_budget_fn: Callback returning remaining global budget.

    Returns:
        Dict summarising the campaign outcome.
    """
    from . import fuzz_harness  # local import avoids circular at module level

    path: str = target.get("path", "")
    basename = Path(path).name if path else "unknown"
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in basename)

    target_dir = stage_dir / safe_name
    assert_under_dir(run_dir, target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    seeds_dir = target_dir / "seeds"
    output_dir = target_dir / "afl_output"
    dict_path = target_dir / "afl.dict"
    harness_path = target_dir / "harness_config.json"
    assert_under_dir(run_dir, seeds_dir)
    assert_under_dir(run_dir, output_dir)
    assert_under_dir(run_dir, dict_path)
    assert_under_dir(run_dir, harness_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    limitations: list[str] = []

    # --- generate harness artefacts --------------------------------------
    seed_count = fuzz_harness.generate_seed_corpus(target, seeds_dir, run_dir)
    dict_count = fuzz_harness.generate_dictionary(run_dir, target, dict_path)
    harness_cfg = fuzz_harness.generate_harness_config(target)
    harness_path.write_text(
        json.dumps(harness_cfg, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # --- generate NVRAM faker stub (C source for cross-compilation) ------
    # Many firmware binaries block on nvram_get() without real hardware.
    # The stub is compiled inside the Docker container at campaign start.
    fuzz_harness.generate_nvram_faker_stub(target_dir)

    # --- generate persistent mode wrapper --------------------------------
    # The wrapper sets up LD_PRELOAD (desock + nvram faker) and library
    # paths, then execs the target.  Avoids fork overhead for heavy init.
    fuzz_harness.generate_persistent_harness(
        target_path=path,
        input_mode=harness_cfg.get("mode", "stdin"),
        harness_dir=target_dir,
    )

    # --- actual time budget for this target ------------------------------
    actual_budget = min(budget_s, int(remaining_budget_fn()))
    if actual_budget < 30:
        return {
            "target": path,
            "skipped": True,
            "skip_reason": "budget_exhausted",
            "limitations": ["budget_exhausted"],
        }

    # --- resolve binary path inside the container mount ------------------
    # `path` from the target descriptor is inventory-relative (e.g. "usr/bin/httpd").
    # The Docker command only mounts run_dir, so we must supply an absolute path
    # that exists under that mount.
    resolved_path: str
    raw_path = Path(path)
    if raw_path.is_absolute() and raw_path.exists():
        # Already an absolute path on the host — use it directly.
        resolved_path = str(raw_path)
    else:
        # Try under the rootfs produced by the extraction stage.
        rootfs_candidate = run_dir / "stages" / "extraction" / "rootfs" / path
        if rootfs_candidate.exists():
            resolved_path = str(rootfs_candidate)
        else:
            # Fall back to run_dir / path (e.g. if caller already prefixed stages/).
            rundir_candidate = run_dir / path
            resolved_path = str(rundir_candidate)
    # Security invariant: resolved path must remain inside run_dir.
    try:
        assert_under_dir(run_dir, Path(resolved_path))
    except AIEdgePolicyViolation:
        return {
            "target": path,
            "skipped": True,
            "skip_reason": "path_outside_run_dir",
            "limitations": ["path_outside_run_dir"],
        }

    # --- build docker command --------------------------------------------
    image = _afl_image()
    arch = target.get("arch", "unknown")

    # Pass harness environment into the container
    env_vars = harness_cfg.get("env", {})

    # Merge AFL++ performance optimisation env vars (entrypoint, inst ranges)
    perf_env = _build_afl_perf_env(target)
    env_vars = {**perf_env, **env_vars}  # harness env takes precedence

    docker_run_base: list[str] = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--privileged",  # needed for AFL++ fork server
        "--ulimit",
        "core=0",
        "-v",
        f"{run_dir}:{run_dir}",
    ]
    for k, v in env_vars.items():
        docker_run_base += ["-e", f"{k}={v}"]
    docker_run_base.append(image)

    afl_args: list[str] = [
        "afl-fuzz",
        "-Q",  # QEMU mode
        "-i",
        str(seeds_dir),
        "-o",
        str(output_dir),
        "-x",
        str(dict_path),
        "-t",
        "1000+",  # timeout per run (+: adaptive)
        "-m",
        "256",  # memory limit MB
        "-V",
        str(actual_budget),  # time limit seconds
    ]

    # CMPLOG mode: dramatically improves coverage of magic-byte comparisons
    # and multi-byte string checks.  Uses the same binary as the CMPLOG
    # target (``-c 0``).  Enabled by default; disable per-target with
    # ``enable_cmplog: false`` in the target descriptor.
    if target.get("enable_cmplog", True):
        afl_args.extend(["-c", "0"])

    afl_args.extend(["--", resolved_path])
    afl_args.extend(harness_cfg.get("extra_args", []))

    full_cmd = docker_run_base + afl_args

    # --- execute campaign ------------------------------------------------
    started_at = time.monotonic()
    docker_rc: int | None = None
    docker_err = ""
    try:
        cp = subprocess.run(
            full_cmd,
            capture_output=True,
            timeout=actual_budget + 30,  # grace period
        )
        # ``CompletedProcess`` exposes ``returncode``; some legacy shims used
        # ``rc``. Preserve the fallback via ``getattr`` which pyright can
        # type-check (direct ``cp.rc`` access triggers reportAttributeAccessIssue).
        docker_rc = getattr(cp, "rc", cp.returncode)
        docker_err = cp.stderr.decode("utf-8", errors="replace")[:2000]
    except subprocess.TimeoutExpired:
        docker_err = "timeout"
        limitations.append("campaign_timeout")
    except Exception as exc:
        docker_err = str(exc)[:500]
        limitations.append("campaign_exception")

    elapsed = time.monotonic() - started_at

    # --- collect stats and crashes ---------------------------------------
    stats = _collect_stats(output_dir)
    _append_campaign_execution_limitations(
        limitations,
        docker_rc=docker_rc,
        docker_err=docker_err,
        stats=stats,
    )

    crashes_dir = output_dir / "default" / "crashes"
    crash_files: list[dict] = []
    if crashes_dir.is_dir():
        for cf in sorted(crashes_dir.glob("id:*"))[:50]:
            try:
                crash_files.append(
                    {
                        "filename": cf.name,
                        "size_bytes": cf.stat().st_size,
                        "sha256": sha256_file(cf),
                        "path": rel_to_run_dir(run_dir, cf),
                    }
                )
            except Exception:
                pass

    # --- multi-instance config (informational, not yet launched) ----------
    multi_configs = _build_multi_instance_configs(target, actual_budget, run_dir)

    return {
        "target": path,
        "basename": basename,
        "arch": arch,
        "score": target.get("score", 0),
        "harness_mode": harness_cfg.get("mode", "stdin"),
        "seeds_generated": seed_count,
        "dict_entries": dict_count,
        "budget_s": actual_budget,
        "elapsed_s": round(elapsed, 2),
        "docker_exit_code": docker_rc,
        "docker_error_snippet": docker_err if docker_err else None,
        "stats": stats,
        "crashes": crash_files,
        "crashes_dir": (
            rel_to_run_dir(run_dir, crashes_dir) if crashes_dir.is_dir() else None
        ),
        "limitations": limitations,
        "skipped": False,
        # Performance optimisation metadata
        "perf_features": {
            "cmplog_enabled": target.get("enable_cmplog", True),
            "entrypoint_set": bool(target.get("entrypoint_offset")),
            "inst_ranges_set": bool(target.get("code_ranges")),
            "afl_fast_cal": True,
            "multi_instance_available": len(multi_configs) > 0,
            "multi_instance_configs": multi_configs if multi_configs else None,
        },
    }


# ---------------------------------------------------------------------------
# Stage implementation
# ---------------------------------------------------------------------------


class FuzzCampaignStage:
    """Pipeline stage: run AFL++ campaigns against top firmware targets.

    Attributes:
        name: Stage name (``"fuzzing"``).
    """

    name = "fuzzing"

    def __init__(
        self,
        run_dir: Path,
        case_id: str | None,
        remaining_budget_s: Callable[[], float],
        no_llm: bool,
    ) -> None:
        self._run_dir = run_dir
        self._case_id = case_id
        self._remaining_budget_s = remaining_budget_s
        self._no_llm = no_llm

    def run(self, ctx: StageContext) -> StageOutcome:  # noqa: C901
        """Execute fuzzing campaigns and write ``campaign_results.json``.

        Returns ``skipped`` when prerequisites are not met (no Docker, no
        suitable targets).  Returns ``partial`` when at least one campaign
        ran.  Returns ``failed`` only on internal errors.
        """
        from . import fuzz_target, fuzz_triage  # defer to avoid circular imports

        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "fuzzing"
        assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)

        results_path = stage_dir / "campaign_results.json"
        assert_under_dir(run_dir, results_path)

        limitations: list[str] = []
        campaign_results: list[dict] = []

        # --- prerequisite: Docker ----------------------------------------
        if not _docker_available():
            limitations.append("docker_not_available")
            outcome = {
                "targets_attempted": 0,
                "targets_completed": 0,
                "total_crashes": 0,
                "campaigns": [],
                "limitations": limitations,
            }
            results_path.write_text(
                json.dumps(outcome, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            return StageOutcome(
                status="skipped",
                details={"skip_reason": "docker_not_available"},
                limitations=limitations,
            )

        # --- prerequisite: time budget -----------------------------------
        remaining = self._remaining_budget_s()
        if remaining < 60:
            limitations.append("budget_exhausted_before_start")
            outcome = {
                "targets_attempted": 0,
                "targets_completed": 0,
                "total_crashes": 0,
                "campaigns": [],
                "limitations": limitations,
            }
            results_path.write_text(
                json.dumps(outcome, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            return StageOutcome(
                status="skipped",
                details={"skip_reason": "budget_exhausted"},
                limitations=limitations,
            )

        # --- select targets ----------------------------------------------
        targets = fuzz_target.select_fuzz_targets(run_dir, max_targets=_max_targets())
        if not targets:
            limitations.append("no_suitable_targets")
            outcome = {
                "targets_attempted": 0,
                "targets_completed": 0,
                "total_crashes": 0,
                "campaigns": [],
                "limitations": limitations,
            }
            results_path.write_text(
                json.dumps(outcome, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            return StageOutcome(
                status="skipped",
                details={"skip_reason": "no_suitable_targets"},
                limitations=limitations,
            )

        # --- per-target time slice ---------------------------------------
        fuzz_budget = _fuzz_budget_s()
        per_target_budget = min(
            fuzz_budget, int(self._remaining_budget_s() // len(targets))
        )

        targets_attempted = 0
        targets_completed = 0
        total_crashes = 0

        for target in targets:
            if self._remaining_budget_s() < 30:
                limitations.append("budget_exhausted_mid_run")
                break

            targets_attempted += 1
            result = _run_campaign(
                target,
                stage_dir,
                run_dir,
                per_target_budget,
                self._remaining_budget_s,
            )

            # --- triage crashes ------------------------------------------
            if result.get("crashes_dir") and not result.get("skipped"):
                crashes_dir = run_dir / result["crashes_dir"]
                triage_out = stage_dir / (
                    Path(result.get("basename", "target")).stem + "_triage.json"
                )
                assert_under_dir(run_dir, triage_out)
                try:
                    triage_summary = fuzz_triage.triage_crashes(
                        crashes_dir=crashes_dir,
                        binary_path=result.get("target", ""),
                        arch=result.get("arch", "unknown"),
                        run_dir=run_dir,
                        output_path=triage_out,
                    )
                    result["triage"] = {
                        "exploitable": triage_summary.get("exploitable", 0),
                        "triage_path": rel_to_run_dir(run_dir, triage_out),
                    }
                    total_crashes += triage_summary.get("crashes_found", 0)
                except Exception as exc:
                    result["triage_error"] = str(exc)[:200]

            campaign_results.append(result)

            if _campaign_completed(result):
                targets_completed += 1
            if result.get("limitations"):
                limitations.extend(result["limitations"])

        # --- write output -------------------------------------------------
        outcome_doc = {
            "targets_selected": [t["path"] for t in targets],
            "targets_attempted": targets_attempted,
            "targets_completed": targets_completed,
            "total_crashes": total_crashes,
            "afl_image": _afl_image(),
            "fuzz_budget_s": fuzz_budget,
            "campaigns": campaign_results,
            "limitations": sorted(set(limitations)),
        }

        results_path.write_text(
            json.dumps(outcome_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        # --- determine status --------------------------------------------
        if targets_completed == 0:
            status: str = "partial" if targets_attempted > 0 else "skipped"
        else:
            status = "ok" if not limitations else "partial"

        return StageOutcome(
            status=status,  # type: ignore[arg-type]
            details={
                "targets_attempted": targets_attempted,
                "targets_completed": targets_completed,
                "total_crashes": total_crashes,
                "results_path": rel_to_run_dir(run_dir, results_path),
            },
            limitations=sorted(set(limitations)),
        )


# ---------------------------------------------------------------------------
# Stage factory
# ---------------------------------------------------------------------------


def make_fuzz_campaign_stage(
    info: object,
    case_id: str | None,
    remaining_budget_s: Callable[[], float],
    no_llm: bool,
) -> FuzzCampaignStage:
    """Factory function for registration in ``_STAGE_FACTORIES``.

    Args:
        info: Run-info object exposing ``firmware_dest`` attribute.
        case_id: Optional case identifier string.
        remaining_budget_s: Callable returning seconds remaining in the
            global analysis budget.
        no_llm: When True the stage should avoid LLM calls (unused here
            but required by the factory protocol).

    Returns:
        Configured :class:`FuzzCampaignStage` instance.
    """
    firmware_dest_any = getattr(info, "firmware_dest", None)
    run_dir = (
        firmware_dest_any.parent if isinstance(firmware_dest_any, Path) else Path(".")
    )
    return FuzzCampaignStage(
        run_dir=run_dir,
        case_id=case_id,
        remaining_budget_s=remaining_budget_s,
        no_llm=no_llm,
    )
