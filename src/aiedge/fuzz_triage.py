"""fuzz_triage.py — AFL++ crash triage and exploitability classification for SCOUT.

Takes the ``crashes/`` directory produced by an AFL++ campaign and:

1. Enumerates crash files (capped at 50).
2. Replays each crash under the appropriate QEMU user-mode binary to obtain
   the signal number.
3. Maps signal → exploitability class.
4. Deduplicates by crash hash.
5. Writes a structured JSON summary.

QEMU availability is checked at runtime; if the correct ``qemu-<arch>``
binary is not on PATH the signal is left as ``"unknown"`` and the crash is
still recorded (hash + size give useful de-dupe data even without replay).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .path_safety import assert_under_dir, sha256_file

# ---------------------------------------------------------------------------
# Signal classification tables
# ---------------------------------------------------------------------------

_SIGNAL_CLASSES: dict[int, str] = {
    2:  "sigint",    # interrupted (rarely a crash of interest)
    4:  "sigill",    # illegal instruction — often ROP gadget misfire
    6:  "sigabrt",   # assertion / stack canary triggered
    7:  "sigbus",    # bus error — misaligned access
    8:  "sigfpe",    # divide-by-zero / FP exception
    9:  "sigkill",   # killed (memory limit / watchdog)
    11: "sigsegv",   # memory violation — highest exploit interest
    13: "sigpipe",   # broken pipe (usually not exploitable)
    15: "sigterm",   # terminated (timeout)
}

# Exploitability judgement per signal class.
# Categories mirror those used by !exploitable / CERT BFF:
#   "probably_exploitable"      — strong primitive, attacker-controlled PC/SP likely
#   "probably_not_exploitable"  — internal assertion / canary; harder to weaponise
#   "unknown"                   — insufficient information to classify
_EXPLOITABILITY: dict[str, str] = {
    "sigsegv": "probably_exploitable",
    "sigbus":  "probably_exploitable",
    "sigill":  "probably_exploitable",   # could be arbitrary-write → PC
    "sigabrt": "probably_not_exploitable",
    "sigfpe":  "probably_not_exploitable",
    "sigpipe": "probably_not_exploitable",
    "sigint":  "probably_not_exploitable",
    "sigkill": "unknown",
    "sigterm": "unknown",
}

# QEMU user-mode binary names per architecture string (as used by SCOUT inventory)
_QEMU_BIN: dict[str, str] = {
    "arm":     "qemu-arm",
    "armbe":   "qemu-armeb",
    "arm64":   "qemu-aarch64",
    "aarch64": "qemu-aarch64",
    "mips":    "qemu-mips",
    "mipsle":  "qemu-mipsel",
    "mips64":  "qemu-mips64",
    "mips64le":"qemu-mips64el",
    "ppc":     "qemu-ppc",
    "ppc64":   "qemu-ppc64",
    "x86":     "qemu-i386",
    "x86_64":  "qemu-x86_64",
    "sh4":     "qemu-sh4",
    "m68k":    "qemu-m68k",
}

_MAX_CRASHES = 50  # hard cap on crash files processed


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _qemu_for_arch(arch: str) -> str | None:
    """Return the QEMU user-mode binary name for *arch*, or None if unknown.

    Args:
        arch: Architecture string from inventory (e.g. ``"mips"``, ``"arm"``).

    Returns:
        Binary name such as ``"qemu-mips"``, or ``None``.
    """
    return _QEMU_BIN.get(arch.lower())


def _replay_crash(crash_file: Path, binary: str, arch: str) -> int | None:
    """Replay a crash input under QEMU user-mode and return the signal number.

    Passes *crash_file* content to *binary* via stdin.  A negative
    ``returncode`` from ``subprocess.run`` indicates the process was killed
    by signal ``-returncode``.

    Args:
        crash_file: Path to the AFL++ crash file.
        binary: Absolute path to the target binary inside the firmware rootfs.
        arch: Architecture string used to select the QEMU binary.

    Returns:
        The signal number (positive integer) if the crash was reproduced, or
        ``None`` if QEMU is unavailable or replay failed.
    """
    qemu_bin = _qemu_for_arch(arch)
    if qemu_bin is None:
        return None
    if not shutil.which(qemu_bin):
        return None

    try:
        with crash_file.open("rb") as stdin_fh:
            cp = subprocess.run(
                [qemu_bin, binary],
                stdin=stdin_fh,
                capture_output=True,
                timeout=5,
            )
        # subprocess encodes signal termination as negative returncode
        if cp.returncode < 0:
            return -cp.returncode
        # Some QEMU versions exit with 128+signal
        if cp.returncode > 128:
            return cp.returncode - 128
    except subprocess.TimeoutExpired:
        # Hang — treat as unknown signal
        return None
    except Exception:
        return None

    return None


def _classify(signal_num: int | None) -> tuple[str, str]:
    """Map a signal number to (signal_name, exploitability).

    Args:
        signal_num: Signal number from QEMU replay, or ``None``.

    Returns:
        Tuple of (signal_name_str, exploitability_str).
    """
    if signal_num is None:
        return "unknown", "unknown"
    signal_name = _SIGNAL_CLASSES.get(signal_num, f"signal_{signal_num}")
    exploitability = _EXPLOITABILITY.get(signal_name, "unknown")
    return signal_name, exploitability


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def triage_crashes(
    crashes_dir: Path,
    binary_path: str,
    arch: str,
    run_dir: Path,
    output_path: Path,
) -> dict:
    """Triage AFL++ crash files and write a structured JSON summary.

    Processes up to ``_MAX_CRASHES`` crash files from *crashes_dir*,
    replaying each under QEMU when available.  Deduplicates by SHA-256 so
    byte-identical inputs are counted once.  Results are sorted with
    ``"probably_exploitable"`` crashes first.

    Args:
        crashes_dir: Directory containing AFL++ crash files (``id:*`` names).
        binary_path: Absolute path to the fuzzed binary (used for QEMU
            replay).
        arch: Architecture string (e.g. ``"mips"``) used to pick the QEMU
            user-mode binary.
        run_dir: Root of the current analysis run (path safety enforcement).
        output_path: Destination JSON file (must be inside *run_dir*).

    Returns:
        Dict with keys ``crashes_found``, ``exploitable``, ``deduplicated``,
        ``results``, ``limitations``.  The same dict is written to
        *output_path*.
    """
    assert_under_dir(run_dir, output_path)

    limitations: list[str] = []

    if not crashes_dir.is_dir():
        summary: dict = {
            "crashes_found": 0,
            "exploitable": 0,
            "deduplicated": 0,
            "results": [],
            "limitations": ["no_crashes_dir"],
        }
        output_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return summary

    # Check QEMU availability upfront for the limitation log
    qemu_bin = _qemu_for_arch(arch)
    if qemu_bin is None or not shutil.which(qemu_bin):
        limitations.append(f"qemu_not_available_for_{arch}")

    crash_files = sorted(crashes_dir.glob("id:*"))
    if len(crash_files) > _MAX_CRASHES:
        limitations.append(f"crashes_capped_at_{_MAX_CRASHES}")
    crash_files = crash_files[:_MAX_CRASHES]

    results: list[dict] = []
    seen_hashes: set[str] = set()
    deduplicated = 0

    for crash_file in crash_files:
        # Hash first for deduplication
        try:
            crash_hash = sha256_file(crash_file)
            crash_size = crash_file.stat().st_size
        except Exception:
            continue

        if crash_hash in seen_hashes:
            deduplicated += 1
            continue
        seen_hashes.add(crash_hash)

        # Attempt QEMU replay
        signal_num = _replay_crash(crash_file, binary_path, arch)
        signal_name, exploitability = _classify(signal_num)

        results.append({
            "crash_file": crash_file.name,
            "crash_sha256": crash_hash,
            "crash_size_bytes": crash_size,
            "signal": signal_name,
            "signal_num": signal_num,
            "exploitability": exploitability,
            "reproducible": signal_num is not None,
        })

    # Sort: exploitable first, then by filename for determinism
    _EXPLOIT_ORDER = {
        "probably_exploitable": 0,
        "unknown": 1,
        "probably_not_exploitable": 2,
    }
    results.sort(key=lambda r: (
        _EXPLOIT_ORDER.get(r["exploitability"], 9),
        r["crash_file"],
    ))

    exploitable_count = sum(
        1 for r in results if r["exploitability"] == "probably_exploitable"
    )

    summary = {
        "crashes_found": len(crash_files),
        "unique_crashes": len(results),
        "deduplicated": deduplicated,
        "exploitable": exploitable_count,
        "arch": arch,
        "binary": binary_path,
        "qemu_replay_available": qemu_bin is not None and shutil.which(qemu_bin or "") is not None,
        "results": results,
        "limitations": limitations,
    }

    output_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


# ---------------------------------------------------------------------------
# Convenience: generate finding candidates from triage results
# ---------------------------------------------------------------------------

def triage_to_finding_candidates(triage_summary: dict, run_dir: Path) -> list[dict]:
    """Convert triage results into finding candidate dicts for the findings stage.

    Only ``"probably_exploitable"`` crashes produce candidates.  Each
    candidate has the minimum fields required by the findings schema:
    ``title``, ``severity``, ``confidence``, ``rationale``, ``evidence``.

    Args:
        triage_summary: Dict returned by :func:`triage_crashes`.
        run_dir: Run directory (for relative path construction).

    Returns:
        List of finding candidate dicts (may be empty).
    """
    candidates: list[dict] = []
    binary = triage_summary.get("binary", "unknown")
    basename = Path(binary).name if binary else "unknown"

    for result in triage_summary.get("results", []):
        if result.get("exploitability") != "probably_exploitable":
            continue

        signal = result.get("signal", "unknown")
        crash_hash = result.get("crash_sha256", "")
        crash_size = result.get("crash_size_bytes", 0)
        reproducible = result.get("reproducible", False)

        title = (
            f"Fuzzing crash in {basename}: {signal.upper()} "
            f"({'reproducible' if reproducible else 'unreproduced'})"
        )
        rationale = (
            f"AFL++ discovered a crash in {basename} triggerable via a "
            f"{crash_size}-byte input.  The process received {signal.upper()} "
            f"({'confirmed via QEMU replay' if reproducible else 'signal inferred from AFL++ metadata'}).  "
            f"Signal class {signal} maps to exploitability: probably_exploitable."
        )

        candidates.append({
            "title": title,
            "severity": "high",
            "confidence": 0.55,  # static-only cap: 0.60 max per confidence_caps.py
            "rationale": rationale,
            "evidence": {
                "type": "fuzzing_crash",
                "binary": binary,
                "crash_sha256": crash_hash,
                "crash_size_bytes": crash_size,
                "signal": signal,
                "reproducible": reproducible,
            },
        })

    return candidates
