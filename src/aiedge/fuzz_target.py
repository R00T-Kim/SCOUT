"""fuzz_target.py — Fuzzing target analysis and scoring for SCOUT.

Selects the highest-value binaries from the inventory stage for AFL++
fuzzing, scoring each candidate on network exposure, dangerous symbol
presence, hardening absence, and known CVE history.
"""

from __future__ import annotations

import json
from pathlib import Path

from .path_safety import env_int

# ---------------------------------------------------------------------------
# Scoring constants
# ---------------------------------------------------------------------------

_INPUT_FUNCTIONS: frozenset[str] = frozenset({
    "recv", "recvfrom", "recvmsg",
    "read", "fread",
    "fgets", "gets",
    "scanf", "sscanf", "fscanf", "vscanf", "vsscanf",
    "getenv", "nvram_get", "websGetVar",
    "readdir", "pread",
})

_DANGEROUS_SINKS: frozenset[str] = frozenset({
    "system", "popen",
    "execve", "execvp", "execl", "execlp", "execle",
    "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "vsprintf", "snprintf",
    "memcpy", "memmove", "memset",
    "gets",
})

_NETWORK_SERVICE_NAMES: frozenset[str] = frozenset({
    "httpd", "lighttpd", "nginx", "sshd", "dropbear",
    "dnsmasq", "telnetd", "ftpd", "uhttpd", "miniupnpd",
    "smbd", "ntpd", "snmpd", "mosquitto",
})


# ---------------------------------------------------------------------------
# Scoring logic
# ---------------------------------------------------------------------------

def score_binary(hit: dict, cve_components: set[str] | None = None) -> int:
    """Score a binary for fuzzing suitability on a 0–100 scale.

    Higher scores indicate more interesting candidates.  The breakdown is:

    * +30  network service indicator (name or ``.cgi`` extension)
    * +20  input-parsing functions present (capped)
    * +20  dangerous sink functions present (capped)
    * +15  hardening absent (canary / PIE / NX each worth +5)
    * +15  component appears in CVE matches

    Args:
        hit: A single entry from ``binary_analysis.json["hits"]``.
        cve_components: Set of component names that have known CVEs.

    Returns:
        Integer score in the range [0, 100].
    """
    score = 0
    symbols: set[str] = set(hit.get("matched_symbols", []))
    hardening: dict = hit.get("hardening", {})
    path: str = hit.get("path", "")
    basename = Path(path).name.lower() if path else ""

    # +30: network service indicator
    if any(s in basename for s in _NETWORK_SERVICE_NAMES) or ".cgi" in basename:
        score += 30

    # +20: input parsing functions (7 pts each, capped at 20)
    input_funcs = symbols & _INPUT_FUNCTIONS
    score += min(20, len(input_funcs) * 7)

    # +20: dangerous sinks (5 pts each, capped at 20)
    dangerous = symbols & _DANGEROUS_SINKS
    score += min(20, len(dangerous) * 5)

    # +15: hardening absence — more attackable surface
    if not hardening.get("canary", True):
        score += 5
    if not hardening.get("pie", True):
        score += 5
    if not hardening.get("nx", True):
        score += 5

    # +15: known CVE history for this component
    if cve_components and basename in cve_components:
        score += 15

    return min(100, score)


def _explain_score(hit: dict, cve_components: set[str] | None = None) -> list[str]:
    """Return human-readable reasons for the score of *hit*.

    Args:
        hit: A single entry from ``binary_analysis.json["hits"]``.
        cve_components: Set of component names that have known CVEs.

    Returns:
        List of short reason strings.
    """
    reasons: list[str] = []
    symbols: set[str] = set(hit.get("matched_symbols", []))
    hardening: dict = hit.get("hardening", {})
    path: str = hit.get("path", "")
    basename = Path(path).name.lower() if path else ""

    if any(s in basename for s in _NETWORK_SERVICE_NAMES) or ".cgi" in basename:
        reasons.append("network_service_or_cgi")

    input_funcs = symbols & _INPUT_FUNCTIONS
    if input_funcs:
        reasons.append(f"input_functions:{','.join(sorted(input_funcs)[:5])}")

    dangerous = symbols & _DANGEROUS_SINKS
    if dangerous:
        reasons.append(f"dangerous_sinks:{','.join(sorted(dangerous)[:5])}")

    missing: list[str] = []
    if not hardening.get("canary", True):
        missing.append("canary")
    if not hardening.get("pie", True):
        missing.append("pie")
    if not hardening.get("nx", True):
        missing.append("nx")
    if missing:
        reasons.append(f"no_hardening:{','.join(missing)}")

    if cve_components and basename in cve_components:
        reasons.append("cve_history")

    return reasons


# ---------------------------------------------------------------------------
# Target selection
# ---------------------------------------------------------------------------

def select_fuzz_targets(
    run_dir: Path,
    *,
    max_targets: int | None = None,
    min_score: int = 20,
) -> list[dict]:
    """Select the top fuzzing targets from the inventory stage output.

    Reads ``stages/inventory/binary_analysis.json`` and optionally
    ``stages/cve_scan/cve_matches.json`` for bonus scoring.  Returns the
    *max_targets* highest-scoring candidates that meet *min_score*.

    Args:
        run_dir: Root of the current analysis run.
        max_targets: Maximum number of targets to return.  Defaults to
            ``AIEDGE_FUZZ_MAX_TARGETS`` (env) or 3.
        min_score: Minimum score threshold; candidates below this are
            excluded.  Default 20.

    Returns:
        List of dicts (sorted descending by score) with keys:
        ``path``, ``score``, ``reasons``, ``arch``, ``hardening``,
        ``matched_symbols``.
    """
    if max_targets is None:
        max_targets = env_int(
            "AIEDGE_FUZZ_MAX_TARGETS", default=3, min_value=1, max_value=20
        )

    # --- binary analysis -------------------------------------------------
    ba_path = run_dir / "stages" / "inventory" / "binary_analysis.json"
    if not ba_path.is_file():
        return []
    try:
        data = json.loads(ba_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    hits: list[dict] = data.get("hits", []) if isinstance(data, dict) else []

    # --- CVE component bonus ---------------------------------------------
    cve_components: set[str] = set()
    cve_path = run_dir / "stages" / "cve_scan" / "cve_matches.json"
    if cve_path.is_file():
        try:
            cve_data = json.loads(cve_path.read_text(encoding="utf-8"))
            for m in cve_data.get("matches", []):
                cve_components.add(str(m.get("component", "")))
        except Exception:
            pass

    # --- score and filter ------------------------------------------------
    scored: list[dict] = []
    for hit in hits:
        if not isinstance(hit, dict) or not hit.get("path"):
            continue
        s = score_binary(hit, cve_components)
        if s < min_score:
            continue
        reasons = _explain_score(hit, cve_components)
        scored.append({
            "path": hit["path"],
            "score": s,
            "reasons": sorted(reasons),
            "arch": hit.get("arch", "unknown"),
            "hardening": hit.get("hardening", {}),
            "matched_symbols": sorted(hit.get("matched_symbols", [])),
        })

    scored.sort(key=lambda x: (-x["score"], x["path"]))
    return scored[:max_targets]
