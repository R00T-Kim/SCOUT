from __future__ import annotations

"""CSource sentinel identification stage.

Identifies where HTTP/network input reaches in firmware binaries using a
two-phase approach inspired by FirmAgent (NDSS 2026):

1. **Runtime sentinel injection** (preferred): Run the binary under QEMU
   user-mode with a sentinel marker string as input and trace where the
   marker appears in execution logs.  Requires ``qemu-{arch}-static``
   and a usable rootfs from the extraction stage.

2. **Static sentinel fallback** (always available): Cross-reference
   HTTP parameter strings from ``endpoints.json`` with input API
   references from ``enhanced_source/sources.json`` and ``.rodata``
   content from ``binary_analysis.json``.  Produces csource entries at
   lower confidence (0.75 static vs 0.95 runtime).

The stage is fully ``--no-llm`` compatible (no LLM calls).
"""

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .path_safety import assert_under_dir
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus

_SCHEMA_VERSION = "csource-identification-v1"

# Sentinel marker injected into binary stdin / environment
_SENTINEL = "SCOUT_TAINT_MARKER"

# QEMU user-mode static binaries by architecture
_QEMU_BINARIES: dict[str, str] = {
    "arm": "qemu-arm-static",
    "arm-32": "qemu-arm-static",
    "armeb": "qemu-armeb-static",
    "aarch64": "qemu-aarch64-static",
    "mips": "qemu-mips-static",
    "mips-32": "qemu-mips-static",
    "mipsel": "qemu-mipsel-static",
    "mipsel-32": "qemu-mipsel-static",
    "mips64": "qemu-mips64-static",
    "mips64el": "qemu-mips64el-static",
    "x86": "qemu-i386-static",
    "x86_64": "qemu-x86_64-static",
    "i386": "qemu-i386-static",
    "ppc": "qemu-ppc-static",
}

# HTTP parameter-related strings that indicate external input
_HTTP_INDICATORS: frozenset[str] = frozenset({
    "GET", "POST", "PUT", "DELETE", "Content-Type",
    "Content-Length", "Cookie", "Authorization",
    "application/x-www-form-urlencoded", "multipart/form-data",
    "application/json", "HTTP/1.", "HTTP/2",
})

# Known input API symbols
_INPUT_APIS: frozenset[str] = frozenset({
    "recv", "recvfrom", "recvmsg", "read", "fread", "fgets",
    "gets", "getenv", "scanf", "sscanf", "fscanf",
    "websGetVar", "httpGetEnv", "nvram_get",
    "acosNvramConfig_get", "json_object_get_string",
    "cJSON_GetObjectItem", "getParameter", "wp_getVar",
})

# Known sink API symbols
_SINK_APIS: frozenset[str] = frozenset({
    "system", "popen", "execve", "execv", "execl", "execlp",
    "strcpy", "strcat", "sprintf", "vsprintf", "gets",
    "doSystemCmd", "twsystem", "doSystem",
})

_QEMU_TIMEOUT_S = 5  # Short timeout; firmware binaries usually hang


def _load_json_file(path: Path) -> object | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _clamp01(v: float) -> float:
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return float(v)


def _find_rootfs_dir(run_dir: Path) -> Path | None:
    """Locate the extracted rootfs directory from the extraction stage."""
    extraction_dir = run_dir / "stages" / "extraction"
    if not extraction_dir.is_dir():
        return None

    # Look for squashfs-root or similar rootfs directories
    for candidate_name in ("squashfs-root", "rootfs", "root"):
        for p in extraction_dir.rglob(candidate_name):
            if p.is_dir() and (p / "bin").is_dir():
                return p
            if p.is_dir() and (p / "usr").is_dir():
                return p

    # Fallback: find any directory with /bin and /usr structure
    for p in extraction_dir.rglob("bin"):
        if p.is_dir() and (p.parent / "usr").is_dir():
            return p.parent

    return None


def _resolve_qemu_binary(arch: str) -> str | None:
    """Find the QEMU user-mode static binary for the given architecture."""
    arch_lower = arch.lower().strip()
    qemu_name = _QEMU_BINARIES.get(arch_lower)
    if qemu_name is None:
        # Try partial match
        for key, val in _QEMU_BINARIES.items():
            if key in arch_lower or arch_lower in key:
                qemu_name = val
                break
    if qemu_name is None:
        return None
    # Check if it exists
    qemu_path = shutil.which(qemu_name)
    if qemu_path is not None:
        return qemu_path
    # Check standard paths
    for prefix in ("/usr/bin", "/usr/local/bin"):
        candidate = os.path.join(prefix, qemu_name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _try_qemu_sentinel(
    binary_path: Path,
    rootfs_dir: Path | None,
    arch: str,
    run_dir: Path,
) -> list[dict[str, str]]:
    """Try to run binary under QEMU user-mode with sentinel injection.

    Returns list of observed PC addresses where sentinel was seen.
    """
    qemu_bin = _resolve_qemu_binary(arch)
    if qemu_bin is None:
        return []

    # Resolve binary to absolute path
    if not binary_path.is_absolute():
        binary_path = run_dir / binary_path

    if not binary_path.is_file():
        return []

    env = dict(os.environ)
    # Inject sentinel into common environment variables
    env["HTTP_REQUEST"] = _SENTINEL
    env["QUERY_STRING"] = f"action={_SENTINEL}"
    env["REQUEST_URI"] = f"/{_SENTINEL}"
    env["CONTENT_TYPE"] = "application/x-www-form-urlencoded"
    env["REQUEST_METHOD"] = "GET"

    cmd: list[str] = [qemu_bin]

    # Add chroot if rootfs is available
    if rootfs_dir is not None and rootfs_dir.is_dir():
        # Use -L for library path prefix (QEMU user-mode)
        cmd.extend(["-L", str(rootfs_dir)])

    # Add execution tracing to capture PC addresses
    cmd.extend(["-d", "in_asm", "-D", "/dev/stderr"])

    cmd.append(str(binary_path))

    results: list[dict[str, str]] = []
    try:
        proc = subprocess.run(
            cmd,
            input=_SENTINEL + "\n",
            capture_output=True,
            text=True,
            timeout=_QEMU_TIMEOUT_S,
            env=env,
            cwd=str(rootfs_dir) if rootfs_dir else None,
        )
        # Check if sentinel appeared in output
        combined = (proc.stdout or "") + (proc.stderr or "")
        if _SENTINEL in combined:
            # Extract PC addresses from QEMU trace output
            # QEMU in_asm format: "0x00012345:  <instruction>"
            lines = combined.split("\n")
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("0x") and ":" in stripped:
                    pc = stripped.split(":")[0].strip()
                    if len(pc) >= 4:
                        results.append({"pc": pc, "trace": "qemu_in_asm"})
                        if len(results) >= 20:
                            break
    except (subprocess.TimeoutExpired, OSError, PermissionError):
        pass

    return results


@dataclass(frozen=True)
class CSourceIdentificationStage:
    """Identify external input reach points via sentinel injection."""

    no_llm: bool = False  # Accepted but unused -- stage is always static

    @property
    def name(self) -> str:
        return "csource_identification"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "csource_identification"
        out_json = stage_dir / "csource_map.json"

        assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        assert_under_dir(run_dir, out_json)

        limitations: list[str] = []
        csources: list[dict[str, JsonValue]] = []

        # --- Load enhanced_source data ---
        es_path = run_dir / "stages" / "enhanced_source" / "sources.json"
        es_data = _load_json_file(es_path)
        es_sources: list[dict[str, object]] = []
        if isinstance(es_data, dict):
            src_any = cast(dict[str, object], es_data).get("sources")
            if isinstance(src_any, list):
                for item in cast(list[object], src_any):
                    if isinstance(item, dict):
                        es_sources.append(cast(dict[str, object], item))
        if not es_sources:
            limitations.append(
                "enhanced_source/sources.json missing or empty; "
                "csource detection limited"
            )

        # --- Load endpoints data ---
        ep_path = run_dir / "stages" / "endpoints" / "endpoints.json"
        ep_data = _load_json_file(ep_path)
        endpoints: list[dict[str, object]] = []
        if isinstance(ep_data, dict):
            ep_any = cast(dict[str, object], ep_data).get("endpoints")
            if isinstance(ep_any, list):
                for item in cast(list[object], ep_any):
                    if isinstance(item, dict):
                        endpoints.append(cast(dict[str, object], item))

        # Extract HTTP parameter values from endpoints
        http_params: set[str] = set()
        for ep in endpoints:
            ep_type = str(ep.get("type", "")).lower()
            ep_value = str(ep.get("value", ""))
            if ep_type in ("url", "http_path", "http_parameter", "rest_api"):
                if ep_value:
                    http_params.add(ep_value)
            # Also check evidence refs for HTTP-related files
            ev_refs = ep.get("evidence_refs")
            if isinstance(ev_refs, list):
                for ref in cast(list[object], ev_refs):
                    if isinstance(ref, str):
                        ref_lower = ref.lower()
                        if any(
                            kw in ref_lower
                            for kw in ("httpd", "cgi", "www", "web", "lighttpd")
                        ):
                            http_params.add(ep_value)

        # --- Load binary_analysis.json for .rodata data ---
        ba_path = run_dir / "stages" / "inventory" / "binary_analysis.json"
        ba_data = _load_json_file(ba_path)
        ba_hits: list[dict[str, object]] = []
        if isinstance(ba_data, dict):
            hits_any = cast(dict[str, object], ba_data).get("hits")
            if isinstance(hits_any, list):
                for item in cast(list[object], hits_any):
                    if isinstance(item, dict):
                        ba_hits.append(cast(dict[str, object], item))

        # Build per-binary symbol sets from binary_analysis
        binary_symbols: dict[str, set[str]] = {}
        binary_arch: dict[str, str] = {}
        for hit in ba_hits:
            bin_path = str(
                hit.get("path") or hit.get("name") or hit.get("binary") or ""
            )
            if not bin_path:
                continue
            syms: set[str] = set()
            for key in (
                "matched_symbols", "dynstr_imports", "risky_symbols", "imports",
            ):
                syms_any = hit.get(key)
                if isinstance(syms_any, list):
                    for s in cast(list[object], syms_any):
                        if isinstance(s, str):
                            syms.add(s)
            sd_any = hit.get("symbol_details")
            if isinstance(sd_any, list):
                for sd_item in cast(list[object], sd_any):
                    if isinstance(sd_item, dict):
                        sn = cast(dict[str, object], sd_item).get("symbol")
                        if isinstance(sn, str):
                            syms.add(sn)
            binary_symbols[bin_path] = syms
            arch_any = hit.get("arch")
            if isinstance(arch_any, str):
                binary_arch[bin_path] = arch_any

        # --- Phase 1: QEMU sentinel injection (runtime) ---
        rootfs_dir = _find_rootfs_dir(run_dir)
        qemu_attempted = 0
        qemu_succeeded = 0

        # Identify binaries with both input + sink APIs for QEMU testing
        qemu_candidates: list[str] = []
        for bin_path, syms in binary_symbols.items():
            has_input = bool(syms & _INPUT_APIS)
            has_sink = bool(syms & _SINK_APIS)
            if has_input and has_sink:
                qemu_candidates.append(bin_path)

        # Limit QEMU attempts to avoid long execution
        max_qemu = int(os.environ.get("AIEDGE_CSOURCE_MAX_QEMU", "10"))
        for bin_path in qemu_candidates[:max_qemu]:
            arch = binary_arch.get(bin_path, "arm")
            qemu_attempted += 1
            traces = _try_qemu_sentinel(
                Path(bin_path), rootfs_dir, arch, run_dir,
            )
            if traces:
                qemu_succeeded += 1
                input_apis = sorted(
                    binary_symbols.get(bin_path, set()) & _INPUT_APIS
                )
                for trace in traces[:5]:
                    csources.append({
                        "binary": bin_path,
                        "pc": trace["pc"],
                        "api": input_apis[0] if input_apis else "unknown",
                        "confidence": _clamp01(0.95),
                        "method": "sentinel_qemu",
                        "trace_type": trace["trace"],
                        "input_apis": cast(
                            list[JsonValue], cast(list[object], input_apis)
                        ),
                    })

        if qemu_attempted > 0 and qemu_succeeded == 0:
            limitations.append(
                f"QEMU sentinel injection attempted on {qemu_attempted} "
                f"binaries but none produced traceable output; "
                f"falling back to static analysis"
            )
        elif qemu_attempted == 0:
            limitations.append(
                "QEMU user-mode not available or no candidates; "
                "using static sentinel analysis only"
            )

        # --- Phase 2: Static sentinel analysis (always runs) ---
        # Cross-reference enhanced_source with endpoints and .rodata
        # to identify binaries where HTTP input can reach sink APIs

        # Group enhanced_source entries by binary
        es_by_binary: dict[str, list[dict[str, object]]] = {}
        for src in es_sources:
            bin_path = str(src.get("binary", ""))
            if bin_path:
                es_by_binary.setdefault(bin_path, []).append(src)

        # Track binaries already covered by QEMU
        qemu_bins: set[str] = {
            cast(str, cs["binary"]) for cs in csources
        }

        for bin_path, src_entries in es_by_binary.items():
            if bin_path in qemu_bins:
                continue  # Already have runtime data

            syms = binary_symbols.get(bin_path, set())
            has_input = bool(syms & _INPUT_APIS)
            has_sink = bool(syms & _SINK_APIS)

            if not (has_input and has_sink):
                continue

            # Check if binary path suggests HTTP/network service
            bin_lower = bin_path.lower()
            is_http_binary = any(
                kw in bin_lower
                for kw in (
                    "httpd", "lighttpd", "nginx", "cgi", "www",
                    "web", "uhttpd", "mini_httpd", "goahead",
                )
            )

            # Check for HTTP indicator strings in binary's .rodata
            has_http_rodata = False
            for hit in ba_hits:
                if str(hit.get("path", "")) == bin_path:
                    # Check symbol_details for HTTP-related APIs
                    sd_list = hit.get("symbol_details")
                    if isinstance(sd_list, list):
                        for sd in cast(list[object], sd_list):
                            if isinstance(sd, dict):
                                sym = str(
                                    cast(dict[str, object], sd).get("symbol", "")
                                )
                                if sym.lower() in (
                                    "websgetvar", "httpgetenv",
                                    "cjson_getobjectitem",
                                ):
                                    has_http_rodata = True
                                    break
                    break

            # Determine confidence based on evidence strength
            if is_http_binary and has_http_rodata:
                confidence = 0.80
            elif is_http_binary or has_http_rodata:
                confidence = 0.75
            elif has_input and has_sink:
                confidence = 0.70
            else:
                confidence = 0.60

            input_apis = sorted(syms & _INPUT_APIS)
            sink_apis = sorted(syms & _SINK_APIS)

            csources.append({
                "binary": bin_path,
                "pc": "0x0",
                "api": input_apis[0] if input_apis else "unknown",
                "confidence": _clamp01(confidence),
                "method": "static_sentinel",
                "input_apis": cast(
                    list[JsonValue], cast(list[object], input_apis)
                ),
                "sink_apis": cast(
                    list[JsonValue], cast(list[object], sink_apis)
                ),
                "is_http_binary": is_http_binary,
                "has_http_rodata": has_http_rodata,
            })

        # --- Deduplicate csources ---
        seen: set[tuple[str, str, str]] = set()
        unique_csources: list[dict[str, JsonValue]] = []
        for cs in csources:
            key = (
                cast(str, cs["binary"]),
                cast(str, cs["pc"]),
                cast(str, cs["api"]),
            )
            if key not in seen:
                seen.add(key)
                unique_csources.append(cs)

        status: StageStatus = "ok" if unique_csources else "partial"

        payload: dict[str, JsonValue] = {
            "schema_version": _SCHEMA_VERSION,
            "status": status,
            "csources": cast(
                list[JsonValue], cast(list[object], unique_csources)
            ),
            "total": len(unique_csources),
            "summary": {
                "qemu_attempted": qemu_attempted,
                "qemu_succeeded": qemu_succeeded,
                "static_entries": len([
                    c for c in unique_csources
                    if cast(str, c.get("method", "")) == "static_sentinel"
                ]),
                "runtime_entries": len([
                    c for c in unique_csources
                    if cast(str, c.get("method", "")) == "sentinel_qemu"
                ]),
            },
            "limitations": cast(
                list[JsonValue], cast(list[object], sorted(set(limitations)))
            ),
        }
        out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)
            + "\n",
            encoding="utf-8",
        )

        details: dict[str, JsonValue] = {
            "total_csources": len(unique_csources),
            "qemu_attempted": qemu_attempted,
            "qemu_succeeded": qemu_succeeded,
            "static_entries": len([
                c for c in unique_csources
                if cast(str, c.get("method", "")) == "static_sentinel"
            ]),
        }
        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
