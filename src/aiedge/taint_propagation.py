from __future__ import annotations

"""LLM-guided inter-procedural taint propagation stage.

Traces data flow from identified external input sources to dangerous
sink functions using decompiled code and optional LLM reasoning.
Skips entirely under ``--no-llm``.
"""

import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ._typing_helpers import safe_float, safe_int
from .code_slicing import maybe_slice
from .confidence_caps import (
    DECOMPILED_COLOCATED_CAP,
    PCODE_VERIFIED_CAP,
    STATIC_CODE_VERIFIED_CAP,
    SYMBOL_COOCCURRENCE_CAP,
)
from .evidence_tier import annotate_findings_with_evidence_tiers
from .llm_driver import resolve_driver
from .llm_prompts import TAINT_SYSTEM, TEMPERATURE_DETERMINISTIC
from .path_safety import assert_under_dir
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus

_SCHEMA_VERSION = "taint-propagation-v1"
_LLM_TIMEOUT_S = 120.0
_LLM_MAX_ATTEMPTS = 3
_RETRYABLE_TOKENS: tuple[str, ...] = (
    "stream disconnected",
    "error sending request",
    "connection reset",
    "connection refused",
    "timed out",
    "timeout",
    "temporary failure",
    "503",
    "502",
    "429",
)

_SINK_SYMBOLS: frozenset[str] = frozenset(
    {
        # -- CWE-78 command / process injection --
        "system",
        "popen",
        "execve",
        "execvp",
        "execvpe",
        "execl",
        "execlp",
        "execle",
        "execv",
        "wordexp",
        "posix_spawn",
        "posix_spawnp",
        # -- CWE-120/121 buffer overflow (string) --
        "strcpy",
        "sprintf",
        "strcat",
        "strncpy",
        "strncat",
        "gets",
        "vsprintf",
        # -- CWE-120 buffer overflow (memory) --
        "memcpy",
        "memmove",
        # -- CWE-134 format string --
        "printf",
        "fprintf",
        "syslog",
        "vprintf",
        "vfprintf",
        "snprintf",
        "vsnprintf",
        "dprintf",
        "vdprintf",
        # -- CWE-20 input parsing --
        "scanf",
        "sscanf",
        "fscanf",
        # -- CWE-22 / CWE-73 path traversal --
        "fopen",
        "open",
        "openat",
        "freopen",
        "chdir",
        "realpath",
        # -- CWE-426 untrusted search path / dynamic loading --
        "dlopen",
        "dlsym",
        "dlmopen",
        # -- CWE-732 incorrect permission assignment --
        "chmod",
        "fchmod",
        "chown",
        "fchown",
        "lchown",
        # -- CWE-377 insecure temporary file --
        "mktemp",
        "tmpnam",
        "tempnam",
        "tmpfile",
        # -- CWE-250 / CWE-269 privilege management --
        "chroot",
        "setuid",
        "seteuid",
        "setgid",
        "setegid",
        # -- CWE-454 environment injection --
        "putenv",
        "setenv",
        "unsetenv",
    }
)

_FORMAT_STRING_SINKS: frozenset[str] = frozenset(
    {
        "printf",
        "fprintf",
        "syslog",
        "vprintf",
        "vfprintf",
        "snprintf",
        "vsnprintf",
        "dprintf",
        "vdprintf",
        "swprintf",
        "vswprintf",
        "wprintf",
        "vwprintf",
        "fwprintf",
        "vfwprintf",
    }
)

_MAX_PATHS = 200
_MAX_ALERTS = 100

# FP Rule 2: symbols that indicate network/external input reachability
_NETWORK_INPUT_SYMBOLS: frozenset[str] = frozenset(
    {
        "listen",
        "accept",
        "bind",
        "socket",
        "getenv",
        "nvram_get",
        "recv",
        "recvfrom",
        "recvmsg",
        "fgets",
        "gets",
        "scanf",
        "read",
        "fread",
    }
)

# FP Rule 3: sanitizer symbols that convert strings to integers (injection-safe)
_SANITIZER_SYMBOLS: frozenset[str] = frozenset(
    {
        "atoi",
        "atol",
        "atoll",
        "strtol",
        "strtoul",
        "strtoll",
        "strtoull",
        "inet_aton",
        "inet_addr",
    }
)


def _trace_call_chain(
    xref_map: dict[str, list[str]],
    source: str,
    sink: str,
    max_depth: int = 5,
) -> list[str] | None:
    """BFS through xref_map to find a call path from *source* to *sink*."""
    if not xref_map or not source or not sink:
        return None
    queue: deque[tuple[str, list[str]]] = deque([(source, [source])])
    visited: set[str] = {source}
    while queue:
        current, path = queue.popleft()
        if len(path) > max_depth:
            continue
        for callee in xref_map.get(current, []):
            if callee == sink:
                return path + [sink]
            if callee not in visited:
                visited.add(callee)
                queue.append((callee, path + [callee]))
    return None


def _check_constant_sink(
    func_map: dict[str, dict[str, str]],
    sink_sym: str,
    binary_basename: str = "",
) -> bool:
    """FP Rule 1: return True only if EVERY call to *sink_sym* passes a literal.

    Returns False (not a FP) when any variable-argument call is found, or when
    no evidence exists.  Filters by *binary_basename* when provided so that a
    constant ``system("/bin/reboot")`` in one binary does not suppress a
    variable ``system(user_buf)`` in another.
    """
    literal_pat = re.compile(
        r"\b" + re.escape(sink_sym) + r'\s*\(\s*(?:"[^"]*"|0x[0-9a-fA-F]+|\d+)',
        re.IGNORECASE,
    )
    variable_pat = re.compile(
        r"\b" + re.escape(sink_sym) + r"\s*\(\s*[a-zA-Z_]",
        re.IGNORECASE,
    )
    found_literal = False
    for finfo in func_map.values():
        fb = finfo.get("binary", "")
        if binary_basename and fb and binary_basename not in fb:
            continue
        body = finfo.get("body", "")
        if variable_pat.search(body):
            return False
        if literal_pat.search(body):
            found_literal = True
    return found_literal


def _is_format_string_variable(
    sink_sym: str,
    decompiled_body: str,
) -> bool:
    """Return True if sink_sym is called with a variable (non-literal) format string.

    Recognised variable forms (anything whose first argument is *not* a string
    literal): bare identifiers (``printf(buf)``), function-call results
    (``printf(get_str())``), struct field access (``printf(obj->field)`` /
    ``printf(obj.field)``), array subscripts (``printf(arr[i])``), C-style
    casts (``printf((char *) buf)``), parenthesised expressions including
    ternaries (``printf((cond ? a : b))``).
    """
    if sink_sym not in _FORMAT_STRING_SINKS:
        return False
    # Match the sink call with a first argument whose first non-whitespace
    # character is anything other than a double-quote (string literal). Any
    # non-literal first argument — identifier, function call, ``(`` for cast or
    # ternary, ``*``/``&`` for pointer operations — is treated as variable.
    variable_fmt_pat = re.compile(
        r"\b" + re.escape(sink_sym) + r'\s*\(\s*[^"\s\)]',
    )
    return bool(variable_fmt_pat.search(decompiled_body))


def _has_network_input_symbol(import_symbols: set[str]) -> bool:
    """FP Rule 2: binary has at least one network/external-input symbol."""
    return bool(import_symbols & _NETWORK_INPUT_SYMBOLS)


def _has_sanitizer_symbol(import_symbols: set[str]) -> bool:
    """FP Rule 3: binary imports a string-to-integer sanitizer."""
    return bool(import_symbols & _SANITIZER_SYMBOLS)


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


def _truncate_text(text: str, *, max_chars: int = 6000) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def _hash_body(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()


def _build_taint_prompt(
    source_api: str,
    sink_symbol: str,
    function_bodies: list[dict[str, str]],
) -> str:
    code_blocks = ""
    for fb in function_bodies:
        fname = fb.get("name", "unknown")
        # Phase 2C+.1 (LATTE): when AIEDGE_LATTE_SLICING=1, replace the full
        # body with a backward slice rooted at the sink call. Default-off so
        # behaviour stays byte-identical when the env var is unset.
        body_raw = fb.get("body", "")
        body_sliced = maybe_slice(body_raw, sink_symbol)
        body = _truncate_text(body_sliced, max_chars=2000)
        code_blocks += f"\n### {fname}\n```c\n{body}\n```\n"

    return (
        "You are a firmware taint analysis expert.\n"
        f"Can data from the input API `{source_api}` reach the dangerous "
        f"sink `{sink_symbol}`?\n"
        "Trace the data flow through these decompiled functions:\n"
        f"{code_blocks}\n"
        "## Rules\n"
        "- Follow return values, pointer parameters, and global variables\n"
        "- Note any sanitization or validation along the path\n"
        "- If taint CANNOT reach the sink, explain why\n\n"
        "## Output Format\n"
        "Return ONLY a JSON object (no markdown fences):\n"
        "{\n"
        '  "taint_reaches_sink": true|false,\n'
        '  "confidence": 0.0-1.0,\n'
        '  "path_description": "<trace description>",\n'
        '  "sanitizers_found": ["<sanitizer_name>", ...],\n'
        '  "rationale": "<explanation>"\n'
        "}\n\n"
        "## Example Output\n"
        '{"taint_reaches_sink": true, "confidence": 0.75, '
        '"path_description": "recv() -> buffer -> sprintf() -> system()", '
        '"sanitizers_found": [], '
        '"rationale": "User-controlled data from recv() is copied into buffer '
        'via sprintf() without validation, then passed directly to system()."}\n'
    )


def _build_http_taint_path(
    binary: str,
    input_api: str,
    sink: str,
    hardening: str,
) -> str:
    """Build a structured taint path description for web server binaries."""
    basename = binary.rsplit("/", 1)[-1] if "/" in binary else binary
    return (
        f"HTTP_REQUEST -> {basename}:{input_api}() -> ... -> {basename}:{sink}(). "
        f"Web server binary processes HTTP input via {input_api}() which may "
        f"reach dangerous sink {sink}() without sanitization. "
        f"Hardening: {hardening or 'unknown'}"
    )


def _parse_json_response(stdout: str) -> dict[str, object] | None:
    from .llm_driver import parse_json_from_llm_output

    return parse_json_from_llm_output(stdout)


@dataclass(frozen=True)
class TaintPropagationStage:
    """LLM-guided inter-procedural taint analysis."""

    no_llm: bool = False

    @property
    def name(self) -> str:
        return "taint_propagation"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "taint_propagation"
        results_json = stage_dir / "taint_results.json"
        alerts_json = stage_dir / "alerts.json"

        assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        assert_under_dir(run_dir, results_json)
        assert_under_dir(run_dir, alerts_json)

        limitations: list[str] = []
        taint_results: list[dict[str, JsonValue]] = []
        alerts: list[dict[str, JsonValue]] = []

        # --- Load sources from enhanced_source ---
        sources_path = run_dir / "stages" / "enhanced_source" / "sources.json"
        sources_data = _load_json_file(sources_path)
        source_list: list[dict[str, object]] = []
        if isinstance(sources_data, dict):
            src_any = cast(dict[str, object], sources_data).get("sources")
            if isinstance(src_any, list):
                for s in cast(list[object], src_any):
                    if isinstance(s, dict):
                        source_list.append(cast(dict[str, object], s))
        if not source_list:
            limitations.append("No sources from enhanced_source stage")

        # --- Fallback 1: source_sink_graph paths as source-sink pairs ---
        ss_path = run_dir / "stages" / "surfaces" / "source_sink_graph.json"
        ss_data = _load_json_file(ss_path)
        ss_paths: list[dict[str, object]] = []
        sink_binaries: list[dict[str, object]] = []
        if isinstance(ss_data, dict):
            paths_any = cast(dict[str, object], ss_data).get("paths")
            if isinstance(paths_any, list):
                for p in cast(list[object], paths_any):
                    if isinstance(p, dict):
                        p_obj = cast(dict[str, object], p)
                        ss_paths.append(p_obj)
                        sink_any = p_obj.get("sink")
                        if isinstance(sink_any, dict):
                            sink_binaries.append(cast(dict[str, object], sink_any))
        if not sink_binaries:
            limitations.append("No sinks from source_sink_graph")

        # --- Fallback 2: binary_analysis.json for binaries with both input+sink ---
        ba_path = run_dir / "stages" / "inventory" / "binary_analysis.json"
        ba_data = _load_json_file(ba_path)
        ba_pairs: list[dict[str, object]] = []
        if isinstance(ba_data, dict):
            ba_hits_any = cast(dict[str, object], ba_data).get("hits")
            if isinstance(ba_hits_any, list):
                for hit_any in cast(list[object], ba_hits_any):
                    if not isinstance(hit_any, dict):
                        continue
                    hit = cast(dict[str, object], hit_any)
                    syms: set[str] = set()
                    ms_any = hit.get("matched_symbols")
                    if isinstance(ms_any, list):
                        for s in cast(list[object], ms_any):
                            if isinstance(s, str):
                                syms.add(s)
                    sd_any = hit.get("symbol_details")
                    if isinstance(sd_any, list):
                        for sd_item in cast(list[object], sd_any):
                            if isinstance(sd_item, dict):
                                sn = cast(dict[str, object], sd_item).get("symbol")
                                if isinstance(sn, str):
                                    syms.add(sn)
                    input_syms = {
                        s
                        for s in syms
                        if s.lower()
                        in {
                            "recv",
                            "recvfrom",
                            "recvmsg",
                            "read",
                            "fread",
                            "fgets",
                            "gets",
                            "getenv",
                            "scanf",
                            "sscanf",
                            "fscanf",
                        }
                    }
                    sink_syms = {
                        s
                        for s in syms
                        if s.lower()
                        in {
                            "system",
                            "popen",
                            "execve",
                            "execv",
                            "strcpy",
                            "sprintf",
                            "strcat",
                            "vsprintf",
                            "gets",
                        }
                    }
                    if sink_syms:  # At minimum need sinks
                        ba_pairs.append(
                            {
                                "binary": str(hit.get("path", "")),
                                "input_syms": sorted(input_syms),
                                "sink_syms": sorted(sink_syms),
                                "arch": str(hit.get("arch", "unknown")),
                                "hardening": hit.get("hardening", {}),
                            }
                        )

        # --- Load decompiled functions from ghidra_analysis ---
        ghidra_dir = run_dir / "stages" / "ghidra_analysis"
        decompiled_path = ghidra_dir / "decompiled_functions.json"
        func_data = _load_json_file(decompiled_path)
        func_map: dict[str, dict[str, str]] = {}
        if isinstance(func_data, list):
            for f in cast(list[object], func_data):
                if isinstance(f, dict):
                    fd = cast(dict[str, object], f)
                    fname = str(fd.get("name", ""))
                    body = str(fd.get("body", ""))
                    binary = str(fd.get("binary", ""))
                    if fname and body:
                        key = f"{binary}:{fname}" if binary else fname
                        func_map[key] = {"name": fname, "body": body, "binary": binary}
        elif isinstance(func_data, dict):
            funcs_any = cast(dict[str, object], func_data).get("functions")
            if isinstance(funcs_any, list):
                for f in cast(list[object], funcs_any):
                    if isinstance(f, dict):
                        fd = cast(dict[str, object], f)
                        fname = str(fd.get("name", ""))
                        body = str(fd.get("body", ""))
                        binary = str(fd.get("binary", ""))
                        if fname and body:
                            key = f"{binary}:{fname}" if binary else fname
                            func_map[key] = {
                                "name": fname,
                                "body": body,
                                "binary": binary,
                            }
        if not func_map:
            limitations.append("No decompiled function bodies available")

        # --- Load xref_graph for call chain traversal ---
        xref_map: dict[str, list[str]] = {}
        for xref_file in ghidra_dir.rglob("xref_graph.json"):
            xref_data = _load_json_file(xref_file)
            if isinstance(xref_data, list):
                for entry in cast(list[object], xref_data):
                    if not isinstance(entry, dict):
                        continue
                    caller = str(cast(dict[str, object], entry).get("caller", ""))
                    callee = str(cast(dict[str, object], entry).get("callee", ""))
                    if caller and callee:
                        xref_map.setdefault(caller, []).append(callee)

        # === P-CODE TAINT (Ghidra P-code SSA verified paths — highest confidence) ===
        pcode_verified_binaries: set[str] = set()
        trace_count = 0
        for pcode_file in ghidra_dir.rglob("pcode_taint.json"):
            pcode_data = _load_json_file(pcode_file)
            if not isinstance(pcode_data, dict):
                continue
            pcode_traces = pcode_data.get("traces", [])
            if not isinstance(pcode_traces, list):
                continue
            for pt in cast(list[object], pcode_traces):
                if not isinstance(pt, dict):
                    continue
                pt_d = cast(dict[str, object], pt)
                src_api = str(pt_d.get("source_api", ""))
                sink_sym = str(pt_d.get("sink", ""))
                func_name = str(pt_d.get("function", ""))
                func_addr = str(pt_d.get("function_address", ""))
                src_addr = str(pt_d.get("source_address", "0x0"))
                sink_addr = str(pt_d.get("sink_address", "0x0"))
                sanitized = bool(pt_d.get("sanitized", False))
                depth = safe_int(pt_d.get("depth"), default=0)

                # Resolve binary from parent dir name (hash-keyed cache)
                pcode_binary = pcode_file.parent.name

                trace_method = str(pt_d.get("method", "pcode_dataflow"))
                conf = float(str(pt_d.get("confidence", 0.75)))
                if sanitized:
                    conf = min(conf, 0.20)
                # Apply method-specific confidence cap
                if trace_method == "pcode_dataflow":
                    conf = min(conf, PCODE_VERIFIED_CAP)  # 0.75
                elif trace_method == "pcode_colocated":
                    conf = min(conf, 0.65)  # P-code verified colocated
                elif trace_method == "decompiled_colocated":
                    # Body-text co-occurrence in decompiled function.
                    # See confidence_caps.py for evidence-level rationale.
                    conf = min(conf, DECOMPILED_COLOCATED_CAP)
                elif trace_method == "decompiled_interprocedural":
                    conf = min(
                        conf, 0.60
                    )  # cross-function body text, higher than colocated
                else:
                    conf = min(conf, PCODE_VERIFIED_CAP)

                method_label = {
                    "pcode_dataflow": "P-code verified dataflow",
                    "pcode_colocated": "P-code colocated (same function, no direct flow)",
                    "decompiled_colocated": "Decompiled function colocated",
                }.get(trace_method, "P-code verified")
                path_desc = (
                    f"{method_label}: {src_api}() and "
                    f"{sink_sym}() in {func_name} @ {func_addr}. "
                    f"Depth: {depth}."
                    + (" Sanitizer detected — taint neutralized." if sanitized else "")
                )

                taint_entry: dict[str, JsonValue] = {
                    "source_api": src_api,
                    "source_binary": pcode_binary,
                    "sink_symbol": sink_sym,
                    "taint_reaches_sink": not sanitized,
                    "confidence": _clamp01(conf),
                    "path_description": path_desc,
                    "method": (
                        trace_method
                        if trace_method != "pcode_dataflow"
                        else "pcode_verified"
                    ),
                    "source_type": trace_method,
                    "web_server": False,
                    "call_chain": cast(
                        list[JsonValue],
                        [
                            {
                                "step": "source",
                                "function": f"{func_name}:{src_api}",
                                "address": src_addr,
                            },
                            {
                                "step": "sink",
                                "function": f"{func_name}:{sink_sym}",
                                "address": sink_addr,
                            },
                        ],
                    ),
                }
                taint_results.append(taint_entry)
                if not sanitized:
                    alerts.append(
                        {
                            "source_api": src_api,
                            "source_binary": pcode_binary,
                            "source_address": src_addr,
                            "sink_symbol": sink_sym,
                            "confidence": _clamp01(conf),
                            "path_description": path_desc,
                            "method": (
                                trace_method
                                if trace_method != "pcode_dataflow"
                                else "pcode_verified"
                            ),
                            "source_type": trace_method,
                            "web_server": False,
                        }
                    )
                pcode_verified_binaries.add(pcode_binary)
                trace_count += 1
                if trace_count >= _MAX_PATHS:
                    break
            if trace_count >= _MAX_PATHS:
                break

        # === STATIC TAINT INFERENCE (always runs, no LLM needed) ===
        # Infer taint paths from binaries that have both input and sink symbols
        # Skip binaries already covered by P-code verified traces

        # From enhanced_source sources (which now contain matched_sink_apis)
        # Prioritize web server binaries so they don't get crowded out by _MAX_PATHS
        sorted_sources = sorted(
            source_list,
            key=lambda s: (
                not bool(s.get("web_server")),
                -safe_float(s.get("confidence"), default=0.0),
            ),
        )
        seen_static: set[tuple[str, str, str]] = set()
        for source in sorted_sources:
            src_api = str(source.get("api", ""))
            src_binary = str(source.get("binary", ""))
            sink_apis_any = source.get("matched_sink_apis")
            sink_list: list[str] = []
            if isinstance(sink_apis_any, list):
                for sa in cast(list[object], sink_apis_any):
                    if isinstance(sa, str):
                        sink_list.append(sa)

            # Collect import symbols for this source entry (for FP rules 2 & 3)
            src_import_syms: set[str] = set()
            ms_any = source.get("matched_symbols")
            if isinstance(ms_any, list):
                for _s in cast(list[object], ms_any):
                    if isinstance(_s, str):
                        src_import_syms.add(_s.lower())
            mi_any = source.get("matched_input_apis")
            if isinstance(mi_any, list):
                for _s in cast(list[object], mi_any):
                    if isinstance(_s, str):
                        src_import_syms.add(_s.lower())

            for sink_sym in sink_list:
                dedup_key = (src_binary, src_api, sink_sym)
                if dedup_key in seen_static:
                    continue
                seen_static.add(dedup_key)
                if trace_count >= _MAX_PATHS:
                    break

                # Skip if P-code already verified this binary with higher confidence
                src_basename_for_pcode = (
                    src_binary.rsplit("/", 1)[-1] if "/" in src_binary else src_binary
                )
                if src_basename_for_pcode in pcode_verified_binaries:
                    continue

                hardening_any = source.get("hardening")
                hardening_str = ""
                if isinstance(hardening_any, dict):
                    h = cast(dict[str, object], hardening_any)
                    parts: list[str] = []
                    if not h.get("canary"):
                        parts.append("no_canary")
                    if not h.get("nx"):
                        parts.append("no_nx")
                    if not h.get("pie"):
                        parts.append("no_pie")
                    hardening_str = ", ".join(parts) if parts else "hardened"

                conf = 0.45
                input_apis_any = source.get("matched_input_apis")
                has_real_input = (
                    isinstance(input_apis_any, list) and len(input_apis_any) > 0
                )
                if has_real_input:
                    conf = 0.55

                # HTTP-aware taint path for web server binaries
                source_type = str(source.get("source_type", ""))
                is_web = bool(source.get("web_server", False))
                if is_web:
                    conf = 0.60
                    path_desc = _build_http_taint_path(
                        src_binary,
                        src_api,
                        sink_sym,
                        hardening_str,
                    )
                else:
                    path_desc = (
                        f"Static inference: {src_binary} imports both "
                        f"{src_api}() and {sink_sym}(). "
                        f"Hardening: {hardening_str or 'unknown'}"
                    )

                # Compute binary basename early for FP rules
                src_basename = (
                    src_binary.rsplit("/", 1)[-1] if "/" in src_binary else src_binary
                )

                # --- FP Rule 1: constant-sink gate (Ghidra data required) ---
                if func_map and _check_constant_sink(func_map, sink_sym, src_basename):
                    limitations.append(
                        f"FP suppressed (constant-sink): {src_binary}:{sink_sym}"
                    )
                    continue

                # --- FP Rule 2: non-network binary gate ---
                # If binary has no network/external-input symbols, attacker
                # cannot supply tainted data → lower confidence below threshold.
                if not is_web and not _has_network_input_symbol(src_import_syms):
                    conf = min(conf, 0.25)  # below fp_verification threshold (0.30)

                # --- FP Rule 3: sanitizer detection ---
                if _has_sanitizer_symbol(src_import_syms):
                    conf = max(0.0, conf - 0.15)

                # --- 2-tier confidence cap ---
                if func_map:
                    # Ghidra code available: code-verified tier
                    conf = min(conf, STATIC_CODE_VERIFIED_CAP)
                else:
                    # Symbol co-occurrence only
                    conf = min(conf, SYMBOL_COOCCURRENCE_CAP)

                call_chain: list[dict[str, str]] = []
                if is_web:
                    call_chain = [
                        {
                            "step": "entry",
                            "function": f"{src_basename}:main",
                            "type": "http_handler",
                        },
                        {
                            "step": "input",
                            "function": f"{src_basename}:{src_api}",
                            "type": "http_param_read",
                        },
                        {
                            "step": "sink",
                            "function": f"{src_basename}:{sink_sym}",
                            "type": "command_execution",
                        },
                    ]

                taint_entry: dict[str, JsonValue] = {
                    "source_api": src_api,
                    "source_binary": src_binary,
                    "sink_symbol": sink_sym,
                    "taint_reaches_sink": True,
                    "confidence": _clamp01(conf),
                    "path_description": path_desc,
                    "method": "static_inference",
                    "source_type": source_type or "generic",
                    "web_server": is_web,
                    "call_chain": cast(list[JsonValue], cast(list[object], call_chain)),
                }
                taint_results.append(taint_entry)
                alerts.append(
                    {
                        "source_api": src_api,
                        "source_binary": src_binary,
                        "source_address": str(source.get("address", "0x0")),
                        "sink_symbol": sink_sym,
                        "confidence": _clamp01(conf),
                        "path_description": path_desc,
                        "method": "static_inference",
                        "source_type": source_type or "generic",
                        "web_server": is_web,
                    }
                )
                trace_count += 1

        # From binary_analysis pairs (fallback if enhanced_source was sparse)
        for bp in ba_pairs:
            if trace_count >= _MAX_PATHS:
                break
            bp_binary = str(bp.get("binary", ""))
            bp_inputs = bp.get("input_syms", [])
            bp_sinks = bp.get("sink_syms", [])
            if not isinstance(bp_inputs, list):
                bp_inputs = []
            if not isinstance(bp_sinks, list):
                bp_sinks = []

            # Collect all symbols for FP rules
            bp_all_syms: set[str] = set()
            for _s in (bp_inputs if isinstance(bp_inputs, list) else []):
                if isinstance(_s, str):
                    bp_all_syms.add(_s.lower())
            for _s in (bp_sinks if isinstance(bp_sinks, list) else []):
                if isinstance(_s, str):
                    bp_all_syms.add(_s.lower())

            src_apis = bp_inputs if bp_inputs else bp_sinks
            for src_api_str in src_apis:
                if not isinstance(src_api_str, str):
                    continue
                for sink_str in bp_sinks:
                    if not isinstance(sink_str, str):
                        continue
                    dedup_key = (bp_binary, src_api_str, sink_str)
                    if dedup_key in seen_static:
                        continue
                    seen_static.add(dedup_key)
                    if trace_count >= _MAX_PATHS:
                        break

                    # FP Rule 1: constant-sink gate
                    if func_map and _check_constant_sink(func_map, sink_str):
                        limitations.append(
                            f"FP suppressed (constant-sink): {bp_binary}:{sink_str}"
                        )
                        continue

                    bp_conf = 0.50 if bp_inputs else 0.40

                    # FP Rule 2: non-network binary
                    if not _has_network_input_symbol(bp_all_syms):
                        bp_conf = min(bp_conf, 0.25)

                    # FP Rule 3: sanitizer
                    if _has_sanitizer_symbol(bp_all_syms):
                        bp_conf = max(0.0, bp_conf - 0.15)

                    # 2-tier confidence cap
                    if func_map:
                        bp_conf = min(bp_conf, STATIC_CODE_VERIFIED_CAP)
                    else:
                        bp_conf = min(bp_conf, SYMBOL_COOCCURRENCE_CAP)
                    taint_entry_bp: dict[str, JsonValue] = {
                        "source_api": src_api_str,
                        "source_binary": bp_binary,
                        "sink_symbol": sink_str,
                        "taint_reaches_sink": True,
                        "confidence": _clamp01(bp_conf),
                        "path_description": (
                            f"Static inference from binary_analysis: "
                            f"{bp_binary} imports {src_api_str}() and "
                            f"{sink_str}()"
                        ),
                        "method": "static_inference_ba",
                    }
                    taint_results.append(taint_entry_bp)
                    alerts.append(
                        {
                            "source_api": src_api_str,
                            "source_binary": bp_binary,
                            "source_address": "0x0",
                            "sink_symbol": sink_str,
                            "confidence": _clamp01(bp_conf),
                            "path_description": cast(
                                str, taint_entry_bp["path_description"]
                            ),
                            "method": "static_inference_ba",
                        }
                    )
                    trace_count += 1

        # From source_sink_graph paths
        for ssp in ss_paths:
            if trace_count >= _MAX_PATHS:
                break
            sink_any = ssp.get("sink")
            source_any = ssp.get("source")
            if not isinstance(sink_any, dict):
                continue
            sink_obj = cast(dict[str, object], sink_any)
            sink_bin = str(sink_obj.get("binary", ""))
            sink_syms_list: list[str] = []
            ss_any = sink_obj.get("symbols")
            if isinstance(ss_any, list):
                for s in cast(list[object], ss_any):
                    if isinstance(s, str):
                        sink_syms_list.append(s)
            src_type = ""
            if isinstance(source_any, dict):
                src_type = str(cast(dict[str, object], source_any).get("type", ""))
            ssp_conf_any = ssp.get("confidence")
            ssp_conf = (
                _clamp01(float(ssp_conf_any))
                if isinstance(ssp_conf_any, (int, float))
                else 0.40
            )

            for ss_sym in sink_syms_list:
                dedup_key = (sink_bin, src_type or "network", ss_sym)
                if dedup_key in seen_static:
                    continue
                seen_static.add(dedup_key)
                if trace_count >= _MAX_PATHS:
                    break
                taint_entry_ss: dict[str, JsonValue] = {
                    "source_api": src_type or "network_input",
                    "source_binary": sink_bin,
                    "sink_symbol": ss_sym,
                    "taint_reaches_sink": True,
                    "confidence": _clamp01(min(ssp_conf, 0.50)),
                    "path_description": (
                        f"Source-sink graph path: {src_type} source -> "
                        f"{sink_bin} -> {ss_sym}()"
                    ),
                    "method": "source_sink_graph",
                }
                taint_results.append(taint_entry_ss)
                alerts.append(
                    {
                        "source_api": src_type or "network_input",
                        "source_binary": sink_bin,
                        "source_address": "0x0",
                        "sink_symbol": ss_sym,
                        "confidence": _clamp01(min(ssp_conf, 0.50)),
                        "path_description": cast(
                            str, taint_entry_ss["path_description"]
                        ),
                        "method": "source_sink_graph",
                    }
                )
                trace_count += 1

        # === LLM TAINT TRACE (when available and not --no-llm) ===
        if not self.no_llm and source_list and func_map:
            driver = resolve_driver()
            if not driver.available():
                limitations.append("LLM driver not available for taint analysis")
            else:
                # Collect unique sink symbols
                sink_symbols: set[str] = set()
                for sb in sink_binaries:
                    syms_any2 = sb.get("symbols")
                    if isinstance(syms_any2, list):
                        for sym in cast(list[object], syms_any2):
                            if isinstance(sym, str) and sym.lower() in {
                                s.lower() for s in _SINK_SYMBOLS
                            }:
                                sink_symbols.add(sym)
                if not sink_symbols:
                    sink_symbols = {"system", "popen", "strcpy"}

                body_cache: dict[str, dict[str, object]] = {}
                for source in source_list[:_MAX_PATHS]:
                    src_api = str(source.get("api", ""))
                    src_binary = str(source.get("binary", ""))
                    src_addr = str(source.get("address", "0x0"))

                    for sink_sym in sorted(sink_symbols):
                        if trace_count >= _MAX_PATHS:
                            limitations.append(
                                f"Taint trace capped at {_MAX_PATHS} paths"
                            )
                            break

                        relevant_funcs: list[dict[str, str]] = []
                        llm_src_basename = (
                            src_binary.rsplit("/", 1)[-1]
                            if "/" in src_binary
                            else src_binary
                        )
                        src_lower = src_api.lower()
                        sink_lower = sink_sym.lower()
                        # Prioritize: functions with BOTH source+sink, then single match
                        both_match: list[dict[str, str]] = []
                        single_match: list[dict[str, str]] = []
                        for _key, finfo in func_map.items():
                            fb = finfo.get("binary", "")
                            if llm_src_basename and fb and llm_src_basename not in fb:
                                continue
                            body_lower = finfo["body"].lower()
                            has_src = src_lower in body_lower
                            has_sink = sink_lower in body_lower
                            if has_src and has_sink:
                                both_match.append(finfo)
                            elif has_src or has_sink:
                                single_match.append(finfo)
                        # Prepend xref call chain functions if available
                        chain_funcs: list[dict[str, str]] = []
                        if xref_map:
                            chain = _trace_call_chain(xref_map, src_api, sink_sym)
                            if chain:
                                seen_names = set()
                                for cfname in chain:
                                    for _k, fi in func_map.items():
                                        if (
                                            fi["name"] == cfname
                                            and fi["name"] not in seen_names
                                        ):
                                            fb = fi.get("binary", "")
                                            if (
                                                not llm_src_basename
                                                or not fb
                                                or llm_src_basename in fb
                                            ):
                                                chain_funcs.append(fi)
                                                seen_names.add(fi["name"])
                                                break
                        # Merge: chain functions first, then both-match, then single
                        seen = {f["name"] for f in chain_funcs}
                        merged = list(chain_funcs)
                        for f in both_match + single_match:
                            if f["name"] not in seen:
                                merged.append(f)
                                seen.add(f["name"])
                        relevant_funcs = merged[:10]

                        if not relevant_funcs:
                            continue

                        combined_hash = _hash_body(
                            "|".join(f["body"] for f in relevant_funcs)
                            + f"|{src_api}|{sink_sym}"
                        )
                        if combined_hash in body_cache:
                            cached = body_cache[combined_hash]
                            taint_results.append(
                                cast(dict[str, JsonValue], dict(cached))
                            )
                            if cached.get("taint_reaches_sink"):
                                alerts.append(
                                    {
                                        "source_api": src_api,
                                        "source_binary": src_binary,
                                        "source_address": src_addr,
                                        "sink_symbol": sink_sym,
                                        "confidence": _clamp01(
                                            safe_float(
                                                cached.get("confidence"),
                                                default=0.5,
                                            )
                                        ),
                                        "path_description": str(
                                            cached.get("path_description", "")
                                        ),
                                        "method": "llm_taint_trace",
                                        "cached": True,
                                    }
                                )
                            trace_count += 1
                            continue

                        prompt = _build_taint_prompt(src_api, sink_sym, relevant_funcs)
                        result = driver.execute(
                            prompt=prompt,
                            run_dir=run_dir,
                            timeout_s=_LLM_TIMEOUT_S,
                            max_attempts=_LLM_MAX_ATTEMPTS,
                            retryable_tokens=_RETRYABLE_TOKENS,
                            model_tier="sonnet",
                            system_prompt=TAINT_SYSTEM,
                            temperature=TEMPERATURE_DETERMINISTIC,
                        )

                        trace_entry_llm: dict[str, object] = {
                            "source_api": src_api,
                            "source_binary": src_binary,
                            "sink_symbol": sink_sym,
                            "taint_reaches_sink": False,
                            "confidence": 0.0,
                            "path_description": "",
                            "llm_status": result.status,
                        }

                        if result.status == "ok":
                            parsed = _parse_json_response(result.stdout)
                            if parsed is not None:
                                reaches = bool(parsed.get("taint_reaches_sink", False))
                                conf_any = parsed.get("confidence", 0.5)
                                conf_val = (
                                    _clamp01(float(conf_any))
                                    if isinstance(conf_any, (int, float))
                                    else 0.5
                                )
                                # Cap LLM confidence to match governance model
                                conf_val = min(conf_val, STATIC_CODE_VERIFIED_CAP)
                                path_desc = str(parsed.get("path_description", ""))
                                sanitizers = parsed.get("sanitizers_found", [])

                                trace_entry_llm["taint_reaches_sink"] = reaches
                                trace_entry_llm["confidence"] = conf_val
                                trace_entry_llm["path_description"] = path_desc
                                trace_entry_llm["sanitizers_found"] = sanitizers

                                if reaches:
                                    alerts.append(
                                        {
                                            "source_api": src_api,
                                            "source_binary": src_binary,
                                            "source_address": src_addr,
                                            "sink_symbol": sink_sym,
                                            "confidence": conf_val,
                                            "path_description": path_desc,
                                            "sanitizers_found": cast(
                                                list[JsonValue],
                                                (
                                                    cast(list[object], sanitizers)
                                                    if isinstance(sanitizers, list)
                                                    else []
                                                ),
                                            ),
                                            "method": "llm_taint_trace",
                                            "cached": False,
                                        }
                                    )

                        body_cache[combined_hash] = trace_entry_llm
                        taint_results.append(
                            cast(dict[str, JsonValue], trace_entry_llm)
                        )
                        trace_count += 1

                    if trace_count >= _MAX_PATHS:
                        break
        elif self.no_llm:
            limitations.append("LLM taint tracing skipped (no_llm mode)")

        # Cap alerts
        if len(alerts) > _MAX_ALERTS:
            limitations.append(f"Alerts capped at {_MAX_ALERTS}")
            alerts = alerts[:_MAX_ALERTS]

        try:
            annotate_findings_with_evidence_tiers(
                cast(list[dict[str, object]], cast(list[object], taint_results))
            )
            annotate_findings_with_evidence_tiers(
                cast(list[dict[str, object]], cast(list[object], alerts))
            )
        except Exception:
            pass

        _write_results(
            stage_dir,
            results_json,
            alerts_json,
            taint_results,
            alerts,
            limitations,
        )

        status: StageStatus = "ok" if alerts else "partial"
        if not source_list and not ba_pairs and not ss_paths:
            status = "partial"

        details: dict[str, JsonValue] = {
            "traces": len(taint_results),
            "alerts": len(alerts),
            "static_inferences": sum(
                1
                for t in taint_results
                if isinstance(t, dict) and str(t.get("method", "")).startswith("static")
            ),
        }
        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )


def _write_skipped(
    stage_dir: Path,
    results_json: Path,
    alerts_json: Path,
) -> None:
    for path, key in ((results_json, "results"), (alerts_json, "alerts")):
        payload: dict[str, JsonValue] = {
            "schema_version": _SCHEMA_VERSION,
            "status": "skipped",
            "reason": "no_llm_mode",
            key: [],
        }
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )


def _write_results(
    stage_dir: Path,
    results_json: Path,
    alerts_json: Path,
    taint_results: list[dict[str, JsonValue]],
    alerts: list[dict[str, JsonValue]],
    limitations: list[str],
) -> None:
    results_payload: dict[str, JsonValue] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "ok" if taint_results else "partial",
        "total_traces": len(taint_results),
        "results": cast(list[JsonValue], cast(list[object], taint_results)),
        "limitations": cast(
            list[JsonValue], cast(list[object], sorted(set(limitations)))
        ),
    }
    results_json.write_text(
        json.dumps(results_payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    alerts_payload: dict[str, JsonValue] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "ok" if alerts else "partial",
        "total_alerts": len(alerts),
        "alerts": cast(list[JsonValue], cast(list[object], alerts)),
        "limitations": cast(
            list[JsonValue], cast(list[object], sorted(set(limitations)))
        ),
    }
    alerts_json.write_text(
        json.dumps(alerts_payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
