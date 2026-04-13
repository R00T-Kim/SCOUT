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

import hashlib
import json
import logging
import os
import subprocess
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

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_STAGE_NAME = "ghidra_analysis"

# Symbols that raise exploitation interest and drive binary prioritisation
_RISKY_SYMBOLS: frozenset[str] = frozenset(
    {
        "system",
        "popen",
        "execve",
        "execvp",
        "execl",
        "execle",
        "execlp",
        "strcpy",
        "strcat",
        "sprintf",
        "vsprintf",
        "gets",
    }
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
# PyGhidra fallback
# ---------------------------------------------------------------------------

_MAX_FUNCTIONS_PER_BINARY = 500


def _pyghidra_available() -> bool:
    """Return True if pyghidra can be imported."""
    try:
        import pyghidra as _pg  # type: ignore[import-not-found]  # noqa: F401  # optional runtime dep

        return True
    except ImportError:
        return False


def _run_pyghidra_decompile(
    binary_path: Path,
    output_dir: Path,
    run_dir: Path,
    timeout_s: float = 300.0,
) -> dict[str, object]:
    """Decompile a binary using the pyghidra API (Ghidra 12+ fallback).

    Writes ``decompile_all.json`` and ``xref_graph.json`` into
    ``output_dir/<sha256>/``.  Returns the same dict shape as
    :func:`ghidra_bridge.analyze_binary`.
    """
    h = hashlib.sha256()
    with open(binary_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    binary_hash = h.hexdigest()

    cache_dir = output_dir / binary_hash
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

    decompile_out = cache_dir / "decompile_all.json"
    xref_out = cache_dir / "xref_graph.json"
    pcode_out = cache_dir / "pcode_taint.json"

    # We run pyghidra in a subprocess to isolate JVM state and enforce timeout
    script = _PYGHIDRA_SCRIPT.format(
        binary_path=str(binary_path),
        decompile_out=str(decompile_out),
        xref_out=str(xref_out),
        pcode_out=str(pcode_out),
        max_functions=_MAX_FUNCTIONS_PER_BINARY,
    )

    # Ensure GHIDRA_INSTALL_DIR is set for pyghidra.start()
    env = os.environ.copy()
    ghidra_home = env.get("AIEDGE_GHIDRA_HOME", "")
    if ghidra_home and "GHIDRA_INSTALL_DIR" not in env:
        env["GHIDRA_INSTALL_DIR"] = ghidra_home

    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            ["python3", "-c", script],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=env,
        )
        if proc.returncode != 0:
            _log.warning(
                "pyghidra subprocess failed for %s: %s",
                binary_path.name,
                (proc.stderr or proc.stdout)[:500],
            )
    except subprocess.TimeoutExpired:
        _log.warning(
            "pyghidra timed out for %s after %.0fs", binary_path.name, timeout_s
        )
    except Exception as exc:
        _log.warning("pyghidra launch failed for %s: %s", binary_path.name, exc)

    duration = time.monotonic() - t0

    result_files: dict[str, str | None] = {}
    for name, path in [
        ("decompile_all.json", decompile_out),
        ("xref_graph.json", xref_out),
        ("pcode_taint.json", pcode_out),
    ]:
        if path.is_file():
            try:
                result_files[name] = str(path.relative_to(run_dir))
            except ValueError:
                result_files[name] = str(path)
        else:
            result_files[name] = None

    succeeded_count = sum(1 for v in result_files.values() if v is not None)
    if succeeded_count == len(result_files) and succeeded_count > 0:
        status = "ok"
    elif succeeded_count > 0:
        status = "partial"
    else:
        status = "failed"

    return {
        "status": status,
        "binary_hash": binary_hash,
        "binary_path": str(binary_path),
        "result_files": result_files,
        "duration_s": round(duration, 2),
        "error": None,
        "method": "pyghidra",
    }


# Inline Python script executed in a subprocess for JVM isolation
_PYGHIDRA_SCRIPT = r"""
import json, sys, os

binary_path = r"{binary_path}"
decompile_out = r"{decompile_out}"
xref_out = r"{xref_out}"
pcode_out = r"{pcode_out}"
max_functions = {max_functions}

SOURCE_APIS = frozenset([
    "recv", "recvfrom", "recvmsg", "read", "fread", "fgets", "gets",
    "getenv", "nvram_get", "nvram_safe_get", "acosNvramConfig_get",
    "websGetVar", "httpGetEnv", "wp_getVar",
    "scanf", "sscanf", "fscanf",
    "cJSON_GetObjectItem", "json_object_get_string",
    "cJSON_Parse", "json_tokener_parse",
])
SINK_APIS = frozenset([
    "system", "popen", "execve", "execv", "execl", "execlp", "execle",
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "memcpy",
    "doSystemCmd", "twsystem", "doSystem",
])
SANITIZER_APIS = frozenset([
    "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull",
    "inet_aton", "inet_addr", "inet_pton",
])
HIGH_RISK_SINKS = frozenset([
    "system", "popen", "execve", "execv", "execl", "execlp", "execle",
    "doSystemCmd", "twsystem", "doSystem",
])

def resolve_call_target(call_op, high_func):
    if call_op.getNumInputs() < 1:
        return ""
    target_vn = call_op.getInput(0)
    if target_vn is None:
        return ""
    addr = target_vn.getAddress()
    if addr is None:
        return ""
    prog = high_func.getFunction().getProgram()
    f = prog.getFunctionManager().getFunctionAt(addr)
    if f is not None:
        return f.getName()
    s = prog.getSymbolTable().getPrimarySymbol(addr)
    if s is not None:
        return s.getName()
    return ""

def trace_pcode_forward(high_func, source_call_addr, max_depth=8):
    traces = []
    if high_func is None:
        return traces
    pcode_iter = high_func.getPcodeOps()
    if pcode_iter is None:
        return traces
    all_ops = []
    while pcode_iter.hasNext():
        all_ops.append(pcode_iter.next())
    # Find CALL ops near source address
    source_outputs = []
    for op in all_ops:
        if op.getOpcode() not in (4, 5):
            continue
        diff = abs(op.getSeqnum().getTarget().getOffset() - source_call_addr.getOffset())
        if diff > 16:
            continue
        out = op.getOutput()
        if out is not None:
            source_outputs.append(out)
    if not source_outputs:
        return traces
    visited = set()
    queue = list(source_outputs)
    sanitized = False
    reached = []
    depth = 0
    while queue and depth < max_depth:
        nxt = []
        for vn in queue:
            vid = vn.getUniqueId()
            if vid in visited:
                continue
            visited.add(vid)
            desc = vn.getDescendants()
            if desc is None:
                continue
            while desc.hasNext():
                use_op = desc.next()
                if use_op.getOpcode() in (4, 5):
                    callee = resolve_call_target(use_op, high_func)
                    if callee in SINK_APIS:
                        reached.append({{"sink": callee, "address": str(use_op.getSeqnum().getTarget()), "depth": depth}})
                    elif callee in SANITIZER_APIS:
                        sanitized = True
                out = use_op.getOutput()
                if out is not None:
                    nxt.append(out)
        queue = nxt
        depth += 1
    for r in reached:
        conf = 0.75
        if sanitized:
            conf = 0.20
        elif r["sink"] in HIGH_RISK_SINKS:
            conf = 0.80
        traces.append({{
            "sink": r["sink"], "sink_address": r["address"], "depth": r["depth"],
            "sanitized": sanitized, "confidence": max(0.10, min(0.90, conf)),
            "source_address": str(source_call_addr),
        }})
    return traces

try:
    import pyghidra
    pyghidra.start()
    from ghidra.app.decompiler import DecompInterface

    functions_data = []
    xref_data = []
    pcode_traces = []
    pcode_errors = []

    with pyghidra.open_program(binary_path) as flat:
        prog = flat.getCurrentProgram()
        decomp = DecompInterface()
        decomp.openProgram(prog)
        sym_table = prog.getSymbolTable()
        ref_mgr = prog.getReferenceManager()
        fm = prog.getFunctionManager()

        func = flat.getFirstFunction()
        count = 0
        while func and count < max_functions:
            entry = str(func.getEntryPoint())
            fname = func.getName()
            body = ""
            try:
                results = decomp.decompileFunction(func, 30, None)
                if results and results.decompileCompleted():
                    c = results.getDecompiledFunction()
                    if c:
                        body = c.getC()
            except Exception:
                pass

            functions_data.append({{
                "name": fname,
                "address": entry,
                "body": body,
            }})

            # Collect cross-references (callers -> callee)
            try:
                refs = func.getCallingFunctions(None)
                if refs:
                    for caller in refs:
                        xref_data.append({{
                            "caller": caller.getName(),
                            "caller_addr": str(caller.getEntryPoint()),
                            "callee": fname,
                            "callee_addr": entry,
                        }})
            except Exception:
                pass

            func = flat.getFunctionAfter(func)
            count += 1

        # --- P-code taint analysis ---
        # Strategy 1: symbol table xrefs (works for non-stripped binaries)
        source_sites = {{}}
        sink_funcs = set()
        for api in SOURCE_APIS:
            for sym in sym_table.getGlobalSymbols(api):
                for ref in ref_mgr.getReferencesTo(sym.getAddress()):
                    if not ref.getReferenceType().isCall():
                        continue
                    caller = fm.getFunctionContaining(ref.getFromAddress())
                    if caller:
                        e = caller.getEntryPoint()
                        source_sites.setdefault(e, []).append((ref.getFromAddress(), api))

        for api in SINK_APIS:
            for sym in sym_table.getGlobalSymbols(api):
                for ref in ref_mgr.getReferencesTo(sym.getAddress()):
                    if ref.getReferenceType().isCall():
                        caller = fm.getFunctionContaining(ref.getFromAddress())
                        if caller:
                            sink_funcs.add(caller.getEntryPoint())

        candidates = set(source_sites.keys()) & sink_funcs

        # Strategy 2: fallback — scan decompiled body text for source/sink calls
        # This handles stripped binaries where getGlobalSymbols returns nothing
        if not candidates and functions_data:
            import re as _re
            _src_pat = _re.compile(r'\b(' + '|'.join(sorted(SOURCE_APIS)) + r')\s*\(')
            _sink_pat = _re.compile(r'\b(' + '|'.join(sorted(SINK_APIS)) + r')\s*\(')
            _body_source_funcs = {{}}  # func_entry -> [(entry_addr, api_name)]
            _body_sink_funcs = set()
            _func_lookup = {{}}  # name -> Function
            f2 = flat.getFirstFunction()
            while f2:
                _func_lookup[f2.getName()] = f2
                f2 = flat.getFunctionAfter(f2)

            for fd in functions_data:
                fname = fd.get("name", "")
                body = fd.get("body", "")
                if not body or not fname:
                    continue
                f_obj = _func_lookup.get(fname)
                if f_obj is None:
                    continue
                entry = f_obj.getEntryPoint()
                src_matches = _src_pat.findall(body)
                sink_matches = _sink_pat.findall(body)
                if src_matches:
                    for api in set(src_matches):
                        _body_source_funcs.setdefault(entry, []).append((entry, api))
                if sink_matches:
                    _body_sink_funcs.add(entry)

            candidates = set(_body_source_funcs.keys()) & _body_sink_funcs
            if candidates:
                source_sites = _body_source_funcs
        analyzed_pcode = 0
        for func_entry in sorted(candidates, key=lambda a: a.getOffset()):
            if analyzed_pcode >= 100:
                break
            f = fm.getFunctionAt(func_entry)
            if f is None:
                continue
            try:
                res = decomp.decompileFunction(f, 10, None)
                if res is None or not res.decompileCompleted():
                    continue
                hf = res.getHighFunction()
                if hf is None:
                    continue

                # Collect source APIs expected in this function
                expected_sources = set()
                for _, api in source_sites.get(func_entry, []):
                    expected_sources.add(api)

                # Scan ALL CALL ops in P-code to find source API calls directly
                pcode_iter2 = hf.getPcodeOps()
                if pcode_iter2 is not None:
                    source_call_ops = []
                    while pcode_iter2.hasNext():
                        op = pcode_iter2.next()
                        if op.getOpcode() in (4, 5):
                            callee = resolve_call_target(op, hf)
                            if callee in expected_sources or callee in SOURCE_APIS:
                                out = op.getOutput()
                                if out is not None:
                                    source_call_ops.append((op, callee, out))

                    # For each source call, do forward taint from its output varnode
                    for src_op, src_api_name, src_out in source_call_ops:
                        visited = set()
                        queue = [src_out]
                        sanitized = False
                        reached = []
                        depth = 0
                        while queue and depth < 8:
                            nxt = []
                            for vn in queue:
                                vid = vn.getUniqueId()
                                if vid in visited:
                                    continue
                                visited.add(vid)
                                desc = vn.getDescendants()
                                if desc is None:
                                    continue
                                while desc.hasNext():
                                    use_op = desc.next()
                                    if use_op.getOpcode() in (4, 5):
                                        callee2 = resolve_call_target(use_op, hf)
                                        if callee2 in SINK_APIS:
                                            reached.append({{"sink": callee2, "address": str(use_op.getSeqnum().getTarget()), "depth": depth}})
                                        elif callee2 in SANITIZER_APIS:
                                            sanitized = True
                                    out2 = use_op.getOutput()
                                    if out2 is not None:
                                        nxt.append(out2)
                            queue = nxt
                            depth += 1

                        for r in reached:
                            conf = 0.75
                            if sanitized:
                                conf = 0.20
                            elif r["sink"] in HIGH_RISK_SINKS:
                                conf = 0.80
                            pcode_traces.append({{
                                "source_api": src_api_name,
                                "sink": r["sink"],
                                "sink_address": r["address"],
                                "source_address": str(src_op.getSeqnum().getTarget()),
                                "function": f.getName(),
                                "function_address": str(func_entry),
                                "depth": r["depth"],
                                "sanitized": sanitized,
                                "confidence": max(0.10, min(0.90, conf)),
                                "risk": "high" if r["sink"] in HIGH_RISK_SINKS else "medium",
                                "method": "pcode_dataflow",
                            }})

                # Fallback: if no dataflow traces found but source+sink CALLs both exist
                # in P-code, emit a "pcode_colocated" trace (higher than symbol co-occurrence)
                if not any(t.get("function") == f.getName() for t in pcode_traces):
                    pcode_iter3 = hf.getPcodeOps()
                    found_sources_in_pcode = set()
                    found_sinks_in_pcode = set()
                    if pcode_iter3 is not None:
                        while pcode_iter3.hasNext():
                            op3 = pcode_iter3.next()
                            if op3.getOpcode() in (4, 5):
                                callee3 = resolve_call_target(op3, hf)
                                if callee3 in SOURCE_APIS:
                                    found_sources_in_pcode.add(callee3)
                                elif callee3 in SINK_APIS:
                                    found_sinks_in_pcode.add(callee3)
                    if found_sources_in_pcode and found_sinks_in_pcode:
                        for src_a in found_sources_in_pcode:
                            for sink_a in found_sinks_in_pcode:
                                conf = 0.60
                                if sink_a in HIGH_RISK_SINKS:
                                    conf = 0.65
                                pcode_traces.append({{
                                    "source_api": src_a,
                                    "sink": sink_a,
                                    "sink_address": "0x0",
                                    "source_address": "0x0",
                                    "function": f.getName(),
                                    "function_address": str(func_entry),
                                    "depth": -1,
                                    "sanitized": False,
                                    "confidence": conf,
                                    "risk": "high" if sink_a in HIGH_RISK_SINKS else "medium",
                                    "method": "pcode_colocated",
                                }})
            except Exception as ex:
                pcode_errors.append({{"function": f.getName(), "error": str(ex)}})
            analyzed_pcode += 1

        # Strategy 3: decompiled body text analysis (most robust for stripped binaries)
        # If P-code analysis found no traces, fall back to function-level body scanning
        if not pcode_traces and functions_data:
            import re as _re2
            _src_pat2 = _re2.compile(r'\b(' + '|'.join(sorted(SOURCE_APIS)) + r')\s*\(')
            _sink_pat2 = _re2.compile(r'\b(' + '|'.join(sorted(SINK_APIS)) + r')\s*\(')
            _san_pat2 = _re2.compile(r'\b(' + '|'.join(sorted(SANITIZER_APIS)) + r')\s*\(')
            for fd in functions_data:
                fname = fd.get("name", "")
                body = fd.get("body", "")
                addr = fd.get("address", "0x0")
                if not body or not fname:
                    continue
                src_hits = set(_src_pat2.findall(body))
                sink_hits = set(_sink_pat2.findall(body))
                if not src_hits or not sink_hits:
                    continue
                san_hits = set(_san_pat2.findall(body))
                sanitized = len(san_hits) > 0
                for src_a in src_hits:
                    for sink_a in sink_hits:
                        conf = 0.45
                        if sanitized:
                            conf = 0.25
                        elif sink_a in HIGH_RISK_SINKS:
                            conf = 0.50
                        pcode_traces.append({{
                            "source_api": src_a,
                            "sink": sink_a,
                            "sink_address": "0x0",
                            "source_address": "0x0",
                            "function": fname,
                            "function_address": addr,
                            "depth": -1,
                            "sanitized": sanitized,
                            "confidence": conf,
                            "risk": "high" if sink_a in HIGH_RISK_SINKS else "medium",
                            "method": "decompiled_colocated",
                        }})

        # Strategy 4: Interprocedural — cross-function source→sink via xref chain
        # Uses xref_data (caller→callee) to find: func A has source, calls func B which has sink
        if functions_data and xref_data:
            import re as _re3
            _src_pat3 = _re3.compile(r'\b(' + '|'.join(sorted(SOURCE_APIS)) + r')\s*\(')
            _sink_pat3 = _re3.compile(r'\b(' + '|'.join(sorted(SINK_APIS)) + r')\s*\(')
            _san_pat3 = _re3.compile(r'\b(' + '|'.join(sorted(SANITIZER_APIS)) + r')\s*\(')

            # Build per-function source/sink sets from body text
            _func_sources = {{}}  # fname -> set of source APIs
            _func_sinks = {{}}    # fname -> set of sink APIs
            _func_addr = {{}}     # fname -> address
            _func_san = {{}}      # fname -> bool (has sanitizer)
            for fd in functions_data:
                fn = fd.get("name", "")
                body = fd.get("body", "")
                if not fn or not body:
                    continue
                _func_addr[fn] = fd.get("address", "0x0")
                s = set(_src_pat3.findall(body))
                k = set(_sink_pat3.findall(body))
                if s:
                    _func_sources[fn] = s
                if k:
                    _func_sinks[fn] = k
                _func_san[fn] = bool(_san_pat3.findall(body))

            # Build caller→callee map (1-hop)
            _call_graph = {{}}  # caller_name -> [callee_names]
            for xr in xref_data:
                if not isinstance(xr, dict):
                    continue
                caller_n = xr.get("caller", "")
                callee_n = xr.get("callee", "")
                if caller_n and callee_n:
                    _call_graph.setdefault(caller_n, []).append(callee_n)

            # Find interprocedural pairs: source_func calls sink_func
            _seen_interproc = set()
            for src_func, src_apis in _func_sources.items():
                if src_func in _func_sinks:
                    continue  # already intraprocedural — handled by Strategy 3
                for callee_name in _call_graph.get(src_func, []):
                    if callee_name not in _func_sinks:
                        continue
                    sink_apis_in_callee = _func_sinks[callee_name]
                    sanitized = _func_san.get(src_func, False) or _func_san.get(callee_name, False)
                    for src_a in src_apis:
                        for sink_a in sink_apis_in_callee:
                            pair_key = (src_func, callee_name, src_a, sink_a)
                            if pair_key in _seen_interproc:
                                continue
                            _seen_interproc.add(pair_key)
                            conf = 0.55
                            if sanitized:
                                conf = 0.25
                            elif sink_a in HIGH_RISK_SINKS:
                                conf = 0.60
                            pcode_traces.append({{
                                "source_api": src_a,
                                "sink": sink_a,
                                "sink_address": _func_addr.get(callee_name, "0x0"),
                                "source_address": _func_addr.get(src_func, "0x0"),
                                "function": "{{0}}->{{1}}".format(src_func, callee_name),
                                "function_address": _func_addr.get(src_func, "0x0"),
                                "depth": 1,
                                "sanitized": sanitized,
                                "confidence": conf,
                                "risk": "high" if sink_a in HIGH_RISK_SINKS else "medium",
                                "method": "decompiled_interprocedural",
                            }})

        decomp.dispose()

    with open(decompile_out, "w") as f:
        json.dump(functions_data, f, indent=2)
    with open(xref_out, "w") as f:
        json.dump(xref_data, f, indent=2)
    with open(pcode_out, "w") as f:
        json.dump({{
            "schema_version": "pcode-taint-v1",
            "traces": pcode_traces,
            "summary": {{
                "candidate_functions": len(candidates),
                "analyzed_functions": analyzed_pcode,
                "total_traces": len(pcode_traces),
                "high_risk_traces": sum(1 for t in pcode_traces if t.get("risk") == "high"),
                "sanitized_traces": sum(1 for t in pcode_traces if t.get("sanitized")),
            }},
            "errors": pcode_errors,
        }}, f, indent=2)

except Exception as e:
    print(f"pyghidra error: {{e}}", file=sys.stderr)
    sys.exit(1)
"""


def _aggregate_decompiled_functions(
    stage_dir: Path,
    run_dir: Path,
    analysis_results: list[dict[str, object]],
) -> bool:
    """Aggregate all decompiled functions into a single JSON file.

    Returns True if the file was written successfully.
    """
    all_functions: list[dict[str, str]] = []

    results_dir = stage_dir / "results"
    if not results_dir.is_dir():
        return False

    for result in analysis_results:
        binary_name = str(result.get("binary", ""))
        result_files = result.get("result_files", {})
        if not isinstance(result_files, dict):
            continue
        decompile_rel = result_files.get("decompile_all.json")
        if not decompile_rel:
            continue
        decompile_path = run_dir / decompile_rel
        if not decompile_path.is_file():
            continue
        try:
            data = json.loads(decompile_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        for entry in data:
            if isinstance(entry, dict):
                all_functions.append(
                    {
                        "name": str(entry.get("name", "")),
                        "binary": binary_name,
                        "address": str(entry.get("address", "")),
                        "body": str(entry.get("body", "")),
                    }
                )

    if not all_functions:
        return False

    out_path = stage_dir / "decompiled_functions.json"
    try:
        assert_under_dir(run_dir, out_path)
        out_path.write_text(
            json.dumps({"functions": all_functions}, ensure_ascii=False, indent=2)
            + "\n",
            encoding="utf-8",
        )
        return True
    except (OSError, AIEdgePolicyViolation):
        return False


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
        _has_headless = ghidra_available()
        _has_pyghidra = _pyghidra_available()
        if not _has_headless and not _has_pyghidra:
            return StageOutcome(
                status="skipped",
                details={
                    "reason": "Neither analyzeHeadless nor pyghidra available; set AIEDGE_GHIDRA_HOME"
                },
                limitations=["ghidra_not_installed"],
            )

        # ------------------------------------------------------------------
        # 2. Load inventory binary_analysis.json
        # ------------------------------------------------------------------
        inv_path = run_dir / "stages" / "inventory" / "binary_analysis.json"
        if not inv_path.is_file():
            return StageOutcome(
                status="skipped",
                details={
                    "reason": "binary_analysis.json missing; inventory stage required"
                },
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
            h
            for h in (hits_raw if isinstance(hits_raw, list) else [])
            if isinstance(h, dict) and h.get("path")
        ]

        # ------------------------------------------------------------------
        # 3. Select and prioritise binaries
        # ------------------------------------------------------------------
        max_binaries = env_int(
            "AIEDGE_GHIDRA_MAX_BINARIES", default=10, min_value=1, max_value=50
        )
        timeout_per = float(
            env_int(
                "AIEDGE_GHIDRA_TIMEOUT_S", default=300, min_value=30, max_value=1800
            )
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

            result: dict[str, object] | None = None

            # Try analyzeHeadless first (works with older Ghidra versions)
            if _has_headless:
                result = analyze_binary(
                    binary_path=bin_path,
                    output_dir=results_dir,
                    run_dir=run_dir,
                    timeout_s=timeout_per,
                )
                # Check if all result_files are null (analyzeHeadless failed)
                rf = result.get("result_files", {})
                all_null = (
                    isinstance(rf, dict) and rf and all(v is None for v in rf.values())
                )
                if result.get("status") == "failed" or all_null:
                    if _has_pyghidra:
                        _log.info(
                            "analyzeHeadless failed for %s, trying pyghidra fallback",
                            bin_path.name,
                        )
                        result = None  # fall through to pyghidra

            # PyGhidra fallback (Ghidra 12+ with pyghidra)
            if result is None and _has_pyghidra:
                result = _run_pyghidra_decompile(
                    binary_path=bin_path,
                    output_dir=results_dir,
                    run_dir=run_dir,
                    timeout_s=timeout_per,
                )

            if result is None:
                result = {
                    "status": "failed",
                    "binary_hash": "",
                    "binary_path": str(bin_path),
                    "result_files": {},
                    "duration_s": 0.0,
                    "error": "no_ghidra_backend_available",
                }

            analysis_results.append(
                {
                    "binary": str(hit.get("path", "")),
                    "status": result.get("status", "failed"),
                    "binary_hash": result.get("binary_hash", ""),
                    "result_files": result.get("result_files", {}),
                    "duration_s": result.get("duration_s", 0.0),
                    "error": result.get("error"),
                    "method": result.get("method", "analyzeHeadless"),
                }
            )

        # ------------------------------------------------------------------
        # 6. Compute aggregate statistics
        # ------------------------------------------------------------------
        binaries_succeeded = sum(1 for r in analysis_results if r.get("status") == "ok")
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
        # 7b. Aggregate decompiled functions across all binaries
        # ------------------------------------------------------------------
        if _aggregate_decompiled_functions(stage_dir, run_dir, analysis_results):
            _log.info("Wrote aggregated decompiled_functions.json")

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
        firmware_dest_any.parent if isinstance(firmware_dest_any, Path) else Path(".")
    )
    return GhidraAnalysisStage(
        run_dir=run_dir,
        case_id=case_id,
        remaining_budget_s=remaining_budget_s,
        no_llm=no_llm,
    )
