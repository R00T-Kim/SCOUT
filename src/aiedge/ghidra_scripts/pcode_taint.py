# Ghidra headless script for SCOUT
# @category SCOUT
# @description P-code based forward/backward taint analysis from sources to sinks
#
# Invoked by ghidra_bridge.py via:
#   analyzeHeadless ... -postScript pcode_taint.py <output_json_path>
#
# Unlike dataflow_trace.py (symbol co-occurrence only), this script uses
# Ghidra's High P-code SSA form to trace actual dataflow from source API
# return values through def-use chains to sink API parameters.
#
# Globals provided by Ghidra runtime: currentProgram, monitor, getScriptArgs

import json
import time

# --- Source APIs: functions that introduce external/untrusted data ---
SOURCE_APIS = frozenset([
    "recv", "recvfrom", "recvmsg", "read", "fread", "fgets", "gets",
    "getenv", "nvram_get", "nvram_safe_get", "acosNvramConfig_get",
    "websGetVar", "httpGetEnv", "wp_getVar", "getParameter",
    "scanf", "sscanf", "fscanf",
    "cJSON_GetObjectItem", "json_object_get_string",
    "cJSON_Parse", "json_tokener_parse",
])

# --- Sink APIs: functions where tainted data causes harm ---
SINK_APIS = frozenset([
    "system", "popen", "execve", "execv", "execl", "execlp", "execle",
    "strcpy", "strcat", "sprintf", "vsprintf", "gets",
    "memcpy", "memmove",
    "doSystemCmd", "twsystem", "doSystem",
])

# --- Sanitizer APIs: functions that convert tainted data to safe types ---
SANITIZER_APIS = frozenset([
    "atoi", "atol", "atoll",
    "strtol", "strtoul", "strtoll", "strtoull",
    "strtod", "strtof",
    "inet_aton", "inet_addr", "inet_pton",
    "isValidIpAddr",
])

# High-risk sinks that indicate command injection / code execution
HIGH_RISK_SINKS = frozenset([
    "system", "popen", "execve", "execv", "execl", "execlp", "execle",
    "doSystemCmd", "twsystem", "doSystem",
])

_MAX_FUNCTIONS = 100
_FUNCTION_TIMEOUT_S = 10
_MAX_TRACE_DEPTH = 8


def _get_high_function(decomp_iface, func, timeout_s=10):
    """Decompile function and return HighFunction with P-code SSA."""
    result = decomp_iface.decompileFunction(func, int(timeout_s), monitor)  # noqa: F821
    if result is None or not result.decompileCompleted():
        return None
    return result.getHighFunction()


def _resolve_symbol_refs(prog, sym_table, ref_mgr, fm, api_names):
    """Find all call sites for given API names.

    Returns dict: caller_func_addr -> [(call_addr, api_name)]
    """
    from ghidra.program.model.symbol import SourceType  # noqa: F401

    call_sites = {}
    for api_name in api_names:
        for sym in sym_table.getGlobalSymbols(api_name):
            for ref in ref_mgr.getReferencesTo(sym.getAddress()):
                if not ref.getReferenceType().isCall():
                    continue
                caller = fm.getFunctionContaining(ref.getFromAddress())
                if caller:
                    entry = caller.getEntryPoint()
                    call_sites.setdefault(entry, []).append(
                        (ref.getFromAddress(), api_name)
                    )
    return call_sites


def _trace_forward_pcode(high_func, source_call_addr, sink_apis, sanitizer_apis):
    """Forward taint trace using P-code SSA varnodes.

    Starting from the output varnode of a source call, follow def-use chains
    to see if tainted data reaches a sink call parameter.

    Returns list of trace dicts if taint reaches sink, empty list otherwise.
    """
    traces = []
    if high_func is None:
        return traces

    pcode_ops = high_func.getPcodeOps()
    if pcode_ops is None:
        return traces

    # Collect all P-code ops indexed by address and by output varnode
    ops_by_addr = {}
    ops_by_output = {}
    all_ops = []

    while pcode_ops.hasNext():
        op = pcode_ops.next()
        all_ops.append(op)
        addr = op.getSeqnum().getTarget()
        ops_by_addr.setdefault(str(addr), []).append(op)
        out = op.getOutput()
        if out is not None:
            ops_by_output[out.getUniqueId()] = op

    # Find CALL ops near the source call address
    source_output_varnodes = []
    for op in all_ops:
        opcode = op.getOpcode()
        # CALL = 4, CALLIND = 5
        if opcode not in (4, 5):
            continue
        op_addr = op.getSeqnum().getTarget()
        # Check if this call is at or near the source call address
        addr_diff = abs(op_addr.getOffset() - source_call_addr.getOffset())
        if addr_diff > 16:
            continue
        out = op.getOutput()
        if out is not None:
            source_output_varnodes.append(out)

    if not source_output_varnodes:
        return traces

    # BFS: follow def-use chain from source output varnodes
    visited = set()
    queue = list(source_output_varnodes)
    taint_path = []
    sanitized = False
    reached_sinks = []

    depth = 0
    while queue and depth < _MAX_TRACE_DEPTH:
        next_queue = []
        for varnode in queue:
            vid = varnode.getUniqueId()
            if vid in visited:
                continue
            visited.add(vid)

            # Check all P-code ops that use this varnode as input
            desc_iter = varnode.getDescendants()
            if desc_iter is None:
                continue

            while desc_iter.hasNext():
                use_op = desc_iter.next()
                use_opcode = use_op.getOpcode()

                # Check if this use is a CALL to a sink
                if use_opcode in (4, 5):
                    # Try to resolve called function name
                    callee_name = _resolve_call_target(use_op, high_func)
                    if callee_name in sink_apis:
                        reached_sinks.append({
                            "sink": callee_name,
                            "address": str(use_op.getSeqnum().getTarget()),
                            "depth": depth,
                        })
                    elif callee_name in sanitizer_apis:
                        sanitized = True
                        taint_path.append(
                            "sanitizer:%s@%s" % (callee_name, str(use_op.getSeqnum().getTarget()))
                        )

                # Propagate taint through the output of this op
                out = use_op.getOutput()
                if out is not None:
                    next_queue.append(out)
                    taint_path.append(
                        "op:%d@%s" % (use_opcode, str(use_op.getSeqnum().getTarget()))
                    )

        queue = next_queue
        depth += 1

    for sink_info in reached_sinks:
        traces.append({
            "source_address": str(source_call_addr),
            "sink": sink_info["sink"],
            "sink_address": sink_info["address"],
            "depth": sink_info["depth"],
            "sanitized": sanitized,
            "path_length": len(taint_path),
        })

    return traces


def _resolve_call_target(call_op, high_func):
    """Try to resolve the name of the function called by a CALL p-code op."""
    # Input 0 of a CALL is the target address
    if call_op.getNumInputs() < 1:
        return ""
    target_vn = call_op.getInput(0)
    if target_vn is None:
        return ""

    addr = target_vn.getAddress()
    if addr is None:
        return ""

    prog = high_func.getFunction().getProgram()
    fm = prog.getFunctionManager()
    func = fm.getFunctionAt(addr)
    if func is not None:
        return func.getName()

    # Try symbol table fallback
    sym = prog.getSymbolTable().getPrimarySymbol(addr)
    if sym is not None:
        return sym.getName()

    return ""


def run():
    args = getScriptArgs()  # noqa: F821 — Ghidra global
    output_path = args[0] if args else "/tmp/pcode_taint_output.json"

    results = {
        "schema_version": "pcode-taint-v1",
        "traces": [],
        "summary": {},
        "errors": [],
    }

    try:
        from ghidra.app.decompiler import DecompInterface

        prog = currentProgram  # noqa: F821
        sym_table = prog.getSymbolTable()
        ref_mgr = prog.getReferenceManager()
        fm = prog.getFunctionManager()

        decomp = DecompInterface()
        decomp.openProgram(prog)

        # Find all source and sink call sites
        source_sites = _resolve_symbol_refs(prog, sym_table, ref_mgr, fm, SOURCE_APIS)
        sink_sites = _resolve_symbol_refs(prog, sym_table, ref_mgr, fm, SINK_APIS)

        # Only analyze functions that have BOTH source and sink calls
        candidate_funcs = set(source_sites.keys()) & set(sink_sites.keys())

        analyzed = 0
        total_traces = 0
        t_start = time.time()

        for func_entry in sorted(candidate_funcs, key=lambda a: a.getOffset()):
            if analyzed >= _MAX_FUNCTIONS:
                break

            func = fm.getFunctionAt(func_entry)
            if func is None:
                continue

            # Per-function timeout
            func_start = time.time()
            try:
                high_func = _get_high_function(decomp, func, _FUNCTION_TIMEOUT_S)
                if high_func is None:
                    results["errors"].append({
                        "function": func.getName(),
                        "address": str(func_entry),
                        "error": "decompilation_failed",
                    })
                    analyzed += 1
                    continue

                # For each source call in this function, trace forward to sinks
                for call_addr, source_api in source_sites[func_entry]:
                    if time.time() - func_start > _FUNCTION_TIMEOUT_S:
                        break

                    traces = _trace_forward_pcode(
                        high_func, call_addr, SINK_APIS, SANITIZER_APIS
                    )

                    for trace in traces:
                        trace["function"] = func.getName()
                        trace["function_address"] = str(func_entry)
                        trace["source_api"] = source_api
                        trace["risk"] = (
                            "high" if trace["sink"] in HIGH_RISK_SINKS else "medium"
                        )
                        trace["confidence"] = _compute_confidence(trace)
                        results["traces"].append(trace)
                        total_traces += 1

            except Exception as e:
                results["errors"].append({
                    "function": func.getName() if func else "unknown",
                    "address": str(func_entry),
                    "error": str(e),
                })

            analyzed += 1

        decomp.dispose()

        results["summary"] = {
            "candidate_functions": len(candidate_funcs),
            "analyzed_functions": analyzed,
            "total_traces": total_traces,
            "high_risk_traces": sum(
                1 for t in results["traces"] if t.get("risk") == "high"
            ),
            "sanitized_traces": sum(
                1 for t in results["traces"] if t.get("sanitized", False)
            ),
            "duration_s": round(time.time() - t_start, 2),
        }

    except Exception as e:
        results["errors"].append({"fatal_error": str(e)})

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)


def _compute_confidence(trace):
    """Compute confidence score for a P-code verified trace."""
    base = 0.75
    if trace.get("sanitized", False):
        base = 0.20  # sanitized path — effectively suppressed
    elif trace.get("risk") == "high":
        base = 0.80  # high-risk sink (command execution)
    if trace.get("depth", 0) > 5:
        base -= 0.05  # long chain — slightly less confident
    return max(0.10, min(0.90, base))


run()
