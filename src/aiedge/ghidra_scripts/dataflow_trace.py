# Ghidra headless script for SCOUT
# @category SCOUT
# @description Trace dataflow from input sources to dangerous sinks
#
# Invoked by ghidra_bridge.py via:
#   analyzeHeadless ... -postScript dataflow_trace.py <output_json_path>
#
# Globals provided by Ghidra runtime: currentProgram, monitor, getScriptArgs

import json

SOURCE_FUNCTIONS = [
    "recv", "recvfrom", "read", "fread", "fgets",
    "getenv", "nvram_get", "websGetVar",
    "scanf", "sscanf", "fscanf",
]

SINK_FUNCTIONS = [
    "system", "popen", "execve", "execl", "execv",
    "strcpy", "sprintf", "strcat", "gets",
    "memcpy",
]


def run():
    args = getScriptArgs()  # noqa: F821 — Ghidra global
    output_path = args[0] if args else "/tmp/dataflow_output.json"

    results = {"traces": [], "source_sinks_in_same_function": [], "errors": []}

    try:
        prog = currentProgram  # noqa: F821
        sym_table = prog.getSymbolTable()
        ref_mgr = prog.getReferenceManager()
        fm = prog.getFunctionManager()

        # Build maps: caller function name -> list of source/sink names it calls
        source_callers = {}  # {caller_func_name: [source_func_names]}
        sink_callers = {}    # {caller_func_name: [sink_func_names]}

        for src_name in SOURCE_FUNCTIONS:
            for sym in sym_table.getGlobalSymbols(src_name):
                for ref in ref_mgr.getReferencesTo(sym.getAddress()):
                    caller = fm.getFunctionContaining(ref.getFromAddress())
                    if caller:
                        cname = caller.getName()
                        source_callers.setdefault(cname, []).append(src_name)

        for sink_name in SINK_FUNCTIONS:
            for sym in sym_table.getGlobalSymbols(sink_name):
                for ref in ref_mgr.getReferencesTo(sym.getAddress()):
                    caller = fm.getFunctionContaining(ref.getFromAddress())
                    if caller:
                        cname = caller.getName()
                        sink_callers.setdefault(cname, []).append(sink_name)

        # Find functions that call BOTH a source and a sink
        common_funcs = set(source_callers.keys()) & set(sink_callers.keys())

        for func_name in sorted(common_funcs):
            func = None
            for sym in sym_table.getGlobalSymbols(func_name):
                func = fm.getFunctionAt(sym.getAddress())
                if func:
                    break
            if not func:
                func = next(
                    (f for f in fm.getFunctions(True) if f.getName() == func_name),
                    None,
                )

            entry = {
                "function": func_name,
                "address": str(func.getEntryPoint()) if func else "unknown",
                "sources": sorted(set(source_callers[func_name])),
                "sinks": sorted(set(sink_callers[func_name])),
                "risk": "high" if any(
                    s in ("system", "popen", "execve")
                    for s in sink_callers[func_name]
                ) else "medium",
            }
            results["source_sinks_in_same_function"].append(entry)

        results["summary"] = {
            "functions_with_source_and_sink": len(common_funcs),
            "high_risk_count": sum(
                1 for e in results["source_sinks_in_same_function"]
                if e["risk"] == "high"
            ),
            "total_source_callers": len(source_callers),
            "total_sink_callers": len(sink_callers),
        }

    except Exception as e:
        results["fatal_error"] = str(e)

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)


run()
