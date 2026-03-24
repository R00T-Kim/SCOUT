# Ghidra headless script for SCOUT
# @category SCOUT
# @description Build cross-reference graph for dangerous function calls
#
# Invoked by ghidra_bridge.py via:
#   analyzeHeadless ... -postScript xref_graph.py <output_json_path>
#
# Globals provided by Ghidra runtime: currentProgram, monitor, getScriptArgs

import json

DANGEROUS_FUNCTIONS = [
    "system", "popen", "execve", "execl", "execlp", "execle",
    "execv", "execvp", "execvpe",
    "strcpy", "strcat", "sprintf", "vsprintf", "gets",
    "scanf", "sscanf", "fscanf",
    "memcpy", "memmove",
]


def run():
    args = getScriptArgs()  # noqa: F821 — Ghidra global
    output_path = args[0] if args else "/tmp/xref_output.json"

    results = {"dangerous_calls": [], "summary": {}, "errors": []}

    try:
        prog = currentProgram  # noqa: F821
        sym_table = prog.getSymbolTable()
        ref_mgr = prog.getReferenceManager()
        fm = prog.getFunctionManager()

        for func_name in DANGEROUS_FUNCTIONS:
            symbols = sym_table.getGlobalSymbols(func_name)
            for sym in symbols:
                callers = []
                refs = ref_mgr.getReferencesTo(sym.getAddress())
                for ref in refs:
                    from_addr = ref.getFromAddress()
                    caller_func = fm.getFunctionContaining(from_addr)
                    caller_name = caller_func.getName() if caller_func else "unknown"
                    callers.append({
                        "caller": caller_name,
                        "address": str(from_addr),
                        "ref_type": str(ref.getReferenceType()),
                    })

                if callers:
                    results["dangerous_calls"].append({
                        "target_function": func_name,
                        "target_address": str(sym.getAddress()),
                        "callers": callers,
                        "call_count": len(callers),
                    })

        results["summary"] = {
            "total_dangerous_targets": len(results["dangerous_calls"]),
            "total_call_sites": sum(
                entry["call_count"] for entry in results["dangerous_calls"]
            ),
        }

    except Exception as e:
        results["fatal_error"] = str(e)

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)


run()
