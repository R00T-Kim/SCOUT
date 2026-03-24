# Ghidra headless script for SCOUT
# @category SCOUT
# @description Decompile all functions to JSON output
#
# Invoked by ghidra_bridge.py via:
#   analyzeHeadless ... -postScript decompile_all.py <output_json_path>
#
# Globals provided by Ghidra runtime: currentProgram, monitor, getScriptArgs

import json


def run():
    args = getScriptArgs()  # noqa: F821 — Ghidra global
    output_path = args[0] if args else "/tmp/decompile_output.json"

    results = {"functions": [], "errors": []}

    try:
        from ghidra.app.decompiler import DecompInterface

        decomp = DecompInterface()
        decomp.openProgram(currentProgram)  # noqa: F821

        fm = currentProgram.getFunctionManager()  # noqa: F821
        func_iter = fm.getFunctions(True)

        count = 0
        max_functions = 500  # Safety limit

        while func_iter.hasNext() and count < max_functions:
            func = func_iter.next()
            try:
                dec_result = decomp.decompileFunction(func, 30, monitor)  # noqa: F821
                decompiled_c = ""
                if dec_result and dec_result.decompileCompleted():
                    decompiled_func = dec_result.getDecompiledFunction()
                    if decompiled_func:
                        decompiled_c = decompiled_func.getC()

                results["functions"].append({
                    "name": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "signature": str(func.getSignature()),
                    "size": func.getBody().getNumAddresses(),
                    "decompiled": decompiled_c[:10000] if decompiled_c else "",
                })
                count += 1
            except Exception as e:
                results["errors"].append({
                    "function": func.getName(),
                    "error": str(e),
                })

        decomp.dispose()
        results["total_functions"] = fm.getFunctionCount()
        results["decompiled_count"] = count

    except Exception as e:
        results["fatal_error"] = str(e)

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)


run()
