# Ghidra Headless Script
# exports_function_info.py
# @category SCOUT
# @author SCOUT_Agent

import json
import os
from ghidra.util.task import TaskMonitor
from ghidra.program.model.symbol import SymbolType

def get_function_data():
    function_manager = currentProgram.getFunctionManager()
    functions = function_manager.getFunctions(True)
    
    signals = []
    
    # Simple dangerous function list
    dangerous_funcs = ["strcpy", "system", "sprintf", "popen", "exec"]
    
    for func in functions:
        func_name = func.getName()
        entry = func.getEntryPoint()
        
        # Check references to dangerous functions
        # This logic is simplified; usually we check calls *from* a function *to* dangerous ones
        # Here we iterate all functions, find if they are dangerous, and find who calls them.
        
        if func_name in dangerous_funcs:
            refs = getReferencesTo(entry)
            for ref in refs:
                caller = getFunctionContaining(ref.getFromAddress())
                if caller:
                    signals.append({
                        "binary": currentProgram.getName(),
                        "function": caller.getName(),
                        "description": f"Call to dangerous function '{func_name}'",
                        "line": ref.getFromAddress().toString(),
                        "pattern": func_name
                    })
                    
    return signals

def main():
    print("Starting SCOUT Ghidra Analysis...")
    output_dir = os.environ.get("SCOUT_OUTPUT_DIR", "/tmp")
    output_file = os.path.join(output_dir, f"{currentProgram.getName()}_signals.json")
    
    data = get_function_data()
    
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
        
    print(f"Analysis complete. Saved to {output_file}")

if __name__ == "__main__":
    main()
