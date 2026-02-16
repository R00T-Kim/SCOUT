# IDAPython Headless Script
# exports_function_info.py

import json
import os
import idc
import idautils
import idaapi
import ida_auto
import ida_funcs
import ida_name

def get_function_data():
    """
    Scans for dangerous functions and their callers.
    """
    signals = []
    
    # Simple dangerous function list
    dangerous_funcs = ["strcpy", "system", "sprintf", "popen", "exec", "memcpy", "gets"]
    
    # Wait for auto-analysis to finish
    print("[*] Waiting for auto-analysis...")
    ida_auto.auto_wait()
    print("[*] Analysis finished.")

    binary_name = idc.get_root_filename()

    for func_name in dangerous_funcs:
        # Find the address of the dangerous function (e.g., imported or defined)
        # We try multiple ways because names can vary (e.g., _strcpy, .strcpy)
        ea = idc.get_name_ea_simple(func_name)
        if ea == idc.BADADDR:
            # Try prepending underscore
            ea = idc.get_name_ea_simple("_" + func_name)
            
        if ea != idc.BADADDR:
            print(f"[*] Found dangerous function '{func_name}' at {hex(ea)}")
            
            # Find cross-references to this address
            for xref in idautils.XrefsTo(ea):
                # We only care about code references (Call, Jump)
                if not (xref.type == idautils.fl_CN or xref.type == idautils.fl_CF or xref.type == idautils.fl_JN or xref.type == idautils.fl_JF):
                    continue
                    
                caller_ea = xref.frm
                caller_func = ida_funcs.get_func(caller_ea)
                
                if caller_func:
                    caller_name = ida_name.get_name(caller_func.start_ea)
                    
                    # Avoid duplicates or self-references if necessary
                    signals.append({
                        "binary": binary_name,
                        "function": caller_name,
                        "description": f"Call to dangerous function '{func_name}'",
                        "line": hex(caller_ea), # Address as string
                        "pattern": func_name
                    })
        else:
            # print(f"[-] '{func_name}' not found in binary.")
            pass
                    
    return signals

def main():
    print("Starting SCOUT IDA Analysis...")
    
    # Output directory from env or temp
    output_dir = os.environ.get("SCOUT_OUTPUT_DIR", os.path.dirname(os.path.abspath(__file__)))
    # If no env, fallback to script dir? Better to strict check env in runner.
    
    output_file = os.path.join(output_dir, f"{idc.get_root_filename()}_signals.json")
    
    data = get_function_data()
    
    try:
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Analysis complete. Saved to {output_file}")
    except Exception as e:
        print(f"[!] Error saving JSON: {e}")

    # Exit IDA
    idc.qexit(0)

if __name__ == "__main__":
    main()
