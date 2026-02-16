import subprocess
import os
import sys
import time

class IDARunner:
    def __init__(self, binary_path: str, output_dir: str = "./logs/ida"):
        self.binary_path = os.path.abspath(binary_path)
        self.output_dir = os.path.abspath(output_dir)
        # Assumes idat64 (or idat) is in PATH or defined via env
        self.ida_path = os.getenv("IDA_PATH", "idat64") 
        
    def check_prerequisites(self) -> bool:
        if not os.path.exists(self.binary_path):
            print(f"[!] Binary not found: {self.binary_path}")
            return False
            
        # Optional: Check if ida_path executable exists (if it's a full path)
        # if os.path.isabs(self.ida_path) and not os.path.exists(self.ida_path):
        #     print(f"[!] IDA executable not found at {self.ida_path}")
        #     return False
            
        return True

    def run(self) -> str:
        """
        Runs IDA Headless Analysis.
        Returns path to generated JSON.
        """
        if not self.check_prerequisites():
            return ""

        os.makedirs(self.output_dir, exist_ok=True)
        
        script_path = os.path.abspath("./collect/ida_scripts/exports_function_info.py")
        
        print(f"[*] Starting IDA analysis on {self.binary_path}...")
        
        # Env var for script to know where to output
        env = os.environ.copy()
        env["SCOUT_OUTPUT_DIR"] = self.output_dir
        
        # Command: idat64 -A -S<script> <binary>
        # -A: Autonomous mode (no GUI, auto-analysis)
        # -S: Run script
        
        # Note: If running on Windows directly, paths are fine.
        # If running from WSL invoking Windows binary, might need path conversion.
        # For now, we assume simple execution.
        
        cmd = [
            self.ida_path,
            "-A",
            f"-S{script_path}", # No space between -S and script path usually recommended
            self.binary_path
        ]
        
        try:
            # We don't capture stdout/stderr strictly because IDA prints to its own console window often
            # or creates an .id0/idb file. 
            # With -A, it should proceed.
            
            print(f"[*] Executing: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # Save log from stdout (IDA prints some stuff there)
            with open(os.path.join(self.output_dir, "ida_launch.log"), "w") as f:
                f.write(process.stdout)

            # Check for output JSON
            output_json = os.path.join(self.output_dir, f"{os.path.basename(self.binary_path)}_signals.json")
            
            # IDA might return immediately while doing analysis if not careful, 
            # but usually -A -Sscript waits if script calls qexit.
            
            if os.path.exists(output_json):
                print(f"[+] IDA Analysis Finished. Result: {output_json}")
                return output_json
            else:
                print(f"[!] Output JSON not found. Check logs/ida directory.")
                return ""
                
        except FileNotFoundError:
            print(f"[!] IDA executable '{self.ida_path}' not found. Set IDA_PATH env var.")
            return ""
        except Exception as e:
            print(f"[!] Error running IDA: {e}")
            return ""

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 ida_runner.py <binary_path>")
        sys.exit(1)
        
    runner = IDARunner(sys.argv[1])
    runner.run()
