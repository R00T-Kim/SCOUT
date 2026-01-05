import subprocess
import os
import sys
import time

class GhidraRunner:
    def __init__(self, binary_path: str, output_dir: str = "./logs/ghidra"):
        self.binary_path = os.path.abspath(binary_path)
        self.output_dir = os.path.abspath(output_dir)
        # Assumes analyzeHeadless is in PATH or defined in env
        self.analyze_headless = os.getenv("GHIDRA_HEADLESS_PATH", "analyzeHeadless")
        self.project_location = os.path.join(self.output_dir, "ghidra_proj")
        self.project_name = "scout_analysis"
        
    def check_prerequisites(self) -> bool:
        if not os.path.exists(self.binary_path):
            print(f"[!] Binary not found: {self.binary_path}")
            return False
        return True

    def run(self) -> str:
        """
        Runs Ghidra Headless Analysis.
        Returns path to generated JSON.
        """
        if not self.check_prerequisites():
            return ""

        os.makedirs(self.output_dir, exist_ok=True)
        # Clean previous project if exists (optional, or reuse)
        
        script_path = os.path.abspath("./collect/ghidra_scripts/exports_function_info.py")
        script_dir = os.path.dirname(script_path)
        script_name = os.path.basename(script_path)
        
        print(f"[*] Starting Ghidra analysis on {self.binary_path}...")
        
        # Env var for script to know where to output
        env = os.environ.copy()
        env["SCOUT_OUTPUT_DIR"] = self.output_dir

        cmd = [
            self.analyze_headless,
            self.project_location,
            self.project_name,
            "-import", self.binary_path,
            "-scriptPath", script_dir,
            "-postScript", script_name,
            "-deleteProject" # Don't keep the project to save space
        ]
        
        try:
            # Check if analyzeHeadless is callable
            # subprocess.run([self.analyze_headless, "--help"], stdout=subprocess.DEVNULL) 
            
            process = subprocess.run(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # Save log for debug
            with open(os.path.join(self.output_dir, "ghidra.log"), "w") as f:
                f.write(process.stdout)
                
            if process.returncode != 0:
                print(f"[!] Ghidra failed with code {process.returncode}. See ghidra.log")
                return ""
            
            output_json = os.path.join(self.output_dir, f"{os.path.basename(self.binary_path)}_signals.json")
            if os.path.exists(output_json):
                print(f"[+] Ghidra Analysis Finished. Result: {output_json}")
                return output_json
            else:
                print("[!] Output JSON not found after analysis.")
                return ""
                
        except FileNotFoundError:
            print("[!] analyzeHeadless not found. Set GHIDRA_HEADLESS_PATH env var.")
            return ""
        except Exception as e:
            print(f"[!] Error running Ghidra: {e}")
            return ""

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 ghidra_runner.py <binary_path>")
        sys.exit(1)
        
    runner = GhidraRunner(sys.argv[1])
    runner.run()
