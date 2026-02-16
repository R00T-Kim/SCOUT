import subprocess
import os
import sys
import time
import shutil

class FirmAERunner:
    def __init__(self, firmware_path: str, firmae_dir: str = "/home/rootk1m/FirmAE", log_dir: str = "./logs/firmae"):
        self.firmware_path = os.path.abspath(firmware_path)
        self.firmae_dir = firmae_dir # Assumes default install location or passed via env
        self.log_dir = os.path.abspath(log_dir)
        
    def check_prerequisites(self) -> bool:
        """Check if FirmAE is available."""
        # Note: On Windows, os.path.exists for WSL path might work if mapped, but safest is to skip deep check 
        # or check via wsl command. For now we assume user has it if they are running real mode.
        if os.name == 'nt':
             return True 

        if not os.path.exists(self.firmware_path):
            print(f"[!] Firmware not found: {self.firmware_path}")
            return False
        
        if not os.path.exists(os.path.join(self.firmae_dir, "run.sh")):
            print(f"[!] FirmAE not found at {self.firmae_dir}. Set firmae_dir correctly.")
            return False
            
        return True

    def run(self, brand: str = "auto") -> str:
        """
        Runs FirmAE emulation.
        """
        if not self.check_prerequisites():
            return ""

        os.makedirs(self.log_dir, exist_ok=True)
        firmware_id = os.path.basename(self.firmware_path).split('.')[0] 
        
        print(f"[*] Starting FirmAE emulation on {self.firmware_path}...")
        
        # 1. Run Emulation
        cmd_run = [
            "./run.sh",
            "-r",
            brand,
            self.firmware_path
        ]
        
        # Check if we need to wrap with WSL (if running on Windows)
        cwd_arg = self.firmae_dir
        if os.name == 'nt':
            # We are on Windows, needing to execute a Linux script in WSL
            # Convert path: //wsl.localhost/Ubuntu-22.04/... -> /...
            wsl_firmware_path = self.firmware_path.replace("\\", "/")
            if "//wsl.localhost/Ubuntu-22.04" in wsl_firmware_path:
                 wsl_firmware_path = wsl_firmware_path.replace("//wsl.localhost/Ubuntu-22.04", "")
            
            # Use bash -c to change directory inside WSL and run
            # Single quote firmware path to handle spaces
            bash_cmd = f"cd {self.firmae_dir} && ./run.sh -r {brand} '{wsl_firmware_path}'" 
            cmd_run = ["wsl", "bash", "-c", bash_cmd]
            cwd_arg = None # wsl.exe will be run from current dir, but bash command changes dir
        
        log_run_path = os.path.join(self.log_dir, "firmae_run.log")
        
        try:
            with open(log_run_path, "w", encoding='utf-8') as log_file:
                process = subprocess.Popen(
                    cmd_run,
                    cwd=cwd_arg,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding='utf-8', # Force UTF-8 for reading WSL output
                    errors='replace'  # Replace invalid chars instead of crashing
                )
                
                # Stream output (FirmAE takes a long time, so streaming is important)
                try:
                    for line in process.stdout:
                        print(line, end="")
                        log_file.write(line)
                        log_file.flush() # Ensure it's written immediately
                        
                    process.wait()
                except KeyboardInterrupt:
                    print("\n    [!] User skipped FirmAE (KeyboardInterrupt). Terminating process...")
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except:
                        process.kill()
                    return ""
                
            print(f"[+] FirmAE run finished. Log saved to {log_run_path}")
            return log_run_path
            
        except Exception as e:
            print(f"[!] Error running FirmAE: {e}")
            return ""

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 firmae_runner.py <firmware_path>")
        sys.exit(1)
        
    runner = FirmAERunner(sys.argv[1])
    runner.run()
