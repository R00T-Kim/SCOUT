import subprocess
import os
import sys
import time

class EMBARunner:
    def __init__(self, firmware_path: str, log_dir: str = "./logs/emba"):
        self.firmware_path = os.path.abspath(firmware_path)
        self.log_dir = os.path.abspath(log_dir)
        self.container_image = "embeddedanalyzer/emba" # Updated to official image name
        
    def check_prerequisites(self) -> bool:
        """Check if docker is available and firmware exists."""
        if not os.path.exists(self.firmware_path):
            print(f"[!] Firmware not found: {self.firmware_path}")
            return False
            
        try:
            subprocess.run(["docker", "--version"], check=True, stdout=subprocess.DEVNULL)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("[!] Docker is not installed or not in PATH.")
            return False
            
        return True

    def run(self) -> str:
        """
        Runs EMBA via Docker.
        Returns the path to the generated log file.
        """
        if not self.check_prerequisites():
            return ""

        os.makedirs(self.log_dir, exist_ok=True)
        log_file_path = os.path.join(self.log_dir, f"emba_{int(time.time())}.log")
        
        print(f"[*] Starting EMBA analysis on {self.firmware_path}...")
        print(f"[*] Logs will be saved to {log_file_path}")

        # EMBA Docker Command Construction
        # Volume mount: Firmware -> /firmware, Logs -> /logs
        # Command: ./emba -f /firmware/<basename> -l /logs
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{os.path.dirname(self.firmware_path)}:/firmware",
            "-v", f"{self.log_dir}:/logs",
            self.container_image,
            "./emba",
            "-f", f"/firmware/{os.path.basename(self.firmware_path)}",
            "-l", "/logs",
            "-p", "./scan_profiles/default_scan.emba" # Assuming default profile
        ]
        
        # In a real scenario, we might want to use Popen to stream output
        # For simplicity in this script, we'll write stdout to file and print
        try:
            with open(log_file_path, "w") as log_file:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                
                # Stream output
                for line in process.stdout:
                    print(line, end="")
                    log_file.write(line)
                    
                process.wait()
                
            if process.returncode == 0:
                print("\n[+] EMBA Analysis Finished Successfully.")
                return log_file_path
            else:
                print(f"\n[!] EMBA finished with error code {process.returncode}")
                return ""
                
        except Exception as e:
            print(f"[!] Error running EMBA: {e}")
            return ""

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 emba_runner.py <firmware_path>")
        sys.exit(1)
        
    runner = EMBARunner(sys.argv[1])
    runner.run()
