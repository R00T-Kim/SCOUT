import subprocess
import os
import sys
import shutil

class BinwalkRunner:
    def __init__(self, binary_path: str, output_dir: str = "./logs/binwalk"):
        self.binary_path = os.path.abspath(binary_path)
        self.output_dir = os.path.abspath(output_dir)
        self.binwalk_cmd = "binwalk" # Assumes binwalk is in PATH

    def check_prerequisites(self) -> bool:
        if not os.path.exists(self.binary_path):
            print(f"[!] Binary not found: {self.binary_path}")
            return False
        
        if shutil.which(self.binwalk_cmd) is None:
            print("[!] binwalk command not found in PATH.")
            return False
            
        return True

    def run(self) -> str:
        """
        Runs Binwalk extraction.
        Returns path to the extracted directory.
        """
        if not self.check_prerequisites():
            return ""

        os.makedirs(self.output_dir, exist_ok=True)
        
        print(f"[*] Starting Binwalk extraction on {self.binary_path}...")

        # -e: extract known file types
        # -M: recursively scan extracted files
        # -q: quiet mode (optional, but we want logs)
        # -C: download directory (we want to specify output dir, but binwalk -C is for directory)
        # Binwalk extracts to current directory or defined -C.
        # Ideally we cd to output_dir or use -C.
        
        # Command: binwalk -eM <binary> -C <output>
        cmd = [
            self.binwalk_cmd,
            "--run-as=root",
            "-e",
            "-M",
            self.binary_path,
            "-C", self.output_dir
        ]
        
        try:
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # Save log
            log_path = os.path.join(self.output_dir, "binwalk.log")
            with open(log_path, "w") as f:
                f.write(process.stdout)
                
            if process.returncode != 0:
                print(f"[!] Binwalk failed with code {process.returncode}. See {log_path}")
                # Binwalk sometimes returns non-zero even on partial success, so check dir
            
            # Check for extracted directory
            # Binwalk creates usually "_<binary_name>.extracted"
            extracted_dirname = f"_{os.path.basename(self.binary_path)}.extracted"
            extracted_path = os.path.join(self.output_dir, extracted_dirname)
            
            if os.path.exists(extracted_path):
                print(f"[+] Binwalk Extraction Finished. Extracted to: {extracted_path}")
                return extracted_path
            else:
                # Fallback check: sometimes it might be just flat if not recursing deep? 
                # But standard binwalk behavior is _filename.extracted
                print(f"[!] Extracted directory not found at expected path: {extracted_path}")
                return ""
                
        except Exception as e:
            print(f"[!] Error running Binwalk: {e}")
            return ""

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 binwalk_runner.py <binary_path>")
        sys.exit(1)
        
    runner = BinwalkRunner(sys.argv[1])
    runner.run()
