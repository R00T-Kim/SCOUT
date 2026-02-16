import os
import re
import mmap

class SimpleStaticScanner:
    def __init__(self, extracted_path: str):
        self.extracted_path = extracted_path
        
        # Patterns to look for
        self.interesting_files = [
            "etc/passwd", "etc/shadow", "etc/rc.d", "etc/init.d",
            ".pem", ".crt", ".key", "id_rsa", "authorized_keys",
            "wpa_supplicant.conf", "httpd.conf", "nginx.conf"
        ]
        
        self.risky_binaries = [
            "telnetd", "telnet", "nc", "netcat", "gdb", "strace", "tcpdump", "curl", "wget"
        ]
        
        self.secret_patterns = {
            "private_key": re.compile(b"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"),
            "ipv4": re.compile(b"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"),
            "url": re.compile(b"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"),
            "api_key_candidate": re.compile(b"(?i)(api[-_]?key|access[-_]?key|secret[-_]?key)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{20,})['\"]?"),
            "hardcoded_password": re.compile(b"(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9@#$%^&*]{5,})['\"]?")
        }

    def scan(self) -> dict:
        """
        Walks the directory and aggregates findings.
        Returns a dict compatible with StaticFacts structure (roughly).
        """
        results = {
            "files": [],
            "binaries": [],
            "secrets": [],
            "services": []
        }
        
        print(f"[*] Starting Simple Static Scan on {self.extracted_path}...")
        
        for root, dirs, files in os.walk(self.extracted_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, self.extracted_path)
                
                # 1. Check Filenames
                for pattern in self.interesting_files:
                    if pattern in rel_path:
                        results["files"].append(rel_path)
                
                if filename in self.risky_binaries:
                    results["binaries"].append(rel_path)
                    
                # 2. Check Content (Briefly)
                # Skip overly large files to save time
                try:
                    size = os.path.getsize(file_path)
                    if size > 10 * 1024 * 1024: # Skip > 10MB
                        continue
                        
                    with open(file_path, "rb") as f:
                        if size == 0: continue
                        
                        try:
                            # Memory map for efficiency
                            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                                for label, pattern in self.secret_patterns.items():
                                    matches = pattern.findall(mm)
                                    for m in matches[:5]: # Cap at 5 matches per pattern per file
                                        val = m if isinstance(m, bytes) else m[0]
                                        try:
                                            decoded_val = val.decode('utf-8', errors='ignore')
                                            # Filter out common false positives for IPs/URLs if needed
                                            if label == "ipv4" and decoded_val.startswith("127.0.0"): continue
                                            
                                            results["secrets"].append({
                                                "file": rel_path,
                                                "type": label,
                                                "content": decoded_val
                                            })
                                        except:
                                            pass
                        except ValueError:
                            # Empty file or mmap error
                            pass
                            
                except (PermissionError, FileNotFoundError):
                    pass

        # Deduplicate
        results["files"] = list(set(results["files"]))
        results["binaries"] = list(set(results["binaries"]))
        
        print(f"  - Found {len(results['files'])} interesting files, {len(results['binaries'])} binaries, {len(results['secrets'])} potential secrets")
        return results
