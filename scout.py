import sys
import argparse
import os
from normalize.static_parser import StaticParser
from normalize.dynamic_parser import DynamicParser
from normalize.code_parser import CodeParser
from agent.core import ScoutAgent
from validate.validator import Validator
from report.reporter import Reporter
from collect.emba_runner import EMBARunner
from collect.ghidra_runner import GhidraRunner
from collect.firmae_runner import FirmAERunner
from collect.binwalk_runner import BinwalkRunner
from collect.static_scanner import SimpleStaticScanner
from utils.schemas import StaticFacts, DynamicFacts, CodeFacts, ServiceFact, SecretFact, Evidence

def run_mock_pipeline():
    print("\n[Mode] Running in MOCK Mode (No firmware provided)...")
    try:
        with open("samples/emba_mock.txt", "r") as f: emba_content = f.read()
        with open("samples/firmae_mock.txt", "r") as f: firmae_content = f.read()
        with open("samples/ghidra_mock.json", "r") as f: ghidra_content = f.read()
    except FileNotFoundError:
        print("Error: Sample files not found.")
        sys.exit(1)
        
    static_facts = StaticParser().parse(emba_content)
    dynamic_facts = DynamicParser().parse(firmae_content)
    code_facts = CodeParser().parse(ghidra_content)
    
    return static_facts, dynamic_facts, code_facts

def run_real_pipeline(firmware_path):
    print(f"\n[Mode] Running in REAL Mode on {firmware_path}...")
    
    # 1. EMBA (Static Analysis)
    print("  [1/3] Running EMBA (Static Analysis)...")
    emba_log = EMBARunner(firmware_path).run()
    static_facts = None
    
    if emba_log and os.path.exists(emba_log):
        with open(emba_log, "r", errors='ignore') as f: 
            static_facts = StaticParser().parse(f.read())
            
    # Fallback: Binwalk + Simple Static Scanner
    if not static_facts or (len(static_facts.services) == 0 and len(static_facts.secrets) == 0):
        print("    [!] EMBA failed or produced no findings. Attempting Binwalk Fallback...")
        extracted_path = BinwalkRunner(firmware_path).run()
        if extracted_path:
            scanner_results = SimpleStaticScanner(extracted_path).scan()
            # Convert scanner dict to StaticFacts
            static_facts = StaticFacts()
            
            # Map Files
            for f in scanner_results.get("files", []):
                static_facts.services.append(ServiceFact(
                    service_name="unknown",
                    protocol="file",
                    port=0,
                    evidence=Evidence(source="static", description=f"Interesting file: {f}", location=f)
                ))
            
            # Map Binaries
            for b in scanner_results.get("binaries", []):
                static_facts.services.append(ServiceFact(
                    service_name=b.split("/")[-1],
                    protocol="binary",
                    port=0,
                    evidence=Evidence(source="static", description=f"Risky binary: {b}", location=b)
                ))

            # Map Secrets
            for s in scanner_results.get("secrets", []):
                static_facts.secrets.append(SecretFact(
                    type=s["type"],
                    value_masked=s["content"][:3]+"***",
                    file_path=s["file"],
                    evidence=Evidence(source="static", description=f"Potential {s['type']}: {s['content']}", location=s["file"])
                ))
        else:
            print("    [!] Binwalk extraction failed properly. No static facts available.")
            static_facts = StaticFacts() # Return empty if both fail

    # 2. FirmAE (Dynamic Analysis)
    print("  [2/3] Running FirmAE (Dynamic Analysis)...")
    firmae_log = FirmAERunner(firmware_path).run()
    if firmae_log and os.path.exists(firmae_log):
        with open(firmae_log, "r", errors='ignore') as f: 
            dynamic_facts = DynamicParser().parse(f.read())
    else:
        print("    [!] FirmAE failed or produced no log. Using empty input.")
        dynamic_facts = DynamicParser().parse("") # Empty facts
        
    # 3. Ghidra (Code Analysis)
    print("  [3/3] Running Ghidra (Code Analysis)...")
    ghidra_json = GhidraRunner(firmware_path).run()
    if ghidra_json and os.path.exists(ghidra_json):
        with open(ghidra_json, "r", errors='ignore') as f: 
            code_facts = CodeParser().parse(f.read())
    else:
         print("    [!] Ghidra failed or produced no log. Using empty input.")
         code_facts = CodeParser().parse("[]") # Empty facts
         
    return static_facts, dynamic_facts, code_facts

def main():
    parser = argparse.ArgumentParser(description="SCOUT Firmware Vulnerability Scanner")
    parser.add_argument("--firmware", "-f", help="Path to the firmware file to analyze")
    args = parser.parse_args()

    print("[SCOUT] Starting Firmware Vulnerability Campaign...")
    
    # Phase 1: Collection & Normalization
    if args.firmware:
        static_facts, dynamic_facts, code_facts = run_real_pipeline(args.firmware)
    else:
        static_facts, dynamic_facts, code_facts = run_mock_pipeline()

    print(f"\n[Phase 1] Collection & Normalization Complete")
    print(f"  - Static Facts: {len(static_facts.services) + len(static_facts.files if hasattr(static_facts, 'files') else [])} findings")
    print(f"  - Dynamic Facts: {len(dynamic_facts.open_ports)} ports, {len(dynamic_facts.web_endpoints)} web paths")
    print(f"  - Code Signals: {len(code_facts.signals)} signals")

    # Phase 2: Agent Synthesis
    print("\n[Phase 2] Agent Synthesis...")
    agent = ScoutAgent() 
    candidates = agent.synthesize(static_facts, dynamic_facts, code_facts)
    print(f"  - Generated {len(candidates)} candidates")

    # Phase 3: Validation
    print("\n[Phase 3] Validation...")
    validator = Validator()
    valid_candidates = [c for c in candidates if validator.validate_candidate(c)]
    print(f"  - {len(valid_candidates)} valid candidates retained")

    # Phase 4: Reporting
    print("\n[Phase 4] generating Report...")
    output_file = "report/report_real_scan.md" if args.firmware else "report/report_mock.md"
    reporter = Reporter()
    reporter.generate_report(valid_candidates, output_path=output_file)
    
    print(f"\n[SCOUT] Campaign Finished. Check {output_file}")

if __name__ == "__main__":
    main()

