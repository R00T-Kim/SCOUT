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

def run_mock_pipeline():
    print("\n[Mode] Running in MOCK Mode (No firmware provided)...")
    try:
        with open("samples/emba_mock.txt", "r") as f: emba_content = f.read()
        with open("samples/firmae_mock.txt", "r") as f: firmae_content = f.read()
        with open("samples/ghidra_mock.json", "r") as f: ghidra_content = f.read()
    except FileNotFoundError:
        print("Error: Sample files not found.")
        sys.exit(1)
    return emba_content, firmae_content, ghidra_content

def run_real_pipeline(firmware_path):
    print(f"\n[Mode] Running in REAL Mode on {firmware_path}...")
    
    # 1. EMBA
    print("  [1/3] Running EMBA (Static Analysis)...")
    emba_log = EMBARunner(firmware_path).run()
    if emba_log and os.path.exists(emba_log):
        with open(emba_log, "r", errors='ignore') as f: emba_content = f.read()
    else:
        print("    [!] EMBA failed or produced no log. Using empty input.")
        emba_content = ""

    # 2. FirmAE
    print("  [2/3] Running FirmAE (Dynamic Analysis)...")
    firmae_log = FirmAERunner(firmware_path).run()
    if firmae_log and os.path.exists(firmae_log):
        with open(firmae_log, "r", errors='ignore') as f: firmae_content = f.read()
    else:
        print("    [!] FirmAE failed or produced no log. Using empty input.")
        firmae_content = ""
        
    # 3. Ghidra
    print("  [3/3] Running Ghidra (Code Analysis)...")
    # Note: Ghidra needs a binary, not the full firmware image usually.
    # For SCOUT prototype, we'll try to run it on the firmware image itself 
    # OR ideally we should extract the file system first. 
    # For now, we pass the firmware image, but in reality we'd need an extractor step.
    # Let's assume the user extracts it or we just analyze the image blob.
    ghidra_json = GhidraRunner(firmware_path).run()
    if ghidra_json and os.path.exists(ghidra_json):
        with open(ghidra_json, "r", errors='ignore') as f: ghidra_content = f.read()
    else:
         print("    [!] Ghidra failed or produced no log. Using empty input.")
         ghidra_content = "[]"
         
    return emba_content, firmae_content, ghidra_content

def main():
    parser = argparse.ArgumentParser(description="SCOUT Firmware Vulnerability Scanner")
    parser.add_argument("--firmware", "-f", help="Path to the firmware file to analyze")
    args = parser.parse_args()

    print("[SCOUT] Starting Firmware Vulnerability Campaign...")
    
    # Phase 1: Collection
    if args.firmware:
        emba_content, firmae_content, ghidra_content = run_real_pipeline(args.firmware)
    else:
        emba_content, firmae_content, ghidra_content = run_mock_pipeline()

    # Phase 1.5: Normalization
    print("\n[Phase 1] Normalizing Tool Outputs...")
    static_facts = StaticParser().parse(emba_content)
    dynamic_facts = DynamicParser().parse(firmae_content)
    code_facts = CodeParser().parse(ghidra_content)
    
    print(f"  - Static Facts: {len(static_facts.services)} services, {len(static_facts.secrets)} secrets")
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

