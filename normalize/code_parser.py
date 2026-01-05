import json
from typing import List, Dict, Any
from utils.schemas import CodeFacts, CodeSignal, Evidence

class CodeParser:
    def parse(self, raw_content: str) -> CodeFacts:
        """
        Parses JSON output from Ghidra mock and returns CodeFacts.
        """
        facts = CodeFacts()
        try:
            data = json.loads(raw_content)
            if not isinstance(data, list):
                print(f"Warning: Expected list JSON for Ghidra output, got {type(data)}")
                return facts
                
            for item in data:
                # Map patterns to simplified signal types
                signal_type = "unknown_pattern"
                desc = item.get("description", "").lower()
                if "command injection" in desc:
                    signal_type = "command_injection_sink"
                elif "buffer overflow" in desc:
                    signal_type = "buffer_overflow_risk"
                
                facts.signals.append(CodeSignal(
                    binary_name=item.get("binary"),
                    function_name=item.get("function"),
                    signal_type=signal_type,
                    confidence="medium", # Default from static scan
                    evidence=Evidence(
                        source="code",
                        description=item.get("description"),
                        location=f"{item.get('binary')}:{item.get('function')} @ {item.get('line')}",
                        raw_data=item
                    )
                ))
        except json.JSONDecodeError as e:
            print(f"Error decoding Ghidra JSON: {e}")
            
        return facts
