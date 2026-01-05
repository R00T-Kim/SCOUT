import re
import uuid
from typing import List, Dict, Any
from utils.schemas import StaticFacts, ServiceFact, SecretFact, UpdateMechanismFact, Evidence

class StaticParser:
    def __init__(self):
        pass

    def parse(self, raw_content: str) -> StaticFacts:
        """
        Parses raw text output from EMBA/Firmwalker mock and returns StaticFacts.
        """
        facts = StaticFacts()
        
        # Parse Services/Daemons
        # Example: [+] Binary /usr/bin/telnetd is potentially vulnerable
        service_pattern = re.compile(r"\[\+\] Binary (.+?) is potentially vulnerable")
        for match in service_pattern.finditer(raw_content):
            binary_path = match.group(1)
            service_name = binary_path.split("/")[-1]
            facts.services.append(ServiceFact(
                protocol="tcp", # Assumption for now, or infer from service name
                port=23 if "telnet" in service_name else 80, # Simple heuristic for mock
                service_name=service_name,
                evidence=Evidence(
                    source="static",
                    description=f"Potential vulnerable binary found: {binary_path}",
                    location=binary_path,
                    raw_data={"line": match.group(0)}
                )
            ))

        # Parse Backdoors/Init Scripts
        # Example: [+] Found potential backdoor in /etc/init.d/rcS
        backdoor_pattern = re.compile(r"\[\+\] Found potential backdoor in (.+)")
        for match in backdoor_pattern.finditer(raw_content):
            file_path = match.group(1)
            facts.update_mechanisms.append(UpdateMechanismFact(
                script_path=file_path,
                mechanism_type="init_script",
                evidence=Evidence(
                    source="static",
                    description=f"Potential backdoor/init script found: {file_path}",
                    location=file_path,
                    raw_data={"line": match.group(0)}
                )
            ))

        # Parse Secrets
        # Example: [+] User 'admin' with password '1234' found in /etc/shadow
        secret_pattern = re.compile(r"\[\+\] User '(.+?)' with password '(.+?)' found in (.+)")
        for match in secret_pattern.finditer(raw_content):
            user = match.group(1)
            password = match.group(2)
            file_path = match.group(3)
            facts.secrets.append(SecretFact(
                type="hardcoded_credential",
                value_masked=f"{user}:*****", # Masking password
                file_path=file_path,
                evidence=Evidence(
                    source="static",
                    description=f"Hardcoded credential for user '{user}' found",
                    location=file_path,
                    raw_data={"line": match.group(0)}
                )
            ))
            
        return facts
