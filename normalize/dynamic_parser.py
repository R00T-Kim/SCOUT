import re
from typing import List, Dict, Any
from utils.schemas import DynamicFacts, ServiceFact, WebPathFact, Evidence

class DynamicParser:
    def parse(self, raw_content: str) -> DynamicFacts:
        """
        Parses raw text output from FirmAE mock and returns DynamicFacts.
        """
        facts = DynamicFacts()
        
        # Parse Network Services
        # Example: 192.168.0.1:80 (http) - Title: "Router Login"
        net_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+\((.+?)\)\s+-\s+(.+)")
        for match in net_pattern.finditer(raw_content):
            ip = match.group(1)
            port = int(match.group(2))
            protocol = match.group(3)
            details = match.group(4)
            
            facts.open_ports.append(ServiceFact(
                protocol="tcp", # FirmAE usually scans TCP
                port=port,
                service_name=protocol,
                evidence=Evidence(
                    source="dynamic",
                    description=f"Open port {port} ({protocol}) observed. {details}",
                    location=f"{ip}:{port}",
                    raw_data={"line": match.group(0)}
                )
            ))

        # Parse Web Pages
        # Example: [+] Web page found: /cgi-bin/login.cgi (Status: 200)
        web_pattern = re.compile(r"\[\+\] Web page found: (.+?) \(Status: (\d+)\)")
        for match in web_pattern.finditer(raw_content):
            path = match.group(1)
            status = match.group(2)
            
            facts.web_endpoints.append(WebPathFact(
                path=path,
                evidence=Evidence(
                    source="dynamic",
                    description=f"Web endpoint found: {path} (Status: {status})",
                    location=path,
                    raw_data={"line": match.group(0)}
                )
            ))
            
        return facts
