from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field

# --- Evidence Models ---

class Evidence(BaseModel):
    source: Literal["static", "dynamic", "code"]
    description: str
    location: Optional[str] = None  # e.g., file path, line number, specific string
    raw_data: Optional[Dict[str, Any]] = None # Original raw data snippet

# --- Fact Models (Normalization Layer) ---

class ServiceFact(BaseModel):
    protocol: str       # tcp, udp
    port: int
    service_name: Optional[str] = None # e.g., httpd, telnetd
    process_name: Optional[str] = None
    evidence: Evidence

class WebPathFact(BaseModel):
    path: str           # e.g., /cgi-bin/upload.cgi
    method: Optional[str] = None # GET, POST
    handler: Optional[str] = None # Binary or script handling this path
    evidence: Evidence

class SecretFact(BaseModel):
    type: str           # password, token, key, etc.
    value_masked: str   # e.g., "admin:*****"
    file_path: str
    evidence: Evidence

class CodeSignal(BaseModel):
    binary_name: str
    function_name: Optional[str] = None
    signal_type: str    # e.g., command_injection_sink, auth_check_bypass
    confidence: Literal["low", "medium", "high"]
    evidence: Evidence

class UpdateMechanismFact(BaseModel):
    script_path: str
    mechanism_type: str # e.g., script, binary
    has_signature_verification: Optional[bool] = None
    evidence: Evidence

# --- Aggregated Facts ---

class StaticFacts(BaseModel):
    services: List[ServiceFact] = Field(default_factory=list)
    web_paths: List[WebPathFact] = Field(default_factory=list)
    secrets: List[SecretFact] = Field(default_factory=list)
    update_mechanisms: List[UpdateMechanismFact] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict) # Firmware info

class DynamicFacts(BaseModel):
    open_ports: List[ServiceFact] = Field(default_factory=list)
    web_endpoints: List[WebPathFact] = Field(default_factory=list)
    runtime_logs: List[str] = Field(default_factory=list)

class CodeFacts(BaseModel):
    signals: List[CodeSignal] = Field(default_factory=list)

# --- Final Candidate Model ---

class VulnerabilityCandidate(BaseModel):
    candidate_id: str
    candidate_type: str # e.g., command_injection, hardcoded_cred
    confidence: Literal["low", "medium", "high"]
    
    # Attack Surface Anchor (Where does this start?)
    anchor: str # e.g., "tcp:80/cgi-bin/login.cgi" or "file:/etc/shadow"
    
    # Aggregated Evidence
    evidence: List[Evidence]
    
    # Reasoning
    why_this_matters: str
    reproduction_steps: List[str]
    next_actions: List[str]

class ScoutReport(BaseModel):
    target_firmware: str
    candidates: List[VulnerabilityCandidate]
