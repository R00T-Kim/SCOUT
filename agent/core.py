import os
import json
import logging
from typing import List, Dict, Any
from openai import OpenAI
from dotenv import load_dotenv
from utils.schemas import StaticFacts, DynamicFacts, CodeFacts, VulnerabilityCandidate, Evidence

# Load environment variables
load_dotenv()

class ScoutAgent:
    def __init__(self, model_name: str = "xiaomi/mimo-v2-flash:free"):
        self.model_name = model_name
        self.api_key = os.getenv("OPENROUTER_API_KEY")
        
        if not self.api_key:
            logging.warning("OPENROUTER_API_KEY not found in environment variables. Agent will fail to run.")
        
        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=self.api_key,
        )
        
        self.prompt_template = """
You are SCOUT, a firmware vulnerability triage agent.
Your goal is to analyze the provided FACTS and generate a list of high-value VULNERABILITY CANDIDATES for manual verification.

RULES:
1. DO NOT CLAIM vulnerability exists. Only suggest CANDIDATES backed by EVIDENCE.
2. EVIDENCE must strictly come from the provided FACTS.
3. ANCHOR must be a specific entry point (e.g., a service, port, file, or function).
4. If High Confidence, you must link at least 2 distinct pieces of evidence.
5. You must respond with valid JSON only. Do not include markdown formatting (```json ... ```).

FACTS:
Static Analysis: {static_facts}
Dynamic Analysis: {dynamic_facts}
Code Signals: {code_facts}

OUTPUT FORMAT:
Return a JSON list of objects matching the VulnerabilityCandidate schema.
Example:
[
  {{
    "candidate_id": "CAND-001",
    "candidate_type": "insecure_service",
    "confidence": "high",
    "anchor": "tcp:23/telnetd",
    "evidence": [...],
    "why_this_matters": "...",
    "reproduction_steps": [...],
    "next_actions": [...]
  }}
]
"""

    def synthesize(self, static: StaticFacts, dynamic: DynamicFacts, code: CodeFacts) -> List[VulnerabilityCandidate]:
        """
        Synthesis logic using OpenRouter API.
        """
        if not self.api_key:
            print("[Agent] Error: API Key missing. Skipping synthesis.")
            return []

        # 1. Prepare Context
        context = self.prompt_template.format(
            static_facts=static.model_dump_json(),
            dynamic_facts=dynamic.model_dump_json(),
            code_facts=code.model_dump_json()
        )
        
        # 2. Call LLM
        print(f"[Agent] Sending context to {self.model_name} (Length: {len(context)})")
        
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are a helpful and strict security analysis assistant. Output JSON only."},
                    {"role": "user", "content": context}
                ],
                temperature=0.2, # Low temperature for more deterministic output
            )
            content = response.choices[0].message.content.strip()
            
            # Remove markdown code blocks if present
            if content.startswith("```json"):
                content = content[7:]
            # Parse JSON
            try:
                # Sanitize markdown code blocks if present
                clean_content = content.replace("```json", "").replace("```", "").strip()
                data = json.loads(clean_content)
                
                candidates = []
                for item in data:
                    # Fix: Ensure evidence is a list of objects
                    if "evidence" in item and isinstance(item["evidence"], list):
                        fixed_evidence = []
                        for ev in item["evidence"]:
                            if isinstance(ev, str):
                                # 'source' must be 'static', 'dynamic', or 'code'. defaulting to static for simplified fallback
                                fixed_evidence.append({"description": ev, "source": "static", "confidence": "low"})
                            elif isinstance(ev, dict):
                                if "source" not in ev or ev["source"] not in ["static", "dynamic", "code"]:
                                     ev["source"] = "static" # Fix invalid source in dict too
                                fixed_evidence.append(ev)
                        item["evidence"] = fixed_evidence
                        
                    try:
                        candidates.append(VulnerabilityCandidate(**item))
                    except Exception as e:
                        print(f"  [!] validation error for candidate: {e}")
                        continue
                        
                return candidates
            except json.JSONDecodeError:
                print(f"  [!] Failed to parse LLM response as JSON: {content[:100]}...")
                return []   

        except Exception as e:
            print(f"[Agent] API Error: {e}")
            return []
