from typing import List, Dict, Any
from utils.schemas import VulnerabilityCandidate, ScoutReport

class Validator:
    def validate_candidate(self, candidate: VulnerabilityCandidate) -> bool:
        """
        Validates a single candidate against critical rules.
        Returns True if valid, False otherwise.
        """
        # Rule 1: Must have at least 2 pieces of evidence for High confidence
        if candidate.confidence == "high" and len(candidate.evidence) < 2:
            print(f"Validation Warning: High confidence candidate {candidate.candidate_id} has insufficient evidence.")
            return False
            
        # Rule 2: Anchor must be specified
        if not candidate.anchor:
            print(f"Validation Error: Candidate {candidate.candidate_id} has no anchor.")
            return False

        return True

    def validate_report(self, report: ScoutReport) -> bool:
        """
        Validates the entire report structure.
        """
        if not report.candidates:
            print("Validation Warning: Report contains no candidates.")
            return True # Empty report is technically valid structure-wise

        valid_count = 0
        for cand in report.candidates:
            if self.validate_candidate(cand):
                valid_count += 1
        
        print(f"Validation Complete: {valid_count}/{len(report.candidates)} candidates valid.")
        return valid_count > 0
