from typing import List
from utils.schemas import ScoutReport, VulnerabilityCandidate

class Reporter:
    def generate_report(self, candidates: List[VulnerabilityCandidate], output_path: str = "report/report.md"):
        """
        Generates a Markdown report from the candidates.
        """
        report_content = "# SCOUT Vulnerability Candidate Report\n\n"
        
        if not candidates:
            report_content += "No high-value candidates found in this scan.\n"
        else:
            report_content += f"**Total Candidates Found:** {len(candidates)}\n\n"
            report_content += "---\n\n"
            
            for cand in candidates:
                report_content += f"## [{cand.confidence.upper()}] {cand.candidate_type}\n"
                report_content += f"**ID:** {cand.candidate_id} | **Anchor:** `{cand.anchor}`\n\n"
                report_content += f"### Why this matters\n{cand.why_this_matters}\n\n"
                
                report_content += "### Evidence\n"
                for ev in cand.evidence:
                    report_content += f"- **[{ev.source}]** {ev.description} (`{ev.location}`)\n"
                report_content += "\n"
                
                report_content += "### Reproduction Steps\n"
                for i, step in enumerate(cand.reproduction_steps, 1):
                    report_content += f"{i}. {step}\n"
                report_content += "\n"
                
                report_content += "### Next Actions\n"
                for action in cand.next_actions:
                    report_content += f"- [ ] {action}\n"
                
                report_content += "\n---\n\n"
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_content)
        
        print(f"[Reporter] Report saved to {output_path}")
