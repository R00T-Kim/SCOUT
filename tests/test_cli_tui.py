from __future__ import annotations

import json
from pathlib import Path

import pytest

from aiedge.__main__ import main


def test_tui_cli_requires_existing_run_dir(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing_run_dir = tmp_path / "missing-run"
    rc = main(["tui", str(missing_run_dir)])
    captured = capsys.readouterr()
    assert rc == 20
    assert "Run directory not found" in captured.err


def test_tui_cli_renders_candidate_dashboard(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir = tmp_path / "run"
    report_dir = run_dir / "report"
    findings_dir = run_dir / "stages" / "findings"
    report_dir.mkdir(parents=True)
    findings_dir.mkdir(parents=True)

    _ = (run_dir / "manifest.json").write_text(
        json.dumps({"profile": "exploit"}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _ = (report_dir / "report.json").write_text(
        json.dumps(
            {
                "llm": {"status": "ok"},
                "report_completeness": {"status": "complete", "gate_passed": True},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _ = (report_dir / "analyst_digest.json").write_text(
        json.dumps(
            {
                "exploitability_verdict": {
                    "state": "NOT_ATTEMPTED",
                    "reason_codes": ["NOT_ATTEMPTED_REQUIRED_VERIFIER_MISSING"],
                }
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _ = (findings_dir / "exploit_candidates.json").write_text(
        json.dumps(
            {
                "schema_version": "exploit-candidates-v1",
                "summary": {
                    "candidate_count": 1,
                    "chain_backed": 0,
                    "high": 0,
                    "medium": 1,
                    "low": 0,
                },
                "candidates": [
                    {
                        "candidate_id": "candidate:1",
                        "priority": "medium",
                        "score": 0.76,
                        "source": "pattern",
                        "families": ["cmd_exec_injection_risk"],
                        "path": "stages/extraction/rootfs/opt/vyatta/sbin/vyatta-link-detect",
                        "attack_hypothesis": "Potential command injection if untrusted input reaches shell/eval execution path.",
                        "expected_impact": ["Arbitrary command execution in service context."],
                        "validation_plan": [
                            "Trace sink arguments to identify untrusted input propagation."
                        ],
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    rc = main(["tui", str(run_dir), "--limit", "5"])
    captured = capsys.readouterr()
    assert rc == 0
    out = captured.out
    assert "AIEdge TUI ::" in out
    assert "Exploit Candidate Map" in out
    assert "candidate_count=1" in out
    assert "[medium] score=0.760" in out
    assert "attack: Potential command injection" in out
    assert "next: Trace sink arguments" in out


def test_tui_cli_rejects_invalid_limit(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True)
    rc = main(["tui", str(run_dir), "--limit", "0"])
    captured = capsys.readouterr()
    assert rc == 20
    assert "Invalid --limit value" in captured.err

