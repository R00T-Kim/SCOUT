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
    assert "Top 1 candidate(s) [compact]" in out
    assert "[M] 0.760 cmd_exec_injection_risk" in out
    assert "Hypothesis groups: 1 unique" in out
    assert "G01 [M] family=cmd_exec_injection_risk" in out
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


def test_tui_cli_watch_renders_only_when_snapshot_changes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True)

    snapshots = iter(
        [
            ["header", "candidate_count=1"],
            ["header", "candidate_count=1"],
            ["header", "candidate_count=2"],
        ]
    )

    from aiedge import __main__ as cli

    def fake_snapshot_lines(*, run_dir: Path, limit: int) -> list[str]:
        _ = (run_dir, limit)
        return list(next(snapshots))

    sleep_count = {"value": 0}

    def fake_sleep(seconds: float) -> None:
        _ = seconds
        sleep_count["value"] += 1
        if sleep_count["value"] >= 3:
            raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_build_tui_snapshot_lines", fake_snapshot_lines)
    monkeypatch.setattr(cli.time, "sleep", fake_sleep)

    rc = main(["tui", str(run_dir), "--watch", "--interval-s", "0.1"])
    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out.count("candidate_count=1") == 1
    assert captured.out.count("candidate_count=2") == 1


def test_tui_cli_interactive_requires_tty(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True)
    rc = main(["tui", str(run_dir), "--interactive"])
    captured = capsys.readouterr()
    assert rc == 20
    assert "Interactive mode requires a TTY" in captured.err


def test_tui_cli_rejects_watch_and_interactive_together(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True)
    rc = main(["tui", str(run_dir), "--interactive", "--watch"])
    captured = capsys.readouterr()
    assert rc == 20
    assert "--interactive and --watch cannot be combined" in captured.err
