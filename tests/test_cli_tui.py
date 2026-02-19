from __future__ import annotations

import json
from pathlib import Path

import pytest

from aiedge.__main__ import main


def _seed_minimal_run(run_dir: Path, *, candidate_count: int = 1) -> None:
    report_dir = run_dir / "report"
    findings_dir = run_dir / "stages" / "findings"
    report_dir.mkdir(parents=True)
    findings_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(
        json.dumps({"profile": "exploit"}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (report_dir / "report.json").write_text(
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
    (report_dir / "analyst_digest.json").write_text(
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
    (findings_dir / "exploit_candidates.json").write_text(
        json.dumps(
            {
                "schema_version": "exploit-candidates-v1",
                "summary": {
                    "candidate_count": int(candidate_count),
                    "chain_backed": 0,
                    "high": 0,
                    "medium": int(candidate_count),
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
    _seed_minimal_run(run_dir)

    rc = main(["tui", str(run_dir), "--limit", "5"])
    captured = capsys.readouterr()
    assert rc == 0
    out = captured.out
    assert "AIEdge TUI ::" in out
    assert "Exploit Candidate Map" in out
    assert "candidate_count=1" in out
    assert "Top 1 grouped candidate(s) [compact]" in out
    assert "Candidate groups: 1 unique" in out
    assert "G01 [M] family=cmd_exec_injection_risk" in out
    assert "attack: Potential command injection" in out
    assert "next: Trace sink arguments" in out


def test_tui_cli_shows_threat_model_overview(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir = tmp_path / "run"
    _seed_minimal_run(run_dir)
    threat_dir = run_dir / "stages" / "threat_model"
    threat_dir.mkdir(parents=True)
    (threat_dir / "threat_model.json").write_text(
        json.dumps(
            {
                "status": "ok",
                "summary": {
                    "attack_surface_items": 5,
                    "threats": 3,
                    "unknowns": 1,
                    "mitigations": 2,
                    "assumptions": 1,
                    "classification": "candidate",
                    "observation": "deterministic_static_inference",
                },
                "threats": [
                    {
                        "category": "elevation_of_privilege",
                        "title": "Privilege escalation path",
                        "endpoint": {"type": "url", "value": "http://192.0.2.10/admin"},
                    },
                    {
                        "category": "tampering",
                        "title": "Firmware update tampering",
                        "endpoint": {"type": "url", "value": "http://192.0.2.10/update"},
                    },
                    {
                        "category": "information_disclosure",
                        "title": "Config disclosure path",
                        "endpoint": {"type": "url", "value": "http://192.0.2.10/config"},
                    },
                ],
                "unknowns": [{"reason": "manual review"}],
                "mitigations": [{"category": "tampering"}],
                "assumptions": [{"id": "tm.assumption.static-only"}],
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
    assert "Threat Modeling Overview" in out
    assert "threat_model: status=ok | threats=3 | unknowns=1" in out
    assert "categories: elevation_of_privilege=1" in out
    assert "top_threats:" in out


def test_tui_cli_defaults_to_latest_run_dir(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runs_dir = tmp_path / "aiedge-runs"
    old_run = runs_dir / "run-old"
    new_run = runs_dir / "run-new"
    _seed_minimal_run(old_run, candidate_count=1)
    _seed_minimal_run(new_run, candidate_count=2)

    old_ts = 1_700_000_000
    new_ts = old_ts + 100
    old_manifest = old_run / "manifest.json"
    new_manifest = new_run / "manifest.json"
    old_manifest.touch()
    new_manifest.touch()
    import os

    os.utime(old_manifest, (old_ts, old_ts))
    os.utime(new_manifest, (new_ts, new_ts))

    monkeypatch.chdir(tmp_path)
    rc = main(["tui", "--limit", "1"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "run-new" in captured.out
    assert "candidate_count=2" in captured.out


def test_tui_cli_defaults_fail_without_any_runs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    rc = main(["tui"])
    captured = capsys.readouterr()
    assert rc == 20
    assert "Run directory not found" in captured.err


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


def test_tui_cli_shows_chain_linked_exploit_bundle_evidence(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir = tmp_path / "run"
    report_dir = run_dir / "report"
    findings_dir = run_dir / "stages" / "findings"
    exploits_dir = run_dir / "exploits" / "chain_alpha"
    (exploits_dir).mkdir(parents=True)
    (run_dir / "manifest.json").write_text(
        json.dumps({"profile": "exploit"}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report_dir.mkdir(parents=True)
    (report_dir / "report.json").write_text(
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
    (report_dir / "analyst_digest.json").write_text(
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
    (exploits_dir / "evidence_bundle.json").write_text(
        json.dumps({"chain_id": "alpha"}, sort_keys=True) + "\n", encoding="utf-8"
    )
    findings_dir.mkdir(parents=True)
    (findings_dir / "exploit_candidates.json").write_text(
        json.dumps(
            {
                "schema_version": "exploit-candidates-v1",
                "summary": {
                    "candidate_count": 1,
                    "chain_backed": 1,
                    "high": 0,
                    "medium": 1,
                    "low": 0,
                },
                "candidates": [
                    {
                        "candidate_id": "candidate:alpha",
                        "priority": "high",
                        "score": 0.92,
                        "source": "pattern",
                        "chain_id": "alpha",
                        "families": ["cmd_exec_injection_risk"],
                        "path": "stages/extraction/rootfs/opt/vyatta/sbin/vyatta-link-detect",
                        "attack_hypothesis": "Potential command injection if untrusted input reaches shell/eval execution path.",
                        "expected_impact": ["Arbitrary command execution in service context."],
                        "validation_plan": [
                            "Trace sink arguments to identify untrusted input propagation."
                        ],
                        "evidence_refs": [],
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    rc = main(["tui", str(run_dir)])
    captured = capsys.readouterr()
    assert rc == 0
    out = captured.out
    assert "Verifier artifacts:" in out
    assert "exploit_bundles=1" in out
    assert "exploit_bundle" in out
    assert "chain_linked" in out
