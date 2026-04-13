"""Unit tests for handoff_writer.write_firmware_handoff."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from aiedge.handoff_writer import (
    HANDOFF_SCHEMA_VERSION,
    collect_handoff_bundles,
    write_firmware_handoff,
)


@dataclass
class _FakeRunInfo:
    """Minimal duck-typed RunInfo for test isolation.

    Matches the attribute surface that write_firmware_handoff reads:
    ``manifest_path``, ``run_dir``, ``run_id``, ``report_json_path``,
    ``report_html_path``.
    """

    run_id: str
    run_dir: Path
    manifest_path: Path
    report_json_path: Path
    report_html_path: Path


def _setup_run_skeleton(tmp_path: Path, *, with_stage: bool = True) -> _FakeRunInfo:
    """Create a minimal on-disk run_dir layout for handoff tests."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "report").mkdir()
    (run_dir / "stages").mkdir()

    manifest_path = run_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps({"profile": "discovery"}) + "\n", encoding="utf-8"
    )

    report_json_path = run_dir / "report" / "report.json"
    report_json_path.write_text(json.dumps({"ok": True}) + "\n", encoding="utf-8")
    report_html_path = run_dir / "report" / "report.html"
    report_html_path.write_text("<html></html>\n", encoding="utf-8")

    if with_stage:
        stage_dir = run_dir / "stages" / "tooling"
        stage_dir.mkdir()
        # Create a tooling artifact referenced from stage.json.
        artifact_rel = "stages/tooling/tool_report.json"
        artifact_path = run_dir / artifact_rel
        artifact_path.write_text(json.dumps({"tool": "ok"}) + "\n", encoding="utf-8")
        stage_json = {
            "contract_version": "1.0",
            "stage_name": "tooling",
            "stage_identity": "tooling@test",
            "attempt": 1,
            "status": "ok",
            "limitations": [],
            "artifacts": [{"path": artifact_rel, "sha256": "fakehash"}],
        }
        (stage_dir / "stage.json").write_text(
            json.dumps(stage_json) + "\n", encoding="utf-8"
        )

    return _FakeRunInfo(
        run_id="test-run-id",
        run_dir=run_dir,
        manifest_path=manifest_path,
        report_json_path=report_json_path,
        report_html_path=report_html_path,
    )


def test_write_firmware_handoff_creates_file(tmp_path: Path) -> None:
    """Basic happy path: file is created with required top-level keys."""
    info = _setup_run_skeleton(tmp_path)

    write_firmware_handoff(info=info, profile="discovery", max_wallclock_per_run=600)

    handoff_path = info.run_dir / "firmware_handoff.json"
    assert handoff_path.is_file()
    payload = json.loads(handoff_path.read_text(encoding="utf-8"))

    # Required schema keys.
    for key in (
        "schema_version",
        "generated_at",
        "profile",
        "policy",
        "aiedge",
        "bundles",
    ):
        assert key in payload, f"missing key: {key}"

    assert payload["schema_version"] == HANDOFF_SCHEMA_VERSION
    assert payload["profile"] == "discovery"
    assert payload["policy"]["max_wallclock_per_run"] == 600
    assert payload["policy"]["max_reruns_per_stage"] == 3
    assert payload["policy"]["max_total_stage_attempts"] == 64
    assert payload["aiedge"]["run_id"] == "test-run-id"
    assert payload["aiedge"]["report_json"] == "report/report.json"
    assert payload["aiedge"]["report_html"] == "report/report.html"


def test_write_firmware_handoff_includes_bundles(tmp_path: Path) -> None:
    """Bundle list should contain the stage manifest we created."""
    info = _setup_run_skeleton(tmp_path)

    write_firmware_handoff(info=info, profile="discovery", max_wallclock_per_run=600)

    payload = json.loads(
        (info.run_dir / "firmware_handoff.json").read_text(encoding="utf-8")
    )
    bundles = payload["bundles"]
    assert isinstance(bundles, list)
    assert len(bundles) >= 1
    tooling_bundles = [b for b in bundles if b.get("stage") == "tooling"]
    assert tooling_bundles, "tooling bundle missing"
    tooling = tooling_bundles[0]
    assert tooling["status"] == "ok"
    assert "stages/tooling/stage.json" in tooling["artifacts"]


def test_write_firmware_handoff_fallback_when_no_stages(tmp_path: Path) -> None:
    """If there are no stage bundles, fall back to run-metadata bundle."""
    info = _setup_run_skeleton(tmp_path, with_stage=False)

    write_firmware_handoff(info=info, profile="discovery", max_wallclock_per_run=600)

    payload = json.loads(
        (info.run_dir / "firmware_handoff.json").read_text(encoding="utf-8")
    )
    bundles = payload["bundles"]
    assert len(bundles) == 1
    assert bundles[0]["id"] == "run-metadata"
    assert bundles[0]["stage"] == "run"
    # Should list the report.json (and manifest.json) as artifacts.
    arts = bundles[0]["artifacts"]
    assert "report/report.json" in arts


def test_write_firmware_handoff_exploit_gate_included_for_exploit_profile(
    tmp_path: Path,
) -> None:
    """When profile='exploit' and manifest has exploit_gate, include it."""
    info = _setup_run_skeleton(tmp_path)
    info.manifest_path.write_text(
        json.dumps(
            {
                "profile": "exploit",
                "exploit_gate": {"decision": "go", "score": 0.9},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    write_firmware_handoff(info=info, profile="exploit", max_wallclock_per_run=1200)

    payload = json.loads(
        (info.run_dir / "firmware_handoff.json").read_text(encoding="utf-8")
    )
    assert payload["profile"] == "exploit"
    assert "exploit_gate" in payload
    assert payload["exploit_gate"]["decision"] == "go"


def test_write_firmware_handoff_exploit_gate_omitted_for_discovery_profile(
    tmp_path: Path,
) -> None:
    """Exploit gate must NOT be included for non-exploit profiles."""
    info = _setup_run_skeleton(tmp_path)
    info.manifest_path.write_text(
        json.dumps(
            {
                "profile": "discovery",
                "exploit_gate": {"decision": "go"},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    write_firmware_handoff(info=info, profile="discovery", max_wallclock_per_run=600)

    payload = json.loads(
        (info.run_dir / "firmware_handoff.json").read_text(encoding="utf-8")
    )
    assert "exploit_gate" not in payload


def test_write_firmware_handoff_adversarial_triage_reference(tmp_path: Path) -> None:
    """Adversarial triage schema reference should be attached when the artifact exists."""
    info = _setup_run_skeleton(tmp_path)
    adv_dir = info.run_dir / "stages" / "adversarial_triage"
    adv_dir.mkdir()
    (adv_dir / "triaged_findings.json").write_text(
        json.dumps(
            {
                "schema_version": "adversarial-triage-v1",
                "summary": {"total": 3, "maintained": 2, "downgraded": 1},
                "triaged_findings": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    write_firmware_handoff(info=info, profile="discovery", max_wallclock_per_run=600)

    payload = json.loads(
        (info.run_dir / "firmware_handoff.json").read_text(encoding="utf-8")
    )
    assert "adversarial_triage" in payload
    adv = payload["adversarial_triage"]
    assert adv["artifact"] == "stages/adversarial_triage/triaged_findings.json"
    assert adv["schema"]["version"] == "adversarial-triage-v1"
    assert adv["schema"]["findings_key"] == "triaged_findings"
    assert adv["summary"]["total"] == 3


def test_write_firmware_handoff_max_wallclock_minimum_one(tmp_path: Path) -> None:
    """max_wallclock_per_run should be clamped to >=1."""
    info = _setup_run_skeleton(tmp_path)

    write_firmware_handoff(info=info, profile="discovery", max_wallclock_per_run=0)

    payload = json.loads(
        (info.run_dir / "firmware_handoff.json").read_text(encoding="utf-8")
    )
    assert payload["policy"]["max_wallclock_per_run"] == 1


def test_collect_handoff_bundles_empty_when_no_stages_dir(tmp_path: Path) -> None:
    """collect_handoff_bundles returns [] if stages/ is absent."""
    run_dir = tmp_path / "empty_run"
    run_dir.mkdir()
    bundles = collect_handoff_bundles(run_dir)
    assert bundles == []


def test_collect_handoff_bundles_includes_findings_artifacts(tmp_path: Path) -> None:
    """Findings directory contents should surface as a findings-artifacts bundle."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    findings_dir = run_dir / "stages" / "findings"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps({"findings": []}) + "\n", encoding="utf-8"
    )

    bundles = collect_handoff_bundles(run_dir)
    findings_bundles = [b for b in bundles if b["stage"] == "findings"]
    assert findings_bundles, "findings-artifacts bundle missing"
    fb = findings_bundles[0]
    assert fb["id"] == "findings-artifacts"
    assert "stages/findings/findings.json" in fb["artifacts"]


def test_write_firmware_handoff_json_is_deterministic(tmp_path: Path) -> None:
    """JSON output uses sort_keys=True so top-level ordering is stable."""
    info = _setup_run_skeleton(tmp_path)

    write_firmware_handoff(info=info, profile="discovery", max_wallclock_per_run=600)

    raw = (info.run_dir / "firmware_handoff.json").read_text(encoding="utf-8")
    # sort_keys=True ⇒ 'aiedge' precedes 'bundles' precedes 'generated_at', etc.
    idx_aiedge = raw.index('"aiedge"')
    idx_bundles = raw.index('"bundles"')
    idx_generated = raw.index('"generated_at"')
    idx_policy = raw.index('"policy"')
    idx_profile = raw.index('"profile"')
    idx_schema = raw.index('"schema_version"')
    assert (
        idx_aiedge < idx_bundles < idx_generated < idx_policy < idx_profile < idx_schema
    )
