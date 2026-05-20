from __future__ import annotations

import json
from pathlib import Path

from aiedge.script_analyzer import ScriptAnalyzer
from aiedge.stage import StageContext


def _ctx(run_dir: Path) -> StageContext:
    return StageContext(
        run_dir=run_dir,
        logs_dir=run_dir / "logs",
        report_dir=run_dir / "report",
    )


def _write_inventory(run_dir: Path, scripts: list[object]) -> None:
    inv_dir = run_dir / "stages" / "inventory"
    inv_dir.mkdir(parents=True)
    _ = (inv_dir / "inventory.json").write_text(
        json.dumps({"scripts": scripts}) + "\n",
        encoding="utf-8",
    )


def test_script_analyzer_uses_inventory_scripts_and_emits_normalized_findings(tmp_path: Path) -> None:
    script = tmp_path / "stages" / "extraction" / "rootfs" / "etc" / "init.d" / "svc"
    script.parent.mkdir(parents=True)
    _ = script.write_text(
        "#!/bin/sh\n"
        "eval $USER_INPUT\n"
        "echo safe\n",
        encoding="utf-8",
    )
    rel = script.relative_to(tmp_path).as_posix()
    _write_inventory(tmp_path, [rel])

    out = ScriptAnalyzer().run(_ctx(tmp_path))

    assert out.status == "ok"
    assert out.limitations == []
    assert out.details["scripts_discovered"] == 1
    assert out.details["scripts_analyzed"] == 1
    findings = out.details["findings"]
    assert isinstance(findings, list)
    assert any(
        isinstance(f, dict)
        and str(f.get("id", "")).startswith("script_analysis.shell.eval.variable:")
        and f.get("source_type") == "shell_script"
        and f.get("confidence") == "medium"
        for f in findings
    )


def test_script_analyzer_reports_inventory_contract_gap(tmp_path: Path) -> None:
    inv_dir = tmp_path / "stages" / "inventory"
    inv_dir.mkdir(parents=True)
    _ = (inv_dir / "inventory.json").write_text("{}\n", encoding="utf-8")

    out = ScriptAnalyzer().run(_ctx(tmp_path))

    assert out.status == "partial"
    assert out.details["scripts_discovered"] == 0
    assert "inventory_schema_missing:scripts" in out.limitations


def test_script_analyzer_counts_missing_script_paths(tmp_path: Path) -> None:
    _write_inventory(tmp_path, ["stages/extraction/rootfs/missing.sh"])

    out = ScriptAnalyzer().run(_ctx(tmp_path))

    assert out.status == "partial"
    assert out.details["scripts_discovered"] == 1
    assert out.details["scripts_analyzed"] == 0
    assert out.details["scripts_missing"] == 1
    assert "script_path_miss_count:1" in out.limitations


def test_script_analyzer_caps_finding_volume(tmp_path: Path) -> None:
    script = tmp_path / "stages" / "extraction" / "rootfs" / "many.sh"
    script.parent.mkdir(parents=True)
    _ = script.write_text("#!/bin/sh\n" + "eval $X\n" * 600, encoding="utf-8")
    _write_inventory(tmp_path, [script.relative_to(tmp_path).as_posix()])

    out = ScriptAnalyzer().run(_ctx(tmp_path))

    assert out.status == "partial"
    assert out.details["findings_truncated"] is True
    findings = out.details["findings"]
    assert isinstance(findings, list)
    assert len(findings) == out.details["max_findings"] == 500
    assert "script_findings_truncated:max_findings=500" in out.limitations


def test_script_analysis_report_summary_preserves_failure_counters() -> None:
    from aiedge.run import _apply_stage_result_to_report
    from aiedge.stage import StageResult

    report: dict[str, object] = {}
    result = StageResult(
        stage="script_analysis",
        status="partial",
        started_at="2026-05-20T00:00:00Z",
        finished_at="2026-05-20T00:00:01Z",
        duration_s=1.0,
        details={
            "findings": [],
            "scripts_discovered": 3,
            "scripts_analyzed": 1,
            "scripts_missing": 1,
            "scripts_read_failed": 1,
            "findings_truncated": True,
        },
        limitations=["script_path_miss_count:1"],
        error=None,
        timed_out=False,
    )

    _apply_stage_result_to_report(report, result, budget_s=3600)

    script_report = report["script_analysis"]
    assert isinstance(script_report, dict)
    assert script_report["summary"] == {
        "scripts_discovered": 3,
        "scripts_analyzed": 1,
        "scripts_missing": 1,
        "scripts_read_failed": 1,
        "findings_truncated": True,
        "total_findings": 0,
    }
