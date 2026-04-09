from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def test_reevaluate_benchmark_results_normalizes_legacy_archive_layout(
    tmp_path: Path,
) -> None:
    repo_root = Path(__file__).resolve().parent.parent
    results_dir = tmp_path / "benchmark-results" / "sample"
    bundle_dir = results_dir / "archives" / "acme" / "deadbeefcafe"

    nested_run = (
        bundle_dir
        / "home"
        / "user"
        / "repo"
        / "aiedge-runs"
        / "2026-04-09_0000_sha256-deadbeefcafe"
    )
    _write_json(
        nested_run / "stages" / "extraction" / "stage.json",
        {"status": "ok"},
    )
    _write_json(
        nested_run / "stages" / "inventory" / "inventory.json",
        {"quality": {"status": "sufficient", "files_seen": 10, "binaries_seen": 2}},
    )
    _write_json(
        nested_run / "stages" / "inventory" / "stage.json",
        {"status": "ok"},
    )
    _write_json(
        nested_run / "stages" / "findings" / "findings.json",
        {"findings": [{"id": "f1", "severity": "high"}]},
    )
    _write_json(
        nested_run / "stages" / "findings" / "exploit_candidates.json",
        {"candidates": [{"candidate_id": "c1"}]},
    )
    _write_json(
        nested_run / "stages" / "findings" / "stage.json",
        {"status": "ok"},
    )
    _write_json(
        nested_run / "stages" / "llm_triage" / "triage.json",
        {"status": "ok", "model_tier": "haiku", "rankings": [{"candidate_id": "c1", "priority": "high"}]},
    )
    _write_json(
        nested_run / "stages" / "adversarial_triage" / "triaged_findings.json",
        {"triaged_findings": []},
    )
    _write_json(
        nested_run / "stages" / "fp_verification" / "verified_alerts.json",
        {"verified_alerts": []},
    )
    _write_json(
        nested_run / "stages" / "graph" / "communication_graph.json",
        {"nodes": [], "edges": [], "summary": {"fallback_reference_graph": {"nodes": 1, "edges": 1}}},
    )
    _write_json(
        nested_run / "stages" / "graph" / "reference_graph.json",
        {"nodes": [{"id": "n1"}], "edges": [{"src": "n1", "dst": "n1", "edge_type": "x"}]},
    )
    _write_json(
        nested_run / "stages" / "attack_surface" / "attack_surface.json",
        {"attack_surface": []},
    )
    _write_json(
        bundle_dir / "manifest.json",
        {
            "run_id": "2026-04-09_0000_sha256-deadbeefcafe",
            "analyzed_input_sha256": "a" * 64,
            "analyzed_input_size_bytes": 1234,
            "created_at": "2026-04-09T00:00:00Z",
        },
    )
    _write_json(
        bundle_dir / "analyst_digest.json",
        {
            "schema_version": "analyst_digest-v1",
            "run": {
                "run_id": "2026-04-09_0000_sha256-deadbeefcafe",
                "firmware_sha256": "a" * 64,
                "generated_at": "2026-04-09T00:00:01Z",
            },
            "top_risk_summary": {
                "total_findings": 1,
                "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            },
            "finding_verdicts": [
                {
                    "finding_id": "f1",
                    "verdict": "NOT_ATTEMPTED",
                    "reason_codes": ["NOT_ATTEMPTED_REQUIRED_VERIFIER_MISSING"],
                    "evidence_refs": ["stages/findings/findings.json"],
                    "verifier_refs": ["stages/findings/findings.json"],
                }
            ],
            "exploitability_verdict": {
                "state": "NOT_ATTEMPTED",
                "reason_codes": ["NOT_ATTEMPTED_REQUIRED_VERIFIER_MISSING"],
                "aggregation_rule": "worst_state_precedence_v1",
            },
            "evidence_index": [{"ref": "stages/findings/findings.json", "sha256": "b" * 64}],
            "next_actions": ["Run required verifier pipeline to produce verified_chain artifacts."],
        },
    )
    _write_json(
        bundle_dir / "analyst_report.json",
        {"artifacts": {}, "claims": [], "sections": {}},
    )
    _write_json(bundle_dir / "analyst_report_v2.json", {"schema_version": "0.2", "source": "findings", "summary": {}, "top_risk_claims": [], "evidence_index": []})
    _write_json(bundle_dir / "analyst_overview.json", {"schema_version": "analyst_overview-v1", "summary": {}, "gates": [], "artifacts": [], "links": {}, "panes": [], "cockpit": {}})
    _write_json(bundle_dir / "report.json", {"overview": {"run_id": "2026-04-09_0000_sha256-deadbeefcafe"}})

    _write_json(
        results_dir / "benchmark_detail.json",
        {
            "generated_at": "2026-04-09T00:00:00Z",
            "rows": [
                {
                    "vendor": "acme",
                    "firmware": "fw.bin",
                    "sha256": "deadbeefcafe",
                    "status": "success",
                    "duration_s": "10",
                }
            ],
        },
    )

    script = repo_root / "scripts" / "reevaluate_benchmark_results.py"
    subprocess.run(
        [sys.executable, str(script), "--results-dir", str(results_dir)],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )

    csv_path = results_dir / "benchmark_analyst_readiness.csv"
    json_path = results_dir / "benchmark_analyst_readiness.json"
    assert csv_path.is_file()
    assert json_path.is_file()

    with csv_path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["vendor"] == "acme"
    assert rows[0]["analyst_readiness"] in {"ready", "degraded", "blocked"}
    assert rows[0]["bundle_dir"].endswith("archives/acme/deadbeefcafe")

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["summary"]["overall"]["total"] == 1
