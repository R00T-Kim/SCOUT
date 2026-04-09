from __future__ import annotations

import json
from pathlib import Path

from aiedge.benchmark_eval import (
    collect_run_metrics,
    copy_run_bundle,
    evaluate_analyst_readiness,
    manifest_primary_sha256,
    manifest_primary_size_bytes,
)


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def test_manifest_primary_fields_prefer_analyzed_input() -> None:
    manifest = {
        "sha256": "legacy",
        "file_size_bytes": 1,
        "input_sha256": "input",
        "input_size_bytes": 2,
        "analyzed_input_sha256": "analyzed",
        "analyzed_input_size_bytes": 3,
    }

    assert manifest_primary_sha256(manifest) == "analyzed"
    assert manifest_primary_size_bytes(manifest) == 3


def test_copy_run_bundle_preserves_run_relative_layout(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_json(run_dir / "report" / "analyst_digest.json", {"ok": True})
    _write_json(run_dir / "stages" / "llm_triage" / "triage.json", {"status": "ok"})
    _write_json(run_dir / "stages" / "llm_triage" / "stage.json", {"status": "ok"})

    archive_dir = tmp_path / "archive"
    copy_run_bundle(run_dir, archive_dir)

    assert (archive_dir / "report" / "analyst_digest.json").is_file()
    assert (archive_dir / "stages" / "llm_triage" / "triage.json").is_file()
    assert not (archive_dir / "analyst_digest.json").exists()


def test_collect_run_metrics_and_readiness_ready(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_json(
        run_dir / "manifest.json",
        {
            "analyzed_input_sha256": "a" * 64,
            "analyzed_input_size_bytes": 4096,
        },
    )
    _write_json(run_dir / "stages" / "extraction" / "stage.json", {"status": "ok"})
    _write_json(
        run_dir / "stages" / "inventory" / "inventory.json",
        {"quality": {"status": "sufficient", "files_seen": 10, "binaries_seen": 4}},
    )
    _write_json(run_dir / "stages" / "inventory" / "stage.json", {"status": "ok"})
    _write_json(
        run_dir / "stages" / "findings" / "findings.json",
        {"findings": [{"severity": "high"}]},
    )
    _write_json(
        run_dir / "stages" / "findings" / "exploit_candidates.json",
        {"candidates": [{"candidate_id": "c1"}]},
    )
    _write_json(run_dir / "stages" / "findings" / "stage.json", {"status": "ok"})
    _write_json(
        run_dir / "stages" / "llm_triage" / "triage.json",
        {"status": "ok", "model_tier": "haiku", "rankings": [{"candidate_id": "c1", "priority": "high"}]},
    )
    _write_json(run_dir / "stages" / "llm_triage" / "stage.json", {"status": "ok"})
    _write_json(
        run_dir / "stages" / "adversarial_triage" / "triaged_findings.json",
        {
            "triaged_findings": [
                {
                    "advocate_argument": {"argument": "reachable"},
                    "critic_rebuttal": {"rebuttal": "none"},
                }
            ]
        },
    )
    _write_json(run_dir / "stages" / "adversarial_triage" / "stage.json", {"status": "ok"})
    _write_json(
        run_dir / "stages" / "fp_verification" / "verified_alerts.json",
        {"verified_alerts": [{"fp_verdict": "TP"}]},
    )
    _write_json(run_dir / "stages" / "fp_verification" / "stage.json", {"status": "ok"})
    _write_json(
        run_dir / "stages" / "graph" / "communication_graph.json",
        {"nodes": [{"id": "n1"}], "edges": [{"source": "n1", "target": "n1"}]},
    )
    _write_json(run_dir / "stages" / "graph" / "stage.json", {"status": "ok"})
    _write_json(
        run_dir / "stages" / "attack_surface" / "attack_surface.json",
        {"attack_surface": [{"promotion_status": "promoted_runtime"}]},
    )
    _write_json(run_dir / "stages" / "attack_surface" / "stage.json", {"status": "ok"})

    metrics = collect_run_metrics(run_dir)
    readiness = evaluate_analyst_readiness(
        metrics=metrics,
        digest_verifier={"ok": True},
        report_verifier={"ok": True},
    )

    assert metrics["actionable_candidate_count"] == 1
    assert metrics["graph_empty"] is False
    assert readiness["analyst_readiness"] == "ready"
    assert readiness["analyst_reason_codes"] == []


def test_evaluate_analyst_readiness_blocks_on_verifier_failure(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_json(run_dir / "stages" / "extraction" / "stage.json", {"status": "ok"})
    _write_json(
        run_dir / "stages" / "inventory" / "inventory.json",
        {"quality": {"status": "sufficient", "files_seen": 1, "binaries_seen": 1}},
    )

    metrics = collect_run_metrics(run_dir)
    readiness = evaluate_analyst_readiness(
        metrics=metrics,
        digest_verifier={"ok": False},
        report_verifier={"ok": True},
    )

    assert readiness["analyst_readiness"] == "blocked"
    assert "digest_verifier_failed" in readiness["analyst_reason_codes"]
