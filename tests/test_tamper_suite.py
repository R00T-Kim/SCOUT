from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import cast


_CANONICAL_SHA256 = "387d97fd925125471691d5c565fcc0ff009e111bdbdfd2ddb057f9212a939c8a"

_REQUIRED_SECTIONS: tuple[str, ...] = (
    "attribution",
    "endpoints",
    "surfaces",
    "graph",
    "attack_surface",
    "threat_model",
    "functional_spec",
    "poc_validation",
    "llm_synthesis",
)

_STAGE_ARTIFACTS: dict[str, str] = {
    "attribution": "stages/attribution/attribution.json",
    "endpoints": "stages/endpoints/endpoints.json",
    "surfaces": "stages/surfaces/surfaces.json",
    "graph": "stages/graph/comm_graph.json",
    "attack_surface": "stages/attack_surface/attack_surface.json",
    "threat_model": "stages/threat_model/threat_model.json",
    "functional_spec": "stages/functional_spec/functional_spec.json",
    "poc_validation": "stages/poc_validation/poc_validation.json",
    "llm_synthesis": "stages/llm_synthesis/llm_synthesis.json",
    "findings_pattern_scan": "stages/findings/pattern_scan.json",
    "findings_binary_strings_hits": "stages/findings/binary_strings_hits.json",
}

_REQUIRED_STAGE_SCHEMAS: dict[str, str] = {
    "findings_pattern_scan": "pattern-scan-v1",
    "findings_binary_strings_hits": "binary-strings-hits-v1",
}


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    _ = path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_quality_manifest(path: Path) -> None:
    payload = {
        "corpus_id": "tamper-suite",
        "version": "1.0.0",
        "samples": [
            {
                "id": "s1",
                "path": "fixtures/s1.json",
                "split": "dev",
                "labels": ["attack_surface"],
                "predicted_labels": ["attack_surface"],
                "license": "MIT",
            },
            {
                "id": "s2",
                "path": "fixtures/s2.json",
                "split": "eval",
                "labels": ["metrics"],
                "predicted_labels": ["metrics"],
                "license": "MIT",
            },
            {
                "id": "s3",
                "path": "fixtures/s3.json",
                "split": "holdout",
                "labels": ["reference_context"],
                "predicted_labels": ["reference_context"],
                "license": "MIT",
            },
            {
                "id": "s4",
                "path": "fixtures/s4.json",
                "split": "dev",
                "labels": ["taxonomy"],
                "predicted_labels": ["taxonomy"],
                "license": "MIT",
            },
        ],
    }
    _write_json(path, payload)


def _make_quality_manifest_threshold_miss(path: Path) -> None:
    payload = {
        "corpus_id": "tamper-suite",
        "version": "1.0.0",
        "samples": [
            {
                "id": "s1",
                "path": "fixtures/s1.json",
                "split": "dev",
                "labels": ["attack_surface"],
                "predicted_labels": ["metrics"],
                "license": "MIT",
            },
            {
                "id": "s2",
                "path": "fixtures/s2.json",
                "split": "eval",
                "labels": ["metrics"],
                "predicted_labels": ["reference_context"],
                "license": "MIT",
            },
            {
                "id": "s3",
                "path": "fixtures/s3.json",
                "split": "holdout",
                "labels": ["reference_context"],
                "predicted_labels": ["taxonomy"],
                "license": "MIT",
            },
            {
                "id": "s4",
                "path": "fixtures/s4.json",
                "split": "dev",
                "labels": ["taxonomy"],
                "predicted_labels": ["attack_surface"],
                "license": "MIT",
            },
        ],
    }
    _write_json(path, payload)


def _write_release_run_fixture(tmp_path: Path) -> tuple[Path, Path]:
    run_dir = tmp_path / "run"
    report_dir = run_dir / "report"
    report_dir.mkdir(parents=True)

    _ = (run_dir / "stages" / "surfaces").mkdir(parents=True, exist_ok=True)
    _ = (run_dir / "stages" / "endpoints").mkdir(parents=True, exist_ok=True)
    _ = (run_dir / "stages" / "surfaces" / "surface.txt").write_text(
        "surface\n", encoding="utf-8"
    )
    _ = (run_dir / "stages" / "endpoints" / "endpoint.txt").write_text(
        "endpoint\n", encoding="utf-8"
    )

    report: dict[str, object] = {
        "report_completeness": {"gate_passed": True},
        "run_completion": {
            "is_final": True,
            "conclusion_ready": True,
            "required_stage_statuses": {"findings": "ok"},
        },
        "duplicate_gate": {
            "taxonomy_version": "duplicate-taxonomy-v1",
            "artifact": "report/duplicate_gate.json",
        },
        "firmware_lineage": {
            "details": {
                "lineage": "stages/firmware_lineage/lineage.json",
                "lineage_diff": "stages/firmware_lineage/lineage_diff.json",
            }
        },
        "findings": [],
    }
    manifest: dict[str, object] = {
        "track": {
            "track_id": "8mb",
            "canonical_sha256_prefix": _CANONICAL_SHA256[:12],
            "canonical_size_bytes": 8_388_608,
        },
        "input_sha256": _CANONICAL_SHA256,
        "source_input_sha256": _CANONICAL_SHA256,
        "analyzed_input_sha256": _CANONICAL_SHA256,
        "input_size_bytes": 8_388_608,
        "source_input_size_bytes": 8_388_608,
        "analyzed_input_size_bytes": 8_388_608,
    }

    analyst_report: dict[str, object] = {
        "schema_version": "0.1",
        "claims": [
            {
                "claim_type": "summary.endpoints.count",
                "value": 1,
                "confidence": 0.9,
                "evidence_refs": ["stages/endpoints/endpoint.txt"],
            }
        ],
        "artifacts": {
            "section_evidence_paths": {
                section: [_STAGE_ARTIFACTS[section]] for section in _REQUIRED_SECTIONS
            }
        },
        "limitations": [],
    }
    for section in _REQUIRED_SECTIONS:
        analyst_report[section] = {
            "status": "ok",
            "evidence": [{"path": _STAGE_ARTIFACTS[section]}],
        }

    for section, rel_path in _STAGE_ARTIFACTS.items():
        stage_path = run_dir / rel_path
        stage_path.parent.mkdir(parents=True, exist_ok=True)
        stage_payload: dict[str, object] = {
            "section": section,
            "status": "ok",
            "evidence_refs": [
                "stages/surfaces/surface.txt",
                "stages/endpoints/endpoint.txt",
            ],
        }
        required_schema = _REQUIRED_STAGE_SCHEMAS.get(section)
        if required_schema is not None:
            stage_payload["schema_version"] = required_schema
        _write_json(stage_path, stage_payload)

    _write_json(
        report_dir / "duplicate_gate.json",
        {
            "schema_version": "duplicate-gate-v1",
            "novelty": [],
            "ranked": [],
        },
    )
    _ = (run_dir / "stages" / "firmware_lineage").mkdir(parents=True, exist_ok=True)
    _write_json(
        run_dir / "stages" / "firmware_lineage" / "lineage.json",
        {
            "schema_version": 1,
            "lineage": [],
        },
    )
    _write_json(
        run_dir / "stages" / "firmware_lineage" / "lineage_diff.json",
        {
            "schema_version": 1,
            "diff": {},
        },
    )

    _write_json(report_dir / "report.json", report)
    _write_json(run_dir / "manifest.json", manifest)
    _write_json(report_dir / "analyst_report.json", analyst_report)

    quality_manifest = tmp_path / "quality_manifest.json"
    _make_quality_manifest(quality_manifest)
    return run_dir, quality_manifest


def _run_release_gate(
    run_dir: Path, quality_manifest: Path, *, llm_fixture: Path | None = None
) -> subprocess.CompletedProcess[str]:
    repo_root = _repo_root()
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root / "src")
    env["AIEDGE_SKIP_TAMPER_TESTS"] = "1"
    argv = [
        "bash",
        str(repo_root / "scripts" / "release_gate.sh"),
        "--run-dir",
        str(run_dir),
        "--manifest",
        str(quality_manifest),
        "--metrics-out",
        str(run_dir / "metrics.json"),
        "--quality-out",
        str(run_dir / "quality_gate.json"),
    ]
    if llm_fixture is not None:
        argv.extend(["--llm-fixture", str(llm_fixture)])
    return subprocess.run(
        argv,
        cwd=repo_root,
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


def _run_analyst_verifier(run_dir: Path) -> subprocess.CompletedProcess[str]:
    repo_root = _repo_root()
    return subprocess.run(
        [
            sys.executable,
            str(repo_root / "scripts" / "verify_aiedge_analyst_report.py"),
            "--run-dir",
            str(run_dir),
        ],
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
    )


def test_tamper_report_mutation_fails_unified_release_gate(tmp_path: Path) -> None:
    run_dir, quality_manifest = _write_release_run_fixture(tmp_path)
    report_path = run_dir / "report" / "report.json"
    report_obj = cast(
        dict[str, object], json.loads(report_path.read_text(encoding="utf-8"))
    )
    run_completion = cast(dict[str, object], report_obj["run_completion"])
    run_completion["is_final"] = False
    _write_json(report_path, report_obj)

    res = _run_release_gate(run_dir, quality_manifest)
    assert res.returncode != 0
    assert "[GATE][FAIL][CONTRACT_FINAL]" in res.stdout


def test_tamper_path_poisoning_absolute_path_is_rejected(tmp_path: Path) -> None:
    run_dir, _ = _write_release_run_fixture(tmp_path)
    report_path = run_dir / "report" / "analyst_report.json"
    report_obj = cast(
        dict[str, object], json.loads(report_path.read_text(encoding="utf-8"))
    )
    claims = cast(list[object], report_obj["claims"])
    claim0 = cast(dict[str, object], claims[0])
    claim0["evidence_refs"] = ["/tmp/poisoned-evidence.json"]
    _write_json(report_path, report_obj)

    res = _run_analyst_verifier(run_dir)
    assert res.returncode != 0
    assert "must be run-relative path" in res.stdout


def test_tamper_evidence_drift_is_rejected(tmp_path: Path) -> None:
    run_dir, _ = _write_release_run_fixture(tmp_path)
    graph_artifact = run_dir / "stages" / "graph" / "comm_graph.json"
    artifact_obj = cast(
        dict[str, object], json.loads(graph_artifact.read_text(encoding="utf-8"))
    )
    artifact_obj["evidence_refs"] = ["stages/surfaces/missing-surface.txt"]
    _write_json(graph_artifact, artifact_obj)

    res = _run_analyst_verifier(run_dir)
    assert res.returncode != 0
    assert "dangling path" in res.stdout


def test_tamper_llm_fixture_pass_baseline_unified_release_gate(tmp_path: Path) -> None:
    run_dir, quality_manifest = _write_release_run_fixture(tmp_path)
    fixture_path = tmp_path / "llm_gate_fixture.json"
    _write_json(fixture_path, {"verdict": "pass"})

    res = _run_release_gate(run_dir, quality_manifest, llm_fixture=fixture_path)
    assert res.returncode == 0
    assert "[GATE][PASS][QUALITY_POLICY]" in res.stdout


def test_tamper_llm_fixture_invalid_json_fails_closed(tmp_path: Path) -> None:
    run_dir, quality_manifest = _write_release_run_fixture(tmp_path)
    fixture_path = tmp_path / "llm_gate_fixture.json"
    _ = fixture_path.write_text("{", encoding="utf-8")

    res = _run_release_gate(run_dir, quality_manifest, llm_fixture=fixture_path)
    assert res.returncode != 0
    assert "[GATE][FAIL][QUALITY_POLICY]" in res.stdout
    assert "[GATE][LOG][QUALITY_POLICY]" in res.stdout
    assert "QUALITY_GATE_LLM_INVALID" in res.stdout


def test_tamper_llm_fixture_absolute_evidence_path_rejected(tmp_path: Path) -> None:
    run_dir, quality_manifest = _write_release_run_fixture(tmp_path)
    fixture_path = tmp_path / "llm_gate_fixture.json"
    _write_json(
        fixture_path,
        {
            "verdict": "pass",
            "evidence_refs": ["/tmp/abs"],
        },
    )

    res = _run_release_gate(run_dir, quality_manifest, llm_fixture=fixture_path)
    assert res.returncode != 0
    assert "[GATE][FAIL][QUALITY_POLICY]" in res.stdout
    assert "QUALITY_GATE_LLM_INVALID" in res.stdout


def test_tamper_llm_fixture_pass_cannot_override_threshold_miss(tmp_path: Path) -> None:
    run_dir, _ = _write_release_run_fixture(tmp_path)
    quality_manifest = tmp_path / "quality_manifest_threshold_miss.json"
    _make_quality_manifest_threshold_miss(quality_manifest)
    fixture_path = tmp_path / "llm_gate_fixture.json"
    _write_json(fixture_path, {"verdict": "pass"})

    res = _run_release_gate(run_dir, quality_manifest, llm_fixture=fixture_path)
    assert res.returncode != 0
    assert "[GATE][FAIL][QUALITY_POLICY]" in res.stdout
    assert "QUALITY_GATE_THRESHOLD_MISS" in res.stdout
