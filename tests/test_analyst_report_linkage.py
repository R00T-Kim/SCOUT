from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import cast

from aiedge.reporting import build_analyst_report
from aiedge.run import analyze_run, create_run
from aiedge.schema import JsonValue, validate_analyst_report

REQUIRED_SECTIONS: tuple[str, ...] = (
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

STAGE_ARTIFACTS: dict[str, str] = {
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

ATTACK_SURFACE_METRICS_REL = "stages/attack_surface/attack_surface_metrics.json"
RUN_LOCAL_BENCHMARK_FIXTURE_REL = (
    "benchmarks/attack_surface_accuracy/benchmark_fixture.json"
)


def _run_verifier(run_dir: Path) -> subprocess.CompletedProcess[str]:
    repo_root = Path(__file__).resolve().parents[1]
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


def _write_minimal_linkage_fixture(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    (run_dir / "report").mkdir(parents=True)

    for section in REQUIRED_SECTIONS:
        stage_dir = run_dir / "stages" / section
        stage_dir.mkdir(parents=True, exist_ok=True)

    _ = (run_dir / "stages" / "surfaces" / "surface.txt").write_text(
        "surface\n", encoding="utf-8"
    )
    _ = (run_dir / "stages" / "endpoints" / "endpoint.txt").write_text(
        "endpoint\n", encoding="utf-8"
    )

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
                section: [STAGE_ARTIFACTS[section]] for section in REQUIRED_SECTIONS
            }
        },
        "limitations": [],
    }
    for section in REQUIRED_SECTIONS:
        analyst_report[section] = {
            "status": "ok",
            "evidence": [
                {
                    "path": STAGE_ARTIFACTS[section],
                }
            ],
        }

    _ = (run_dir / "report" / "analyst_report.json").write_text(
        json.dumps(analyst_report, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    for section, rel_path in STAGE_ARTIFACTS.items():
        stage_obj: dict[str, object] = {
            "status": "ok",
            "evidence_refs": [
                "stages/surfaces/surface.txt",
                "stages/endpoints/endpoint.txt",
            ],
            "section": section,
        }
        required_schema = _REQUIRED_STAGE_SCHEMAS.get(section)
        if required_schema is not None:
            stage_obj["schema_version"] = required_schema
        artifact_path = run_dir / rel_path
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        _ = artifact_path.write_text(
            json.dumps(stage_obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

    return run_dir


def _attach_metrics_artifact(run_dir: Path, *, dangling_ref: bool) -> None:
    benchmark_fixture_path = run_dir / RUN_LOCAL_BENCHMARK_FIXTURE_REL
    benchmark_fixture_path.parent.mkdir(parents=True, exist_ok=True)
    _ = benchmark_fixture_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source": "run-local",
                "categories": [{"name": "taxonomy", "refs": ["r1"]}],
                "labels": {
                    "positive": {
                        "endpoint_candidates": [
                            {
                                "type": "domain",
                                "value": "example.test",
                            }
                        ],
                        "promotion_labels": [
                            {
                                "type": "domain",
                                "value": "example.test",
                            }
                        ],
                    },
                    "negative": {"noise_tokens": ["*.ko"]},
                },
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        )
        + "\n",
        encoding="utf-8",
    )

    metrics_refs = [
        STAGE_ARTIFACTS["attack_surface"],
        RUN_LOCAL_BENCHMARK_FIXTURE_REL,
    ]
    if dangling_ref:
        metrics_refs.append("stages/attack_surface/missing-proof.json")

    _ = (run_dir / ATTACK_SURFACE_METRICS_REL).write_text(
        json.dumps(
            {
                "schema_version": 1,
                "fixture": RUN_LOCAL_BENCHMARK_FIXTURE_REL,
                "metrics": {
                    "duplicate_ratio": 0.0,
                    "promotion_precision": 1.0,
                    "promotion_recall": 1.0,
                    "static_only_ratio": 0.0,
                    "taxonomy_precision": 1.0,
                    "taxonomy_recall": 1.0,
                },
                "calibration": {
                    "mode": "rule_based",
                    "dataset": "benchmark_fixture_labels",
                    "supports_probability_calibration": False,
                },
                "evidence_refs": metrics_refs,
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        )
        + "\n",
        encoding="utf-8",
    )

    report_path = run_dir / "report" / "analyst_report.json"
    report = cast(
        dict[str, object], json.loads(report_path.read_text(encoding="utf-8"))
    )
    artifacts = cast(dict[str, object], report["artifacts"])
    section_evidence_paths = cast(
        dict[str, object], artifacts["section_evidence_paths"]
    )
    attack_surface_paths = list(
        cast(list[object], section_evidence_paths["attack_surface"])
    )
    attack_surface_paths.append(ATTACK_SURFACE_METRICS_REL)
    section_evidence_paths["attack_surface"] = sorted(
        {p for p in attack_surface_paths if isinstance(p, str) and p}
    )
    _ = report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def test_analyze_run_writes_analyst_report_files(tmp_path: Path) -> None:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes((b"ABCD" * 4096)[:8192])

    info = create_run(
        str(fw),
        case_id="analyst-report-write",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _ = analyze_run(info, time_budget_s=0, no_llm=True)

    report_dir = info.run_dir / "report"
    analyst_json = report_dir / "analyst_report.json"
    analyst_md = report_dir / "analyst_report.md"

    assert analyst_json.is_file()
    assert analyst_md.is_file()

    report_obj = cast(
        dict[str, object], json.loads(analyst_json.read_text(encoding="utf-8"))
    )
    assert report_obj.get("schema_version") == "0.1"
    assert isinstance(report_obj.get("claims"), list)
    assert isinstance(report_obj.get("artifacts"), dict)
    assert isinstance(report_obj.get("limitations"), list)
    for section in REQUIRED_SECTIONS:
        assert isinstance(report_obj.get(section), dict)
    assert validate_analyst_report(report_obj) == []
    assert "created_at" not in analyst_json.read_text(encoding="utf-8")


def test_verify_analyst_report_linkage_ok(tmp_path: Path) -> None:
    run_dir = _write_minimal_linkage_fixture(tmp_path)
    res = _run_verifier(run_dir)
    assert res.returncode == 0
    assert res.stdout.startswith("[OK] analyst report linkage verified:")


def test_verify_analyst_report_linkage_fails_on_dangling_path(tmp_path: Path) -> None:
    run_dir = _write_minimal_linkage_fixture(tmp_path)
    graph_path = run_dir / STAGE_ARTIFACTS["graph"]
    obj = cast(dict[str, object], json.loads(graph_path.read_text(encoding="utf-8")))
    obj["evidence_refs"] = ["stages/surfaces/missing.txt"]
    _ = graph_path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    res = _run_verifier(run_dir)
    assert res.returncode != 0
    assert "dangling path" in res.stdout


def test_verify_analyst_report_linkage_fails_on_missing_task5_artifact(
    tmp_path: Path,
) -> None:
    run_dir = _write_minimal_linkage_fixture(tmp_path)
    missing_path = run_dir / STAGE_ARTIFACTS["findings_pattern_scan"]
    missing_path.unlink()

    res = _run_verifier(run_dir)
    assert res.returncode != 0
    assert "missing stage artifact for findings_pattern_scan" in res.stdout


def test_verify_analyst_report_linkage_rejects_absolute_path_strings_anywhere(
    tmp_path: Path,
) -> None:
    run_dir = _write_minimal_linkage_fixture(tmp_path)
    artifact_path = run_dir / STAGE_ARTIFACTS["findings_pattern_scan"]
    artifact = cast(dict[str, object], json.loads(artifact_path.read_text("utf-8")))
    artifact["notes"] = {"raw_path": "/tmp/leak-path"}
    _ = artifact_path.write_text(
        json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    res = _run_verifier(run_dir)
    assert res.returncode != 0
    assert "absolute path string not allowed" in res.stdout


def test_verify_analyst_report_linkage_validates_section_evidence_json_refs(
    tmp_path: Path,
) -> None:
    run_dir = _write_minimal_linkage_fixture(tmp_path)
    _attach_metrics_artifact(run_dir, dangling_ref=False)

    report = cast(
        dict[str, object],
        json.loads((run_dir / "report" / "analyst_report.json").read_text("utf-8")),
    )
    artifacts = cast(dict[str, object], report["artifacts"])
    section_evidence_paths = cast(
        dict[str, object], artifacts["section_evidence_paths"]
    )
    attack_surface_paths = cast(list[object], section_evidence_paths["attack_surface"])
    assert ATTACK_SURFACE_METRICS_REL in attack_surface_paths

    res = _run_verifier(run_dir)
    assert res.returncode == 0


def test_verify_analyst_report_linkage_fails_on_nested_dangling_section_evidence_ref(
    tmp_path: Path,
) -> None:
    run_dir = _write_minimal_linkage_fixture(tmp_path)
    _attach_metrics_artifact(run_dir, dangling_ref=True)

    res = _run_verifier(run_dir)
    assert res.returncode != 0
    assert "section_evidence_paths.attack_surface" in res.stdout
    assert "dangling path" in res.stdout


def test_build_analyst_report_dedupes_and_sorts_claims_deterministically() -> None:
    report: dict[str, JsonValue] = {
        "limitations": [],
        "attribution": {
            "evidence": [{"path": "stages/attribution/attribution.json"}],
            "claims": [
                {
                    "claim_type": "vendor",
                    "value": "Acme",
                    "confidence": 0.8,
                    "evidence_refs": ["stages/attribution/attribution.json"],
                },
                {
                    "claim_type": "vendor",
                    "value": "Acme",
                    "confidence": 0.8,
                    "evidence_refs": ["stages/attribution/attribution.json"],
                },
            ],
        },
        "endpoints": {},
        "surfaces": {},
        "graph": {},
        "attack_surface": {},
        "threat_model": {},
        "functional_spec": {},
        "poc_validation": {},
        "llm_synthesis": {
            "evidence": [{"path": "stages/llm_synthesis/llm_synthesis.json"}],
            "claims": [
                {
                    "claim_type": "summary.endpoints.count",
                    "value": 2,
                    "confidence": 0.9,
                    "evidence_refs": ["stages/llm_synthesis/llm_synthesis.json"],
                }
            ],
        },
    }

    analyst = build_analyst_report(report)
    claims = cast(list[dict[str, object]], analyst["claims"])
    assert len(claims) == 2
    assert claims[0]["claim_type"] == "summary.endpoints.count"
    assert claims[1]["claim_type"] == "vendor"
    assert validate_analyst_report(analyst) == []
