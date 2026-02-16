from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import cast

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

    v2_report: dict[str, object] = {
        "schema_version": "0.2",
        "top_risk_claims": [
            {
                "claim_type": "risk.alpha",
                "severity": "high",
                "confidence": 0.95,
                "evidence_refs": ["stages/endpoints/endpoint.txt"],
            }
        ],
    }
    _ = (run_dir / "report" / "analyst_report_v2.json").write_text(
        json.dumps(v2_report, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    _ = (run_dir / "report" / "analyst_report_v2.md").write_text(
        "# analyst report v2\n",
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


def test_verify_analyst_report_v2_fails_on_dangling_claim_evidence_ref(
    tmp_path: Path,
) -> None:
    run_dir = _write_minimal_linkage_fixture(tmp_path)
    v2_path = run_dir / "report" / "analyst_report_v2.json"
    v2 = cast(dict[str, object], json.loads(v2_path.read_text(encoding="utf-8")))
    top_claims = cast(list[object], v2["top_risk_claims"])
    first_claim = cast(dict[str, object], top_claims[0])
    first_claim["evidence_refs"] = ["stages/surfaces/missing-v2.txt"]
    _ = v2_path.write_text(
        json.dumps(v2, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    res = _run_verifier(run_dir)

    assert res.returncode != 0
    assert "analyst_report_v2" in res.stdout
    assert "dangling path" in res.stdout


def test_verify_analyst_report_v2_passes_when_claim_refs_exist(tmp_path: Path) -> None:
    run_dir = _write_minimal_linkage_fixture(tmp_path)

    res = _run_verifier(run_dir)

    assert res.returncode == 0
    assert res.stdout.startswith("[OK] analyst report linkage verified:")


def test_verify_analyst_report_v2_fails_on_task5_schema_mismatch(
    tmp_path: Path,
) -> None:
    run_dir = _write_minimal_linkage_fixture(tmp_path)
    artifact_path = run_dir / STAGE_ARTIFACTS["findings_pattern_scan"]
    artifact = cast(dict[str, object], json.loads(artifact_path.read_text("utf-8")))
    artifact["schema_version"] = "pattern-scan-v0"
    _ = artifact_path.write_text(
        json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    res = _run_verifier(run_dir)

    assert res.returncode != 0
    assert "pattern_scan.json.schema_version" in res.stdout
