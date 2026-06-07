from __future__ import annotations

import hashlib
import json
from pathlib import Path

from aiedge.phase12_progress import (
    build_phase1_pair_matrix,
    build_phase2_novelty_dossier,
)


def _write(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _manifest(tmp_path: Path) -> Path:
    v1 = _write(tmp_path / "fw" / "v1.bin", b"vulnerable")
    p1 = _write(tmp_path / "fw" / "p1.bin", b"patched")
    v2 = _write(tmp_path / "fw" / "v2.bin", b"second-vulnerable")
    p2 = _write(tmp_path / "fw" / "p2.bin", b"second-patched")
    payload = {
        "schema_version": "pair-eval-v1",
        "pairs": [
            {
                "pair_id": "vendor-model-cve-1",
                "vendor": "vendor",
                "model": "model",
                "cve_id": "CVE-2099-0001",
                "vulnerable": {"firmware_path": "fw/v1.bin", "sha256": v1},
                "patched": {"firmware_path": "fw/p1.bin", "sha256": p1},
            },
            {
                "pair_id": "vendor-model-cve-2",
                "vendor": "vendor",
                "model": "model2",
                "cve_id": "CVE-2099-0002",
                "vulnerable": {"firmware_path": "fw/v2.bin", "sha256": v2},
                "patched": {"firmware_path": "fw/p2.bin", "sha256": p2},
            },
        ],
    }
    path = tmp_path / "pairs.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _real_pair_report(tmp_path: Path) -> None:
    report = {
        "schema_version": "real-firmware-pair-aeg-gate-v1",
        "pair_id": "vendor-model-cve-1",
        "cve_id": "CVE-2099-0001",
        "pattern_id": "pattern-one",
        "promotable_real_firmware_pair": True,
        "verdict": "promotable",
        "runs": {
            "vulnerable": {"gate_passed": True, "missing_gate_artifacts": []},
            "patched": {
                "gate_passed": False,
                "failed_checks": ["autopoc_runner_pass"],
                "dynamic_failed_checks": ["autopoc_runner_pass"],
                "missing_gate_artifacts": [],
            },
        },
    }
    out = tmp_path / "docs" / "pov" / "vendor-model-cve-1_real_pair.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report), encoding="utf-8")


def test_phase1_pair_matrix_tracks_promoted_and_queued_pairs(tmp_path: Path) -> None:
    pairs_path = _manifest(tmp_path)
    _real_pair_report(tmp_path)

    matrix = build_phase1_pair_matrix(repo_root=tmp_path, pairs_path=pairs_path, phase1_scale_target=3)

    assert matrix["schema_version"] == "scout-phase1-pair-matrix-v1"
    assert matrix["summary"]["promotable_real_pair_count"] == 1
    assert matrix["summary"]["local_firmware_pair_ready_count"] == 2
    assert matrix["summary"]["phase1_scale_target_met"] is False
    assert matrix["summary"]["next_pair_run_queue"] == ["vendor-model-cve-2"]
    first = matrix["pairs"][0]
    assert first["control_fail_reason"] == "dynamic_fail_closed"
    assert first["emulation_ready"] is True
    assert first["counted_for_phase1_scale"] is True


def test_phase2_novelty_dossier_excludes_known_pairs_from_zero_day_kpi(tmp_path: Path) -> None:
    pairs_path = _manifest(tmp_path)
    _real_pair_report(tmp_path)
    matrix = build_phase1_pair_matrix(repo_root=tmp_path, pairs_path=pairs_path)

    dossier = build_phase2_novelty_dossier(matrix, repo_root=tmp_path)

    assert dossier["schema_version"] == "scout-zero-day-novelty-dossier-v1"
    assert dossier["dashboard"]["candidate_count"] == 2
    assert dossier["dashboard"]["known_or_one_day_count"] == 2
    assert dossier["dashboard"]["unknown_hypothesis_count"] == 0
    assert dossier["dashboard"]["zero_day_kpi_count"] == 0
    required = set(dossier["required_candidate_fields"])
    assert required == {
        "known_cve_overlap",
        "public_advisory_overlap",
        "pattern_seed_used",
        "lineage_delta",
        "dynamic_reachability",
    }
    assert all(required <= set(candidate) for candidate in dossier["candidates"])
    assert all(candidate["zero_day_eligible"] is False for candidate in dossier["candidates"])
