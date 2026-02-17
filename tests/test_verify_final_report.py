from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import cast


_CANONICAL_SHA256 = "387d97fd925125471691d5c565fcc0ff009e111bdbdfd2ddb057f9212a939c8a"


def _write_run_fixture(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    report_dir = run_dir / "report"
    report_dir.mkdir(parents=True)

    report = {
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
    }
    manifest = {
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

    _ = (report_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    _ = (report_dir / "duplicate_gate.json").write_text(
        json.dumps(
            {
                "schema_version": "duplicate-gate-v1",
                "novelty": [],
                "ranked": [],
            },
            ensure_ascii=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _ = (run_dir / "stages" / "firmware_lineage").mkdir(parents=True, exist_ok=True)
    _ = (run_dir / "stages" / "firmware_lineage" / "lineage.json").write_text(
        json.dumps({"schema_version": 1, "lineage": []}, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    _ = (run_dir / "stages" / "firmware_lineage" / "lineage_diff.json").write_text(
        json.dumps({"schema_version": 1, "diff": {}}, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    _ = (run_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    return run_dir


def _run_verifier(run_dir: Path) -> subprocess.CompletedProcess[str]:
    repo_root = Path(__file__).resolve().parents[1]
    return subprocess.run(
        [
            sys.executable,
            str(repo_root / "scripts" / "verify_aiedge_final_report.py"),
            "--run-dir",
            str(run_dir),
        ],
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
    )


def test_verify_final_report_ok(tmp_path: Path) -> None:
    run_dir = _write_run_fixture(tmp_path)
    res = _run_verifier(run_dir)
    assert res.returncode == 0
    assert res.stdout.startswith("[OK] finalized report contract verified:")


def test_verify_final_report_fails_when_findings_pending(tmp_path: Path) -> None:
    run_dir = _write_run_fixture(tmp_path)
    report_path = run_dir / "report" / "report.json"
    report_obj = cast(
        dict[str, object], json.loads(report_path.read_text(encoding="utf-8"))
    )
    run_completion = cast(dict[str, object], report_obj["run_completion"])
    required_stage_statuses = cast(
        dict[str, object], run_completion["required_stage_statuses"]
    )
    required_stage_statuses["findings"] = "pending"
    _ = report_path.write_text(
        json.dumps(report_obj, ensure_ascii=True) + "\n", encoding="utf-8"
    )

    res = _run_verifier(run_dir)
    assert res.returncode != 0
    assert (
        "[FAIL] run_completion.required_stage_statuses.findings is pending"
        in res.stdout
    )


def test_verify_final_report_fails_when_manifest_track_missing(tmp_path: Path) -> None:
    run_dir = _write_run_fixture(tmp_path)
    manifest_path = run_dir / "manifest.json"
    manifest_obj = cast(
        dict[str, object], json.loads(manifest_path.read_text(encoding="utf-8"))
    )
    del manifest_obj["track"]
    _ = manifest_path.write_text(
        json.dumps(manifest_obj, ensure_ascii=True) + "\n", encoding="utf-8"
    )

    res = _run_verifier(run_dir)
    assert res.returncode != 0
    assert "[FAIL] canonical 8MB-only verifier:" in res.stdout
    assert "manifest.track is required" in res.stdout


def test_verify_final_report_fails_when_manifest_track_not_object(tmp_path: Path) -> None:
    for i, bad_track in enumerate(("8mb", None)):
        case_root = tmp_path / f"case_{i}"
        run_dir = _write_run_fixture(case_root)
        manifest_path = run_dir / "manifest.json"
        manifest_obj = cast(
            dict[str, object], json.loads(manifest_path.read_text(encoding="utf-8"))
        )
        manifest_obj["track"] = bad_track
        _ = manifest_path.write_text(
            json.dumps(manifest_obj, ensure_ascii=True) + "\n", encoding="utf-8"
        )

        res = _run_verifier(run_dir)
        assert res.returncode != 0
        assert "[FAIL] canonical 8MB-only verifier:" in res.stdout
        assert "manifest.track is required" in res.stdout


def test_verify_final_report_fails_when_manifest_identity_mismatch(
    tmp_path: Path,
) -> None:
    run_dir = _write_run_fixture(tmp_path)
    manifest_path = run_dir / "manifest.json"
    manifest_obj = cast(
        dict[str, object], json.loads(manifest_path.read_text(encoding="utf-8"))
    )
    track = cast(dict[str, object], manifest_obj["track"])
    track["track_id"] = "other"
    _ = manifest_path.write_text(
        json.dumps(manifest_obj, ensure_ascii=True) + "\n", encoding="utf-8"
    )

    res = _run_verifier(run_dir)
    assert res.returncode != 0
    assert "[FAIL] manifest.track.track_id != '8mb'" in res.stdout


def test_verify_final_report_fails_when_duplicate_gate_missing_required_keys(
    tmp_path: Path,
) -> None:
    run_dir = _write_run_fixture(tmp_path)
    report_path = run_dir / "report" / "report.json"
    report_obj = cast(dict[str, object], json.loads(report_path.read_text("utf-8")))
    report_obj["duplicate_gate"] = {}
    _ = report_path.write_text(
        json.dumps(report_obj, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    res = _run_verifier(run_dir)
    assert res.returncode != 0
    assert "report.duplicate_gate.taxonomy_version" in res.stdout
