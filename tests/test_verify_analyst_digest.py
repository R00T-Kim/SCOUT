from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import cast


def _run_verifier(run_dir: Path) -> subprocess.CompletedProcess[str]:
    repo_root = Path(__file__).resolve().parents[1]
    return subprocess.run(
        [
            sys.executable,
            str(repo_root / "scripts" / "verify_analyst_digest.py"),
            "--run-dir",
            str(run_dir),
        ],
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
    )


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _write_digest_fixture(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"

    pattern_scan = run_dir / "stages" / "findings" / "pattern_scan.json"
    _ = pattern_scan.parent.mkdir(parents=True, exist_ok=True)
    _ = pattern_scan.write_text('{"ok": true}\n', encoding="utf-8")

    verified_chain = run_dir / "verified_chain" / "verified_chain.json"
    _ = verified_chain.parent.mkdir(parents=True, exist_ok=True)
    _ = verified_chain.write_text('{"state": "pass"}\n', encoding="utf-8")

    digest: dict[str, object] = {
        "schema_version": "analyst_digest-v1",
        "run": {
            "run_id": "fixture-run",
            "firmware_sha256": "a" * 64,
            "generated_at": "2026-02-17T00:00:00Z",
        },
        "top_risk_summary": {
            "total_findings": 1,
            "severity_counts": {
                "critical": 1,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
        },
        "finding_verdicts": [
            {
                "finding_id": "F-001",
                "verdict": "VERIFIED",
                "reason_codes": [
                    "VERIFIED_ALL_GATES_PASSED",
                    "VERIFIED_REPRO_3_OF_3",
                ],
                "evidence_refs": ["stages/findings/pattern_scan.json"],
                "verifier_refs": ["verified_chain/verified_chain.json"],
            }
        ],
        "exploitability_verdict": {
            "state": "VERIFIED",
            "reason_codes": [
                "VERIFIED_ALL_GATES_PASSED",
                "VERIFIED_REPRO_3_OF_3",
            ],
            "aggregation_rule": "worst_state_precedence_v1",
        },
        "evidence_index": [
            {
                "ref": "stages/findings/pattern_scan.json",
                "sha256": _sha256_file(pattern_scan),
            },
            {
                "ref": "verified_chain/verified_chain.json",
                "sha256": _sha256_file(verified_chain),
            },
        ],
        "next_actions": ["Review verified exploit chain artifacts."],
    }
    _write_json(run_dir / "report" / "analyst_digest.json", digest)
    return run_dir


def _write_not_attempted_digest_fixture(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"

    pattern_scan = run_dir / "stages" / "findings" / "pattern_scan.json"
    _ = pattern_scan.parent.mkdir(parents=True, exist_ok=True)
    _ = pattern_scan.write_text('{"ok": true}\n', encoding="utf-8")

    digest: dict[str, object] = {
        "schema_version": "analyst_digest-v1",
        "run": {
            "run_id": "fixture-run",
            "firmware_sha256": "a" * 64,
            "generated_at": "2026-02-17T00:00:00Z",
        },
        "top_risk_summary": {
            "total_findings": 1,
            "severity_counts": {
                "critical": 1,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
        },
        "finding_verdicts": [
            {
                "finding_id": "F-001",
                "verdict": "NOT_ATTEMPTED",
                "reason_codes": ["NOT_ATTEMPTED_REQUIRED_VERIFIER_MISSING"],
                "evidence_refs": ["stages/findings/pattern_scan.json"],
                "verifier_refs": [],
            }
        ],
        "exploitability_verdict": {
            "state": "NOT_ATTEMPTED",
            "reason_codes": ["NOT_ATTEMPTED_REQUIRED_VERIFIER_MISSING"],
            "aggregation_rule": "worst_state_precedence_v1",
        },
        "evidence_index": [
            {
                "ref": "stages/findings/pattern_scan.json",
                "sha256": _sha256_file(pattern_scan),
            }
        ],
        "next_actions": ["Run required verifier pipeline to produce verified_chain artifacts."],
    }
    _write_json(run_dir / "report" / "analyst_digest.json", digest)
    return run_dir


def test_verify_analyst_digest_ok(tmp_path: Path) -> None:
    run_dir = _write_digest_fixture(tmp_path)
    res = _run_verifier(run_dir)

    assert res.returncode == 0
    assert res.stdout.startswith("[OK] analyst_digest verified:")


def test_verify_analyst_digest_ok_with_empty_verifier_refs(tmp_path: Path) -> None:
    run_dir = _write_not_attempted_digest_fixture(tmp_path)
    res = _run_verifier(run_dir)

    assert res.returncode == 0
    assert res.stdout.startswith("[OK] analyst_digest verified:")


def test_verify_analyst_digest_fails_when_referenced_file_missing(
    tmp_path: Path,
) -> None:
    run_dir = _write_digest_fixture(tmp_path)
    missing_path = run_dir / "stages" / "findings" / "pattern_scan.json"
    missing_path.unlink()

    res = _run_verifier(run_dir)

    assert res.returncode != 0
    assert "[FAIL] missing_required_artifact:" in res.stdout


def test_verify_analyst_digest_fails_when_evidence_hash_tampered(
    tmp_path: Path,
) -> None:
    run_dir = _write_digest_fixture(tmp_path)
    tamper_path = run_dir / "stages" / "findings" / "pattern_scan.json"
    _ = tamper_path.write_text('{"ok": false}\n', encoding="utf-8")

    res = _run_verifier(run_dir)

    assert res.returncode != 0
    assert "[FAIL] evidence_hash_mismatch:" in res.stdout


def test_verify_analyst_digest_fails_on_absolute_path_injection(tmp_path: Path) -> None:
    run_dir = _write_digest_fixture(tmp_path)
    digest_path = run_dir / "report" / "analyst_digest.json"
    digest = cast(
        dict[str, object], json.loads(digest_path.read_text(encoding="utf-8"))
    )
    finding_verdicts = cast(list[object], digest["finding_verdicts"])
    finding = cast(dict[str, object], finding_verdicts[0])
    finding["evidence_refs"] = ["/tmp/escape.json"]
    _write_json(digest_path, digest)

    res = _run_verifier(run_dir)

    assert res.returncode != 0
    assert "[FAIL] invalid_contract:" in res.stdout
    assert "run-relative path" in res.stdout
