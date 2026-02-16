from __future__ import annotations

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
            str(repo_root / "scripts" / "verify_verified_chain.py"),
            "--run-dir",
            str(run_dir),
        ],
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
    )


def _write_verified_chain_fixture(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    verified_dir = run_dir / "verified_chain"
    dynamic_dir = run_dir / "stages" / "dynamic_validation"
    chain_dir = run_dir / "exploits" / "chain_er_e50_demo"

    verified_dir.mkdir(parents=True, exist_ok=True)
    dynamic_dir.mkdir(parents=True, exist_ok=True)
    chain_dir.mkdir(parents=True, exist_ok=True)

    _ = (dynamic_dir / "boot.log").write_text("boot ok\n", encoding="utf-8")
    _ = (dynamic_dir / "services.json").write_text("{}\n", encoding="utf-8")
    _ = (chain_dir / "execution_log_1.txt").write_text("attempt1\n", encoding="utf-8")
    _ = (chain_dir / "execution_log_2.txt").write_text("attempt2\n", encoding="utf-8")
    _ = (chain_dir / "execution_log_3.txt").write_text("attempt3\n", encoding="utf-8")
    _ = (chain_dir / "network_capture.pcap").write_bytes(b"pcap")
    _ = (chain_dir / "evidence_bundle.json").write_text("{}\n", encoding="utf-8")

    contract: dict[str, object] = {
        "schema_version": "verified-chain-v1",
        "generated_at": "2026-02-17T00:00:00Z",
        "run_id": "fixture-run-id",
        "firmware": {
            "sha256": "a" * 64,
            "profile": "exploit",
        },
        "tool_versions": {
            "firmae_commit": "unknown",
            "firmae_version": "unknown",
            "tcpdump": "unknown",
            "iproute2": "unknown",
        },
        "timestamps": {
            "started_at": "2026-02-17T00:00:00Z",
            "finished_at": "2026-02-17T00:10:00Z",
        },
        "dynamic_validation": {
            "bundle_dir": "stages/dynamic_validation",
            "isolation_verified": True,
            "evidence_refs": [
                "stages/dynamic_validation/boot.log",
                "stages/dynamic_validation/services.json",
            ],
        },
        "verdict": {
            "state": "pass",
            "reason_codes": ["repro_3_of_3", "isolation_verified"],
            "evidence_refs": ["stages/dynamic_validation/boot.log"],
        },
        "attempts": [
            {
                "attempt": 1,
                "status": "pass",
                "bundle_dir": "exploits/chain_er_e50_demo",
                "started_at": "2026-02-17T00:01:00Z",
                "finished_at": "2026-02-17T00:01:30Z",
                "evidence_refs": [
                    "exploits/chain_er_e50_demo/execution_log_1.txt",
                    "exploits/chain_er_e50_demo/network_capture.pcap",
                    "exploits/chain_er_e50_demo/evidence_bundle.json",
                ],
            },
            {
                "attempt": 2,
                "status": "pass",
                "bundle_dir": "exploits/chain_er_e50_demo",
                "started_at": "2026-02-17T00:02:00Z",
                "finished_at": "2026-02-17T00:02:30Z",
                "evidence_refs": [
                    "exploits/chain_er_e50_demo/execution_log_2.txt",
                    "exploits/chain_er_e50_demo/network_capture.pcap",
                    "exploits/chain_er_e50_demo/evidence_bundle.json",
                ],
            },
            {
                "attempt": 3,
                "status": "pass",
                "bundle_dir": "exploits/chain_er_e50_demo",
                "started_at": "2026-02-17T00:03:00Z",
                "finished_at": "2026-02-17T00:03:30Z",
                "evidence_refs": [
                    "exploits/chain_er_e50_demo/execution_log_3.txt",
                    "exploits/chain_er_e50_demo/network_capture.pcap",
                    "exploits/chain_er_e50_demo/evidence_bundle.json",
                ],
            },
        ],
        "evidence_refs": [
            "stages/dynamic_validation/boot.log",
            "exploits/chain_er_e50_demo/evidence_bundle.json",
        ],
    }

    _ = (verified_dir / "verified_chain.json").write_text(
        json.dumps(contract, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return run_dir


def test_verify_verified_chain_ok(tmp_path: Path) -> None:
    run_dir = _write_verified_chain_fixture(tmp_path)
    res = _run_verifier(run_dir)
    assert res.returncode == 0
    assert res.stdout.startswith("[OK] verified_chain contract verified:")


def test_verify_verified_chain_fails_when_dynamic_bundle_missing(
    tmp_path: Path,
) -> None:
    run_dir = _write_verified_chain_fixture(tmp_path)
    dynamic_dir = run_dir / "stages" / "dynamic_validation"
    for child in dynamic_dir.iterdir():
        child.unlink()
    dynamic_dir.rmdir()

    res = _run_verifier(run_dir)

    assert res.returncode != 0
    assert "[FAIL] missing_dynamic_bundle:" in res.stdout


def test_verify_verified_chain_fails_when_reason_codes_invalid_for_pass(
    tmp_path: Path,
) -> None:
    run_dir = _write_verified_chain_fixture(tmp_path)
    contract_path = run_dir / "verified_chain" / "verified_chain.json"
    contract = cast(dict[str, object], json.loads(contract_path.read_text("utf-8")))
    verdict = cast(dict[str, object], contract["verdict"])
    verdict["reason_codes"] = ["repro_3_of_3"]
    _ = contract_path.write_text(
        json.dumps(contract, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    res = _run_verifier(run_dir)

    assert res.returncode != 0
    assert "[FAIL] invalid_contract:" in res.stdout
    assert "pass verdict missing required reason codes" in res.stdout
