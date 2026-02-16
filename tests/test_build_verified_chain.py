from __future__ import annotations

import json
import struct
import subprocess
import sys
from ipaddress import IPv4Address
from pathlib import Path
from typing import cast


def _run_builder(run_dir: Path) -> subprocess.CompletedProcess[str]:
    repo_root = Path(__file__).resolve().parents[1]
    return subprocess.run(
        [
            sys.executable,
            str(repo_root / "scripts" / "build_verified_chain.py"),
            "--run-dir",
            str(run_dir),
        ],
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
    )


def _run_contract_verifier(run_dir: Path) -> subprocess.CompletedProcess[str]:
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


def _ipv4_packet(*, src_ip: str, dst_ip: str) -> bytes:
    src = IPv4Address(src_ip).packed
    dst = IPv4Address(dst_ip).packed
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20,
        0,
        0,
        64,
        6,
        0,
        src,
        dst,
    )
    ethernet_header = b"\x00" * 12 + b"\x08\x00"
    return ethernet_header + ip_header


def _pcap_with_destinations(destinations: list[str]) -> bytes:
    global_header = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        1,
    )
    packets: list[bytes] = []
    for dst in destinations:
        frame = _ipv4_packet(src_ip="192.168.1.20", dst_ip=dst)
        packet_header = struct.pack("<IIII", 0, 0, len(frame), len(frame))
        packets.append(packet_header + frame)
    return global_header + b"".join(packets)


def _write_fixture(
    tmp_path: Path,
    *,
    pcap_destinations: list[str],
    boot_flaky: bool,
) -> Path:
    run_dir = tmp_path / "run"
    stage_dir = run_dir / "stages" / "dynamic_validation"
    isolation_dir = stage_dir / "isolation"
    pcap_dir = stage_dir / "pcap"
    firmae_dir = stage_dir / "firmae"
    network_dir = stage_dir / "network"
    probes_dir = stage_dir / "probes"
    chain_dir = run_dir / "exploits" / "chain_demo"

    isolation_dir.mkdir(parents=True, exist_ok=True)
    pcap_dir.mkdir(parents=True, exist_ok=True)
    firmae_dir.mkdir(parents=True, exist_ok=True)
    network_dir.mkdir(parents=True, exist_ok=True)
    probes_dir.mkdir(parents=True, exist_ok=True)
    chain_dir.mkdir(parents=True, exist_ok=True)

    _ = (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": "fixture-run-id",
                "profile": "exploit",
                "analyzed_input_sha256": "a" * 64,
                "created_at": "2026-02-17T00:00:00Z",
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        )
        + "\n",
        encoding="utf-8",
    )

    _ = (firmae_dir / "boot.log").write_text("boot attempt\n", encoding="utf-8")
    _ = (network_dir / "interfaces.json").write_text("{}\n", encoding="utf-8")
    _ = (network_dir / "ports.json").write_text("{}\n", encoding="utf-8")
    _ = (probes_dir / "http.json").write_text("{}\n", encoding="utf-8")
    _ = (isolation_dir / "firewall_snapshot.txt").write_text(
        "iptables-save output\n",
        encoding="utf-8",
    )
    _ = (pcap_dir / "dynamic_validation.pcap").write_bytes(
        _pcap_with_destinations(pcap_destinations)
    )

    limitations = ["boot_flaky"] if boot_flaky else []
    dynamic_summary = {
        "schema_version": "1.0",
        "status": "partial" if boot_flaky else "ok",
        "isolation": {
            "firewall_snapshot": "stages/dynamic_validation/isolation/firewall_snapshot.txt",
            "pcap": "stages/dynamic_validation/pcap/dynamic_validation.pcap",
        },
        "boot": {
            "log": "stages/dynamic_validation/firmae/boot.log",
            "success": True,
        },
        "network": {
            "interfaces": "stages/dynamic_validation/network/interfaces.json",
            "ports": "stages/dynamic_validation/network/ports.json",
        },
        "probes": {
            "http": "stages/dynamic_validation/probes/http.json",
        },
        "versions": {
            "firmae": {
                "git_commit": "1" * 40,
                "git_describe": "1ee7a16",
            },
            "tools": {
                "ip": "ip utility, iproute2-6.1.0",
                "tcpdump": "tcpdump version 4.99.4",
            },
        },
        "limitations": limitations,
    }
    _ = (stage_dir / "dynamic_validation.json").write_text(
        json.dumps(dynamic_summary, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    _ = (stage_dir / "stage.json").write_text(
        json.dumps(
            {
                "started_at": "2026-02-17T00:00:00Z",
                "finished_at": "2026-02-17T00:05:00Z",
                "artifacts": [
                    {"path": "stages/dynamic_validation/dynamic_validation.json"},
                    {"path": "stages/dynamic_validation/firmae/boot.log"},
                    {"path": "stages/dynamic_validation/network/interfaces.json"},
                    {"path": "stages/dynamic_validation/network/ports.json"},
                    {"path": "stages/dynamic_validation/probes/http.json"},
                    {
                        "path": "stages/dynamic_validation/isolation/firewall_snapshot.txt"
                    },
                    {"path": "stages/dynamic_validation/pcap/dynamic_validation.pcap"},
                ],
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        )
        + "\n",
        encoding="utf-8",
    )

    attempts: list[dict[str, object]] = []
    execution_logs: list[str] = []
    for idx in range(1, 4):
        log_path = chain_dir / f"execution_log_{idx}.txt"
        _ = log_path.write_text(
            "uid=0(root) gid=0(root) command executed\n",
            encoding="utf-8",
        )
        attempts.append(
            {
                "attempt": idx,
                "status": "pass",
                "timestamp": f"2026-02-17T00:0{idx}:00Z",
                "proof_type": "shell",
                "proof_evidence": "uid=0(root) command executed",
                "reason_code": "attempt_pass",
            }
        )
        execution_logs.append(
            log_path.resolve().relative_to(run_dir.resolve()).as_posix()
        )

    _ = (chain_dir / "network_capture.pcap").write_bytes(
        _pcap_with_destinations(["192.168.1.99"])
    )
    _ = (chain_dir / "poc_sha256.txt").write_text("b" * 64 + "\n", encoding="utf-8")

    bundle = {
        "schema_version": "exploit-evidence-v1",
        "chain_id": "ER-e50_v3.0.1:test",
        "generated_at": "2026-02-17T00:10:00Z",
        "reproducibility": {
            "attempted": 3,
            "passed": 3,
            "reason_code": "repro_pass",
            "requested": 3,
            "status": "pass",
        },
        "attempts": attempts,
        "artifacts": {
            "execution_logs": execution_logs,
            "network_capture": "exploits/chain_demo/network_capture.pcap",
            "poc_sha256": "exploits/chain_demo/poc_sha256.txt",
        },
        "pcap": {
            "status": "captured",
            "reason_code": "pcap_placeholder_unavailable",
        },
    }
    _ = (chain_dir / "evidence_bundle.json").write_text(
        json.dumps(bundle, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    return run_dir


def _load_contract(run_dir: Path) -> dict[str, object]:
    contract_path = run_dir / "verified_chain" / "verified_chain.json"
    return cast(
        dict[str, object], json.loads(contract_path.read_text(encoding="utf-8"))
    )


def test_build_verified_chain_pass_path(tmp_path: Path) -> None:
    run_dir = _write_fixture(
        tmp_path,
        pcap_destinations=["192.168.1.50", "10.0.0.8", "127.0.0.1"],
        boot_flaky=False,
    )

    res = _run_builder(run_dir)
    assert res.returncode == 0
    assert res.stdout.startswith("[OK] built verified_chain:")

    contract = _load_contract(run_dir)
    verdict = cast(dict[str, object], contract["verdict"])
    assert verdict["state"] == "pass"
    assert verdict["reason_codes"] == ["isolation_verified", "repro_3_of_3"]

    verify_res = _run_contract_verifier(run_dir)
    assert verify_res.returncode == 0
    assert verify_res.stdout.startswith("[OK] verified_chain contract verified:")


def test_build_verified_chain_inconclusive_boot_flaky(tmp_path: Path) -> None:
    run_dir = _write_fixture(
        tmp_path,
        pcap_destinations=["192.168.1.10"],
        boot_flaky=True,
    )

    res = _run_builder(run_dir)
    assert res.returncode == 0

    contract = _load_contract(run_dir)
    verdict = cast(dict[str, object], contract["verdict"])
    assert verdict["state"] == "inconclusive"
    assert "boot_flaky" in cast(list[object], verdict["reason_codes"])

    verify_res = _run_contract_verifier(run_dir)
    assert verify_res.returncode == 0


def test_build_verified_chain_fail_on_egress_violation(tmp_path: Path) -> None:
    run_dir = _write_fixture(
        tmp_path,
        pcap_destinations=["8.8.8.8"],
        boot_flaky=False,
    )

    res = _run_builder(run_dir)
    assert res.returncode == 0

    contract = _load_contract(run_dir)
    verdict = cast(dict[str, object], contract["verdict"])
    assert verdict["state"] == "fail"
    assert "isolation_violation" in cast(list[object], verdict["reason_codes"])

    verify_res = _run_contract_verifier(run_dir)
    assert verify_res.returncode == 0
