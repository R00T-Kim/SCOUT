from __future__ import annotations

import json
import struct
import subprocess
import sys
from ipaddress import IPv4Address
from pathlib import Path


def _run_verifier(run_dir: Path) -> subprocess.CompletedProcess[str]:
    repo_root = Path(__file__).resolve().parents[1]
    return subprocess.run(
        [
            sys.executable,
            str(repo_root / "scripts" / "verify_network_isolation.py"),
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


def _pcap_with_ipv4_destinations(destinations: list[str]) -> bytes:
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
        frame = _ipv4_packet(src_ip="192.168.1.10", dst_ip=dst)
        packet_header = struct.pack("<IIII", 0, 0, len(frame), len(frame))
        packets.append(packet_header + frame)
    return global_header + b"".join(packets)


def _write_run_dir_fixture(tmp_path: Path, *, destinations: list[str]) -> Path:
    run_dir = tmp_path / "run"
    stage_dir = run_dir / "stages" / "dynamic_validation"
    isolation_dir = stage_dir / "isolation"
    pcap_dir = stage_dir / "pcap"
    isolation_dir.mkdir(parents=True, exist_ok=True)
    pcap_dir.mkdir(parents=True, exist_ok=True)

    _ = (isolation_dir / "firewall_snapshot.txt").write_text(
        "iptables-save output\n",
        encoding="utf-8",
    )
    _ = (pcap_dir / "dynamic_validation.pcap").write_bytes(
        _pcap_with_ipv4_destinations(destinations)
    )

    summary = {
        "schema_version": "1.0",
        "isolation": {
            "firewall_snapshot": "stages/dynamic_validation/isolation/firewall_snapshot.txt",
            "pcap": "stages/dynamic_validation/pcap/dynamic_validation.pcap",
        },
    }
    _ = (stage_dir / "dynamic_validation.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return run_dir


def test_verify_network_isolation_ok_with_private_destinations(tmp_path: Path) -> None:
    run_dir = _write_run_dir_fixture(
        tmp_path,
        destinations=["192.168.1.50", "10.0.0.8", "169.254.1.2", "127.0.0.1"],
    )

    res = _run_verifier(run_dir)
    assert res.returncode == 0
    assert res.stdout.startswith("[OK] network isolation verified:")


def test_verify_network_isolation_fails_on_public_egress(tmp_path: Path) -> None:
    run_dir = _write_run_dir_fixture(
        tmp_path,
        destinations=["192.168.1.50", "8.8.8.8"],
    )

    res = _run_verifier(run_dir)
    assert res.returncode != 0
    assert "[FAIL] egress_violation:" in res.stdout
    assert "8.8.8.8" in res.stdout


def test_verify_network_isolation_fails_when_required_artifacts_missing(
    tmp_path: Path,
) -> None:
    run_dir = _write_run_dir_fixture(tmp_path, destinations=["192.168.1.50"])
    (
        run_dir
        / "stages"
        / "dynamic_validation"
        / "isolation"
        / "firewall_snapshot.txt"
    ).unlink()

    res = _run_verifier(run_dir)
    assert res.returncode != 0
    assert "[FAIL] missing_required_artifact:" in res.stdout
