from __future__ import annotations

import json
import struct
from ipaddress import IPv4Address
from pathlib import Path
from typing import cast

from aiedge.reporting import build_analyst_digest
from aiedge.schema import JsonValue


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
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


def _prepare_run_dir(
    tmp_path: Path,
    *,
    pcap_destinations: list[str] | None,
    with_bundle: bool,
    with_evidence_dirs: bool = True,
) -> Path:
    run_dir = tmp_path / "run"
    _write_json(
        run_dir / "manifest.json",
        {
            "run_id": "fixture-run-id",
            "profile": "exploit",
            "analyzed_input_sha256": "a" * 64,
            "created_at": "2026-02-17T00:00:00Z",
        },
    )
    _write_json(run_dir / "report" / "report.json", {"ok": True})
    _ = (run_dir / "stages" / "findings").mkdir(parents=True, exist_ok=True)
    _ = (run_dir / "stages" / "findings" / "pattern_scan.json").write_text(
        "{}\n", encoding="utf-8"
    )

    if with_bundle and not with_evidence_dirs:
        raise ValueError("with_bundle requires with_evidence_dirs")

    if with_evidence_dirs:
        _ = (run_dir / "verified_chain").mkdir(parents=True, exist_ok=True)
        _ = (run_dir / "exploits").mkdir(parents=True, exist_ok=True)

    if pcap_destinations is not None:
        _ = (run_dir / "stages" / "dynamic_validation" / "isolation").mkdir(
            parents=True, exist_ok=True
        )
        _ = (run_dir / "stages" / "dynamic_validation" / "pcap").mkdir(
            parents=True, exist_ok=True
        )
        _ = (run_dir / "stages" / "dynamic_validation" / "firmae").mkdir(
            parents=True, exist_ok=True
        )
        _ = (run_dir / "stages" / "dynamic_validation" / "network").mkdir(
            parents=True, exist_ok=True
        )
        _ = (run_dir / "stages" / "dynamic_validation" / "probes").mkdir(
            parents=True, exist_ok=True
        )
        _ = (
            run_dir
            / "stages"
            / "dynamic_validation"
            / "isolation"
            / "firewall_snapshot.txt"
        ).write_text("iptables-save output\n", encoding="utf-8")
        _ = (
            run_dir
            / "stages"
            / "dynamic_validation"
            / "pcap"
            / "dynamic_validation.pcap"
        ).write_bytes(_pcap_with_destinations(pcap_destinations))
        _ = (
            run_dir / "stages" / "dynamic_validation" / "firmae" / "boot.log"
        ).write_text("boot ok\n", encoding="utf-8")
        _write_json(
            run_dir / "stages" / "dynamic_validation" / "network" / "interfaces.json",
            {},
        )
        _write_json(
            run_dir / "stages" / "dynamic_validation" / "network" / "ports.json",
            {},
        )
        _write_json(
            run_dir / "stages" / "dynamic_validation" / "probes" / "http.json",
            {},
        )
        _write_json(
            run_dir / "stages" / "dynamic_validation" / "dynamic_validation.json",
            {
                "schema_version": "1.0",
                "status": "ok",
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
                "probes": {"http": "stages/dynamic_validation/probes/http.json"},
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
                "limitations": [],
            },
        )
        _write_json(
            run_dir / "stages" / "dynamic_validation" / "stage.json",
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
        )

    if with_bundle:
        chain_dir = run_dir / "exploits" / "chain_demo"
        _ = chain_dir.mkdir(parents=True, exist_ok=True)
        attempts: list[dict[str, object]] = []
        execution_logs: list[str] = []
        for idx in range(1, 4):
            log_path = chain_dir / f"execution_log_{idx}.txt"
            _ = log_path.write_text(
                "uid=0(root) gid=0(root) command executed\n", encoding="utf-8"
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
        _write_json(
            chain_dir / "evidence_bundle.json",
            {
                "schema_version": "exploit-evidence-v1",
                "chain_id": "ER-demo:test",
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
            },
        )

    return run_dir


def _report_with_single_finding() -> dict[str, JsonValue]:
    return {
        "overview": {
            "run_id": "fixture-run-id",
            "analyzed_input_sha256": "a" * 64,
            "created_at": "2026-02-17T00:11:00Z",
        },
        "findings": [
            {
                "id": "F-001",
                "title": "demo finding",
                "severity": "high",
                "confidence": 0.9,
                "disposition": "confirmed",
                "evidence": [{"path": "stages/findings/pattern_scan.json"}],
            }
        ],
    }


def test_digest_verdict_verified_all_gates_pass(tmp_path: Path) -> None:
    run_dir = _prepare_run_dir(
        tmp_path,
        pcap_destinations=["192.168.1.50", "10.0.0.8", "127.0.0.1"],
        with_bundle=True,
    )
    digest = build_analyst_digest(_report_with_single_finding(), run_dir=run_dir)

    verdict = cast(dict[str, object], digest["exploitability_verdict"])
    assert verdict["state"] == "VERIFIED"
    assert verdict["reason_codes"] == [
        "VERIFIED_ALL_GATES_PASSED",
        "VERIFIED_REPRO_3_OF_3",
    ]


def test_digest_verdict_attempted_inconclusive_when_verifier_fails(
    tmp_path: Path,
) -> None:
    run_dir = _prepare_run_dir(
        tmp_path,
        pcap_destinations=["8.8.8.8"],
        with_bundle=True,
    )
    digest = build_analyst_digest(_report_with_single_finding(), run_dir=run_dir)

    verdict = cast(dict[str, object], digest["exploitability_verdict"])
    assert verdict["state"] == "ATTEMPTED_INCONCLUSIVE"
    assert verdict["reason_codes"] == ["ATTEMPTED_VERIFIER_FAILED"]


def test_digest_verdict_not_attempted_when_required_artifacts_missing(
    tmp_path: Path,
) -> None:
    run_dir = _prepare_run_dir(
        tmp_path,
        pcap_destinations=None,
        with_bundle=True,
    )
    digest = build_analyst_digest(_report_with_single_finding(), run_dir=run_dir)

    verdict = cast(dict[str, object], digest["exploitability_verdict"])
    assert verdict["state"] == "NOT_ATTEMPTED"
    assert verdict["reason_codes"] == ["NOT_ATTEMPTED_DYNAMIC_VALIDATION_MISSING"]
    assert verdict["state"] != "VERIFIED"


def test_digest_verdict_not_attempted_when_verifier_dirs_missing(tmp_path: Path) -> None:
    run_dir = _prepare_run_dir(
        tmp_path,
        pcap_destinations=None,
        with_bundle=False,
        with_evidence_dirs=False,
    )
    digest = build_analyst_digest(_report_with_single_finding(), run_dir=run_dir)

    verdict = cast(dict[str, object], digest["exploitability_verdict"])
    assert verdict["state"] == "NOT_ATTEMPTED"
    assert verdict["reason_codes"] == ["NOT_ATTEMPTED_REQUIRED_VERIFIER_MISSING"]

    finding_verdicts = cast(list[object], digest["finding_verdicts"])
    finding = cast(dict[str, object], finding_verdicts[0])
    assert finding["verifier_refs"] == []


def test_digest_verdict_not_applicable_for_zero_findings(tmp_path: Path) -> None:
    run_dir = _prepare_run_dir(
        tmp_path,
        pcap_destinations=["192.168.1.20"],
        with_bundle=True,
    )
    report: dict[str, JsonValue] = {
        "overview": {
            "run_id": "fixture-run-id",
            "analyzed_input_sha256": "a" * 64,
            "created_at": "2026-02-17T00:11:00Z",
        },
        "findings": [],
    }
    digest = build_analyst_digest(report, run_dir=run_dir)

    verdict = cast(dict[str, object], digest["exploitability_verdict"])
    assert verdict["state"] == "NOT_APPLICABLE"
    assert verdict["reason_codes"] == ["NOT_APPLICABLE_NO_RELEVANT_FINDINGS"]
