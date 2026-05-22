#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import TCPServer
from typing import Any, cast

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from aiedge.aeg_e2e_gate import evaluate_aeg_e2e_gate  # noqa: E402
from aiedge.run import create_run, run_subset  # noqa: E402
from scripts.build_verified_chain import build_verified_chain  # noqa: E402


class _ReusableTCPServer(TCPServer):
    allow_reuse_address = True


class _VulnerableLeakHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        body = b"SCOUT_LEAK:root:x:0:0:lab-root:/root:/bin/sh\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib handler API
        return


class _PatchedNoLeakHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        body = b"patched firmware: probe accepted, no privileged leak\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib handler API
        return


class _VulnerableCommandHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        body = b"uid=0(root) gid=0(root) groups=0(root) synthetic-cmd-proof\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib handler API
        return


class _PatchedCommandHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        body = b"patched firmware: command parameter rejected; no shell readback\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib handler API
        return


def _profile_seed(pattern_id: str) -> dict[str, Any]:
    if pattern_id == "memory_stateful_probe":
        return {
            "candidate_id": "candidate:synthetic-memory-leak",
            "chain_id": "state_chain_memory_leak",
            "title": "Synthetic memory leak AEG pair candidate",
            "families": ["memory_corruption_candidate", "protocol_stateful_probe"],
            "summary": "Synthetic memory leak AEG pair candidate",
            "channels": [
                {"channel_id": "http-direct", "channel_type": "web_api"},
                {"channel_id": "direct-request", "channel_type": "direct_request"},
            ],
            "plan_ir": {"transitions": [{"transition_id": "t_trigger", "event_type": "direct_request"}]},
            "vulnerable_handler": _VulnerableLeakHandler,
            "patched_handler": _PatchedNoLeakHandler,
            "alert_id": "aeg-synthetic-memory-leak",
            "vulnerable_firmware": b"SCOUT-SYNTHETIC-VULNERABLE-FIRMWARE",
            "patched_firmware": b"SCOUT-SYNTHETIC-PATCHED-FIRMWARE",
        }
    if pattern_id == "cgi_param_cmd_injection":
        return {
            "candidate_id": "candidate:synthetic-cgi-cmd-injection",
            "chain_id": "state_chain_cgi_cmd_injection",
            "title": "Synthetic CGI parameter command injection AEG pair candidate",
            "families": ["cmd_injection"],
            "summary": "Synthetic CGI parameter command injection AEG pair candidate",
            "channels": [
                {"channel_id": "http-cgi", "channel_type": "web_api"},
                {"channel_id": "direct-request", "channel_type": "direct_request"},
            ],
            "plan_ir": {"transitions": [{"transition_id": "t_trigger", "event_type": "direct_request"}]},
            "vulnerable_handler": _VulnerableCommandHandler,
            "patched_handler": _PatchedCommandHandler,
            "alert_id": "aeg-synthetic-cgi-cmd-injection",
            "vulnerable_firmware": b"SCOUT-SYNTHETIC-CGI-CMDI-VULNERABLE-FIRMWARE",
            "patched_firmware": b"SCOUT-SYNTHETIC-CGI-CMDI-PATCHED-FIRMWARE",
        }
    if pattern_id == "config_derived_cmd_injection":
        return {
            "candidate_id": "candidate:synthetic-config-cmd-injection",
            "chain_id": "state_chain_config_cmd_injection",
            "title": "Synthetic config-derived command injection AEG pair candidate",
            "families": ["cmd_injection"],
            "summary": "Synthetic config-derived command injection AEG pair candidate",
            "channels": [
                {"channel_id": "http-config-write", "channel_type": "web_api"},
                {"channel_id": "stored-config", "channel_type": "config"},
            ],
            "plan_ir": {"transitions": [{"transition_id": "t_trigger", "event_type": "delayed_parse"}]},
            "vulnerable_handler": _VulnerableCommandHandler,
            "patched_handler": _PatchedCommandHandler,
            "alert_id": "aeg-synthetic-config-cmd-injection",
            "vulnerable_firmware": b"SCOUT-SYNTHETIC-CONFIG-CMDI-VULNERABLE-FIRMWARE",
            "patched_firmware": b"SCOUT-SYNTHETIC-CONFIG-CMDI-PATCHED-FIRMWARE",
        }
    raise ValueError(f"unsupported synthetic pattern: {pattern_id}")


def _write_json(run_dir: Path, rel_path: str, payload: dict[str, Any]) -> None:
    path = run_dir / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _set_exploit_profile(manifest_path: Path) -> None:
    manifest = cast(dict[str, Any], json.loads(manifest_path.read_text(encoding="utf-8")))
    manifest["profile"] = "exploit"
    manifest["exploit_gate"] = {
        "flag": "synthetic-aeg-pair",
        "attestation": "authorized",
        "scope": "lab-only",
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _write_dynamic_validation_bundle(run_dir: Path) -> None:
    _write_json(
        run_dir,
        "stages/dynamic_validation/dynamic_validation.json",
        {
            "status": "ok",
            "isolation": {
                "firewall_snapshot": "stages/dynamic_validation/isolation/firewall_snapshot.txt",
                "pcap": "stages/dynamic_validation/pcap/dynamic_validation.pcap",
            },
            "limitations": [],
            "versions": {"tools": {}, "firmae": {}},
        },
    )
    _write_json(
        run_dir,
        "stages/dynamic_validation/stage.json",
        {
            "status": "ok",
            "started_at": "2026-05-20T00:00:00Z",
            "finished_at": "2026-05-20T00:00:01Z",
            "artifacts": [
                {"path": "stages/dynamic_validation/dynamic_validation.json"},
                {"path": "stages/dynamic_validation/isolation/firewall_snapshot.txt"},
                {"path": "stages/dynamic_validation/pcap/dynamic_validation.pcap"},
            ],
        },
    )

    firewall = run_dir / "stages/dynamic_validation/isolation/firewall_snapshot.txt"
    firewall.parent.mkdir(parents=True, exist_ok=True)
    firewall.write_text("synthetic lab firewall: default deny; loopback lab allowed\n", encoding="utf-8")

    pcap = run_dir / "stages/dynamic_validation/pcap/dynamic_validation.pcap"
    pcap.parent.mkdir(parents=True, exist_ok=True)
    # Valid little-endian libpcap global header with no packets. The isolation
    # verifier accepts no observed destinations as no-egress evidence.
    pcap.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))


def _write_state_machine_seed(run_dir: Path, *, pattern_id: str) -> None:
    profile = _profile_seed(pattern_id)
    families = cast(list[str], profile["families"])
    channels = cast(list[dict[str, object]], profile["channels"])
    plan_ir = cast(dict[str, object], profile["plan_ir"])
    _write_json(
        run_dir,
        "stages/exploit_state_machine/exploit_state_machine.json",
        {
            "schema_version": "exploit-state-machine-v1",
            "status": "ok",
            "claim_boundary": "planned only",
            "machines": [
                {
                    "machine_id": "machine-001",
                    "candidate_id": str(profile["candidate_id"]),
                    "chain_id": str(profile["chain_id"]),
                    "protocol_id": "protocol-001",
                    "title": str(profile["title"]),
                    "families": families,
                    "autopoc_seed": {
                        "candidate_id": str(profile["candidate_id"]),
                        "chain_id": str(profile["chain_id"]),
                        "priority": "high",
                        "score": 0.84,
                        "families": families,
                        "summary": str(profile["summary"]),
                        "channels": channels,
                        "plan_ir": plan_ir,
                    },
                    "channels": channels,
                    "plan_ir": plan_ir,
                    "evidence_refs": ["stages/exploit_state_machine/exploit_state_machine.json"],
                }
            ],
            "summary": {"machine_count": 1},
            "design_refs": [],
            "limitations": [],
        },
    )


def _write_quality_signals(
    run_dir: Path,
    *,
    fpr: float,
    fp_verdict: str,
    alert_id: str,
) -> None:
    _write_json(run_dir, "quality_metrics.json", {"overall": {"fpr": fpr}})
    _write_json(
        run_dir,
        "stages/fp_verification/verified_alerts.json",
        {
            "verified_alerts": [
                {
                    "id": alert_id,
                    "severity": "high",
                    "fp_verdict": fp_verdict,
                }
            ]
        },
    )


def _run_autopoc_against_handler(
    run_dir: Path,
    info: Any,
    handler_cls: type[BaseHTTPRequestHandler],
) -> str:
    server = _ReusableTCPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _, port = cast(tuple[str, int], server.server_address)
    _write_json(run_dir, "stages/dynamic_validation/network/ports.json", {"open_ports": [int(port)]})
    try:
        rep = run_subset(info, ["exploit_autopoc"], time_budget_s=10, no_llm=True)
        return rep.status
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _read_gate_checks(gate: dict[str, object]) -> dict[str, bool]:
    checks = gate.get("checks")
    if not isinstance(checks, list):
        return {}
    out: dict[str, bool] = {}
    for item in checks:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if isinstance(name, str):
            out[name] = item.get("passed") is True
    return out


def _execute_case(
    *,
    work_root: Path,
    case_id: str,
    firmware_bytes: bytes,
    handler_cls: type[BaseHTTPRequestHandler],
    fpr: float,
    fp_verdict: str,
    pattern_id: str,
) -> dict[str, object]:
    firmware = work_root / f"{case_id}.bin"
    firmware.write_bytes(firmware_bytes)
    info = create_run(
        str(firmware),
        case_id=case_id,
        ack_authorization=True,
        runs_root=work_root / "runs",
    )
    _set_exploit_profile(info.manifest_path)
    _write_dynamic_validation_bundle(info.run_dir)
    _write_state_machine_seed(info.run_dir, pattern_id=pattern_id)
    alert_id = str(_profile_seed(pattern_id)["alert_id"])
    _write_quality_signals(info.run_dir, fpr=fpr, fp_verdict=fp_verdict, alert_id=alert_id)

    chain_status = run_subset(
        info,
        ["exploit_gate", "exploit_chain"],
        time_budget_s=5,
        no_llm=True,
    ).status
    autopoc_status = _run_autopoc_against_handler(info.run_dir, info, handler_cls)
    poc_status = run_subset(info, ["poc_validation"], time_budget_s=5, no_llm=True).status
    verified_chain_path, verified_state, verified_reasons = build_verified_chain(info.run_dir)
    gate = evaluate_aeg_e2e_gate(info.run_dir)

    return {
        "case_id": case_id,
        "run_dir": str(info.run_dir),
        "chain_status": chain_status,
        "autopoc_status": autopoc_status,
        "poc_validation_status": poc_status,
        "verified_chain": {
            "path": str(verified_chain_path),
            "state": verified_state,
            "reason_codes": verified_reasons,
        },
        "gate": {
            "passed": gate.get("passed") is True,
            "verdict": gate.get("verdict"),
            "checks": _read_gate_checks(gate),
        },
    }


def run_synthetic_pattern_pair(work_root: Path, *, pattern_id: str) -> dict[str, object]:
    work_root.mkdir(parents=True, exist_ok=True)
    profile = _profile_seed(pattern_id)
    vulnerable = _execute_case(
        work_root=work_root,
        case_id=f"synthetic-aeg-{pattern_id}-vulnerable",
        firmware_bytes=cast(bytes, profile["vulnerable_firmware"]),
        handler_cls=cast(type[BaseHTTPRequestHandler], profile["vulnerable_handler"]),
        fpr=0.0,
        fp_verdict="TP",
        pattern_id=pattern_id,
    )
    patched = _execute_case(
        work_root=work_root,
        case_id=f"synthetic-aeg-{pattern_id}-patched-control",
        firmware_bytes=cast(bytes, profile["patched_firmware"]),
        handler_cls=cast(type[BaseHTTPRequestHandler], profile["patched_handler"]),
        fpr=1.0,
        fp_verdict="FP",
        pattern_id=pattern_id,
    )
    passed = (
        cast(dict[str, object], vulnerable["gate"]).get("passed") is True
        and cast(dict[str, object], patched["gate"]).get("passed") is False
    )
    summary = {
        "schema_version": "synthetic-aeg-pair-v1",
        "pattern_id": pattern_id,
        "passed": passed,
        "policy": {
            "target": "vulnerable must pass; patched/control must fail closed",
            "network": "loopback-only synthetic lab service",
            "raw_public_poc_execution": False,
        },
        "cases": {
            "vulnerable": vulnerable,
            "patched_control": patched,
        },
    }
    summary_path = work_root / "synthetic_aeg_pair_summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return summary


def run_synthetic_pair(work_root: Path) -> dict[str, object]:
    return run_synthetic_pattern_pair(work_root, pattern_id="memory_stateful_probe")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run SCOUT's synthetic AEG vulnerable/control pair: "
            "the vulnerable lab service must pass, and the patched control must fail closed."
        )
    )
    parser.add_argument(
        "--work-root",
        type=Path,
        required=True,
        help="Directory where synthetic firmware inputs, runs, and summary JSON are written.",
    )
    parser.add_argument(
        "--pattern",
        choices=[
            "memory_stateful_probe",
            "cgi_param_cmd_injection",
            "config_derived_cmd_injection",
        ],
        default="memory_stateful_probe",
        help="Exploit Pattern RAG card profile to validate with the synthetic pair.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    summary = run_synthetic_pattern_pair(Path(args.work_root), pattern_id=str(args.pattern))
    print(json.dumps(summary, indent=2, sort_keys=True) + "\n", end="")
    return 0 if summary.get("passed") is True else 41


if __name__ == "__main__":
    raise SystemExit(main())
