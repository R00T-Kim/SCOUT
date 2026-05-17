from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, cast

from aiedge.crash_replay import CrashReplayStage
from aiedge.primitive_verifier import PrimitiveVerifierStage
from aiedge.stage import StageContext


def _write_json(run_dir: Path, rel: str, payload: dict[str, Any]) -> None:
    path = run_dir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _ctx(run_dir: Path) -> StageContext:
    return StageContext(run_dir=run_dir, logs_dir=run_dir / "logs", report_dir=run_dir / "report")


def _base_run(run_dir: Path, *, exploit: bool) -> None:
    rootfs = run_dir / "stages/extraction/rootfs"
    bin_dir = rootfs / "bin"
    lib_dir = rootfs / "lib"
    bin_dir.mkdir(parents=True, exist_ok=True)
    lib_dir.mkdir(parents=True, exist_ok=True)
    binary = bin_dir / "vuln"
    binary.write_bytes(b"#!/bin/sh\n")
    manifest: dict[str, Any] = {"input": {"sha256": "c" * 64}}
    if exploit:
        manifest["profile"] = "exploit"
        manifest["exploit_gate"] = {"flag": "auto", "attestation": "authorized", "scope": "lab-only"}
    _write_json(run_dir, "manifest.json", manifest)
    _write_json(
        run_dir,
        "stages/inventory/binary_analysis.json",
        {
            "status": "ok",
            "hits": [
                {
                    "path": "stages/extraction/rootfs/bin/vuln",
                    "arch": "mipsel-32",
                    "matched_symbols": ["strcpy"],
                }
            ],
        },
    )
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
                    "candidate_id": "candidate:crash-demo",
                    "chain_id": "state_chain_crash",
                    "protocol_id": "protocol-001",
                    "families": ["memory_corruption_candidate", "protocol_stateful_probe"],
                    "autopoc_seed": {
                        "candidate_id": "candidate:crash-demo",
                        "chain_id": "state_chain_crash",
                        "path": "stages/extraction/rootfs/bin/vuln",
                        "families": ["memory_corruption_candidate", "protocol_stateful_probe"],
                    },
                    "evidence_refs": ["stages/exploit_state_machine/exploit_state_machine.json"],
                }
            ],
            "summary": {"machine_count": 1},
            "design_refs": [],
            "limitations": [],
        },
    )


def _fake_qemu(tmp_path: Path) -> Path:
    qemu = tmp_path / "qemu-mipsel"
    qemu.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import sys",
                "_ = sys.stdin.buffer.read()",
                "sys.stderr.write('SIGSEGV pc=0x61616162\\n')",
                "sys.exit(139)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    qemu.chmod(0o755)
    return qemu


def test_crash_replay_executes_fake_qemu_and_feeds_primitive_verifier(tmp_path: Path, monkeypatch) -> None:
    run_dir = tmp_path / "run"
    _base_run(run_dir, exploit=True)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    _fake_qemu(fake_bin)
    monkeypatch.setenv("PATH", str(fake_bin) + os.pathsep + os.environ.get("PATH", ""))

    outcome = CrashReplayStage(timeout_s=1.0, probe_len=128).run(_ctx(run_dir))

    assert outcome.status == "ok"
    replay = cast(
        dict[str, Any],
        json.loads((run_dir / "stages/crash_replay/crash_replay.json").read_text(encoding="utf-8")),
    )
    assert replay["schema_version"] == "crash-replay-v1"
    assert replay["summary"]["crash_observed"] == 1
    attempt = replay["attempts"][0]
    assert attempt["status"] == "crash_observed"
    assert attempt["signal"] == 11
    assert attempt["cyclic_offsets"]
    assert (run_dir / attempt["cyclic_probe"]).is_file()
    assert (run_dir / attempt["gdb_script"]).is_file()

    verifier_outcome = PrimitiveVerifierStage().run(_ctx(run_dir))
    assert verifier_outcome.status == "ok"
    verifier = cast(
        dict[str, Any],
        json.loads((run_dir / "stages/primitive_verifier/primitive_verifier.json").read_text(encoding="utf-8")),
    )
    result = verifier["results"][0]
    assert result["status"] == "control_influence_candidate"
    assert result["primitive"] == "pc_or_register_control"


def test_crash_replay_skips_without_exploit_gate(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _base_run(run_dir, exploit=False)

    outcome = CrashReplayStage(timeout_s=1.0, probe_len=128).run(_ctx(run_dir))

    assert outcome.status == "skipped"
    replay = cast(
        dict[str, Any],
        json.loads((run_dir / "stages/crash_replay/crash_replay.json").read_text(encoding="utf-8")),
    )
    assert replay["summary"]["skipped_gate"] == 1
    attempt = replay["attempts"][0]
    assert attempt["status"] == "skipped_gate"
    assert attempt["cyclic_probe"] == ""
    assert (run_dir / attempt["gdb_script"]).is_file()
