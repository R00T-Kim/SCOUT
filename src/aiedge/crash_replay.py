from __future__ import annotations

"""Lab-gated crash replay collector for SCOUT's Exploit DAG.

The stage converts planned memory-corruption state-machine candidates into bounded
local replay attempts. It only executes under ``profile=exploit`` with
``exploit_gate.scope=lab-only`` and ``attestation=authorized``. When QEMU or a
runnable binary is unavailable it still emits probe and GDB-script artifacts so
analysts can run the same verifier path manually.
"""

import json
import os
import re
import shutil
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .path_safety import assert_under_dir
from .primitive_verifier import cyclic_find, cyclic_pattern
from .schema import JsonValue
from .stage import StageContext, StageOutcome

SCHEMA_VERSION = "crash-replay-v1"
_MAX_MACHINES = 12
_MAX_CAPTURE_BYTES = 16_384
_ARCH_QEMU = {
    "mipsel": "qemu-mipsel",
    "mipsle": "qemu-mipsel",
    "mips32el": "qemu-mipsel",
    "mips": "qemu-mips",
    "mipseb": "qemu-mips",
    "arm": "qemu-arm",
    "armel": "qemu-arm",
    "armhf": "qemu-arm",
    "aarch64": "qemu-aarch64",
    "arm64": "qemu-aarch64",
    "x86_64": "qemu-x86_64",
    "amd64": "qemu-x86_64",
    "i386": "qemu-i386",
    "x86": "qemu-i386",
}
_CRASH_SIGNALS = {4, 6, 7, 11}
_HEX_RE = re.compile(r"\b(?:pc|eip|rip|ra|lr|sp|r0|a0|v0)?\s*=?\s*(0x[0-9a-fA-F]{8,16})\b")


@dataclass(frozen=True)
class _Machine:
    machine_id: str
    candidate_id: str
    chain_id: str
    protocol_id: str
    families: tuple[str, ...]
    binary: str
    evidence_refs: tuple[str, ...]


def _load_json(path: Path) -> dict[str, object] | None:
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return cast(dict[str, object], raw) if isinstance(raw, dict) else None


def _write_json(path: Path, payload: dict[str, JsonValue]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _clean_str(value: object, default: str = "") -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    return default


def _dict(value: object) -> dict[str, object]:
    return cast(dict[str, object], value) if isinstance(value, dict) else {}


def _list_dict(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [cast(dict[str, object], item) for item in cast(list[object], value) if isinstance(item, dict)]


def _clean_refs(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return tuple()
    out: list[str] = []
    for item in cast(list[object], value):
        if isinstance(item, str) and item and not item.startswith("/") and ":\\" not in item and item not in out:
            out.append(item)
    return tuple(out[:24])


def _safe_token(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value.strip()) or "unknown"


def _profile_gate(run_dir: Path) -> tuple[str, dict[str, object] | None]:
    manifest = _load_json(run_dir / "manifest.json") or {}
    profile = _clean_str(manifest.get("profile"), "analysis") or "analysis"
    gate = manifest.get("exploit_gate")
    return profile, cast(dict[str, object], gate) if isinstance(gate, dict) else None


def _gate_allows_execution(profile: str, gate: dict[str, object] | None) -> bool:
    return (
        profile == "exploit"
        and gate is not None
        and gate.get("scope") == "lab-only"
        and gate.get("attestation") == "authorized"
    )


def _collect_machines(run_dir: Path) -> list[_Machine]:
    obj = _load_json(run_dir / "stages" / "exploit_state_machine" / "exploit_state_machine.json")
    if obj is None:
        return []
    out: list[_Machine] = []
    for item in _list_dict(obj.get("machines"))[:_MAX_MACHINES]:
        families_raw = item.get("families")
        families: list[str] = []
        if isinstance(families_raw, list):
            families = [_clean_str(f) for f in cast(list[object], families_raw) if _clean_str(f)]
        if "memory_corruption_candidate" not in families and "protocol_stateful_probe" not in families:
            continue
        seed = _dict(item.get("autopoc_seed"))
        binary = _clean_str(seed.get("path"), _clean_str(item.get("path"), ""))
        out.append(
            _Machine(
                machine_id=_clean_str(item.get("machine_id"), "unknown"),
                candidate_id=_clean_str(item.get("candidate_id"), "unknown"),
                chain_id=_clean_str(item.get("chain_id"), "unknown"),
                protocol_id=_clean_str(item.get("protocol_id"), "unknown"),
                families=tuple(families),
                binary=binary,
                evidence_refs=_clean_refs(item.get("evidence_refs")),
            )
        )
    return out


def _binary_analysis(run_dir: Path) -> list[dict[str, object]]:
    obj = _load_json(run_dir / "stages" / "inventory" / "binary_analysis.json")
    if obj is None:
        return []
    hits = _list_dict(obj.get("hits"))
    if not hits:
        hits = _list_dict(obj.get("binaries"))
    return hits


def _arch_for_binary(run_dir: Path, binary_rel: str) -> str:
    hits = _binary_analysis(run_dir)
    binary_name = binary_rel.rsplit("/", 1)[-1]
    for hit in hits:
        path = _clean_str(hit.get("path"))
        if path == binary_rel or (binary_name and path.endswith("/" + binary_name)):
            arch = _clean_str(hit.get("arch"), _clean_str(hit.get("architecture"), ""))
            if arch:
                return arch.lower()
    profile = _load_json(run_dir / "stages" / "firmware_profile" / "firmware_profile.json") or {}
    return _clean_str(profile.get("arch_guess"), _clean_str(profile.get("architecture"), "unknown")).lower()


def _qemu_for_arch(arch: str) -> str | None:
    norm = arch.lower().replace("-", "_")
    for key, qemu in _ARCH_QEMU.items():
        if key in norm:
            return qemu
    return None


def _resolve_binary(run_dir: Path, binary_rel: str) -> Path | None:
    if not binary_rel or binary_rel.startswith("/") or ":\\" in binary_rel:
        return None
    path = (run_dir / binary_rel).resolve()
    try:
        path.relative_to(run_dir.resolve())
    except ValueError:
        return None
    return path if path.is_file() else None


def _guess_rootfs(run_dir: Path, binary: Path | None) -> Path:
    if binary is not None:
        for parent in [binary.parent, *binary.parents]:
            if parent == run_dir.parent:
                break
            if (parent / "lib").is_dir() or (parent / "usr").is_dir() or (parent / "bin").is_dir():
                try:
                    parent.relative_to(run_dir)
                    return parent
                except ValueError:
                    continue
    extraction = run_dir / "stages" / "extraction"
    for candidate in sorted(extraction.rglob("squashfs-root")) if extraction.exists() else []:
        if candidate.is_dir():
            return candidate
    return run_dir


def _signal_name(number: int | None) -> str:
    if number is None:
        return "unknown"
    try:
        return signal.Signals(number).name
    except Exception:
        return f"SIG{number}"


def _signal_from_returncode(returncode: int) -> int | None:
    if returncode < 0:
        return abs(returncode)
    if returncode >= 128:
        candidate = returncode - 128
        if 0 < candidate < 64:
            return candidate
    return None


def _hex_offsets(text: str) -> list[dict[str, JsonValue]]:
    offsets: list[dict[str, JsonValue]] = []
    seen: set[tuple[str, str]] = set()
    for match in _HEX_RE.finditer(text):
        raw = match.group(1).lower()
        try:
            value = int(raw, 16)
        except ValueError:
            continue
        width = 8 if value > 0xFFFFFFFF else 4
        for endian, blob in (("little", value.to_bytes(width, "little")), ("big", value.to_bytes(width, "big"))):
            key = (raw, endian)
            if key in seen:
                continue
            seen.add(key)
            off = cyclic_find(blob[:4])
            if off >= 0:
                offsets.append({"token": raw, "endian": endian, "offset": off})
    return offsets[:16]


def _gdb_script(machine: _Machine, binary_rel: str, probe_rel: str) -> str:
    return "\n".join(
        [
            "set pagination off",
            "set confirm off",
            f"# SCOUT lab-only replay for {machine.candidate_id}",
            f"# binary: {binary_rel or 'unknown'}",
            f"# cyclic probe: {probe_rel}",
            "run < " + probe_rel,
            "info registers",
            "bt",
            "x/32wx $sp",
            "quit",
            "",
        ]
    )


def _run_qemu(
    *, qemu_path: str, rootfs: Path, binary: Path, probe: bytes, timeout_s: float
) -> tuple[str, int, str, str, str]:
    cmd = [qemu_path, "-L", str(rootfs), str(binary)]
    try:
        cp = subprocess.run(
            cmd,
            input=probe,
            capture_output=True,
            check=False,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or b"")[:_MAX_CAPTURE_BYTES]
        stderr = (exc.stderr or b"")[:_MAX_CAPTURE_BYTES]
        return "timeout", 124, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace"), " ".join(cmd)
    except Exception as exc:
        return "error", -1, "", f"{type(exc).__name__}: {exc}", " ".join(cmd)
    stdout_s = cp.stdout[:_MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
    stderr_s = cp.stderr[:_MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
    return "completed", int(cp.returncode), stdout_s, stderr_s, " ".join(cmd)


@dataclass(frozen=True)
class CrashReplayStage:
    timeout_s: float = float(os.environ.get("AIEDGE_CRASH_REPLAY_TIMEOUT_S", "5.0"))
    probe_len: int = int(os.environ.get("AIEDGE_CRASH_REPLAY_PROBE_LEN", "1024"))

    @property
    def name(self) -> str:
        return "crash_replay"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "crash_replay"
        assert_under_dir(run_dir, stage_dir)
        probes_dir = stage_dir / "probes"
        scripts_dir = stage_dir / "gdb_scripts"
        logs_dir = stage_dir / "logs"
        for path in (stage_dir, probes_dir, scripts_dir, logs_dir):
            path.mkdir(parents=True, exist_ok=True)
        out_json = stage_dir / "crash_replay.json"

        profile, gate = _profile_gate(run_dir)
        limitations: list[str] = []
        machines = _collect_machines(run_dir)
        allowed = _gate_allows_execution(profile, gate)
        if not allowed:
            limitations.append("crash_replay skipped: requires profile=exploit with lab-only authorized exploit_gate")

        probe = cyclic_pattern(max(64, min(8192, int(self.probe_len))))
        attempts: list[dict[str, JsonValue]] = []
        for machine in machines:
            token = _safe_token(machine.machine_id + "_" + machine.chain_id)
            probe_rel = f"stages/crash_replay/probes/{token}.bin"
            gdb_rel = f"stages/crash_replay/gdb_scripts/{token}.gdb"
            probe_path = run_dir / probe_rel
            gdb_path = run_dir / gdb_rel
            if allowed:
                probe_path.write_bytes(probe)
            _write_text(gdb_path, _gdb_script(machine, machine.binary, probe_rel))

            binary_path = _resolve_binary(run_dir, machine.binary)
            arch = _arch_for_binary(run_dir, machine.binary)
            qemu_name = _qemu_for_arch(arch)
            qemu_path = shutil.which(qemu_name) if qemu_name else None
            rootfs = _guess_rootfs(run_dir, binary_path)
            base: dict[str, JsonValue] = {
                "machine_id": machine.machine_id,
                "candidate_id": machine.candidate_id,
                "chain_id": machine.chain_id,
                "protocol_id": machine.protocol_id,
                "families": list(machine.families),
                "binary": machine.binary,
                "arch": arch,
                "qemu": qemu_name or "unknown",
                "rootfs": rootfs.relative_to(run_dir).as_posix() if rootfs.is_relative_to(run_dir) else str(rootfs),
                "cyclic_probe": probe_rel if allowed else "",
                "gdb_script": gdb_rel,
                "evidence_refs": list(machine.evidence_refs) + [gdb_rel],
            }

            if not allowed:
                attempts.append({**base, "status": "skipped_gate", "reason": "exploit gate not satisfied"})
                continue
            if binary_path is None:
                limitations.append(f"crash_replay planned only: binary missing for {machine.candidate_id}")
                attempts.append({**base, "status": "planned_no_binary", "reason": "binary path unavailable"})
                continue
            if qemu_name is None or qemu_path is None:
                limitations.append(f"crash_replay planned only: QEMU missing for arch={arch} candidate={machine.candidate_id}")
                attempts.append({**base, "status": "planned_qemu_missing", "reason": "qemu user-mode binary unavailable"})
                continue

            status, returncode, stdout_s, stderr_s, cmd_s = _run_qemu(
                qemu_path=qemu_path,
                rootfs=rootfs,
                binary=binary_path,
                probe=probe,
                timeout_s=max(1.0, float(self.timeout_s)),
            )
            stdout_rel = f"stages/crash_replay/logs/{token}.stdout.txt"
            stderr_rel = f"stages/crash_replay/logs/{token}.stderr.txt"
            _write_text(run_dir / stdout_rel, stdout_s)
            _write_text(run_dir / stderr_rel, stderr_s)
            sig = _signal_from_returncode(returncode)
            offsets = _hex_offsets(stdout_s + "\n" + stderr_s)
            crash = sig in _CRASH_SIGNALS or bool(offsets)
            attempt_status = "crash_observed" if crash else "no_crash_observed"
            if status == "timeout":
                attempt_status = "timeout"
            elif status == "error":
                attempt_status = "error"
            attempts.append(
                {
                    **base,
                    "status": attempt_status,
                    "runner_status": status,
                    "returncode": returncode,
                    "signal": sig if sig is not None else 0,
                    "signal_name": _signal_name(sig),
                    "command": cmd_s,
                    "stdout": stdout_rel,
                    "stderr": stderr_rel,
                    "stdout_excerpt": stdout_s[:500],
                    "stderr_excerpt": stderr_s[:500],
                    "cyclic_offsets": cast(JsonValue, offsets),
                    "evidence_refs": list(machine.evidence_refs) + [probe_rel, gdb_rel, stdout_rel, stderr_rel],
                }
            )

        summary = {
            "machine_count": len(machines),
            "attempt_count": len(attempts),
            "executed_count": sum(1 for item in attempts if item.get("runner_status") == "completed"),
            "crash_observed": sum(1 for item in attempts if item.get("status") == "crash_observed"),
            "planned_count": sum(1 for item in attempts if str(item.get("status", "")).startswith("planned")),
            "skipped_gate": sum(1 for item in attempts if item.get("status") == "skipped_gate"),
        }
        status_out = "skipped" if not allowed else ("ok" if attempts else "partial")
        payload: dict[str, JsonValue] = {
            "schema_version": SCHEMA_VERSION,
            "status": status_out,
            "profile": profile,
            "claim_boundary": "lab-gated local replay evidence only; no third-party target interaction",
            "attempts": cast(JsonValue, attempts),
            "summary": summary,
            "limitations": cast(JsonValue, limitations),
        }
        _write_json(out_json, payload)
        return StageOutcome(
            status=cast(str, status_out),
            details={"summary": summary, "evidence": [{"path": "stages/crash_replay/crash_replay.json"}]},
            limitations=limitations,
        )
