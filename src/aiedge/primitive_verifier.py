from __future__ import annotations

"""Primitive verifier stage for SCOUT's exploit DAG.

The verifier is intentionally evidence-driven. It does not attempt exploitation;
it classifies existing dynamic evidence bundles, crash logs, and debug snapshots
into primitive states that downstream reports can trust.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .path_safety import assert_under_dir
from .schema import JsonValue
from .stage import StageContext, StageOutcome

SCHEMA_VERSION = "primitive-verifier-v1"
_DEFAULT_ALPHABET = b"abcdefghijklmnopqrstuvwxyz"
_SIGNAL_RE = re.compile(r"\b(SIGSEGV|SIGBUS|SIGILL|SIGABRT|signal\s*=?\s*(?:11|7|4|6))\b", re.IGNORECASE)
_HEX_RE = re.compile(r"\b(?:pc|eip|rip|ra|lr|sp|r0|a0|v0)?\s*=?\s*(0x[0-9a-fA-F]{8,16})\b")
_MAX_TEXT_FILES = 120
_MAX_TEXT_BYTES = 120_000


@dataclass(frozen=True)
class _Machine:
    machine_id: str
    candidate_id: str
    chain_id: str
    protocol_id: str
    families: tuple[str, ...]
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


def _dict(value: object) -> dict[str, object]:
    return cast(dict[str, object], value) if isinstance(value, dict) else {}


def _list_dict(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [cast(dict[str, object], item) for item in cast(list[object], value) if isinstance(item, dict)]


def _clean_str(value: object, default: str = "") -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    return default


def _clean_refs(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return tuple()
    out: list[str] = []
    for item in cast(list[object], value):
        if isinstance(item, str) and item and not item.startswith("/") and ":\\" not in item and item not in out:
            out.append(item)
    return tuple(out[:20])


def _safe_chain_id(chain_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", chain_id.strip()) or "unknown"


def _de_bruijn(alphabet: bytes, n: int) -> bytes:
    k = len(alphabet)
    a = [0] * (k * n)
    sequence: list[int] = []

    def db(t: int, p: int) -> None:
        if t > n:
            if n % p == 0:
                sequence.extend(a[1 : p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return bytes(alphabet[i] for i in sequence)


def cyclic_pattern(length: int, *, alphabet: bytes = _DEFAULT_ALPHABET, n: int = 4) -> bytes:
    """Return a dependency-free de Bruijn pattern compatible with cyclic offset checks."""

    if length <= 0:
        return b""
    if n <= 0 or not alphabet:
        raise ValueError("alphabet and n must be non-empty")
    seq = _de_bruijn(alphabet, n)
    if length <= len(seq):
        return seq[:length]
    return (seq * ((length // len(seq)) + 1))[:length]


def cyclic_find(token: bytes, *, alphabet: bytes = _DEFAULT_ALPHABET, n: int = 4, max_length: int = 8192) -> int:
    if not token:
        return -1
    needle = token[:n]
    return cyclic_pattern(max_length, alphabet=alphabet, n=n).find(needle)


def _hex_offsets(text: str) -> list[dict[str, JsonValue]]:
    offsets: list[dict[str, JsonValue]] = []
    seen: set[str] = set()
    for match in _HEX_RE.finditer(text):
        raw = match.group(1).lower()
        if raw in seen:
            continue
        seen.add(raw)
        try:
            value = int(raw, 16)
        except ValueError:
            continue
        width = 8 if value > 0xFFFFFFFF else 4
        little = value.to_bytes(width, "little", signed=False)
        big = value.to_bytes(width, "big", signed=False)
        for endian, blob in (("little", little), ("big", big)):
            off = cyclic_find(blob[:4])
            if off >= 0:
                offsets.append({"token": raw, "endian": endian, "offset": off})
    return offsets


def _collect_machines(run_dir: Path, limitations: list[str]) -> list[_Machine]:
    obj = _load_json(run_dir / "stages" / "exploit_state_machine" / "exploit_state_machine.json")
    if obj is None:
        limitations.append("primitive_verifier: exploit_state_machine artifact missing")
        return []
    machines: list[_Machine] = []
    for item in _list_dict(obj.get("machines")):
        families_raw = item.get("families")
        families: list[str] = []
        if isinstance(families_raw, list):
            families = [_clean_str(f) for f in cast(list[object], families_raw) if _clean_str(f)]
        machines.append(
            _Machine(
                machine_id=_clean_str(item.get("machine_id"), "unknown"),
                candidate_id=_clean_str(item.get("candidate_id"), "unknown"),
                chain_id=_clean_str(item.get("chain_id"), "unknown"),
                protocol_id=_clean_str(item.get("protocol_id"), "unknown"),
                families=tuple(families),
                evidence_refs=_clean_refs(item.get("evidence_refs")),
            )
        )
    return machines


def _bundle_for_chain(run_dir: Path, chain_id: str) -> dict[str, object] | None:
    safe = _safe_chain_id(chain_id)
    direct = run_dir / "exploits" / f"chain_{safe}" / "evidence_bundle.json"
    obj = _load_json(direct)
    if obj is not None:
        return obj
    for path in sorted((run_dir / "exploits").glob("chain_*/evidence_bundle.json")):
        obj = _load_json(path)
        if obj is not None and _clean_str(obj.get("chain_id")) == chain_id:
            return obj
    return None


def _crash_replay_attempt_for_chain(run_dir: Path, chain_id: str) -> dict[str, object] | None:
    obj = _load_json(run_dir / "stages" / "crash_replay" / "crash_replay.json")
    if obj is None:
        return None
    for attempt in _list_dict(obj.get("attempts")):
        if _clean_str(attempt.get("chain_id")) == chain_id:
            return attempt
    return None


def _crash_replay_verdict(
    attempt: dict[str, object]
) -> tuple[str, str, list[str], list[dict[str, JsonValue]]]:
    status = _clean_str(attempt.get("status"), "unknown")
    refs = _clean_refs(attempt.get("evidence_refs"))
    offsets_raw = attempt.get("cyclic_offsets")
    offsets = _list_dict(offsets_raw)
    if status == "crash_observed" and offsets:
        return "control_influence_candidate", "pc_or_register_control", list(refs), offsets[:12]
    if status == "crash_observed":
        return "crash_observed", "dos_or_memory_corruption_candidate", list(refs), []
    if status in {"planned_no_binary", "planned_qemu_missing", "skipped_gate"}:
        return "planned_no_dynamic_evidence", "unknown", list(refs), []
    return "runner_attempted_nonpass", "unknown", list(refs), []


def _read_dynamic_texts(run_dir: Path) -> list[tuple[str, str]]:
    roots = [
        run_dir / "stages" / "crash_replay",
        run_dir / "stages" / "fuzzing",
        run_dir / "stages" / "dynamic_validation",
        run_dir / "logs",
    ]
    out: list[tuple[str, str]] = []
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if len(out) >= _MAX_TEXT_FILES:
                return out
            if not path.is_file():
                continue
            name = path.name.lower()
            if not any(token in name for token in ("crash", "gdb", "signal", "core", "trace", "log", "json")):
                continue
            try:
                rel = path.resolve().relative_to(run_dir.resolve()).as_posix()
            except Exception:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")[:_MAX_TEXT_BYTES]
            except Exception:
                continue
            out.append((rel, text))
    return out


def _bundle_verdict(bundle: dict[str, object]) -> tuple[str, str, list[str], list[dict[str, JsonValue]]]:
    repro = _dict(bundle.get("reproducibility"))
    status = _clean_str(repro.get("status"), "unknown")
    attempts = _list_dict(bundle.get("attempts"))
    proof_types: list[str] = []
    refs: list[str] = []
    for attempt in attempts:
        if _clean_str(attempt.get("status")) == "pass":
            proof_type = _clean_str(attempt.get("proof_type"), "unknown")
            if proof_type not in proof_types:
                proof_types.append(proof_type)
            evidence = _clean_str(attempt.get("proof_evidence"))
            if evidence and evidence not in refs:
                refs.append(evidence[:180])
    if status == "pass" and proof_types:
        return "verified_dynamic_proof", proof_types[0], refs, []
    return "runner_attempted_nonpass", "unknown", refs, []


def _crash_verdict(dynamic_texts: list[tuple[str, str]]) -> tuple[str, str, list[str], list[dict[str, JsonValue]]]:
    evidence_refs: list[str] = []
    offsets: list[dict[str, JsonValue]] = []
    signal_seen = False
    for rel, text in dynamic_texts:
        if _SIGNAL_RE.search(text):
            signal_seen = True
            evidence_refs.append(rel)
        offsets.extend(_hex_offsets(text))
    if offsets:
        return "control_influence_candidate", "pc_or_register_control", evidence_refs[:10], offsets[:12]
    if signal_seen:
        return "crash_observed", "dos_or_memory_corruption_candidate", evidence_refs[:10], []
    return "planned_no_dynamic_evidence", "unknown", [], []


@dataclass(frozen=True)
class PrimitiveVerifierStage:
    @property
    def name(self) -> str:
        return "primitive_verifier"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "primitive_verifier"
        assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        out_json = stage_dir / "primitive_verifier.json"
        pattern_path = stage_dir / "cyclic_pattern.txt"
        limitations: list[str] = []

        machines = _collect_machines(run_dir, limitations)
        dynamic_texts = _read_dynamic_texts(run_dir)
        pattern_path.write_bytes(cyclic_pattern(512) + b"\n")

        results: list[dict[str, JsonValue]] = []
        for machine in machines:
            bundle = _bundle_for_chain(run_dir, machine.chain_id)
            refs: list[str] = list(machine.evidence_refs)
            offsets: list[dict[str, JsonValue]] = []
            if bundle is not None:
                status, primitive, evidence, offsets = _bundle_verdict(bundle)
                refs.extend(evidence)
            elif (crash_attempt := _crash_replay_attempt_for_chain(run_dir, machine.chain_id)) is not None:
                status, primitive, evidence, offsets = _crash_replay_verdict(crash_attempt)
                refs.extend(evidence)
            else:
                status, primitive, evidence, offsets = _crash_verdict(dynamic_texts)
                refs.extend(evidence)
                if status == "planned_no_dynamic_evidence" and "memory_corruption_candidate" in machine.families:
                    limitations.append(f"primitive_verifier: no crash/debug evidence yet for {machine.candidate_id}")

            results.append(
                {
                    "machine_id": machine.machine_id,
                    "candidate_id": machine.candidate_id,
                    "chain_id": machine.chain_id,
                    "protocol_id": machine.protocol_id,
                    "status": status,
                    "primitive": primitive,
                    "families": list(machine.families),
                    "cyclic_offsets": cast(JsonValue, offsets),
                    "evidence_refs": list(dict.fromkeys(refs))[:24],
                }
            )

        summary = {
            "result_count": len(results),
            "verified_dynamic_proof": sum(1 for r in results if r.get("status") == "verified_dynamic_proof"),
            "control_influence_candidate": sum(1 for r in results if r.get("status") == "control_influence_candidate"),
            "crash_observed": sum(1 for r in results if r.get("status") == "crash_observed"),
            "planned_no_dynamic_evidence": sum(1 for r in results if r.get("status") == "planned_no_dynamic_evidence"),
        }
        payload: dict[str, JsonValue] = {
            "schema_version": SCHEMA_VERSION,
            "status": "ok" if results else "partial",
            "claim_boundary": "primitive classification from verifier evidence only; no exploitability claim without pass evidence",
            "results": cast(JsonValue, results),
            "cyclic_pattern": "stages/primitive_verifier/cyclic_pattern.txt",
            "verifier_refs": [
                "pwntools cyclic/cyclic_find de Bruijn offset model",
                "GDB Python Frame.read_register register snapshot model",
                "QEMU user-mode -g debug endpoint model",
                "ROPgadget architecture support for ROP feasibility review",
            ],
            "summary": summary,
            "limitations": cast(JsonValue, limitations),
        }
        _write_json(out_json, payload)
        return StageOutcome(
            status="ok" if results else "partial",
            details={
                "summary": cast(JsonValue, summary),
                "evidence": [
                    {"path": "stages/primitive_verifier/primitive_verifier.json"},
                    {"path": "stages/primitive_verifier/cyclic_pattern.txt"},
                ],
            },
            limitations=limitations,
        )
