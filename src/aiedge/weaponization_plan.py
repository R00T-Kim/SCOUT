"""Controlled weaponization Plan IR and preflight gates.

The functions in this module are execution-planning and metadata validation only.
They do not generate payload bytes, import private exploit code, or contact a
remote target. Their purpose is to convert existing SCOUT evidence into a
bounded internal-red-team handoff and to fail closed before any private executor
would be allowed to run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from .controlled_weaponization import (
    _as_dict,
    _as_list,
    _attestation_is_authorized,
    _load_json,
    _package_hash,
    _run_firmware_sha256,
    _scope_is_bounded,
    _supported_firmware_hashes,
)

_PLAN_SCHEMA_VERSION = "scout-weaponization-plan-ir-v1"
_PREFLIGHT_SCHEMA_VERSION = "scout-weaponization-preflight-v1"
_DEFAULT_REPRO_REQUIRED = 3
_SAFE_PLAN_PRIMITIVES = {
    "arbitrary_read",
    "auth_bypass",
    "command_effect_marker",
    "config_state_write",
    "constrained_file_write",
    "controlled_crash",
    "path_traversal_marker_read",
    "state_transition",
}


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256_json(payload: dict[str, object]) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _check(name: str, passed: bool, message: str, *, evidence: object = None) -> dict[str, object]:
    out: dict[str, object] = {"name": name, "passed": passed, "message": message}
    if evidence is not None:
        out["evidence"] = evidence
    return out


def _run_manifest(run_dir: Path) -> dict[str, Any]:
    return _load_json(run_dir / "manifest.json") or {}


def _exploit_gate(run_manifest: dict[str, Any]) -> dict[str, Any]:
    return _as_dict(run_manifest.get("exploit_gate"))


def _load_package_manifest(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    return _load_json(path) or {}


def _candidate_records(run_dir: Path) -> list[dict[str, Any]]:
    payload = _load_json(run_dir / "stages" / "findings" / "exploit_candidates.json") or {}
    out: list[dict[str, Any]] = []
    for item in _as_list(payload.get("candidates")):
        if isinstance(item, dict):
            out.append(item)
    return out


def _autopoc_attempts(run_dir: Path) -> list[dict[str, Any]]:
    payload = _load_json(run_dir / "stages" / "exploit_autopoc" / "exploit_autopoc.json") or {}
    out: list[dict[str, Any]] = []
    for item in _as_list(payload.get("attempts")):
        if isinstance(item, dict):
            out.append(item)
    return out


def _state_machine_plan(run_dir: Path, chain_id: str | None) -> dict[str, Any]:
    payload = _load_json(run_dir / "stages" / "exploit_state_machine" / "exploit_state_machine.json") or {}
    for item in _as_list(payload.get("machines")):
        if not isinstance(item, dict):
            continue
        item_chain = str(item.get("chain_id") or "").strip()
        plan = _as_dict(item.get("plan_ir"))
        if plan and (chain_id is None or item_chain == chain_id or plan.get("chain_id") == chain_id):
            return plan
    return {}


def _select_chain_id(package_manifest: dict[str, Any], run_dir: Path, explicit_chain_id: str | None) -> str:
    if explicit_chain_id and explicit_chain_id.strip():
        return explicit_chain_id.strip()
    binding = _as_dict(package_manifest.get("binding"))
    binding_chain = binding.get("scout_chain_id")
    if isinstance(binding_chain, str) and binding_chain.strip():
        return binding_chain.strip()
    for attempt in _autopoc_attempts(run_dir):
        chain_id = attempt.get("chain_id")
        if isinstance(chain_id, str) and chain_id.strip():
            return chain_id.strip()
    for candidate in _candidate_records(run_dir):
        chain_id = candidate.get("chain_id")
        if isinstance(chain_id, str) and chain_id.strip():
            return chain_id.strip()
    return "weaponization:unbound-chain"


def _candidate_for_chain(run_dir: Path, chain_id: str) -> dict[str, Any]:
    attempts = _autopoc_attempts(run_dir)
    candidate_ids = {
        str(attempt.get("candidate_id"))
        for attempt in attempts
        if str(attempt.get("chain_id") or "").strip() == chain_id and attempt.get("candidate_id") is not None
    }
    for candidate in _candidate_records(run_dir):
        if str(candidate.get("chain_id") or "").strip() == chain_id:
            return candidate
        if str(candidate.get("candidate_id") or "") in candidate_ids:
            return candidate
    return {}


def _primitive_from(package_manifest: dict[str, Any], candidate: dict[str, Any], base_plan: dict[str, Any]) -> str:
    capability = _as_dict(package_manifest.get("capability"))
    primitive = capability.get("primitive")
    if isinstance(primitive, str) and primitive in _SAFE_PLAN_PRIMITIVES:
        return primitive
    goal = str(base_plan.get("goal") or "").lower()
    families = " ".join(str(item) for item in _as_list(candidate.get("families"))).lower()
    if "auth" in families:
        return "auth_bypass"
    if "read" in goal or "disclosure" in families or "traversal" in families:
        return "arbitrary_read"
    if "crash" in goal or "memory" in families:
        return "controlled_crash"
    if "cmd" in goal or "command" in families:
        return "command_effect_marker"
    return "state_transition"


def _safe_string_list(value: object, *, fallback: list[str]) -> list[str]:
    out = [str(item).strip() for item in _as_list(value) if str(item).strip()]
    return out if out else list(fallback)


def build_weaponization_plan(
    run_dir: Path,
    *,
    package_manifest_path: Path | None = None,
    chain_id: str | None = None,
    repro_required: int = _DEFAULT_REPRO_REQUIRED,
) -> dict[str, object]:
    """Build a SCOUT-W Plan IR from existing run evidence and package metadata."""
    run_dir = run_dir.resolve()
    package_manifest_path = package_manifest_path.resolve() if package_manifest_path is not None else None
    package_manifest = _load_package_manifest(package_manifest_path)
    run_manifest = _run_manifest(run_dir)
    gate = _exploit_gate(run_manifest)
    selected_chain_id = _select_chain_id(package_manifest, run_dir, chain_id)
    candidate = _candidate_for_chain(run_dir, selected_chain_id)
    base_plan = _state_machine_plan(run_dir, selected_chain_id)
    binding = _as_dict(package_manifest.get("binding"))
    target_profile = _as_dict(package_manifest.get("target_profile"))
    cleanup = _as_dict(package_manifest.get("cleanup"))
    firmware_sha = _run_firmware_sha256(run_manifest)
    supported_hashes = _supported_firmware_hashes(package_manifest)
    primitive = _primitive_from(package_manifest, candidate, base_plan)
    pattern_id = str(binding.get("pattern_id") or candidate.get("pattern_id") or "unbound-pattern")
    preconditions = _safe_string_list(
        package_manifest.get("preconditions") if package_manifest else candidate.get("preconditions"),
        fallback=["authorized bounded scope", "firmware hash identity available", "verifier channel available"],
    )
    validation_plan = _safe_string_list(
        candidate.get("validation_plan"),
        fallback=["confirm preconditions", "observe bounded primitive", "record cleanup and control-pair result"],
    )
    transitions = _as_list(base_plan.get("transitions")) if base_plan else []
    if not transitions:
        transitions = [
            {
                "transition_id": "t_scope_guard",
                "action": "verify_authorized_scope",
                "verifier": "manifest.exploit_gate",
            },
            {
                "transition_id": "t_target_profile",
                "action": "match_target_profile",
                "verifier": "firmware_sha256_and_service_metadata",
            },
            {
                "transition_id": "t_primitive_verifier",
                "action": "observe_bounded_primitive",
                "verifier": "verifier_log_or_evidence_bundle_hash",
            },
            {
                "transition_id": "t_cleanup",
                "action": "verify_cleanup",
                "verifier": "cleanup_log",
            },
        ]

    plan: dict[str, object] = {
        "schema_version": _PLAN_SCHEMA_VERSION,
        "plan_id": f"scout-w:{selected_chain_id}",
        "promotion_target": "L6_CONTROLLED_WEAPONIZATION_PACKAGE",
        "claim_boundary": "Plan/preflight metadata only; private payload execution is out-of-band and separately gated.",
        "run_dir": str(run_dir),
        "firmware_sha256": firmware_sha or "",
        "scope": {
            "mode": gate.get("scope", "missing"),
            "attestation": gate.get("attestation", "missing"),
            "flag": gate.get("flag", "missing"),
            "forbidden_targets": ["unknown_firmware", "unscoped_internet_target", "public_internet"],
        },
        "binding": {
            "scout_chain_id": selected_chain_id,
            "pattern_id": pattern_id,
            "package_manifest": str(package_manifest_path) if package_manifest_path is not None else "",
            "package_hash_sha256": _package_hash(package_manifest) or "",
            "supported_firmware_sha256": supported_hashes,
        },
        "target_profile": {
            "firmware_sha256": target_profile.get("firmware_sha256", firmware_sha or ""),
            "architecture": target_profile.get("architecture", "unknown"),
            "service": target_profile.get("service", candidate.get("target_service", "unknown")),
        },
        "primitive": {"type": primitive, "destructive": False, "expected_effect": "bounded_marker_or_state_change"},
        "preconditions": preconditions,
        "execution": {
            "mode": "authorized_lab_or_engagement_scope_only",
            "repro_required": max(1, int(repro_required)),
            "retry_policy": "conservative",
            "unknown_target_policy": "deny",
        },
        "verification": {
            "validation_plan": validation_plan,
            "evidence_types": ["verifier_log_hash", "target_profile_hash", "cleanup_log_hash", "control_pair_result"],
        },
        "cleanup": {
            "required": True,
            "strategy": cleanup.get("strategy", "restore transient state and remove lab markers"),
            "verification": cleanup.get("verification", "cleanup_log"),
        },
        "transitions": transitions,
        "source_refs": [
            "manifest.json",
            "stages/findings/exploit_candidates.json",
            "stages/exploit_autopoc/exploit_autopoc.json",
            "stages/exploit_state_machine/exploit_state_machine.json",
        ],
    }
    plan["plan_ir_sha256"] = _sha256_json(plan)
    return plan


def evaluate_weaponization_preflight(
    run_dir: Path,
    plan_path: Path,
    *,
    package_manifest_path: Path | None = None,
) -> dict[str, object]:
    """Fail-closed preflight before any private package executor can run."""
    run_dir = run_dir.resolve()
    plan_path = plan_path.resolve()
    plan = _load_json(plan_path) or {}
    package_manifest_path = package_manifest_path.resolve() if package_manifest_path is not None else None
    package_manifest = _load_package_manifest(package_manifest_path)
    run_manifest = _run_manifest(run_dir)
    gate = _exploit_gate(run_manifest)
    firmware_sha = _run_firmware_sha256(run_manifest)
    binding = _as_dict(plan.get("binding"))
    target_profile = _as_dict(plan.get("target_profile"))
    primitive = _as_dict(plan.get("primitive"))
    execution = _as_dict(plan.get("execution"))
    cleanup = _as_dict(plan.get("cleanup"))
    preconditions = _as_list(plan.get("preconditions"))
    supported_hashes = _supported_firmware_hashes(package_manifest) if package_manifest else _safe_string_list(binding.get("supported_firmware_sha256"), fallback=[])

    checks = [
        _check(
            "plan_valid_json",
            bool(plan),
            "Plan path must contain a JSON object.",
            evidence={"plan_path": str(plan_path)},
        ),
        _check(
            "plan_schema_version",
            plan.get("schema_version") == _PLAN_SCHEMA_VERSION,
            f"Plan schema_version must be {_PLAN_SCHEMA_VERSION}.",
            evidence={"schema_version": plan.get("schema_version")},
        ),
        _check(
            "run_scope_authorized_bounded",
            run_manifest.get("profile") == "exploit"
            and _attestation_is_authorized(gate.get("attestation"))
            and _scope_is_bounded(gate.get("scope")),
            "Run must be exploit-profiled with authorized attestation and bounded scope.",
            evidence={"profile": run_manifest.get("profile"), "exploit_gate": gate},
        ),
        _check(
            "firmware_identity_match",
            firmware_sha is not None
            and target_profile.get("firmware_sha256") == firmware_sha
            and (not supported_hashes or firmware_sha in supported_hashes),
            "Plan target profile and package binding must match the run firmware SHA-256.",
            evidence={
                "run_firmware_sha256": firmware_sha,
                "plan_firmware_sha256": target_profile.get("firmware_sha256"),
                "supported_firmware_sha256": supported_hashes,
            },
        ),
        _check(
            "chain_and_pattern_bound",
            isinstance(binding.get("scout_chain_id"), str)
            and bool(str(binding.get("scout_chain_id")).strip())
            and isinstance(binding.get("pattern_id"), str)
            and bool(str(binding.get("pattern_id")).strip())
            and binding.get("pattern_id") != "unbound-pattern",
            "Plan must bind a SCOUT chain id and curated pattern id.",
            evidence={"binding": binding},
        ),
        _check(
            "safe_primitive",
            primitive.get("type") in _SAFE_PLAN_PRIMITIVES and primitive.get("destructive") is False,
            "Plan primitive must be controlled and non-destructive.",
            evidence={"primitive": primitive},
        ),
        _check(
            "preconditions_present",
            len(preconditions) > 0 and all(isinstance(item, str) and item.strip() for item in preconditions),
            "Plan must declare concrete preconditions before private execution.",
            evidence={"precondition_count": len(preconditions)},
        ),
        _check(
            "unknown_target_denied",
            execution.get("unknown_target_policy") == "deny",
            "Plan must deny unknown targets.",
            evidence={"unknown_target_policy": execution.get("unknown_target_policy")},
        ),
        _check(
            "cleanup_required",
            cleanup.get("required") is True and isinstance(cleanup.get("verification"), str),
            "Plan must require cleanup and name a cleanup verification channel.",
            evidence={"cleanup": cleanup},
        ),
    ]
    passed = all(bool(check.get("passed")) for check in checks)
    if not passed and not bool(checks[2].get("passed")):
        decision = "BLOCKED_SCOPE"
    elif not passed and not bool(checks[3].get("passed")):
        decision = "SKIP_UNSUPPORTED_VERSION"
    elif not passed and not bool(checks[6].get("passed")):
        decision = "NEEDS_STATE_SETUP"
    elif not passed:
        decision = "BLOCKED_PRECONDITION"
    else:
        decision = "RUN_PRIVATE_PACKAGE_ALLOWED"
    return {
        "schema_version": _PREFLIGHT_SCHEMA_VERSION,
        "verdict": "pass" if passed else "fail",
        "passed": passed,
        "decision": decision,
        "run_dir": str(run_dir),
        "plan_path": str(plan_path),
        "package_manifest": str(package_manifest_path) if package_manifest_path is not None else "",
        "checks": checks,
        "claim_boundary": "Preflight authorizes only the next gated private-package step; it does not execute payloads.",
    }


def format_preflight_report(payload: dict[str, object]) -> str:
    lines = [
        f"SCOUT-W preflight: {payload.get('verdict')}",
        f"decision: {payload.get('decision')}",
    ]
    for check in _as_list(payload.get("checks")):
        if isinstance(check, dict):
            status = "PASS" if check.get("passed") is True else "FAIL"
            lines.append(f"[{status}] {check.get('name')}: {check.get('message')}")
    return "\n".join(lines) + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SCOUT-W controlled weaponization plan/preflight tools.")
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan", help="Build a controlled weaponization Plan IR from SCOUT evidence.")
    plan.add_argument("run_dir", type=Path)
    plan.add_argument("--package-manifest", type=Path, default=None)
    plan.add_argument("--chain-id", default=None)
    plan.add_argument("--repro-required", type=int, default=_DEFAULT_REPRO_REQUIRED)
    plan.add_argument("--out", type=Path, default=None)

    preflight = sub.add_parser("preflight", help="Fail-closed preflight for a controlled weaponization Plan IR.")
    preflight.add_argument("run_dir", type=Path)
    preflight.add_argument("--plan", required=True, type=Path)
    preflight.add_argument("--package-manifest", type=Path, default=None)
    preflight.add_argument("--out", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "plan":
        out_path = args.out or (args.run_dir / "weaponization_plan.json")
        payload = build_weaponization_plan(
            args.run_dir,
            package_manifest_path=args.package_manifest,
            chain_id=args.chain_id,
            repro_required=int(args.repro_required),
        )
        _write_json(out_path, payload)
        print(json.dumps(payload, indent=2, sort_keys=True) + "\n", end="")
        return 0
    if args.command == "preflight":
        out_path = args.out or (args.run_dir / "weaponization_preflight.json")
        payload = evaluate_weaponization_preflight(
            args.run_dir,
            args.plan,
            package_manifest_path=args.package_manifest,
        )
        _write_json(out_path, payload)
        print(format_preflight_report(payload), end="")
        return 0 if payload.get("passed") is True else 37
    return 20


if __name__ == "__main__":
    raise SystemExit(main())
