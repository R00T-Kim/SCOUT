"""Gated private execution wrapper for SCOUT controlled weaponization.

The wrapper does not contain exploit logic. It verifies the SCOUT-W Plan IR,
preflight decision, and readiness gate before delegating to the existing private
plugin runner, then writes the execution ledger. Working exploit code remains in
an operator-controlled private directory outside the public repository.
"""

from __future__ import annotations

import argparse
import importlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from .controlled_weaponization import _as_dict, _load_json
from .weaponization_ledger import build_weaponization_ledger, format_ledger_report
from .weaponization_package import verify_package
from .weaponization_plan import _PLAN_SCHEMA_VERSION, _PREFLIGHT_SCHEMA_VERSION

_EXIT_PRECHECK_BLOCKED = 39


def _plan_chain_id(plan: dict[str, Any]) -> str:
    binding = _as_dict(plan.get("binding"))
    chain_id = binding.get("scout_chain_id")
    return chain_id.strip() if isinstance(chain_id, str) else ""


def _plan_repro_required(plan: dict[str, Any]) -> int:
    execution = _as_dict(plan.get("execution"))
    raw = execution.get("repro_required")
    return raw if isinstance(raw, int) and raw > 0 else 3


def _readiness_ready(readiness: dict[str, Any]) -> bool:
    return (
        readiness.get("schema_version") == "controlled-weaponization-readiness-v1"
        and readiness.get("ready") is True
        and readiness.get("promotion_level") == "L6_CONTROLLED_WEAPONIZATION_PACKAGE"
    )


def _precheck(
    *,
    plan: dict[str, Any],
    preflight: dict[str, Any],
    readiness: dict[str, Any],
    requested_chain_id: str | None,
) -> tuple[bool, str, str]:
    if plan.get("schema_version") != _PLAN_SCHEMA_VERSION:
        return False, "BLOCKED_INVALID_PLAN", "Plan IR schema is missing or invalid."
    if preflight.get("schema_version") != _PREFLIGHT_SCHEMA_VERSION or preflight.get("passed") is not True:
        return False, "BLOCKED_PREFLIGHT", "weaponization-preflight must pass before private execution."
    if not _readiness_ready(readiness):
        return False, "BLOCKED_READINESS", "weaponization-readiness must promote the package to L6."
    chain_id = _plan_chain_id(plan)
    if not chain_id:
        return False, "BLOCKED_UNBOUND_CHAIN", "Plan IR does not bind a SCOUT chain id."
    if requested_chain_id is not None and requested_chain_id.strip() and requested_chain_id.strip() != chain_id:
        return False, "BLOCKED_CHAIN_MISMATCH", "Requested chain id does not match the Plan IR binding."
    return True, "RUN_PRIVATE_PACKAGE_ALLOWED", chain_id


def _run_private_plugin(run_dir: Path, exploit_dir: Path, chain_id: str, repro: int) -> int:
    runner_mod = importlib.import_module("exploit_runner")
    run_exploit = cast(Callable[..., int], getattr(runner_mod, "run_exploit"))
    return run_exploit(run_dir=run_dir, exploit_dir=exploit_dir, chain_id=chain_id, repro=repro)


def execute_controlled_weaponization(
    run_dir: Path,
    *,
    exploit_dir: Path,
    plan_path: Path,
    preflight_path: Path,
    readiness_path: Path,
    cleanup_log_path: Path,
    approval_path: Path | None = None,
    vault_registry_path: Path | None = None,
    package_hash: str | None = None,
    out_ledger_path: Path | None = None,
    chain_id: str | None = None,
    repro: int | None = None,
) -> int:
    """Run a private plugin only after SCOUT-W gates pass, then ledger evidence."""
    run_dir = run_dir.resolve()
    exploit_dir = exploit_dir.resolve()
    plan_path = plan_path.resolve()
    preflight_path = preflight_path.resolve()
    readiness_path = readiness_path.resolve()
    cleanup_log_path = cleanup_log_path.resolve()
    approval_path = approval_path.resolve() if approval_path is not None else None
    vault_registry_path = vault_registry_path.resolve() if vault_registry_path is not None else None
    out_ledger_path = out_ledger_path.resolve() if out_ledger_path is not None else run_dir / "weaponization_ledger.json"

    plan = _load_json(plan_path) or {}
    preflight = _load_json(preflight_path) or {}
    readiness = _load_json(readiness_path) or {}
    allowed, decision, resolved_chain_id = _precheck(
        plan=plan,
        preflight=preflight,
        readiness=readiness,
        requested_chain_id=chain_id,
    )
    if not allowed:
        print(f"[FAIL] {decision}: {resolved_chain_id}")
        return _EXIT_PRECHECK_BLOCKED

    if vault_registry_path is not None:
        binding = _as_dict(plan.get("binding"))
        target_profile = _as_dict(plan.get("target_profile"))
        resolved_hash = (
            package_hash.strip()
            if isinstance(package_hash, str) and package_hash.strip()
            else str(binding.get("package_hash_sha256") or "").strip()
        )
        vault_report = verify_package(
            vault_registry_path,
            package_hash=resolved_hash,
            firmware_sha256=str(plan.get("firmware_sha256") or target_profile.get("firmware_sha256") or ""),
            pattern_id=str(binding.get("pattern_id") or ""),
            chain_id=resolved_chain_id,
        )
        if vault_report.get("passed") is not True:
            print("[FAIL] BLOCKED_VAULT_REGISTRY: package hash is not approved for this firmware/pattern/chain")
            return _EXIT_PRECHECK_BLOCKED

    requested_repro = repro if isinstance(repro, int) and repro > 0 else _plan_repro_required(plan)
    runner_rc = _run_private_plugin(run_dir, exploit_dir, resolved_chain_id, requested_repro)
    ledger = build_weaponization_ledger(
        run_dir,
        plan_path=plan_path,
        preflight_path=preflight_path,
        readiness_path=readiness_path,
        cleanup_log_path=cleanup_log_path,
        approval_path=approval_path,
    )
    out_ledger_path.parent.mkdir(parents=True, exist_ok=True)
    out_ledger_path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(format_ledger_report(ledger), end="")
    if runner_rc != 0:
        return runner_rc
    return 0 if ledger.get("passed") is True else 38


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Gate private plugin execution through SCOUT-W preflight/readiness, then write the ledger."
    )
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--exploit-dir", required=True, type=Path, help="Private exploit package directory.")
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--readiness", required=True, type=Path)
    parser.add_argument("--cleanup-log", required=True, type=Path)
    parser.add_argument("--approval", default=None, type=Path)
    parser.add_argument("--vault-registry", default=None, type=Path)
    parser.add_argument("--package-hash", default=None)
    parser.add_argument("--chain-id", default=None)
    parser.add_argument("--repro", default=None, type=int)
    parser.add_argument("--out-ledger", default=None, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return execute_controlled_weaponization(
        args.run_dir,
        exploit_dir=args.exploit_dir,
        plan_path=args.plan,
        preflight_path=args.preflight,
        readiness_path=args.readiness,
        cleanup_log_path=args.cleanup_log,
        approval_path=args.approval,
        vault_registry_path=args.vault_registry,
        package_hash=args.package_hash,
        out_ledger_path=args.out_ledger,
        chain_id=args.chain_id,
        repro=args.repro,
    )


if __name__ == "__main__":
    raise SystemExit(main())
