"""Controlled weaponization execution ledger and engagement approval gate.

This module is an evidence aggregator only. It does not generate payloads, import
private exploit packages, or contact targets. It promotes a controlled internal
red-team package from a preflight/readiness state into an execution ledger (L6)
or an engagement-approved package (L7) only when existing artifacts prove scoped
execution, reproducibility, cleanup, and optional engagement approval.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .controlled_weaponization import _as_dict, _as_list, _is_hex64, _load_json
from .weaponization_plan import _PLAN_SCHEMA_VERSION, _PREFLIGHT_SCHEMA_VERSION

_LEDGER_SCHEMA_VERSION = "scout-weaponization-ledger-v1"
_APPROVAL_SCHEMA_VERSION = "scout-engagement-approval-v1"
_READINESS_SCHEMA_VERSION = "controlled-weaponization-readiness-v1"
_EXPLOIT_EVIDENCE_SCHEMA_VERSION = "exploit-evidence-v1"
_DEFAULT_REPRO_REQUIRED = 3
_EXIT_LEDGER_BLOCKED = 38
_ISO8601_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _check(name: str, passed: bool, message: str, *, evidence: object = None) -> dict[str, object]:
    out: dict[str, object] = {"name": name, "passed": passed, "message": message}
    if evidence is not None:
        out["evidence"] = evidence
    return out


def _load_required_json(path: Path) -> dict[str, Any]:
    return _load_json(path) or {}


def _path_evidence(path: Path) -> dict[str, object]:
    exists = path.is_file()
    evidence: dict[str, object] = {"path": str(path), "exists": exists}
    if exists:
        evidence["sha256"] = _sha256_file(path)
        evidence["bytes"] = path.stat().st_size
    return evidence


def _discover_execution_evidence(run_dir: Path) -> list[Path]:
    exploits_dir = run_dir / "exploits"
    if not exploits_dir.is_dir():
        return []
    return sorted(exploits_dir.glob("chain_*/evidence_bundle.json"))


def _evidence_paths(run_dir: Path, explicit_paths: list[Path] | None) -> list[Path]:
    if explicit_paths:
        return [path.resolve() for path in explicit_paths]
    return [path.resolve() for path in _discover_execution_evidence(run_dir)]


def _attempt_passed(attempt: object) -> bool:
    if not isinstance(attempt, dict):
        return False
    return attempt.get("status") == "pass" or attempt.get("success") is True


def _attempt_failed(attempt: object) -> bool:
    if not isinstance(attempt, dict):
        return False
    status = attempt.get("status")
    return status in {"fail", "partial", "error"} or attempt.get("success") is False


def _bundle_reliability(bundle: dict[str, Any]) -> dict[str, int | str]:
    reproducibility = _as_dict(bundle.get("reproducibility"))
    attempted_raw = reproducibility.get("attempted") or reproducibility.get("requested")
    passed_raw = reproducibility.get("passed")
    attempts = _as_list(bundle.get("attempts"))
    attempted = int(attempted_raw) if isinstance(attempted_raw, int) and attempted_raw >= 0 else len(attempts)
    passed = int(passed_raw) if isinstance(passed_raw, int) and passed_raw >= 0 else sum(
        1 for attempt in attempts if _attempt_passed(attempt)
    )
    failed = sum(1 for attempt in attempts if _attempt_failed(attempt))
    if attempted == 0 and bundle.get("success") is True:
        attempted = 1
        passed = 1
    elif attempted == 0 and bundle.get("success") is False:
        attempted = 1
        failed = 1
    return {
        "attempted": attempted,
        "passed": passed,
        "failed": failed,
        "status": str(reproducibility.get("status") or bundle.get("status") or "unknown"),
    }


def _execution_summary(paths: list[Path]) -> dict[str, object]:
    bundles: list[dict[str, object]] = []
    total_attempted = 0
    total_passed = 0
    total_failed = 0
    schema_ok = True
    cleanup_errors: list[str] = []
    chain_ids: list[str] = []
    for path in paths:
        payload = _load_json(path) or {}
        reliability = _bundle_reliability(payload)
        total_attempted += int(reliability.get("attempted", 0))
        total_passed += int(reliability.get("passed", 0))
        total_failed += int(reliability.get("failed", 0))
        schema_ok = schema_ok and payload.get("schema_version") == _EXPLOIT_EVIDENCE_SCHEMA_VERSION
        runtime = _as_dict(payload.get("runtime"))
        cleanup_error = runtime.get("cleanup_error")
        if isinstance(cleanup_error, str) and cleanup_error.strip():
            cleanup_errors.append(cleanup_error.strip())
        chain_id = payload.get("chain_id")
        if isinstance(chain_id, str) and chain_id.strip():
            chain_ids.append(chain_id.strip())
        bundles.append(
            {
                "artifact": _path_evidence(path),
                "chain_id": chain_id if isinstance(chain_id, str) else "",
                "schema_version": payload.get("schema_version"),
                "reliability": reliability,
                "policy": _as_dict(payload.get("policy")),
            }
        )
    return {
        "bundles": bundles,
        "chain_ids": sorted(set(chain_ids)),
        "cleanup_errors": cleanup_errors,
        "schema_ok": schema_ok and bool(paths),
        "total_attempted": total_attempted,
        "total_passed": total_passed,
        "total_failed": total_failed,
    }


def _plan_repro_required(plan: dict[str, Any]) -> int:
    execution = _as_dict(plan.get("execution"))
    raw = execution.get("repro_required")
    return int(raw) if isinstance(raw, int) and raw > 0 else _DEFAULT_REPRO_REQUIRED


def _readiness_ready(readiness: dict[str, Any]) -> bool:
    return (
        readiness.get("schema_version") == _READINESS_SCHEMA_VERSION
        and readiness.get("ready") is True
        and readiness.get("promotion_level") == "L6_CONTROLLED_WEAPONIZATION_PACKAGE"
    )


def _approval_summary(approval_path: Path | None) -> dict[str, object]:
    if approval_path is None:
        return {"provided": False, "passed": False, "artifact": {}}
    payload = _load_json(approval_path) or {}
    scope = _as_dict(payload.get("scope"))
    allowed_targets = [str(item).strip() for item in _as_list(scope.get("allowed_targets")) if str(item).strip()]
    package_hash = payload.get("package_hash_sha256") or _as_dict(payload.get("package")).get("hash_sha256")
    expires_at = scope.get("expires_at")
    passed = (
        payload.get("schema_version") == _APPROVAL_SCHEMA_VERSION
        and payload.get("approved") is True
        and isinstance(payload.get("engagement_id"), str)
        and bool(str(payload.get("engagement_id")).strip())
        and isinstance(payload.get("approver"), str)
        and bool(str(payload.get("approver")).strip())
        and bool(allowed_targets)
        and isinstance(expires_at, str)
        and _ISO8601_DATE_RE.match(expires_at) is not None
        and isinstance(package_hash, str)
        and _is_hex64(package_hash)
    )
    return {
        "provided": True,
        "passed": passed,
        "artifact": _path_evidence(approval_path),
        "engagement_id": payload.get("engagement_id", ""),
        "allowed_target_count": len(allowed_targets),
        "expires_at": expires_at if isinstance(expires_at, str) else "",
    }


def build_weaponization_ledger(
    run_dir: Path,
    *,
    plan_path: Path,
    preflight_path: Path,
    readiness_path: Path,
    execution_evidence_paths: list[Path] | None = None,
    cleanup_log_path: Path | None = None,
    approval_path: Path | None = None,
) -> dict[str, object]:
    """Build a fail-closed L6/L7 execution ledger from existing evidence artifacts."""
    run_dir = run_dir.resolve()
    plan_path = plan_path.resolve()
    preflight_path = preflight_path.resolve()
    readiness_path = readiness_path.resolve()
    cleanup_log_path = cleanup_log_path.resolve() if cleanup_log_path is not None else None
    approval_path = approval_path.resolve() if approval_path is not None else None

    plan = _load_required_json(plan_path)
    preflight = _load_required_json(preflight_path)
    readiness = _load_required_json(readiness_path)
    evidence_paths = _evidence_paths(run_dir, execution_evidence_paths)
    execution = _execution_summary(evidence_paths)
    repro_required = _plan_repro_required(plan)
    cleanup_log = _path_evidence(cleanup_log_path) if cleanup_log_path is not None else {}
    cleanup_log_present = bool(cleanup_log.get("exists"))
    cleanup_errors = _as_list(execution.get("cleanup_errors"))
    approval = _approval_summary(approval_path)

    plan_binding = _as_dict(plan.get("binding"))
    chain_id = str(plan_binding.get("scout_chain_id") or "").strip()
    observed_chains = [str(item) for item in _as_list(execution.get("chain_ids"))]
    total_passed = execution.get("total_passed")
    total_failed = execution.get("total_failed")
    total_passed_int = total_passed if isinstance(total_passed, int) else 0
    total_failed_int = total_failed if isinstance(total_failed, int) else 0

    checks = [
        _check(
            "plan_ir_valid",
            plan.get("schema_version") == _PLAN_SCHEMA_VERSION,
            "Plan IR must use the SCOUT controlled weaponization schema.",
            evidence={"schema_version": plan.get("schema_version"), "artifact": _path_evidence(plan_path)},
        ),
        _check(
            "preflight_passed",
            preflight.get("schema_version") == _PREFLIGHT_SCHEMA_VERSION
            and preflight.get("passed") is True
            and preflight.get("decision") == "RUN_PRIVATE_PACKAGE_ALLOWED",
            "Preflight must fail-open nowhere and explicitly allow the private package step.",
            evidence={"decision": preflight.get("decision"), "artifact": _path_evidence(preflight_path)},
        ),
        _check(
            "readiness_l6_passed",
            _readiness_ready(readiness),
            "Controlled weaponization readiness must have promoted the package to L6.",
            evidence={"promotion_level": readiness.get("promotion_level"), "artifact": _path_evidence(readiness_path)},
        ),
        _check(
            "execution_evidence_present",
            bool(evidence_paths) and bool(execution.get("schema_ok")),
            "At least one exploit-evidence-v1 bundle must be recorded; private source is not copied into the ledger.",
            evidence={"bundle_count": len(evidence_paths), "bundles": execution.get("bundles")},
        ),
        _check(
            "execution_chain_bound",
            bool(chain_id) and (not observed_chains or chain_id in observed_chains),
            "Execution evidence must match the Plan IR chain binding.",
            evidence={"plan_chain_id": chain_id, "observed_chain_ids": observed_chains},
        ),
        _check(
            "reliability_repro_met",
            total_passed_int >= repro_required and total_failed_int == 0,
            "Execution evidence must meet the Plan IR reproducibility requirement with no failed attempts.",
            evidence={
                "repro_required": repro_required,
                "attempted": execution.get("total_attempted"),
                "passed": total_passed_int,
                "failed": total_failed_int,
            },
        ),
        _check(
            "cleanup_verified",
            cleanup_log_present and not cleanup_errors,
            "Cleanup must have an explicit evidence artifact and no recorded cleanup errors.",
            evidence={"cleanup_log": cleanup_log, "cleanup_errors": cleanup_errors},
        ),
    ]

    base_passed = all(bool(check.get("passed")) for check in checks)
    approval_passed = bool(approval.get("passed"))
    if base_passed and approval_passed:
        promotion_level = "L7_ENGAGEMENT_APPROVED_PACKAGE"
        verdict = "engagement-approved"
        passed = True
    elif base_passed:
        promotion_level = "L6_EXECUTION_LEDGER_READY"
        verdict = "ledger-ready"
        passed = True
    elif preflight.get("passed") is True and readiness.get("ready") is True:
        promotion_level = "L6_CONTROLLED_WEAPONIZATION_PACKAGE_BLOCKED"
        verdict = "blocked"
        passed = False
    else:
        promotion_level = "L5_OR_BELOW_BLOCKED"
        verdict = "blocked"
        passed = False

    payload: dict[str, object] = {
        "schema_version": _LEDGER_SCHEMA_VERSION,
        "verdict": verdict,
        "passed": passed,
        "promotion_level": promotion_level,
        "claim_boundary": "Ledger aggregation only; exploit payloads remain private and out-of-band.",
        "run_dir": str(run_dir),
        "artifacts": {
            "plan": _path_evidence(plan_path),
            "preflight": _path_evidence(preflight_path),
            "readiness": _path_evidence(readiness_path),
            "cleanup_log": cleanup_log,
            "approval": approval.get("artifact", {}),
        },
        "reliability": {
            "repro_required": repro_required,
            "attempted": execution.get("total_attempted"),
            "passed": execution.get("total_passed"),
            "failed": execution.get("total_failed"),
            "bundles": execution.get("bundles"),
        },
        "cleanup": {"passed": cleanup_log_present and not cleanup_errors, "errors": cleanup_errors},
        "approval": approval,
        "checks": checks,
    }
    ledger_without_hash = dict(payload)
    payload["ledger_sha256"] = hashlib.sha256(
        json.dumps(ledger_without_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    return payload


def format_ledger_report(payload: dict[str, object]) -> str:
    lines = [
        f"SCOUT-W ledger: {payload.get('verdict')}",
        f"promotion_level: {payload.get('promotion_level')}",
    ]
    for check in _as_list(payload.get("checks")):
        if isinstance(check, dict):
            status = "PASS" if check.get("passed") is True else "FAIL"
            lines.append(f"[{status}] {check.get('name')}: {check.get('message')}")
    approval = _as_dict(payload.get("approval"))
    if approval.get("provided") is True:
        lines.append(f"[{'PASS' if approval.get('passed') is True else 'FAIL'}] engagement_approval")
    else:
        lines.append("[INFO] engagement_approval: not provided; L7 promotion not attempted")
    return "\n".join(lines) + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a controlled weaponization L6/L7 execution ledger from existing artifacts."
    )
    parser.add_argument("run_dir", type=Path, help="Completed SCOUT run directory.")
    parser.add_argument("--plan", required=True, type=Path, help="weaponization_plan.json path.")
    parser.add_argument("--preflight", required=True, type=Path, help="weaponization_preflight.json path.")
    parser.add_argument("--readiness", required=True, type=Path, help="controlled_weaponization_readiness.json path.")
    parser.add_argument(
        "--execution-evidence",
        action="append",
        default=None,
        type=Path,
        help="exploit-evidence-v1 bundle path. May be repeated; defaults to run_dir/exploits/*/evidence_bundle.json.",
    )
    parser.add_argument("--cleanup-log", default=None, type=Path, help="Cleanup verification log/artifact path.")
    parser.add_argument("--approval", default=None, type=Path, help="Optional engagement approval manifest for L7.")
    parser.add_argument("--out", default=None, type=Path, help="Optional output JSON path.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    out_path = args.out or (args.run_dir / "weaponization_ledger.json")
    payload = build_weaponization_ledger(
        args.run_dir,
        plan_path=args.plan,
        preflight_path=args.preflight,
        readiness_path=args.readiness,
        execution_evidence_paths=args.execution_evidence,
        cleanup_log_path=args.cleanup_log,
        approval_path=args.approval,
    )
    _write_json(out_path, payload)
    print(format_ledger_report(payload), end="")
    return 0 if payload.get("passed") is True else _EXIT_LEDGER_BLOCKED


if __name__ == "__main__":
    raise SystemExit(main())
