"""Fail-closed readiness gate for controlled private weaponization packages.

This module intentionally does **not** execute exploit code. It certifies that a
private internal red-team package is bound to an authorized SCOUT run, a scoped
firmware identity, non-destructive capability metadata, cleanup evidence, and a
passing AEG E2E gate before promotion to a controlled weaponization level.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from .aeg_e2e_gate import evaluate_aeg_e2e_gate

_SCHEMA_VERSION = "controlled-weaponization-readiness-v1"
_MANIFEST_SCHEMA_VERSION = "scout-private-exploit-package-v1"
_DEFAULT_FPR_MAX = 0.10
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_PRIMITIVES = {
    "arbitrary_read",
    "auth_bypass",
    "command_effect_marker",
    "config_state_write",
    "constrained_file_write",
    "controlled_crash",
    "path_traversal_marker_read",
    "state_transition",
}
_REQUIRED_EVIDENCE = {
    "target_profile",
    "verifier_log",
    "cleanup_log",
    "plan_ir_hash",
    "package_hash",
}


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _check(name: str, passed: bool, message: str, *, evidence: object = None) -> dict[str, object]:
    out: dict[str, object] = {"name": name, "passed": passed, "message": message}
    if evidence is not None:
        out["evidence"] = evidence
    return out


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _is_hex64(value: object) -> bool:
    return isinstance(value, str) and _HEX64_RE.fullmatch(value.lower()) is not None


def _hash_list(value: object) -> list[str]:
    hashes: list[str] = []
    for item in _as_list(value):
        if isinstance(item, str) and _is_hex64(item):
            hashes.append(item.lower())
        elif isinstance(item, dict):
            raw = item.get("sha256") or item.get("firmware_sha256")
            if isinstance(raw, str) and _is_hex64(raw):
                hashes.append(raw.lower())
    return hashes


def _first_hex64(*values: object) -> str | None:
    for value in values:
        if isinstance(value, str) and _is_hex64(value):
            return value.lower()
    return None


def _run_firmware_sha256(run_manifest: dict[str, Any]) -> str | None:
    firmware = _as_dict(run_manifest.get("firmware"))
    return _first_hex64(
        run_manifest.get("firmware_sha256"),
        run_manifest.get("analyzed_input_sha256"),
        run_manifest.get("input_sha256"),
        run_manifest.get("source_input_sha256"),
        run_manifest.get("sha256"),
        firmware.get("sha256"),
    )


def _package_hash(manifest: dict[str, Any]) -> str | None:
    package = _as_dict(manifest.get("package"))
    evidence = _as_dict(manifest.get("evidence"))
    return _first_hex64(
        manifest.get("package_hash_sha256"),
        manifest.get("package_hash"),
        package.get("hash_sha256"),
        evidence.get("package_hash"),
    )


def _supported_firmware_hashes(manifest: dict[str, Any]) -> list[str]:
    binding = _as_dict(manifest.get("binding"))
    hashes = _hash_list(binding.get("supported_firmware_sha256"))
    if not hashes:
        hashes = _hash_list(binding.get("supported_firmware_hashes"))
    target_profile = _as_dict(manifest.get("target_profile"))
    target_hash = _first_hex64(target_profile.get("firmware_sha256"), target_profile.get("sha256"))
    if target_hash and target_hash not in hashes:
        hashes.append(target_hash)
    return hashes


def _scope_is_bounded(scope: object) -> bool:
    if not isinstance(scope, str):
        return False
    normalized = scope.strip().lower()
    if not normalized:
        return False
    forbidden = ("internet", "public", "0.0.0.0/0", "any", "wildcard", "unknown")
    return not any(token in normalized for token in forbidden)


def _attestation_is_authorized(attestation: object) -> bool:
    return isinstance(attestation, str) and "author" in attestation.strip().lower()


def _artifact_value_present(value: object, *, manifest_dir: Path) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    raw = value.strip()
    if raw.startswith("sha256:"):
        return _is_hex64(raw.split(":", 1)[1])
    if _is_hex64(raw):
        return True
    path = Path(raw)
    if not path.is_absolute():
        path = manifest_dir / path
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def _control_pair_validated(manifest: dict[str, Any], manifest_dir: Path) -> tuple[bool, object]:
    promotion = _as_dict(manifest.get("promotion"))
    control_pair = _as_dict(manifest.get("control_pair"))
    if promotion.get("control_pair_validated") is True or control_pair.get("validated") is True:
        return True, {"source": "manifest", "validated": True}

    report_raw = promotion.get("control_pair_report") or control_pair.get("report") or control_pair.get("report_path")
    if isinstance(report_raw, str) and report_raw.strip():
        report_path = Path(report_raw)
        if not report_path.is_absolute():
            report_path = manifest_dir / report_path
        report = _load_json(report_path)
        if report is not None:
            passed = report.get("passed") is True or report.get("verdict") == "pass"
            return passed, {"source": str(report_path), "passed": passed, "verdict": report.get("verdict")}
    return False, {"source": "missing", "validated": False}


def _required_evidence_names(evidence: dict[str, Any]) -> set[str]:
    raw_required = evidence.get("required")
    required = {str(item) for item in _as_list(raw_required) if str(item).strip()}
    return required | _REQUIRED_EVIDENCE


def evaluate_controlled_weaponization_readiness(
    run_dir: Path,
    package_manifest_path: Path,
    *,
    fpr_max: float = _DEFAULT_FPR_MAX,
    min_runner_pass: int = 1,
    require_control_pair: bool = True,
    require_cleanup: bool = True,
) -> dict[str, object]:
    """Evaluate whether a private package can be promoted for internal red-team use.

    The gate is metadata/evidence-only and fail-closed. It never loads or runs
    private exploit plugin source.
    """
    run_dir = run_dir.resolve()
    package_manifest_path = package_manifest_path.resolve()
    manifest_dir = package_manifest_path.parent
    package_manifest = _load_json(package_manifest_path)
    run_manifest = _load_json(run_dir / "manifest.json") or {}
    aeg_gate = evaluate_aeg_e2e_gate(run_dir, fpr_max=fpr_max, min_runner_pass=min_runner_pass)

    checks: list[dict[str, object]] = []
    checks.append(
        _check(
            "package_manifest_valid_json",
            package_manifest is not None,
            "Private package manifest must be a JSON object.",
            evidence={"path": str(package_manifest_path)},
        )
    )
    if package_manifest is None:
        return _report(
            run_dir=run_dir,
            package_manifest_path=package_manifest_path,
            checks=checks,
            aeg_gate=aeg_gate,
            policy={
                "fpr_max": fpr_max,
                "min_runner_pass": min_runner_pass,
                "require_control_pair": require_control_pair,
                "require_cleanup": require_cleanup,
            },
        )

    package = _as_dict(package_manifest.get("package"))
    binding = _as_dict(package_manifest.get("binding"))
    capability = _as_dict(package_manifest.get("capability"))
    execution_policy = _as_dict(package_manifest.get("execution_policy"))
    target_profile = _as_dict(package_manifest.get("target_profile"))
    cleanup = _as_dict(package_manifest.get("cleanup"))
    evidence = _as_dict(package_manifest.get("evidence"))
    artifacts = _as_dict(evidence.get("artifacts"))
    preconditions = _as_list(package_manifest.get("preconditions"))
    run_hash = _run_firmware_sha256(run_manifest)
    supported_hashes = _supported_firmware_hashes(package_manifest)
    package_hash = _package_hash(package_manifest)

    checks.extend(
        [
            _check(
                "manifest_schema_version",
                package_manifest.get("schema_version") == _MANIFEST_SCHEMA_VERSION,
                f"Manifest schema_version must be {_MANIFEST_SCHEMA_VERSION}.",
                evidence={"schema_version": package_manifest.get("schema_version")},
            ),
            _check(
                "package_classification_controlled",
                package.get("classification") == "controlled-authorized-exploit",
                "Package classification must be controlled-authorized-exploit.",
                evidence={"classification": package.get("classification")},
            ),
            _check(
                "package_hash_pinned",
                package_hash is not None,
                "Package/plugin payload identity must be pinned by a SHA-256 hash.",
                evidence={"package_hash_sha256": package_hash},
            ),
            _check(
                "run_profile_exploit_authorized",
                run_manifest.get("profile") == "exploit"
                and _attestation_is_authorized(_as_dict(run_manifest.get("exploit_gate")).get("attestation"))
                and _scope_is_bounded(_as_dict(run_manifest.get("exploit_gate")).get("scope")),
                "SCOUT run must be exploit-profiled with authorized attestation and bounded scope.",
                evidence={"profile": run_manifest.get("profile"), "exploit_gate": run_manifest.get("exploit_gate")},
            ),
            _check(
                "aeg_e2e_gate_passed",
                aeg_gate.get("passed") is True,
                "AEG E2E gate must pass before controlled weaponization promotion.",
                evidence={"verdict": aeg_gate.get("verdict")},
            ),
            _check(
                "firmware_identity_present",
                run_hash is not None,
                "Run manifest must expose a firmware SHA-256 identity.",
                evidence={"run_firmware_sha256": run_hash},
            ),
            _check(
                "firmware_binding_matches",
                run_hash is not None and run_hash in supported_hashes,
                "Private package must be bound to the exact run firmware SHA-256.",
                evidence={"run_firmware_sha256": run_hash, "supported_firmware_sha256": supported_hashes},
            ),
            _check(
                "chain_pattern_binding_present",
                isinstance(binding.get("scout_chain_id"), str)
                and bool(str(binding.get("scout_chain_id")).strip())
                and isinstance(binding.get("pattern_id"), str)
                and bool(str(binding.get("pattern_id")).strip()),
                "Package must bind to a SCOUT chain id and curated pattern id.",
                evidence={"scout_chain_id": binding.get("scout_chain_id"), "pattern_id": binding.get("pattern_id")},
            ),
            _check(
                "safe_primitive_declared",
                capability.get("primitive") in _SAFE_PRIMITIVES,
                "Capability primitive must be one of the controlled verifier primitive classes.",
                evidence={"primitive": capability.get("primitive"), "allowed": sorted(_SAFE_PRIMITIVES)},
            ),
            _check(
                "no_destructive_or_persistent_capability",
                capability.get("destructive") is False
                and capability.get("persistence") is False
                and capability.get("lateral_movement") is False,
                "Controlled packages must declare non-destructive, non-persistent, no-lateral-movement capability.",
                evidence={
                    "destructive": capability.get("destructive"),
                    "persistence": capability.get("persistence"),
                    "lateral_movement": capability.get("lateral_movement"),
                },
            ),
            _check(
                "execution_policy_fail_closed",
                execution_policy.get("require_scope_token") is True
                and execution_policy.get("require_authorized_attestation") is True
                and execution_policy.get("require_target_profile_match") is True
                and execution_policy.get("deny_unknown_targets") is True,
                "Execution policy must require scope token, authorization, target profile match, and unknown-target denial.",
                evidence=execution_policy,
            ),
            _check(
                "target_profile_minimum_fields",
                _is_hex64(target_profile.get("firmware_sha256"))
                and isinstance(target_profile.get("architecture"), str)
                and bool(str(target_profile.get("architecture")).strip())
                and isinstance(target_profile.get("service"), str)
                and bool(str(target_profile.get("service")).strip()),
                "Target profile must bind firmware_sha256, architecture, and service.",
                evidence=target_profile,
            ),
            _check(
                "preconditions_declared",
                len(preconditions) > 0,
                "Package must declare preconditions so operators do not blind-fire a chain.",
                evidence={"precondition_count": len(preconditions)},
            ),
        ]
    )

    control_ok, control_evidence = _control_pair_validated(package_manifest, manifest_dir)
    checks.append(
        _check(
            "control_pair_validated",
            (not require_control_pair) or control_ok,
            "Control-pair fail-closed proof is required for L6 promotion.",
            evidence=control_evidence,
        )
    )

    cleanup_required = cleanup.get("required") is True or capability.get("cleanup_required") is True
    cleanup_has_plan = isinstance(cleanup.get("strategy"), str) and bool(str(cleanup.get("strategy")).strip())
    cleanup_has_verifier = isinstance(cleanup.get("verification"), str) and bool(str(cleanup.get("verification")).strip())
    checks.append(
        _check(
            "cleanup_strategy_declared",
            (not require_cleanup) or (cleanup_required and cleanup_has_plan and cleanup_has_verifier),
            "Cleanup must be required and have a strategy plus verification channel.",
            evidence={"cleanup": cleanup, "capability_cleanup_required": capability.get("cleanup_required")},
        )
    )

    required_names = _required_evidence_names(evidence)
    missing = sorted(name for name in required_names if name not in artifacts)
    invalid = sorted(
        name
        for name in required_names
        if name in artifacts and not _artifact_value_present(artifacts.get(name), manifest_dir=manifest_dir)
    )
    checks.append(
        _check(
            "evidence_artifacts_present",
            not missing and not invalid,
            "Required evidence artifact ledger entries must be present as existing files or SHA-256 pins.",
            evidence={"required": sorted(required_names), "missing": missing, "invalid": invalid},
        )
    )

    return _report(
        run_dir=run_dir,
        package_manifest_path=package_manifest_path,
        checks=checks,
        aeg_gate=aeg_gate,
        policy={
            "fpr_max": fpr_max,
            "min_runner_pass": min_runner_pass,
            "require_control_pair": require_control_pair,
            "require_cleanup": require_cleanup,
        },
    )


def _report(
    *,
    run_dir: Path,
    package_manifest_path: Path,
    checks: list[dict[str, object]],
    aeg_gate: dict[str, object],
    policy: dict[str, object],
) -> dict[str, object]:
    ready = all(bool(check.get("passed")) for check in checks)
    aeg_passed = aeg_gate.get("passed") is True
    control_passed = any(check.get("name") == "control_pair_validated" and check.get("passed") for check in checks)
    if ready:
        promotion_level = "L6_CONTROLLED_WEAPONIZATION_PACKAGE"
    elif aeg_passed and control_passed:
        promotion_level = "L5_CONTROL_PAIR_VALIDATED_BLOCKED"
    elif aeg_passed:
        promotion_level = "L4_REPRODUCIBLE_POV_BLOCKED"
    else:
        promotion_level = "L3_OR_BELOW_BLOCKED"
    return {
        "schema_version": _SCHEMA_VERSION,
        "verdict": "weaponization-ready" if ready else "blocked",
        "ready": ready,
        "promotion_level": promotion_level,
        "run_dir": str(run_dir),
        "package_manifest": str(package_manifest_path),
        "policy": policy,
        "checks": checks,
        "aeg_e2e_gate": {
            "schema_version": aeg_gate.get("schema_version"),
            "verdict": aeg_gate.get("verdict"),
            "passed": aeg_gate.get("passed"),
            "checks": aeg_gate.get("checks"),
        },
    }


def write_readiness_report(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def format_readiness_report(payload: dict[str, object]) -> str:
    lines = [
        f"SCOUT controlled weaponization readiness: {payload.get('verdict')}",
        f"promotion_level: {payload.get('promotion_level')}",
    ]
    for check in _as_list(payload.get("checks")):
        if isinstance(check, dict):
            status = "PASS" if check.get("passed") is True else "FAIL"
            lines.append(f"[{status}] {check.get('name')}: {check.get('message')}")
    return "\n".join(lines) + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fail-closed readiness gate for private controlled weaponization packages."
    )
    parser.add_argument("run_dir", type=Path, help="Completed SCOUT run directory.")
    parser.add_argument("--package-manifest", required=True, type=Path, help="Private package manifest JSON.")
    parser.add_argument("--out", default=None, type=Path, help="Optional output JSON path.")
    parser.add_argument("--fpr-max", type=float, default=_DEFAULT_FPR_MAX)
    parser.add_argument("--min-runner-pass", type=int, default=1)
    parser.add_argument(
        "--allow-missing-control-pair",
        action="store_true",
        help="Treat the missing vulnerable/control fail-closed proof as an explicit policy exception.",
    )
    parser.add_argument(
        "--allow-missing-cleanup",
        action="store_true",
        help="Do not require cleanup strategy and verification metadata.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    out_path = args.out or (args.run_dir / "controlled_weaponization_readiness.json")
    payload = evaluate_controlled_weaponization_readiness(
        args.run_dir,
        args.package_manifest,
        fpr_max=float(args.fpr_max),
        min_runner_pass=int(args.min_runner_pass),
        require_control_pair=not bool(args.allow_missing_control_pair),
        require_cleanup=not bool(args.allow_missing_cleanup),
    )
    write_readiness_report(out_path, payload)
    print(format_readiness_report(payload), end="")
    return 0 if payload.get("ready") is True else 36


if __name__ == "__main__":
    raise SystemExit(main())
