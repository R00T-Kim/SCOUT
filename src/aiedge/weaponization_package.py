"""Private package manifest linting and metadata-only vault registry.

This module manages only manifest metadata and hashes. It never reads, imports,
or executes private exploit source. The vault registry is a lightweight allowlist
used by SCOUT-W execution gates to prove that a package hash has been reviewed
for a bounded firmware/pattern scope before the private runner is invoked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .controlled_weaponization import (
    _MANIFEST_SCHEMA_VERSION,
    _SAFE_PRIMITIVES,
    _as_dict,
    _as_list,
    _first_hex64,
    _is_hex64,
    _load_json,
    _package_hash,
    _supported_firmware_hashes,
)

_LINT_SCHEMA_VERSION = "scout-private-package-lint-v1"
_VAULT_SCHEMA_VERSION = "scout-private-package-vault-v1"
_EXIT_LINT_FAILED = 40
_EXIT_VAULT_FAILED = 41
_REQUIRED_POLICIES = {
    "require_scope_token",
    "require_authorized_attestation",
    "require_target_profile_match",
    "require_control_pair_for_promotion",
    "deny_unknown_targets",
}
_REQUIRED_EVIDENCE = {"target_profile", "verifier_log", "cleanup_log", "plan_ir_hash", "package_hash"}


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _check(name: str, passed: bool, message: str, *, evidence: object = None) -> dict[str, object]:
    out: dict[str, object] = {"name": name, "passed": passed, "message": message}
    if evidence is not None:
        out["evidence"] = evidence
    return out


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _string_list(value: object) -> list[str]:
    return [str(item).strip() for item in _as_list(value) if str(item).strip()]


def _package_id(manifest: dict[str, Any]) -> str:
    package = _as_dict(manifest.get("package"))
    value = package.get("id")
    return value.strip() if isinstance(value, str) else ""


def _package_version(manifest: dict[str, Any]) -> str:
    package = _as_dict(manifest.get("package"))
    value = package.get("version")
    return value.strip() if isinstance(value, str) else ""


def lint_private_package_manifest(package_manifest_path: Path) -> dict[str, object]:
    """Validate the private package manifest contract without touching payloads."""
    package_manifest_path = package_manifest_path.resolve()
    manifest = _load_json(package_manifest_path)
    checks: list[dict[str, object]] = [
        _check(
            "manifest_valid_json",
            manifest is not None,
            "Private package manifest must be a JSON object.",
            evidence={"path": str(package_manifest_path)},
        )
    ]
    if manifest is None:
        return {
            "schema_version": _LINT_SCHEMA_VERSION,
            "verdict": "fail",
            "passed": False,
            "package_manifest": str(package_manifest_path),
            "checks": checks,
        }

    package = _as_dict(manifest.get("package"))
    binding = _as_dict(manifest.get("binding"))
    target_profile = _as_dict(manifest.get("target_profile"))
    capability = _as_dict(manifest.get("capability"))
    execution_policy = _as_dict(manifest.get("execution_policy"))
    cleanup = _as_dict(manifest.get("cleanup"))
    evidence = _as_dict(manifest.get("evidence"))
    required_evidence = set(_string_list(evidence.get("required")))
    policy_missing = sorted(name for name in _REQUIRED_POLICIES if execution_policy.get(name) is not True)
    evidence_missing = sorted(name for name in _REQUIRED_EVIDENCE if name not in required_evidence)
    supported_hashes = _supported_firmware_hashes(manifest)
    package_hash = _package_hash(manifest)

    checks.extend(
        [
            _check(
                "manifest_schema_version",
                manifest.get("schema_version") == _MANIFEST_SCHEMA_VERSION,
                f"schema_version must be {_MANIFEST_SCHEMA_VERSION}.",
                evidence={"schema_version": manifest.get("schema_version")},
            ),
            _check(
                "package_identity_present",
                bool(_package_id(manifest)) and bool(_package_version(manifest)),
                "Package id and version must be present.",
                evidence={"id": package.get("id"), "version": package.get("version")},
            ),
            _check(
                "classification_controlled_authorized",
                package.get("classification") == "controlled-authorized-exploit",
                "Package classification must be controlled-authorized-exploit.",
                evidence={"classification": package.get("classification")},
            ),
            _check(
                "package_hash_pinned",
                package_hash is not None,
                "Package hash must be pinned by SHA-256 metadata.",
                evidence={"package_hash_sha256": package_hash},
            ),
            _check(
                "chain_and_pattern_bound",
                isinstance(binding.get("scout_chain_id"), str)
                and bool(str(binding.get("scout_chain_id")).strip())
                and isinstance(binding.get("pattern_id"), str)
                and bool(str(binding.get("pattern_id")).strip()),
                "Manifest must bind a SCOUT chain id and curated pattern id.",
                evidence={"scout_chain_id": binding.get("scout_chain_id"), "pattern_id": binding.get("pattern_id")},
            ),
            _check(
                "supported_firmware_hashes_present",
                bool(supported_hashes),
                "Manifest must list exact supported firmware SHA-256 values.",
                evidence={"supported_firmware_sha256": supported_hashes},
            ),
            _check(
                "target_profile_present",
                _first_hex64(target_profile.get("firmware_sha256"), target_profile.get("sha256")) is not None
                and isinstance(target_profile.get("architecture"), str)
                and bool(str(target_profile.get("architecture")).strip())
                and isinstance(target_profile.get("service"), str)
                and bool(str(target_profile.get("service")).strip()),
                "Target profile must include firmware SHA-256, architecture, and service.",
                evidence={"target_profile": target_profile},
            ),
            _check(
                "safe_capability_declared",
                capability.get("primitive") in _SAFE_PRIMITIVES
                and capability.get("destructive") is False
                and capability.get("persistence") is False
                and capability.get("lateral_movement") is False
                and capability.get("cleanup_required") is True,
                "Capability must be a controlled primitive with destructive/persistence/lateral movement disabled.",
                evidence={"capability": capability},
            ),
            _check(
                "execution_policy_fail_closed",
                not policy_missing,
                "Required execution policy toggles must all be true.",
                evidence={"missing_or_false": policy_missing},
            ),
            _check(
                "preconditions_declared",
                bool(_string_list(manifest.get("preconditions"))),
                "At least one concrete precondition must be declared.",
                evidence={"preconditions": _string_list(manifest.get("preconditions"))},
            ),
            _check(
                "cleanup_declared",
                cleanup.get("required") is True
                and isinstance(cleanup.get("strategy"), str)
                and bool(str(cleanup.get("strategy")).strip())
                and isinstance(cleanup.get("verification"), str)
                and bool(str(cleanup.get("verification")).strip()),
                "Cleanup strategy and verification channel must be declared.",
                evidence={"cleanup": cleanup},
            ),
            _check(
                "evidence_requirements_declared",
                not evidence_missing,
                "Manifest must declare required evidence ledger names.",
                evidence={"missing": evidence_missing, "required": sorted(required_evidence)},
            ),
        ]
    )
    passed = all(bool(check.get("passed")) for check in checks)
    return {
        "schema_version": _LINT_SCHEMA_VERSION,
        "verdict": "pass" if passed else "fail",
        "passed": passed,
        "package_manifest": str(package_manifest_path),
        "package_manifest_sha256": _hash_file(package_manifest_path),
        "package_id": _package_id(manifest),
        "package_version": _package_version(manifest),
        "package_hash_sha256": package_hash or "",
        "supported_firmware_sha256": supported_hashes,
        "checks": checks,
    }


def _load_registry(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"schema_version": _VAULT_SCHEMA_VERSION, "packages": []}
    payload = _load_json(path) or {}
    if payload.get("schema_version") != _VAULT_SCHEMA_VERSION:
        return {"schema_version": _VAULT_SCHEMA_VERSION, "packages": []}
    packages = [item for item in _as_list(payload.get("packages")) if isinstance(item, dict)]
    return {"schema_version": _VAULT_SCHEMA_VERSION, "packages": packages}


def _manifest_entry(manifest_path: Path, lint_report: dict[str, object]) -> dict[str, object]:
    manifest = _load_json(manifest_path) or {}
    binding = _as_dict(manifest.get("binding"))
    capability = _as_dict(manifest.get("capability"))
    return {
        "package_id": lint_report.get("package_id", ""),
        "package_version": lint_report.get("package_version", ""),
        "package_hash_sha256": lint_report.get("package_hash_sha256", ""),
        "package_manifest": str(manifest_path.resolve()),
        "package_manifest_sha256": lint_report.get("package_manifest_sha256", ""),
        "scout_chain_id": binding.get("scout_chain_id", ""),
        "pattern_id": binding.get("pattern_id", ""),
        "primitive": capability.get("primitive", ""),
        "supported_firmware_sha256": lint_report.get("supported_firmware_sha256", []),
        "registered_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }


def register_package(registry_path: Path, package_manifest_path: Path) -> dict[str, object]:
    registry_path = registry_path.resolve()
    package_manifest_path = package_manifest_path.resolve()
    lint_report = lint_private_package_manifest(package_manifest_path)
    if lint_report.get("passed") is not True:
        return {
            "schema_version": _VAULT_SCHEMA_VERSION,
            "verdict": "blocked",
            "passed": False,
            "registry": str(registry_path),
            "lint": lint_report,
            "packages": _load_registry(registry_path).get("packages", []),
        }
    registry = _load_registry(registry_path)
    packages = [item for item in _as_list(registry.get("packages")) if isinstance(item, dict)]
    entry = _manifest_entry(package_manifest_path, lint_report)
    package_hash = entry.get("package_hash_sha256")
    packages = [item for item in packages if item.get("package_hash_sha256") != package_hash]
    packages.append(entry)
    payload: dict[str, object] = {
        "schema_version": _VAULT_SCHEMA_VERSION,
        "verdict": "registered",
        "passed": True,
        "registry": str(registry_path),
        "packages": sorted(packages, key=lambda item: str(item.get("package_hash_sha256", ""))),
    }
    _write_json(registry_path, {"schema_version": _VAULT_SCHEMA_VERSION, "packages": payload["packages"]})
    return payload


def verify_package(
    registry_path: Path,
    *,
    package_hash: str,
    firmware_sha256: str | None = None,
    pattern_id: str | None = None,
    chain_id: str | None = None,
) -> dict[str, object]:
    registry_path = registry_path.resolve()
    registry = _load_registry(registry_path)
    packages = [item for item in _as_list(registry.get("packages")) if isinstance(item, dict)]
    normalized_hash = package_hash.lower().strip()
    matched = [item for item in packages if str(item.get("package_hash_sha256", "")).lower() == normalized_hash]
    entry = matched[0] if matched else {}
    firmware_ok = True
    if firmware_sha256:
        firmware_ok = _is_hex64(firmware_sha256) and firmware_sha256.lower() in [
            str(item).lower() for item in _as_list(entry.get("supported_firmware_sha256"))
        ]
    pattern_ok = True if not pattern_id else entry.get("pattern_id") == pattern_id
    chain_ok = True if not chain_id else entry.get("scout_chain_id") == chain_id
    passed = bool(entry) and firmware_ok and pattern_ok and chain_ok
    return {
        "schema_version": _VAULT_SCHEMA_VERSION,
        "verdict": "pass" if passed else "fail",
        "passed": passed,
        "registry": str(registry_path),
        "package_hash_sha256": normalized_hash,
        "checks": [
            _check("package_hash_registered", bool(entry), "Package hash must be registered in the vault."),
            _check("firmware_allowed", firmware_ok, "Requested firmware SHA-256 must be allowed by the registry."),
            _check("pattern_allowed", pattern_ok, "Requested pattern id must match the registry entry."),
            _check("chain_allowed", chain_ok, "Requested chain id must match the registry entry."),
        ],
        "package": entry,
    }


def format_report(payload: dict[str, object]) -> str:
    lines = [f"SCOUT-W package/vault: {payload.get('verdict')}"]
    if payload.get("package_hash_sha256"):
        lines.append(f"package_hash_sha256: {payload.get('package_hash_sha256')}")
    for check in _as_list(payload.get("checks")):
        if isinstance(check, dict):
            status = "PASS" if check.get("passed") is True else "FAIL"
            lines.append(f"[{status}] {check.get('name')}: {check.get('message')}")
    lint = _as_dict(payload.get("lint"))
    if lint:
        lines.append(f"lint: {lint.get('verdict')}")
    return "\n".join(lines) + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lint and register private controlled weaponization package metadata.")
    sub = parser.add_subparsers(dest="command", required=True)

    lint = sub.add_parser("lint", help="Validate a private package manifest without loading exploit source.")
    lint.add_argument("--package-manifest", required=True, type=Path)
    lint.add_argument("--out", default=None, type=Path)

    register = sub.add_parser("register", help="Register a lint-passing package hash in a metadata-only vault registry.")
    register.add_argument("--registry", required=True, type=Path)
    register.add_argument("--package-manifest", required=True, type=Path)
    register.add_argument("--out", default=None, type=Path)

    verify = sub.add_parser("verify", help="Verify a package hash is registered for an optional firmware/pattern/chain scope.")
    verify.add_argument("--registry", required=True, type=Path)
    verify.add_argument("--package-hash", required=True)
    verify.add_argument("--firmware-sha256", default=None)
    verify.add_argument("--pattern-id", default=None)
    verify.add_argument("--chain-id", default=None)
    verify.add_argument("--out", default=None, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "lint":
        payload = lint_private_package_manifest(args.package_manifest)
        if args.out is not None:
            _write_json(args.out, payload)
        print(format_report(payload), end="")
        return 0 if payload.get("passed") is True else _EXIT_LINT_FAILED
    if args.command == "register":
        payload = register_package(args.registry, args.package_manifest)
        if args.out is not None:
            _write_json(args.out, payload)
        print(format_report(payload), end="")
        return 0 if payload.get("passed") is True else _EXIT_VAULT_FAILED
    if args.command == "verify":
        payload = verify_package(
            args.registry,
            package_hash=args.package_hash,
            firmware_sha256=args.firmware_sha256,
            pattern_id=args.pattern_id,
            chain_id=args.chain_id,
        )
        if args.out is not None:
            _write_json(args.out, payload)
        print(format_report(payload), end="")
        return 0 if payload.get("passed") is True else _EXIT_VAULT_FAILED
    return 20


if __name__ == "__main__":
    raise SystemExit(main())
