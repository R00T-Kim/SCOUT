from __future__ import annotations

import json
from pathlib import Path

from aiedge.__main__ import main as aiedge_main
from aiedge.weaponization_package import lint_private_package_manifest, register_package, verify_package

_FIRMWARE_SHA = "a" * 64
_PACKAGE_SHA = "b" * 64
_PLAN_SHA = "c" * 64


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _manifest_payload(*, destructive: bool = False) -> dict[str, object]:
    return {
        "schema_version": "scout-private-exploit-package-v1",
        "package": {
            "id": "pkg-marker-read",
            "version": "1.0.0",
            "classification": "controlled-authorized-exploit",
            "hash_sha256": _PACKAGE_SHA,
        },
        "binding": {
            "scout_chain_id": "chain-http-marker-read",
            "pattern_id": "pattern-marker-read",
            "supported_firmware_sha256": [_FIRMWARE_SHA],
        },
        "target_profile": {
            "firmware_sha256": _FIRMWARE_SHA,
            "architecture": "mips",
            "service": "http",
        },
        "preconditions": ["HTTP service reachable", "lab marker provisioned"],
        "capability": {
            "primitive": "arbitrary_read",
            "destructive": destructive,
            "persistence": False,
            "lateral_movement": False,
            "cleanup_required": True,
        },
        "execution_policy": {
            "require_scope_token": True,
            "require_authorized_attestation": True,
            "require_target_profile_match": True,
            "require_control_pair_for_promotion": True,
            "deny_unknown_targets": True,
        },
        "cleanup": {
            "required": True,
            "strategy": "remove lab marker",
            "verification": "cleanup_log",
        },
        "evidence": {
            "required": ["target_profile", "verifier_log", "cleanup_log", "plan_ir_hash", "package_hash"],
            "artifacts": {
                "target_profile": "sha256:" + _FIRMWARE_SHA,
                "verifier_log": "sha256:" + "d" * 64,
                "cleanup_log": "sha256:" + "e" * 64,
                "plan_ir_hash": "sha256:" + _PLAN_SHA,
                "package_hash": "sha256:" + _PACKAGE_SHA,
            },
        },
    }


def _failed_check_names(payload: dict[str, object]) -> set[str]:
    checks_any = payload.get("checks")
    checks = checks_any if isinstance(checks_any, list) else []
    return {str(check["name"]) for check in checks if isinstance(check, dict) and check.get("passed") is not True}


def test_private_package_lint_passes_for_controlled_manifest(tmp_path: Path) -> None:
    manifest_path = tmp_path / "package.json"
    _write_json(manifest_path, _manifest_payload())

    payload = lint_private_package_manifest(manifest_path)

    assert payload["passed"] is True
    assert payload["package_hash_sha256"] == _PACKAGE_SHA
    assert _failed_check_names(payload) == set()


def test_private_package_lint_fails_destructive_capability(tmp_path: Path) -> None:
    manifest_path = tmp_path / "package.json"
    _write_json(manifest_path, _manifest_payload(destructive=True))

    payload = lint_private_package_manifest(manifest_path)

    assert payload["passed"] is False
    assert "safe_capability_declared" in _failed_check_names(payload)


def test_package_vault_registers_and_verifies_scope(tmp_path: Path) -> None:
    manifest_path = tmp_path / "package.json"
    registry_path = tmp_path / "vault.json"
    _write_json(manifest_path, _manifest_payload())

    registered = register_package(registry_path, manifest_path)
    verified = verify_package(
        registry_path,
        package_hash=_PACKAGE_SHA,
        firmware_sha256=_FIRMWARE_SHA,
        pattern_id="pattern-marker-read",
        chain_id="chain-http-marker-read",
    )
    denied = verify_package(registry_path, package_hash=_PACKAGE_SHA, firmware_sha256="f" * 64)

    assert registered["passed"] is True
    assert registry_path.is_file()
    assert verified["passed"] is True
    assert denied["passed"] is False


def test_weaponization_package_cli_lint_register_verify(tmp_path: Path, capsys) -> None:
    manifest_path = tmp_path / "package.json"
    registry_path = tmp_path / "vault.json"
    lint_path = tmp_path / "lint.json"
    _write_json(manifest_path, _manifest_payload())

    rc_lint = aiedge_main([
        "weaponization-package",
        "lint",
        "--package-manifest",
        str(manifest_path),
        "--out",
        str(lint_path),
    ])
    rc_register = aiedge_main([
        "weaponization-package",
        "register",
        "--registry",
        str(registry_path),
        "--package-manifest",
        str(manifest_path),
    ])
    rc_verify = aiedge_main([
        "weaponization-package",
        "verify",
        "--registry",
        str(registry_path),
        "--package-hash",
        _PACKAGE_SHA,
        "--firmware-sha256",
        _FIRMWARE_SHA,
        "--pattern-id",
        "pattern-marker-read",
        "--chain-id",
        "chain-http-marker-read",
    ])

    assert rc_lint == 0
    assert rc_register == 0
    assert rc_verify == 0
    assert json.loads(lint_path.read_text(encoding="utf-8"))["passed"] is True
    assert "SCOUT-W package/vault" in capsys.readouterr().out
