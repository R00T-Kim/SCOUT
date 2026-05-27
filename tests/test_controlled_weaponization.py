from __future__ import annotations

import json
from pathlib import Path

from aiedge.__main__ import main as aiedge_main
from aiedge.controlled_weaponization import evaluate_controlled_weaponization_readiness

_FIRMWARE_SHA = "a" * 64
_PACKAGE_SHA = "b" * 64
_PLAN_SHA = "c" * 64


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _build_passing_run(run_dir: Path) -> None:
    _write_json(
        run_dir / "manifest.json",
        {
            "profile": "exploit",
            "analyzed_input_sha256": _FIRMWARE_SHA,
            "exploit_gate": {"flag": "lab", "attestation": "authorized", "scope": "lab-only"},
        },
    )
    _write_json(
        run_dir / "stages/exploit_autopoc/exploit_autopoc.json",
        {"status": "ok", "summary": {"runner_pass": 1}},
    )
    _write_json(
        run_dir / "stages/poc_validation/poc_validation.json",
        {"status": "ok", "checks": [], "verification_reason_codes": ["repro_3_of_3"]},
    )
    _write_json(
        run_dir / "verified_chain/verified_chain.json",
        {
            "schema_version": "verified-chain-v1",
            "verdict": {"state": "pass", "reason_codes": ["isolation_verified", "repro_3_of_3"]},
        },
    )
    _write_json(run_dir / "quality_metrics.json", {"overall": {"fpr": 0.0}})
    _write_json(
        run_dir / "stages/fp_verification/verified_alerts.json",
        {"status": "ok", "verified_alerts": [{"severity": "high", "fp_verdict": "TP"}]},
    )


def _manifest_payload(*, firmware_sha: str = _FIRMWARE_SHA, destructive: bool = False) -> dict[str, object]:
    return {
        "schema_version": "scout-private-exploit-package-v1",
        "package": {
            "id": "internal-r7000-marker-read",
            "version": "1.0.0",
            "classification": "controlled-authorized-exploit",
            "hash_sha256": _PACKAGE_SHA,
        },
        "binding": {
            "scout_chain_id": "chain-r7000-001",
            "pattern_id": "pattern-auth-bypass-marker-read",
            "supported_firmware_sha256": [firmware_sha],
            "supported_arch": ["mips"],
        },
        "target_profile": {
            "firmware_sha256": firmware_sha,
            "architecture": "mips",
            "service": "http",
        },
        "preconditions": ["service reachable", "lab marker file provisioned"],
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
            "strategy": "remove lab marker and restore transient config",
            "verification": "cleanup_log",
        },
        "promotion": {"control_pair_validated": True},
        "evidence": {
            "required": ["target_profile", "verifier_log", "cleanup_log", "plan_ir_hash", "package_hash"],
            "artifacts": {
                "target_profile": "sha256:" + firmware_sha,
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


def test_controlled_weaponization_readiness_promotes_l6_for_scoped_private_package(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _build_passing_run(run_dir)
    manifest_path = tmp_path / "package.json"
    _write_json(manifest_path, _manifest_payload())

    payload = evaluate_controlled_weaponization_readiness(run_dir, manifest_path)

    assert payload["ready"] is True
    assert payload["verdict"] == "weaponization-ready"
    assert payload["promotion_level"] == "L6_CONTROLLED_WEAPONIZATION_PACKAGE"
    assert _failed_check_names(payload) == set()


def test_controlled_weaponization_readiness_fails_on_firmware_binding_mismatch(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _build_passing_run(run_dir)
    manifest_path = tmp_path / "package.json"
    _write_json(manifest_path, _manifest_payload(firmware_sha="f" * 64))

    payload = evaluate_controlled_weaponization_readiness(run_dir, manifest_path)

    assert payload["ready"] is False
    failed = _failed_check_names(payload)
    assert "firmware_binding_matches" in failed


def test_controlled_weaponization_readiness_fails_on_destructive_capability(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _build_passing_run(run_dir)
    manifest_path = tmp_path / "package.json"
    _write_json(manifest_path, _manifest_payload(destructive=True))

    payload = evaluate_controlled_weaponization_readiness(run_dir, manifest_path)

    assert payload["ready"] is False
    failed = _failed_check_names(payload)
    assert failed == {"no_destructive_or_persistent_capability"}


def test_weaponization_readiness_cli_writes_report(tmp_path: Path, capsys) -> None:
    run_dir = tmp_path / "run"
    _build_passing_run(run_dir)
    manifest_path = tmp_path / "package.json"
    out = tmp_path / "weaponization.json"
    _write_json(manifest_path, _manifest_payload())

    rc = aiedge_main([
        "weaponization-readiness",
        str(run_dir),
        "--package-manifest",
        str(manifest_path),
        "--out",
        str(out),
    ])

    assert rc == 0
    assert json.loads(out.read_text(encoding="utf-8"))["ready"] is True
    assert "weaponization-ready" in capsys.readouterr().out
