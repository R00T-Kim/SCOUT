from __future__ import annotations

import json
from pathlib import Path

from aiedge.__main__ import main as aiedge_main
from aiedge.weaponization_plan import build_weaponization_plan, evaluate_weaponization_preflight

_FIRMWARE_SHA = "a" * 64
_PACKAGE_SHA = "b" * 64


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _build_run(run_dir: Path, *, scope: str = "lab-only") -> None:
    _write_json(
        run_dir / "manifest.json",
        {
            "profile": "exploit",
            "analyzed_input_sha256": _FIRMWARE_SHA,
            "exploit_gate": {"flag": "lab", "attestation": "authorized", "scope": scope},
        },
    )
    _write_json(
        run_dir / "stages/findings/exploit_candidates.json",
        {
            "candidates": [
                {
                    "candidate_id": "candidate-001",
                    "chain_id": "chain-http-marker-read",
                    "families": ["info_disclosure"],
                    "pattern_id": "pattern-marker-read",
                    "preconditions": ["HTTP service reachable", "lab marker provisioned"],
                    "validation_plan": ["observe bounded marker readback"],
                    "target_service": "http",
                }
            ]
        },
    )
    _write_json(
        run_dir / "stages/exploit_autopoc/exploit_autopoc.json",
        {
            "status": "ok",
            "attempts": [
                {
                    "chain_id": "chain-http-marker-read",
                    "candidate_id": "candidate-001",
                    "runner_exit_code": 0,
                }
            ],
            "summary": {"runner_pass": 1},
        },
    )


def _package_manifest(path: Path, *, firmware_sha: str = _FIRMWARE_SHA) -> None:
    _write_json(
        path,
        {
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
                "supported_firmware_sha256": [firmware_sha],
            },
            "target_profile": {
                "firmware_sha256": firmware_sha,
                "architecture": "mips",
                "service": "http",
            },
            "preconditions": ["HTTP service reachable", "lab marker provisioned"],
            "capability": {
                "primitive": "arbitrary_read",
                "destructive": False,
                "persistence": False,
                "lateral_movement": False,
                "cleanup_required": True,
            },
            "cleanup": {
                "required": True,
                "strategy": "remove lab marker",
                "verification": "cleanup_log",
            },
        },
    )


def _failed_check_names(payload: dict[str, object]) -> set[str]:
    checks_any = payload.get("checks")
    checks = checks_any if isinstance(checks_any, list) else []
    return {str(check["name"]) for check in checks if isinstance(check, dict) and check.get("passed") is not True}


def test_weaponization_plan_builds_firmware_bound_plan_ir(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _build_run(run_dir)
    manifest_path = tmp_path / "package.json"
    _package_manifest(manifest_path)

    plan = build_weaponization_plan(run_dir, package_manifest_path=manifest_path)

    assert plan["schema_version"] == "scout-weaponization-plan-ir-v1"
    assert plan["promotion_target"] == "L6_CONTROLLED_WEAPONIZATION_PACKAGE"
    assert plan["firmware_sha256"] == _FIRMWARE_SHA
    binding = plan["binding"]
    assert isinstance(binding, dict)
    assert binding["scout_chain_id"] == "chain-http-marker-read"
    assert binding["pattern_id"] == "pattern-marker-read"
    assert isinstance(plan["plan_ir_sha256"], str)


def test_weaponization_preflight_passes_for_scoped_plan_and_package(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _build_run(run_dir)
    manifest_path = tmp_path / "package.json"
    plan_path = tmp_path / "plan.json"
    _package_manifest(manifest_path)
    _write_json(plan_path, build_weaponization_plan(run_dir, package_manifest_path=manifest_path))

    payload = evaluate_weaponization_preflight(run_dir, plan_path, package_manifest_path=manifest_path)

    assert payload["passed"] is True
    assert payload["decision"] == "RUN_PRIVATE_PACKAGE_ALLOWED"
    assert _failed_check_names(payload) == set()


def test_weaponization_preflight_blocks_public_scope(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _build_run(run_dir, scope="public-internet")
    manifest_path = tmp_path / "package.json"
    plan_path = tmp_path / "plan.json"
    _package_manifest(manifest_path)
    _write_json(plan_path, build_weaponization_plan(run_dir, package_manifest_path=manifest_path))

    payload = evaluate_weaponization_preflight(run_dir, plan_path, package_manifest_path=manifest_path)

    assert payload["passed"] is False
    assert payload["decision"] == "BLOCKED_SCOPE"
    assert "run_scope_authorized_bounded" in _failed_check_names(payload)


def test_weaponization_plan_and_preflight_cli_write_artifacts(tmp_path: Path, capsys) -> None:
    run_dir = tmp_path / "run"
    _build_run(run_dir)
    manifest_path = tmp_path / "package.json"
    plan_path = tmp_path / "weaponization-plan.json"
    preflight_path = tmp_path / "weaponization-preflight.json"
    _package_manifest(manifest_path)

    rc_plan = aiedge_main([
        "weaponization-plan",
        str(run_dir),
        "--package-manifest",
        str(manifest_path),
        "--out",
        str(plan_path),
    ])
    assert rc_plan == 0
    assert json.loads(plan_path.read_text(encoding="utf-8"))["schema_version"] == "scout-weaponization-plan-ir-v1"

    rc_preflight = aiedge_main([
        "weaponization-preflight",
        str(run_dir),
        "--plan",
        str(plan_path),
        "--package-manifest",
        str(manifest_path),
        "--out",
        str(preflight_path),
    ])
    assert rc_preflight == 0
    assert json.loads(preflight_path.read_text(encoding="utf-8"))["passed"] is True
    assert "RUN_PRIVATE_PACKAGE_ALLOWED" in capsys.readouterr().out
