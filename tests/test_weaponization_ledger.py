from __future__ import annotations

import json
from pathlib import Path

from aiedge.__main__ import main as aiedge_main
from aiedge.controlled_weaponization import evaluate_controlled_weaponization_readiness
from aiedge.weaponization_ledger import build_weaponization_ledger
from aiedge.weaponization_plan import build_weaponization_plan, evaluate_weaponization_preflight

_FIRMWARE_SHA = "a" * 64
_PACKAGE_SHA = "b" * 64
_PLAN_SHA = "c" * 64


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _build_run(run_dir: Path) -> None:
    _write_json(
        run_dir / "manifest.json",
        {
            "profile": "exploit",
            "analyzed_input_sha256": _FIRMWARE_SHA,
            "exploit_gate": {"flag": "lab", "attestation": "authorized", "scope": "lab-only"},
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
            "attempts": [{"chain_id": "chain-http-marker-read", "candidate_id": "candidate-001", "runner_exit_code": 0}],
            "summary": {"runner_pass": 1},
        },
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
    _write_json(
        run_dir / "stages/dynamic_validation/network/interfaces.json",
        {"interfaces": [{"ifname": "target", "ipv4": ["198.51.100.10"]}]},
    )
    _write_json(
        run_dir / "stages/dynamic_validation/network/ports.json",
        {"open_ports": [8080], "target_ip": "198.51.100.10"},
    )


def _package_manifest(path: Path) -> None:
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
                "destructive": False,
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
            "promotion": {"control_pair_validated": True},
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
        },
    )


def _evidence_bundle(path: Path, *, passed: int = 3, attempted: int = 3, cleanup_error: str = "") -> None:
    attempts = [
        {"attempt": idx, "status": "pass" if idx <= passed else "fail", "proof_type": "arbitrary_read"}
        for idx in range(1, attempted + 1)
    ]
    _write_json(
        path,
        {
            "schema_version": "exploit-evidence-v1",
            "chain_id": "chain-http-marker-read",
            "reproducibility": {
                "attempted": attempted,
                "passed": passed,
                "requested": attempted,
                "status": "pass" if passed == attempted else "fail",
            },
            "attempts": attempts,
            "artifacts": {"poc_sha256": "exploits/chain_chain-http-marker-read/poc_sha256.txt"},
            "policy": {"private_plugin_path_recorded": False, "source_copied_to_run_dir": False},
            "runtime": {"cleanup_error": cleanup_error},
        },
    )


def _approval(path: Path) -> None:
    _write_json(
        path,
        {
            "schema_version": "scout-engagement-approval-v1",
            "approved": True,
            "engagement_id": "eng-2026-05-lab",
            "approver": "internal-red-team-lead",
            "package_hash_sha256": _PACKAGE_SHA,
            "scope": {"allowed_targets": ["lab-device-01"], "expires_at": "2027-01-01T00:00:00Z"},
        },
    )


def _private_plugin(exploit_dir: Path) -> None:
    exploit_dir.mkdir(parents=True, exist_ok=True)
    (exploit_dir / "marker_read.py").write_text(
        "\n".join(
            [
                "from __future__ import annotations",
                "from poc_skeletons.interface import PoCResult",
                "",
                "class PoC:",
                "    chain_id = 'chain-http-marker-read'",
                "    target_service = 'http'",
                "    def setup(self, target_ip: str, target_port: int, *, context: dict[str, object]) -> None:",
                "        self.target_ip = target_ip",
                "        self.target_port = target_port",
                "    def execute(self) -> PoCResult:",
                "        return PoCResult(success=True, proof_type='arbitrary_read', proof_evidence='readback_hash=" + ("f" * 64) + " marker=bounded', timestamp='2026-05-27T00:00:00Z')",
                "    def cleanup(self) -> None:",
                "        return",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _build_l6_artifacts(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path, Path, Path]:
    run_dir = tmp_path / "run"
    package_path = tmp_path / "package.json"
    plan_path = tmp_path / "weaponization_plan.json"
    preflight_path = tmp_path / "weaponization_preflight.json"
    readiness_path = tmp_path / "controlled_weaponization_readiness.json"
    evidence_path = run_dir / "exploits/chain_chain-http-marker-read/evidence_bundle.json"
    cleanup_log = tmp_path / "cleanup.log"
    _build_run(run_dir)
    _package_manifest(package_path)
    _write_json(plan_path, build_weaponization_plan(run_dir, package_manifest_path=package_path))
    _write_json(preflight_path, evaluate_weaponization_preflight(run_dir, plan_path, package_manifest_path=package_path))
    _write_json(readiness_path, evaluate_controlled_weaponization_readiness(run_dir, package_path))
    _evidence_bundle(evidence_path)
    cleanup_log.write_text("cleanup verified\n", encoding="utf-8")
    return run_dir, package_path, plan_path, preflight_path, readiness_path, evidence_path, cleanup_log


def test_weaponization_ledger_promotes_l7_with_approval(tmp_path: Path) -> None:
    run_dir, _, plan_path, preflight_path, readiness_path, evidence_path, cleanup_log = _build_l6_artifacts(tmp_path)
    approval_path = tmp_path / "approval.json"
    _approval(approval_path)

    payload = build_weaponization_ledger(
        run_dir,
        plan_path=plan_path,
        preflight_path=preflight_path,
        readiness_path=readiness_path,
        execution_evidence_paths=[evidence_path],
        cleanup_log_path=cleanup_log,
        approval_path=approval_path,
    )

    assert payload["passed"] is True
    assert payload["promotion_level"] == "L7_ENGAGEMENT_APPROVED_PACKAGE"
    assert payload["ledger_sha256"]


def test_weaponization_ledger_passes_l6_without_engagement_approval(tmp_path: Path) -> None:
    run_dir, _, plan_path, preflight_path, readiness_path, evidence_path, cleanup_log = _build_l6_artifacts(tmp_path)

    payload = build_weaponization_ledger(
        run_dir,
        plan_path=plan_path,
        preflight_path=preflight_path,
        readiness_path=readiness_path,
        execution_evidence_paths=[evidence_path],
        cleanup_log_path=cleanup_log,
    )

    assert payload["passed"] is True
    assert payload["promotion_level"] == "L6_EXECUTION_LEDGER_READY"


def test_weaponization_ledger_blocks_when_reliability_does_not_meet_plan(tmp_path: Path) -> None:
    run_dir, _, plan_path, preflight_path, readiness_path, evidence_path, cleanup_log = _build_l6_artifacts(tmp_path)
    _evidence_bundle(evidence_path, passed=1, attempted=3)

    payload = build_weaponization_ledger(
        run_dir,
        plan_path=plan_path,
        preflight_path=preflight_path,
        readiness_path=readiness_path,
        execution_evidence_paths=[evidence_path],
        cleanup_log_path=cleanup_log,
    )

    assert payload["passed"] is False
    assert payload["verdict"] == "blocked"
    checks = payload["checks"]
    assert isinstance(checks, list)
    failed = {str(check["name"]) for check in checks if isinstance(check, dict) and check.get("passed") is not True}
    assert "reliability_repro_met" in failed


def test_weaponization_ledger_cli_writes_artifact(tmp_path: Path, capsys) -> None:
    run_dir, _, plan_path, preflight_path, readiness_path, evidence_path, cleanup_log = _build_l6_artifacts(tmp_path)
    approval_path = tmp_path / "approval.json"
    ledger_path = tmp_path / "weaponization_ledger.json"
    _approval(approval_path)

    rc = aiedge_main(
        [
            "weaponization-ledger",
            str(run_dir),
            "--plan",
            str(plan_path),
            "--preflight",
            str(preflight_path),
            "--readiness",
            str(readiness_path),
            "--execution-evidence",
            str(evidence_path),
            "--cleanup-log",
            str(cleanup_log),
            "--approval",
            str(approval_path),
            "--out",
            str(ledger_path),
        ]
    )

    assert rc == 0
    payload = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert payload["promotion_level"] == "L7_ENGAGEMENT_APPROVED_PACKAGE"
    assert "engagement-approved" in capsys.readouterr().out


def test_weaponization_execute_gates_private_runner_and_writes_ledger(tmp_path: Path, capsys) -> None:
    run_dir, package_path, plan_path, preflight_path, readiness_path, _, cleanup_log = _build_l6_artifacts(tmp_path)
    exploit_dir = tmp_path / "private_exploits"
    ledger_path = tmp_path / "execute_ledger.json"
    vault_path = tmp_path / "vault.json"
    _private_plugin(exploit_dir)
    assert aiedge_main(
        [
            "weaponization-package",
            "register",
            "--registry",
            str(vault_path),
            "--package-manifest",
            str(package_path),
        ]
    ) == 0

    rc = aiedge_main(
        [
            "weaponization-execute",
            str(run_dir),
            "--exploit-dir",
            str(exploit_dir),
            "--plan",
            str(plan_path),
            "--preflight",
            str(preflight_path),
            "--readiness",
            str(readiness_path),
            "--cleanup-log",
            str(cleanup_log),
            "--vault-registry",
            str(vault_path),
            "--out-ledger",
            str(ledger_path),
        ]
    )

    assert rc == 0
    payload = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert payload["promotion_level"] == "L6_EXECUTION_LEDGER_READY"
    assert "exploit evidence captured" in capsys.readouterr().out
