from __future__ import annotations

import json
from pathlib import Path

from aiedge.__main__ import main as aiedge_main
from aiedge.aeg_e2e_gate import evaluate_aeg_e2e_gate
from aiedge.aeg_e2e_gate import main as gate_main


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _build_passing_run(run_dir: Path) -> None:
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
        {"schema_version": "verified-chain-v1", "verdict": {"state": "pass", "reason_codes": ["isolation_verified", "repro_3_of_3"]}},
    )
    _write_json(run_dir / "quality_metrics.json", {"overall": {"fpr": 0.02}})
    _write_json(
        run_dir / "stages/fp_verification/verified_alerts.json",
        {"status": "ok", "verified_alerts": [{"severity": "high", "fp_verdict": "TP"}]},
    )


def test_aeg_e2e_gate_passes_only_with_dynamic_proof_and_fp_evidence(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _build_passing_run(run_dir)

    payload = evaluate_aeg_e2e_gate(run_dir)

    assert payload["passed"] is True
    assert payload["verdict"] == "pass"
    assert {check["name"] for check in payload["checks"]} == {
        "autopoc_runner_pass",
        "poc_validation_reproducible",
        "verified_chain_pass",
        "quality_fpr_ceiling",
        "no_high_severity_fp_verified",
    }


def test_aeg_e2e_gate_fails_closed_without_reproducible_poc_validation(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _build_passing_run(run_dir)
    _write_json(
        run_dir / "stages/poc_validation/poc_validation.json",
        {"status": "failed", "checks": [], "verification_reason_codes": ["poc_repro_failed"]},
    )

    payload = evaluate_aeg_e2e_gate(run_dir)

    assert payload["passed"] is False
    failed = {check["name"] for check in payload["checks"] if not check["passed"]}
    assert failed == {"poc_validation_reproducible"}


def test_aeg_e2e_gate_fails_on_high_severity_fp(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _build_passing_run(run_dir)
    _write_json(
        run_dir / "stages/fp_verification/verified_alerts.json",
        {"status": "ok", "verified_alerts": [{"severity": "critical", "fp_verdict": "FP"}]},
    )

    payload = evaluate_aeg_e2e_gate(run_dir)

    assert payload["passed"] is False
    failed = {check["name"] for check in payload["checks"] if not check["passed"]}
    assert failed == {"no_high_severity_fp_verified"}


def test_aeg_e2e_gate_cli_writes_payload_and_returns_failure(tmp_path: Path, capsys) -> None:
    out = tmp_path / "gate.json"

    rc = gate_main([str(tmp_path / "missing-run"), "--out", str(out)])

    assert rc == 31
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["passed"] is False
    assert json.loads(capsys.readouterr().out)["schema_version"] == "aeg-e2e-gate-v1"


def test_aeg_e2e_gate_product_cli_writes_payload(tmp_path: Path, capsys) -> None:
    run_dir = tmp_path / "run"
    _build_passing_run(run_dir)
    out = tmp_path / "cli-gate.json"

    rc = aiedge_main(["aeg-e2e-gate", str(run_dir), "--out", str(out)])

    assert rc == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert json.loads(capsys.readouterr().out)["verdict"] == "pass"
