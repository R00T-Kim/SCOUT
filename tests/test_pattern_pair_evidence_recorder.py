from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest

from aiedge.exploit_rag import (
    PairEvidenceError,
    build_pair_evidence,
    evaluate_pattern_evidence,
    record_pair_evidence,
)


def _load_record_script() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts" / "record_pattern_pair_evidence.py"
    spec = importlib.util.spec_from_file_location("record_pattern_pair_evidence", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return cast(ModuleType, module)


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
        {
            "schema_version": "verified-chain-v1",
            "verdict": {"state": "pass", "reason_codes": ["isolation_verified", "repro_3_of_3"]},
        },
    )
    _write_json(run_dir / "quality_metrics.json", {"overall": {"fpr": 0.01}})
    _write_json(
        run_dir / "stages/fp_verification/verified_alerts.json",
        {"status": "ok", "verified_alerts": [{"severity": "high", "fp_verdict": "TP"}]},
    )


def _build_control_run(run_dir: Path) -> None:
    _build_passing_run(run_dir)
    _write_json(
        run_dir / "stages/exploit_autopoc/exploit_autopoc.json",
        {"status": "ok", "summary": {"runner_pass": 0}},
    )
    _write_json(
        run_dir / "stages/poc_validation/poc_validation.json",
        {"status": "failed", "checks": [], "verification_reason_codes": ["poc_repro_failed"]},
    )
    _write_json(
        run_dir / "verified_chain/verified_chain.json",
        {
            "schema_version": "verified-chain-v1",
            "verdict": {"state": "fail", "reason_codes": ["no_dynamic_trigger"]},
        },
    )


def _copy_pattern_tree(tmp_path: Path) -> Path:
    source = Path(__file__).resolve().parents[1] / "data" / "exploit_references" / "patterns"
    dest = tmp_path / "patterns"
    shutil.copytree(source, dest)
    return dest


def test_record_real_firmware_pair_evidence_updates_card_and_gate_report(tmp_path: Path) -> None:
    patterns_dir = _copy_pattern_tree(tmp_path)
    vulnerable = tmp_path / "runs" / "known-vulnerable"
    control = tmp_path / "runs" / "patched-control"
    _build_passing_run(vulnerable)
    _build_control_run(control)

    evidence = build_pair_evidence(
        "cgi_param_cmd_injection",
        kind="real_firmware_pair",
        vulnerable_run_dir=vulnerable,
        control_run_dir=control,
        evidence_id="totolink_cmdinj_real_pair",
        vulnerable_firmware_sha256="a" * 64,
        control_firmware_sha256="b" * 64,
        cve="CVE-2024-1781",
        target_family="totolink-cgi-command-injection",
        artifact="docs/pov/totolink_cmdinj_real_pair.json",
        notes="Authorized lab pair with vulnerable firmware and patched/control firmware.",
    )

    assert evidence["status"] == "pass"
    assert evidence["kind"] == "real_firmware_pair"
    assert cast(dict[str, object], evidence["vulnerable_gate"])["passed"] is True
    assert cast(dict[str, object], evidence["control_gate"])["passed"] is False

    updated = record_pair_evidence("cgi_param_cmd_injection", evidence, patterns_dir=patterns_dir)
    assert updated == patterns_dir / "cgi_param_cmd_injection" / "exploit.json"

    report = evaluate_pattern_evidence(patterns_dir)
    payload = report.to_json()
    assert payload["real_firmware_pair_validated"] == 2
    assert "cgi_param_cmd_injection" not in cast(list[str], payload["missing_pair_evidence"])




def test_real_firmware_pair_requires_stable_firmware_metadata(tmp_path: Path) -> None:
    vulnerable = tmp_path / "runs" / "known-vulnerable"
    control = tmp_path / "runs" / "patched-control"
    _build_passing_run(vulnerable)
    _build_control_run(control)

    with pytest.raises(PairEvidenceError, match="stable firmware metadata"):
        build_pair_evidence(
            "cgi_param_cmd_injection",
            kind="real_firmware_pair",
            vulnerable_run_dir=vulnerable,
            control_run_dir=control,
        )


def test_synthetic_pair_does_not_require_real_firmware_metadata(tmp_path: Path) -> None:
    vulnerable = tmp_path / "runs" / "synthetic-vulnerable"
    control = tmp_path / "runs" / "synthetic-control"
    _build_passing_run(vulnerable)
    _build_control_run(control)

    evidence = build_pair_evidence(
        "cgi_param_cmd_injection",
        kind="synthetic_pair",
        vulnerable_run_dir=vulnerable,
        control_run_dir=control,
    )

    assert evidence["kind"] == "synthetic_pair"
    assert "vulnerable_firmware_sha256" not in evidence


def test_pair_evidence_rejects_missing_control_artifacts(tmp_path: Path) -> None:
    vulnerable = tmp_path / "runs" / "known-vulnerable"
    control = tmp_path / "runs" / "missing-control"
    _build_passing_run(vulnerable)
    _build_passing_run(control)
    (control / "stages/poc_validation/poc_validation.json").unlink()

    with pytest.raises(PairEvidenceError, match="control run is missing gate artifacts"):
        build_pair_evidence(
            "cgi_param_cmd_injection",
            kind="real_firmware_pair",
            vulnerable_run_dir=vulnerable,
            control_run_dir=control,
            artifact="docs/pov/test-real-pair.json",
            vulnerable_firmware_sha256="a" * 64,
            control_firmware_sha256="b" * 64,
            cve="CVE-2024-1781",
        )


def test_pair_evidence_rejects_control_that_only_fails_fpr(tmp_path: Path) -> None:
    vulnerable = tmp_path / "runs" / "known-vulnerable"
    control = tmp_path / "runs" / "bad-control"
    _build_passing_run(vulnerable)
    _build_passing_run(control)
    _write_json(control / "quality_metrics.json", {"overall": {"fpr": 0.99}})

    with pytest.raises(PairEvidenceError, match="failed only non-dynamic"):
        build_pair_evidence(
            "cgi_param_cmd_injection",
            kind="real_firmware_pair",
            vulnerable_run_dir=vulnerable,
            control_run_dir=control,
            artifact="docs/pov/test-real-pair.json",
            vulnerable_firmware_sha256="a" * 64,
            control_firmware_sha256="b" * 64,
            cve="CVE-2024-1781",
        )


def test_record_pattern_pair_evidence_cli_dry_run_and_apply(tmp_path: Path, capsys) -> None:
    module = _load_record_script()
    patterns_dir = _copy_pattern_tree(tmp_path)
    vulnerable = tmp_path / "runs" / "known-vulnerable"
    control = tmp_path / "runs" / "patched-control"
    _build_passing_run(vulnerable)
    _build_control_run(control)

    rc = module.main(
        [
            "config_derived_cmd_injection",
            "--kind",
            "real_firmware_pair",
            "--vulnerable-run-dir",
            str(vulnerable),
            "--control-run-dir",
            str(control),
            "--patterns-dir",
            str(patterns_dir),
            "--evidence-id",
            "config_real_pair",
            "--artifact",
            "docs/pov/config_real_pair.json",
            "--vulnerable-firmware-sha256",
            "a" * 64,
            "--control-firmware-sha256",
            "b" * 64,
            "--cve",
            "CVE-2024-1781",
        ]
    )
    assert rc == 0
    dry_payload = json.loads(capsys.readouterr().out)
    assert "updated_card" not in dry_payload

    rc = module.main(
        [
            "config_derived_cmd_injection",
            "--kind",
            "real_firmware_pair",
            "--vulnerable-run-dir",
            str(vulnerable),
            "--control-run-dir",
            str(control),
            "--patterns-dir",
            str(patterns_dir),
            "--evidence-id",
            "config_real_pair",
            "--artifact",
            "docs/pov/config_real_pair.json",
            "--vulnerable-firmware-sha256",
            "a" * 64,
            "--control-firmware-sha256",
            "b" * 64,
            "--cve",
            "CVE-2024-1781",
            "--apply",
        ]
    )
    assert rc == 0
    applied_payload = json.loads(capsys.readouterr().out)
    assert applied_payload["updated_card"].endswith("config_derived_cmd_injection/exploit.json")
