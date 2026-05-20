from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import cast


def _load_script() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts" / "check_real_firmware_pair_aeg.py"
    spec = importlib.util.spec_from_file_location("check_real_firmware_pair_aeg", path)
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


def _pair_manifest(tmp_path: Path) -> Path:
    vuln = tmp_path / "fw" / "vuln.bin"
    patched = tmp_path / "fw" / "patched.bin"
    vuln.parent.mkdir(parents=True, exist_ok=True)
    vuln.write_bytes(b"known-vulnerable")
    patched.write_bytes(b"patched-control")
    import hashlib

    manifest = tmp_path / "pairs.json"
    _write_json(
        manifest,
        {
            "schema_version": "pair-eval-v1",
            "pairs": [
                {
                    "pair_id": "vendor-model-cve-0000-0001",
                    "vendor": "vendor",
                    "model": "model",
                    "cve_id": "CVE-0000-0001",
                    "vulnerable": {
                        "firmware_path": str(vuln),
                        "sha256": hashlib.sha256(b"known-vulnerable").hexdigest(),
                    },
                    "patched": {
                        "firmware_path": str(patched),
                        "sha256": hashlib.sha256(b"patched-control").hexdigest(),
                    },
                }
            ],
        },
    )
    return manifest


def test_real_firmware_pair_gate_promotable_when_vuln_passes_and_control_fails_closed(
    tmp_path: Path, capsys
) -> None:
    module = _load_script()
    manifest = _pair_manifest(tmp_path)
    vulnerable = tmp_path / "runs" / "vulnerable"
    control = tmp_path / "runs" / "control"
    _build_passing_run(vulnerable)
    _build_control_run(control)
    out = tmp_path / "pair-gate.json"

    rc = module.main(
        [
            "--pairs",
            str(manifest),
            "--pair-id",
            "vendor-model-cve-0000-0001",
            "--vulnerable-run-dir",
            str(vulnerable),
            "--control-run-dir",
            str(control),
            "--pattern-id",
            "cgi_param_cmd_injection",
            "--out",
            str(out),
        ]
    )

    assert rc == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["verdict"] == "promotable"
    assert payload["promotable_real_firmware_pair"] is True
    assert payload["blocked_reasons"] == []
    assert "record_pattern_pair_evidence.py" in payload["record_command"]
    assert json.loads(capsys.readouterr().out)["schema_version"] == "real-firmware-pair-aeg-gate-v1"


def test_real_firmware_pair_gate_blocks_missing_control_artifacts(tmp_path: Path) -> None:
    module = _load_script()
    manifest = _pair_manifest(tmp_path)
    vulnerable = tmp_path / "runs" / "vulnerable"
    control = tmp_path / "runs" / "control"
    _build_passing_run(vulnerable)
    _build_control_run(control)
    (control / "verified_chain" / "verified_chain.json").unlink()
    out = tmp_path / "pair-gate.json"

    rc = module.main(
        [
            "--pairs",
            str(manifest),
            "--pair-id",
            "vendor-model-cve-0000-0001",
            "--vulnerable-run-dir",
            str(vulnerable),
            "--control-run-dir",
            str(control),
            "--out",
            str(out),
        ]
    )

    assert rc == 32
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["verdict"] == "blocked"
    assert "patched_gate_artifacts_missing" in payload["blocked_reasons"]
    assert payload["promotable_real_firmware_pair"] is False


def test_real_firmware_pair_gate_discovers_last_run_index(tmp_path: Path) -> None:
    module = _load_script()
    manifest = _pair_manifest(tmp_path)
    vulnerable = tmp_path / "runs" / "vulnerable"
    control = tmp_path / "runs" / "control"
    _build_passing_run(vulnerable)
    _build_control_run(control)
    results = tmp_path / "results"
    _write_json(
        results / "runs/vendor-model-cve-0000-0001/vulnerable/last_run.json",
        {"run_dir": str(vulnerable)},
    )
    _write_json(
        results / "runs/vendor-model-cve-0000-0001/patched/last_run.json",
        {"run_dir": str(control)},
    )

    rc = module.main(
        [
            "--pairs",
            str(manifest),
            "--pair-id",
            "vendor-model-cve-0000-0001",
            "--results-dir",
            str(results),
        ]
    )

    assert rc == 0
