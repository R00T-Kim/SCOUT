from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any, cast

from aiedge.__main__ import main as aiedge_main


def _load_script() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_real_firmware_pair_aeg.py"
    spec = importlib.util.spec_from_file_location("run_real_firmware_pair_aeg", path)
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
            "verdict": {
                "state": "pass",
                "reason_codes": ["isolation_verified", "repro_3_of_3"],
            },
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


def test_runner_reuses_existing_runs_and_emits_promotable_pair_report(
    tmp_path: Path, capsys: Any
) -> None:
    module = _load_script()
    manifest = _pair_manifest(tmp_path)
    vulnerable = tmp_path / "runs" / "vulnerable"
    control = tmp_path / "runs" / "control"
    _build_passing_run(vulnerable)
    _build_control_run(control)
    out = tmp_path / "report.json"

    rc = module.main(
        [
            "--pairs",
            str(manifest),
            "--pair-id",
            "vendor-model-cve-0000-0001",
            "--results-dir",
            str(tmp_path / "results"),
            "--vulnerable-run-dir",
            str(vulnerable),
            "--control-run-dir",
            str(control),
            "--pattern-id",
            "cgi_param_cmd_injection",
            "--skip-post-stages",
            "--skip-verified-chain",
            "--out",
            str(out),
        ]
    )

    assert rc == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "real-firmware-pair-aeg-run-v1"
    assert payload["promotable_real_firmware_pair"] is True
    assert payload["pair_gate"]["verdict"] == "promotable"
    assert {row["status"] for row in payload["analysis"]} == {"reused"}
    assert json.loads(capsys.readouterr().out)["verdict"] == "promotable"


def test_runner_dry_run_writes_commands_and_blocks_without_run_dirs(tmp_path: Path) -> None:
    module = _load_script()
    manifest = _pair_manifest(tmp_path)
    out = tmp_path / "report.json"

    rc = module.main(
        [
            "--pairs",
            str(manifest),
            "--pair-id",
            "vendor-model-cve-0000-0001",
            "--results-dir",
            str(tmp_path / "results"),
            "--dry-run",
            "--no-llm",
            "--out",
            str(out),
        ]
    )

    assert rc == 32
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["verdict"] == "blocked"
    assert [row["status"] for row in payload["analysis"]] == ["dry_run", "dry_run"]
    assert all("--no-llm" in row["cmd"] for row in payload["analysis"])
    assert "vulnerable_gate_artifacts_missing" in payload["pair_gate"]["blocked_reasons"]


def test_runner_executes_scout_for_missing_sides_and_discovers_run_dirs(
    tmp_path: Path, monkeypatch
) -> None:
    module = _load_script()
    manifest = _pair_manifest(tmp_path)
    vulnerable = tmp_path / "aiedge-runs" / "vulnerable"
    control = tmp_path / "aiedge-runs" / "control"
    _build_passing_run(vulnerable)
    _build_control_run(control)
    run_dirs = [vulnerable, control]

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        cmd = cast(list[str], args[0])
        stdout_fh = kwargs.get("stdout")
        assert stdout_fh is not None
        if cmd[:2] == ["./scout", "analyze"]:
            run_dir = run_dirs.pop(0)
            cast(Any, stdout_fh).write((str(run_dir) + "\n").encode())
            return subprocess.CompletedProcess(cmd, 0)
        assert cmd[:2] == ["./scout", "stages"]
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(
        module,
        "_build_verified_chain",
        lambda run_dir: {
            "status": "success",
            "returncode": 0,
            "duration_s": 0.0,
            "contract_path": str(Path(run_dir) / "verified_chain" / "verified_chain.json"),
            "state": "pass",
            "reason_codes": ["isolation_verified", "repro_3_of_3"],
        },
    )
    out = tmp_path / "report.json"

    rc = module.main(
        [
            "--pairs",
            str(manifest),
            "--pair-id",
            "vendor-model-cve-0000-0001",
            "--results-dir",
            str(tmp_path / "results"),
            "--no-llm",
            "--out",
            str(out),
        ]
    )

    assert rc == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["promotable_real_firmware_pair"] is True
    assert [row["status"] for row in payload["analysis"]] == ["success", "success"]
    assert [row["status"] for row in payload["postprocess"]] == ["success", "success"]
    assert {step["kind"] for row in payload["postprocess"] for step in row["steps"]} == {
        "stages",
        "derive_quality_metrics",
        "build_verified_chain",
    }
    assert not run_dirs


def test_runner_derives_quality_metrics_from_fp_verification_summary(tmp_path: Path) -> None:
    module = _load_script()
    run_dir = tmp_path / "run"
    _write_json(
        run_dir / "stages/fp_verification/verified_alerts.json",
        {
            "status": "ok",
            "summary": {"eligible_checked": 10, "false_positives": 1},
            "verified_alerts": [],
        },
    )

    result = module._derive_quality_metrics(run_dir)

    assert result["status"] == "success"
    payload = json.loads((run_dir / "quality_metrics.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "aeg-derived-quality-metrics-v1"
    assert payload["overall"]["fpr"] == 0.1
    assert payload["source"]["kind"] == "fp_verification.summary"


def test_aeg_real_pair_cli_reuses_existing_runs(tmp_path: Path, capsys: Any) -> None:
    manifest = _pair_manifest(tmp_path)
    vulnerable = tmp_path / "runs" / "vulnerable"
    control = tmp_path / "runs" / "control"
    _build_passing_run(vulnerable)
    _build_control_run(control)
    out = tmp_path / "cli-report.json"

    rc = aiedge_main(
        [
            "aeg-real-pair",
            "--pairs",
            str(manifest),
            "--pair-id",
            "vendor-model-cve-0000-0001",
            "--results-dir",
            str(tmp_path / "results"),
            "--vulnerable-run-dir",
            str(vulnerable),
            "--control-run-dir",
            str(control),
            "--pattern-id",
            "cgi_param_cmd_injection",
            "--skip-post-stages",
            "--skip-verified-chain",
            "--out",
            str(out),
        ]
    )

    assert rc == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "real-firmware-pair-aeg-run-v1"
    assert payload["promotable_real_firmware_pair"] is True
    assert payload["pair_gate"]["verdict"] == "promotable"
    assert json.loads(capsys.readouterr().out)["verdict"] == "promotable"
