from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import cast


def _load_script() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts" / "check_aeg_platform_readiness.py"
    spec = importlib.util.spec_from_file_location("check_aeg_platform_readiness", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return cast(ModuleType, module)


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_pattern(patterns_dir: Path, pattern_id: str, evidence: list[dict[str, object]]) -> None:
    _write_json(
        patterns_dir / pattern_id / "exploit.json",
        {
            "schema_version": "scout-exploit-pattern-card-v1",
            "id": pattern_id,
            "family": "cmd_injection",
            "entry_channel": "web_api",
            "bridge_channel": "direct_request",
            "trigger_model": "direct_request",
            "sink": {"type": "shell_command", "api": "system"},
            "payload_context": {},
            "verification": {"preferred": ["vulnerability_trigger"]},
            "adaptation_rules": ["derive target-specific fields from firmware evidence"],
            "forbidden_reuse": ["public exploit literals"],
            "preconditions": ["authorized lab target"],
            "source_refs": [{"id": pattern_id, "type": "test"}],
            "validation_evidence": evidence,
        },
    )


def _real_pair_report(pattern_id: str) -> dict[str, object]:
    return {
        "schema_version": "real-firmware-pair-aeg-gate-v1",
        "pair_id": "vendor-model-cve-0000-0001",
        "pattern_id": pattern_id,
        "verdict": "promotable",
        "promotable_real_firmware_pair": True,
        "blocked_reasons": [],
        "firmware": {
            "vulnerable": {
                "expected_sha256": "a" * 64,
                "actual_sha256": "a" * 64,
                "sha256_match": True,
            },
            "patched": {
                "expected_sha256": "b" * 64,
                "actual_sha256": "b" * 64,
                "sha256_match": True,
            },
        },
        "runs": {
            "vulnerable": {"gate_passed": True},
            "patched": {
                "gate_passed": False,
                "dynamic_failed_checks": ["autopoc_runner_pass"],
            },
        },
    }


def test_aeg_platform_readiness_passes_with_all_patterns_and_real_pair_artifact(
    tmp_path: Path, capsys
) -> None:
    module = _load_script()
    repo_root = tmp_path
    patterns_dir = tmp_path / "patterns"
    artifact = "docs/pov/vendor-model-cve-0000-0001_real_pair.json"
    _write_json(repo_root / artifact, _real_pair_report("real_pattern"))
    _write_pattern(
        patterns_dir,
        "real_pattern",
        [
            {
                "kind": "real_firmware_pair",
                "status": "pass",
                "vulnerable_gate_passed": True,
                "control_gate_failed": True,
                "artifact": artifact,
                "target_family": "real_pattern",
                "vulnerable_firmware_sha256": "a" * 64,
                "control_firmware_sha256": "b" * 64,
            }
        ],
    )
    _write_pattern(
        patterns_dir,
        "synthetic_pattern",
        [
            {
                "kind": "synthetic_pair",
                "status": "pass",
                "vulnerable_gate_passed": True,
                "control_gate_failed": True,
            }
        ],
    )

    rc = module.main(
        [
            "--repo-root",
            str(repo_root),
            "--patterns-dir",
            str(patterns_dir),
        ]
    )

    assert rc == 0
    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert payload["schema_version"] == "aeg-platform-readiness-v1"
    assert payload["ready"] is True
    assert payload["verdict"] == "platform-ready"
    assert payload["blocked_reasons"] == []


def test_aeg_platform_readiness_blocks_missing_stable_real_pair_artifact(
    tmp_path: Path,
) -> None:
    module = _load_script()
    patterns_dir = tmp_path / "patterns"
    _write_pattern(
        patterns_dir,
        "real_pattern",
        [
            {
                "kind": "real_firmware_pair",
                "status": "pass",
                "vulnerable_gate_passed": True,
                "control_gate_failed": True,
                "artifact": "docs/pov/missing.json",
                "target_family": "real_pattern",
                "vulnerable_firmware_sha256": "a" * 64,
                "control_firmware_sha256": "b" * 64,
            }
        ],
    )

    payload = module.build_readiness_report(repo_root=tmp_path, patterns_dir=patterns_dir)

    assert payload["ready"] is False
    assert "real_firmware_evidence_artifact_exists" in payload["blocked_reasons"]


def test_aeg_platform_readiness_blocks_unvalidated_curated_pattern(tmp_path: Path) -> None:
    module = _load_script()
    repo_root = tmp_path
    patterns_dir = tmp_path / "patterns"
    artifact = "docs/pov/vendor-model-cve-0000-0001_real_pair.json"
    _write_json(repo_root / artifact, _real_pair_report("real_pattern"))
    _write_pattern(
        patterns_dir,
        "real_pattern",
        [
            {
                "kind": "real_firmware_pair",
                "status": "pass",
                "vulnerable_gate_passed": True,
                "control_gate_failed": True,
                "artifact": artifact,
                "target_family": "real_pattern",
                "vulnerable_firmware_sha256": "a" * 64,
                "control_firmware_sha256": "b" * 64,
            }
        ],
    )
    _write_pattern(patterns_dir, "metadata_only_pattern", [])

    payload = module.build_readiness_report(repo_root=repo_root, patterns_dir=patterns_dir)

    assert payload["ready"] is False
    assert "curated_patterns_pair_validated" in payload["blocked_reasons"]


def test_aeg_platform_readiness_blocks_absolute_real_pair_artifact(tmp_path: Path) -> None:
    module = _load_script()
    patterns_dir = tmp_path / "patterns"
    absolute_artifact = tmp_path / "docs/pov/vendor-model-cve-0000-0001_real_pair.json"
    _write_json(absolute_artifact, _real_pair_report("real_pattern"))
    _write_pattern(
        patterns_dir,
        "real_pattern",
        [
            {
                "kind": "real_firmware_pair",
                "status": "pass",
                "vulnerable_gate_passed": True,
                "control_gate_failed": True,
                "artifact": str(absolute_artifact),
                "target_family": "real_pattern",
                "vulnerable_firmware_sha256": "a" * 64,
                "control_firmware_sha256": "b" * 64,
            }
        ],
    )

    payload = module.build_readiness_report(repo_root=tmp_path, patterns_dir=patterns_dir)

    assert payload["ready"] is False
    assert "real_firmware_evidence_artifact_repo_relative" in payload["blocked_reasons"]
