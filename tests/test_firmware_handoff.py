from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from aiedge.run import create_run, run_subset


def _firmware(tmp_path: Path) -> Path:
    fw = tmp_path / "firmware.bin"
    _ = fw.write_bytes(b"firmware-handoff-fixture")
    return fw


def _load_json(path: Path) -> dict[str, object]:
    payload_any = cast(object, json.loads(path.read_text(encoding="utf-8")))
    assert isinstance(payload_any, dict)
    return cast(dict[str, object], payload_any)


def _assert_bundle_artifacts_exist(run_dir: Path, handoff: dict[str, object]) -> None:
    bundles_any = handoff.get("bundles")
    assert isinstance(bundles_any, list)
    assert bundles_any
    for bundle_any in cast(list[object], bundles_any):
        assert isinstance(bundle_any, dict)
        bundle = cast(dict[str, object], bundle_any)
        artifacts_any = bundle.get("artifacts")
        assert isinstance(artifacts_any, list)
        assert artifacts_any
        for artifact_any in cast(list[object], artifacts_any):
            assert isinstance(artifact_any, str)
            artifact = artifact_any
            assert not artifact.startswith("/")
            assert (run_dir / artifact).exists()


def test_run_subset_emits_firmware_handoff_with_policy_and_bundles(
    tmp_path: Path,
) -> None:
    info = create_run(
        str(_firmware(tmp_path)),
        case_id="case-handoff-subset",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _ = run_subset(info, ["tooling"], time_budget_s=30, no_llm=True)

    handoff_path = info.run_dir / "firmware_handoff.json"
    assert handoff_path.is_file()
    handoff = _load_json(handoff_path)
    assert handoff.get("profile") == "analysis"

    policy_any = handoff.get("policy")
    assert isinstance(policy_any, dict)
    policy = cast(dict[str, object], policy_any)
    for key in (
        "max_reruns_per_stage",
        "max_total_stage_attempts",
        "max_wallclock_per_run",
    ):
        assert key in policy

    aiedge_any = handoff.get("aiedge")
    assert isinstance(aiedge_any, dict)
    aiedge = cast(dict[str, object], aiedge_any)
    assert aiedge.get("run_id") == info.run_id
    assert aiedge.get("run_dir") == str(info.run_dir.resolve())

    _assert_bundle_artifacts_exist(info.run_dir, handoff)


def test_run_subset_handoff_includes_exploit_gate_when_profile_exploit(
    tmp_path: Path,
) -> None:
    info = create_run(
        str(_firmware(tmp_path)),
        case_id="case-handoff-exploit",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    manifest = _load_json(info.manifest_path)
    manifest["profile"] = "exploit"
    manifest["exploit_gate"] = {
        "flag": "LAB-ONLY",
        "attestation": "authorized",
        "scope": "test-scope",
    }
    _ = info.manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    _ = run_subset(info, ["tooling"], time_budget_s=30, no_llm=True)

    handoff = _load_json(info.run_dir / "firmware_handoff.json")
    assert handoff.get("profile") == "exploit"
    gate_any = handoff.get("exploit_gate")
    assert isinstance(gate_any, dict)
    gate = cast(dict[str, object], gate_any)
    assert gate.get("flag") == "LAB-ONLY"
    assert gate.get("attestation") == "authorized"
    assert gate.get("scope") == "test-scope"
    _assert_bundle_artifacts_exist(info.run_dir, handoff)
