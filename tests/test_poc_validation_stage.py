from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from aiedge.run import create_run, run_subset


def _write_firmware(tmp_path: Path) -> Path:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"FW")
    return fw


def _set_profile_exploit(
    manifest_path: Path, *, attestation: str = "authorized", scope: str = "lab-only"
) -> None:
    obj = cast(dict[str, object], json.loads(manifest_path.read_text(encoding="utf-8")))
    obj["profile"] = "exploit"
    obj["exploit_gate"] = {
        "flag": "flag",
        "attestation": attestation,
        "scope": scope,
    }
    _ = manifest_path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def test_poc_validation_skipped_in_analysis_profile(tmp_path: Path) -> None:
    fw = _write_firmware(tmp_path)
    info = create_run(
        str(fw),
        case_id="case-poc-validation-skip",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    rep = run_subset(info, ["poc_validation"], time_budget_s=5, no_llm=True)
    assert rep.status in ("ok", "partial", "skipped")

    stage_json = info.run_dir / "stages" / "poc_validation" / "stage.json"
    stage_obj = cast(
        dict[str, object], json.loads(stage_json.read_text(encoding="utf-8"))
    )
    assert stage_obj.get("status") == "skipped"

    validation_json = info.run_dir / "stages" / "poc_validation" / "poc_validation.json"
    validation_obj = cast(
        dict[str, object], json.loads(validation_json.read_text(encoding="utf-8"))
    )
    assert validation_obj.get("status") == "skipped"
    blocked = cast(list[object], validation_obj.get("blocked"))
    blocked_codes = [
        cast(dict[str, object], item).get("reason_code")
        for item in blocked
        if isinstance(item, dict)
    ]
    assert blocked_codes == ["POLICY_PROFILE_NOT_EXPLOIT"]


def test_poc_validation_ok_for_gated_exploit_profile(tmp_path: Path) -> None:
    fw = _write_firmware(tmp_path)
    info = create_run(
        str(fw),
        case_id="case-poc-validation-ok",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _set_profile_exploit(info.manifest_path)

    rep = run_subset(
        info,
        ["exploit_gate", "exploit_chain", "poc_validation"],
        time_budget_s=5,
        no_llm=True,
    )
    assert rep.status in ("ok", "partial")

    validation_json = info.run_dir / "stages" / "poc_validation" / "poc_validation.json"
    validation_obj = cast(
        dict[str, object], json.loads(validation_json.read_text(encoding="utf-8"))
    )
    assert validation_obj.get("status") == "ok"
    assert validation_obj.get("blocked") == []
    checked_paths = cast(list[object], validation_obj.get("checked_paths"))
    assert checked_paths == sorted(cast(list[str], checked_paths))


def test_poc_validation_blocks_non_lab_scope(tmp_path: Path) -> None:
    fw = _write_firmware(tmp_path)
    info = create_run(
        str(fw),
        case_id="case-poc-validation-scope-blocked",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _set_profile_exploit(info.manifest_path, scope="broader-than-lab")

    rep = run_subset(
        info,
        ["exploit_gate", "exploit_chain", "poc_validation"],
        time_budget_s=5,
        no_llm=True,
    )
    assert rep.status in ("partial", "failed")

    validation_json = info.run_dir / "stages" / "poc_validation" / "poc_validation.json"
    validation_obj = cast(
        dict[str, object], json.loads(validation_json.read_text(encoding="utf-8"))
    )
    assert validation_obj.get("status") == "failed"
    blocked = cast(list[object], validation_obj.get("blocked"))
    blocked_codes = sorted(
        cast(dict[str, str], item).get("reason_code", "")
        for item in blocked
        if isinstance(item, dict)
    )
    assert "POLICY_SCOPE_NOT_LAB_ONLY" in blocked_codes


def test_exploit_policy_scans_poc_validation_artifacts(tmp_path: Path) -> None:
    fw = _write_firmware(tmp_path)
    info = create_run(
        str(fw),
        case_id="case-poc-policy-scan",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _set_profile_exploit(info.manifest_path)

    poc_dir = info.run_dir / "stages" / "poc_validation"
    poc_dir.mkdir(parents=True, exist_ok=True)
    _ = (poc_dir / "payload.bin").write_bytes(b"X")

    rep = run_subset(info, ["exploit_policy"], time_budget_s=5, no_llm=True)
    assert rep.status in ("partial", "failed")

    policy_json = info.run_dir / "stages" / "exploit_policy" / "policy.json"
    obj = cast(dict[str, object], json.loads(policy_json.read_text(encoding="utf-8")))
    forbidden = cast(list[object], obj.get("forbidden"))
    assert "stages/poc_validation/payload.bin" in forbidden
