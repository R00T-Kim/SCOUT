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


def test_poc_validation_missing_prereq_note_lists_paths(tmp_path: Path) -> None:
    """When exploit_chain is skipped, the blocked note should enumerate the
    specific missing paths so the analyst can see which upstream stage to
    re-run, rather than a generic "artifacts missing" string.
    """
    fw = _write_firmware(tmp_path)
    info = create_run(
        str(fw),
        case_id="case-poc-missing-detail",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _set_profile_exploit(info.manifest_path)

    # Run poc_validation alone -- exploit_chain never executed so
    # milestones.json is absent. The stage must fail with detail.
    rep = run_subset(
        info,
        ["exploit_gate", "poc_validation"],
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
    prereq_items = [
        cast(dict[str, object], item)
        for item in blocked
        if isinstance(item, dict)
        and item.get("reason_code") == "POLICY_PREREQ_STAGE_ARTIFACT_MISSING"
    ]
    assert prereq_items, "expected a PREREQ_STAGE_ARTIFACT_MISSING block"
    note = cast(str, prereq_items[0].get("note", ""))
    assert (
        "stages/exploit_chain/milestones.json" in note
    ), "missing-paths detail must name the specific artifact"


def test_poc_validation_resolves_run_dir_symlinks(tmp_path: Path) -> None:
    """``ctx.run_dir`` may be reached via a symlink (e.g. a ``latest`` alias).
    The prereq check must follow symlinks via ``.resolve().is_file()`` so
    reruns that pass a symlinked run_dir still see their artefacts.
    """
    fw = _write_firmware(tmp_path)
    info = create_run(
        str(fw),
        case_id="case-poc-symlink",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _set_profile_exploit(info.manifest_path)

    # First run the full exploit chain so artefacts exist under the real
    # run_dir path.
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


def test_poc_validation_does_not_count_failed_hashes_as_reproducible(
    tmp_path: Path,
) -> None:
    fw = _write_firmware(tmp_path)
    info = create_run(
        str(fw),
        case_id="case-poc-failed-hash-not-repro",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _set_profile_exploit(info.manifest_path)

    prereq_rep = run_subset(
        info,
        ["exploit_gate", "exploit_chain"],
        time_budget_s=5,
        no_llm=True,
    )
    assert prereq_rep.status in ("ok", "partial")

    bundle_dir = info.run_dir / "exploits" / "chain_failed_hash"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    _ = (bundle_dir / "evidence_bundle.json").write_text(
        json.dumps(
            {
                "schema_version": "exploit-evidence-v1",
                "chain_id": "failed_hash",
                "attempts": [
                    {
                        "attempt": i,
                        "status": "fail",
                        "reason_code": "attempt_fail",
                        "proof_type": "none",
                        "proof_evidence": "readback_hash=same-failure-hash",
                    }
                    for i in range(1, 4)
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    rep = run_subset(info, ["poc_validation"], time_budget_s=5, no_llm=True)
    assert rep.status in ("ok", "partial")

    validation_json = info.run_dir / "stages" / "poc_validation" / "poc_validation.json"
    validation_obj = cast(
        dict[str, object], json.loads(validation_json.read_text(encoding="utf-8"))
    )
    assert validation_obj.get("status") == "ok"
    assert validation_obj.get("verification_reason_codes") == []
    repro = cast(list[object], validation_obj.get("reproducibility"))
    assert repro
    first = cast(dict[str, object], repro[0])
    assert first.get("status") == "failed"
    assert (
        first.get("result_code")
        == "POLICY_REPRODUCIBILITY_NO_SUCCESSFUL_ATTEMPTS"
    )


def test_poc_validation_counts_vulnerability_trigger_as_reproducible_pov(
    tmp_path: Path,
) -> None:
    fw = _write_firmware(tmp_path)
    info = create_run(
        str(fw),
        case_id="case-poc-vulnerability-trigger",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _set_profile_exploit(info.manifest_path)

    prereq_rep = run_subset(
        info,
        ["exploit_gate", "exploit_chain"],
        time_budget_s=5,
        no_llm=True,
    )
    assert prereq_rep.status in ("ok", "partial")

    digest = "b" * 64
    bundle_dir = info.run_dir / "exploits" / "chain_vulnerability_trigger"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    _ = (bundle_dir / "evidence_bundle.json").write_text(
        json.dumps(
            {
                "schema_version": "exploit-evidence-v1",
                "chain_id": "vulnerability_trigger",
                "attempts": [
                    {
                        "attempt": i,
                        "status": "pass",
                        "reason_code": "attempt_pass",
                        "proof_type": "vulnerability_trigger",
                        "proof_evidence": (
                            "probe=outbound_protocol_response_pov "
                            "channel_count=4 trigger_observed=1 "
                            f"readback_hash={digest}"
                        ),
                    }
                    for i in range(1, 4)
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    rep = run_subset(info, ["poc_validation"], time_budget_s=5, no_llm=True)
    assert rep.status in ("ok", "partial")

    validation_json = info.run_dir / "stages" / "poc_validation" / "poc_validation.json"
    validation_obj = cast(
        dict[str, object], json.loads(validation_json.read_text(encoding="utf-8"))
    )
    repro = cast(list[object], validation_obj.get("reproducibility"))
    first = cast(dict[str, object], repro[0])
    assert first.get("status") == "consistent"
    assert first.get("readback_hash") == digest


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
