from __future__ import annotations

import json
import re
from pathlib import Path
from typing import cast

from aiedge.firmware_profile import FirmwareProfileStage
from aiedge.inventory import InventoryStage
from aiedge.stage import StageContext


def _ctx(run_dir: Path) -> StageContext:
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    logs_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


def _assert_run_relative_posix(path_s: str) -> None:
    assert not path_s.startswith("/")
    assert re.match(r"^[A-Za-z]:\\", path_s) is None
    assert "\\" not in path_s


def test_firmware_profile_json_contract_v1_keys_and_types(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    firmware = run_dir / "input" / "firmware.bin"
    firmware.parent.mkdir(parents=True, exist_ok=True)
    _ = firmware.write_bytes(b"contract-test")

    extracted_root = run_dir / "stages" / "extraction" / "_firmware.bin.extracted"
    _ = (extracted_root / "rootfs" / "etc").mkdir(parents=True, exist_ok=True)
    _ = (extracted_root / "rootfs" / "usr").mkdir(parents=True, exist_ok=True)
    _ = (run_dir / "stages" / "carving").mkdir(parents=True, exist_ok=True)
    _ = (run_dir / "stages" / "carving" / "roots.json").write_text(
        json.dumps({"roots": ["stages/carving/roots/root0"]}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    _ = FirmwareProfileStage().run(_ctx(run_dir))

    payload = cast(
        dict[str, object],
        json.loads(
            (
                run_dir / "stages" / "firmware_profile" / "firmware_profile.json"
            ).read_text(encoding="utf-8")
        ),
    )

    assert payload.get("schema_version") == 1
    assert payload.get("os_type_guess") in {
        "linux_fs",
        "rtos_monolithic",
        "unextractable_or_unknown",
    }
    assert payload.get("emulation_feasibility") in {"high", "medium", "low", "unknown"}

    assert isinstance(payload.get("firmware_id"), str)
    assert isinstance(payload.get("limitations"), list)
    assert isinstance(payload.get("sdk_hints"), list)

    branch_plan_obj = payload.get("branch_plan")
    assert isinstance(branch_plan_obj, dict)
    branch_plan = cast(dict[str, object], branch_plan_obj)
    assert branch_plan.get("inventory_mode") in {"filesystem", "binary_only"}
    assert isinstance(branch_plan.get("why"), str)

    evidence_refs_obj = payload.get("evidence_refs")
    assert isinstance(evidence_refs_obj, list)
    for ref in cast(list[object], evidence_refs_obj):
        assert isinstance(ref, str)
        _assert_run_relative_posix(ref)

    assert "started_at" not in payload
    assert "finished_at" not in payload


def test_inventory_json_contract_required_and_optional_shapes(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    extracted_root = (
        run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "fs-root"
    )
    (extracted_root / "etc").mkdir(parents=True, exist_ok=True)
    _ = (extracted_root / "etc" / "passwd").write_text("root:x:0:0\n", encoding="utf-8")

    _ = InventoryStage().run(_ctx(run_dir))

    payload = cast(
        dict[str, object],
        json.loads(
            (run_dir / "stages" / "inventory" / "inventory.json").read_text(
                encoding="utf-8"
            )
        ),
    )

    assert payload.get("status") in {"ok", "partial"}

    summary_obj = payload.get("summary")
    assert isinstance(summary_obj, dict)
    summary = cast(dict[str, object], summary_obj)
    for key in ("roots_scanned", "files", "binaries", "configs", "string_hits"):
        assert isinstance(summary.get(key), int)

    assert isinstance(payload.get("service_candidates"), list)
    assert isinstance(payload.get("services"), list)

    errors_obj = payload.get("errors")
    assert isinstance(errors_obj, list)
    for item in cast(list[object], errors_obj):
        assert isinstance(item, dict)
        err = cast(dict[str, object], item)
        assert isinstance(err.get("path"), str)
        assert isinstance(err.get("op"), str)
        assert isinstance(err.get("error"), str)

    coverage_obj = payload.get("coverage_metrics")
    assert isinstance(coverage_obj, dict)
    coverage = cast(dict[str, object], coverage_obj)
    for key in (
        "roots_considered",
        "roots_scanned",
        "files_seen",
        "binaries_seen",
        "configs_seen",
        "string_hits_seen",
        "skipped_dirs",
        "skipped_files",
    ):
        assert isinstance(coverage.get(key), int)

    roots_obj = payload.get("roots")
    if isinstance(roots_obj, list):
        for root in cast(list[object], roots_obj):
            assert isinstance(root, str)
            _assert_run_relative_posix(root)

    artifacts_obj = payload.get("artifacts")
    if isinstance(artifacts_obj, dict):
        string_hits = cast(dict[str, object], artifacts_obj).get("string_hits")
        assert isinstance(string_hits, str)
        _assert_run_relative_posix(string_hits)
