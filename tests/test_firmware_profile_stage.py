from __future__ import annotations

import json
import re
from pathlib import Path
from typing import cast

from aiedge.firmware_profile import FirmwareProfileStage
from aiedge.run import analyze_run, create_run, run_subset
from aiedge.stage import StageContext


def _make_ctx(run_dir: Path) -> StageContext:
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    logs_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


def _walk_strings(value: object) -> list[str]:
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
        return out
    if isinstance(value, dict):
        for item in cast(dict[object, object], value).values():
            out.extend(_walk_strings(item))
        return out
    if isinstance(value, list):
        for item in cast(list[object], value):
            out.extend(_walk_strings(item))
    return out


def _assert_no_absolute_paths(value: object) -> None:
    for s in _walk_strings(value):
        assert not s.startswith("/"), f"unexpected absolute posix path: {s}"
        assert re.match(r"^[A-Za-z]:\\", s) is None, (
            f"unexpected absolute windows path: {s}"
        )


def test_firmware_profile_linux_fs_is_deterministic(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    firmware = run_dir / "input" / "firmware.bin"
    firmware.parent.mkdir(parents=True, exist_ok=True)
    _ = firmware.write_bytes(b"firmware-bytes")

    extracted_root = run_dir / "stages" / "extraction" / "_firmware.bin.extracted"
    _ = (extracted_root / "rootfs" / "etc").mkdir(parents=True, exist_ok=True)
    _ = (extracted_root / "rootfs" / "usr").mkdir(parents=True, exist_ok=True)
    _ = (run_dir / "stages" / "extraction" / "binwalk.log").parent.mkdir(
        parents=True, exist_ok=True
    )
    _ = (run_dir / "stages" / "extraction" / "binwalk.log").write_text(
        "binwalk output\n", encoding="utf-8"
    )

    stage = FirmwareProfileStage()
    ctx = _make_ctx(run_dir)

    first = stage.run(ctx)
    assert first.details["os_type_guess"] == "linux_fs"
    assert cast(dict[str, object], first.details["branch_plan"])["inventory_mode"] == (
        "filesystem"
    )

    out_path = run_dir / "stages" / "firmware_profile" / "firmware_profile.json"
    first_json = out_path.read_text(encoding="utf-8")
    second = stage.run(ctx)
    second_json = out_path.read_text(encoding="utf-8")

    assert second.details["os_type_guess"] == "linux_fs"
    assert first_json == second_json

    payload = cast(dict[str, object], json.loads(second_json))
    assert payload["schema_version"] == 1
    assert payload["emulation_feasibility"] == "high"
    _assert_no_absolute_paths(payload)


def test_firmware_profile_binary_only_without_rootfs(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    firmware = run_dir / "input" / "firmware.bin"
    firmware.parent.mkdir(parents=True, exist_ok=True)
    _ = firmware.write_bytes(b"blob-only")

    stage = FirmwareProfileStage()
    out = stage.run(_make_ctx(run_dir))

    branch_plan = cast(dict[str, object], out.details["branch_plan"])
    assert branch_plan["inventory_mode"] == "binary_only"

    payload = cast(
        dict[str, object],
        json.loads(
            (
                run_dir / "stages" / "firmware_profile" / "firmware_profile.json"
            ).read_text(encoding="utf-8")
        ),
    )
    assert payload["os_type_guess"] in {
        "rtos_monolithic",
        "unextractable_or_unknown",
    }
    _assert_no_absolute_paths(payload)


def test_firmware_profile_uses_elf_crosscheck_when_rootfs_missing(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    firmware = run_dir / "input" / "firmware.bin"
    firmware.parent.mkdir(parents=True, exist_ok=True)
    _ = firmware.write_bytes(b"blob-only")

    extracted_dir = run_dir / "stages" / "extraction" / "_firmware.bin.extracted"
    elf_path = extracted_dir / "usr" / "bin" / "qnapd"
    elf_path.parent.mkdir(parents=True, exist_ok=True)
    elf = bytearray(64)
    elf[0:4] = b"\x7fELF"
    elf[4] = 2  # 64-bit
    elf[5] = 1  # little-endian
    elf[18] = 0x3E  # EM_X86_64
    elf[19] = 0x00
    _ = elf_path.write_bytes(bytes(elf))

    stage = FirmwareProfileStage()
    out = stage.run(_make_ctx(run_dir))

    assert out.details["os_type_guess"] == "unextractable_or_unknown"
    assert out.details.get("arch_guess") == "x86_64-64"
    branch_plan = cast(dict[str, object], out.details["branch_plan"])
    assert branch_plan["inventory_mode"] == "binary_only"

    payload = cast(
        dict[str, object],
        json.loads(
            (
                run_dir / "stages" / "firmware_profile" / "firmware_profile.json"
            ).read_text(encoding="utf-8")
        ),
    )
    elf_hints = cast(dict[str, object], payload.get("elf_hints", {}))
    assert cast(int, elf_hints.get("elf_count", 0)) >= 1
    assert payload.get("arch_guess") == "x86_64-64"


def test_run_subset_can_execute_firmware_profile_on_existing_run(
    tmp_path: Path,
) -> None:
    firmware = tmp_path / "firmware.bin"
    _ = firmware.write_bytes(b"subset-profile")

    info = create_run(
        str(firmware),
        case_id="case-firmware-profile",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    rep = run_subset(info, ["firmware_profile"], no_llm=True)

    assert [r.stage for r in rep.stage_results] == ["firmware_profile"]
    assert (
        info.run_dir / "stages" / "firmware_profile" / "firmware_profile.json"
    ).is_file()


def test_analyze_run_default_chain_includes_firmware_profile(tmp_path: Path) -> None:
    firmware = tmp_path / "fw-default.bin"
    _ = firmware.write_bytes(b"default-chain")

    info = create_run(
        str(firmware),
        case_id="case-default-chain",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _ = analyze_run(info, time_budget_s=0, no_llm=True)

    report = cast(
        dict[str, object],
        json.loads(
            (info.run_dir / "report" / "report.json").read_text(encoding="utf-8")
        ),
    )
    assert "firmware_profile" in report

    carving_manifest = cast(
        dict[str, object],
        json.loads(
            (info.run_dir / "stages" / "carving" / "stage.json").read_text(
                encoding="utf-8"
            )
        ),
    )
    profile_manifest = cast(
        dict[str, object],
        json.loads(
            (info.run_dir / "stages" / "firmware_profile" / "stage.json").read_text(
                encoding="utf-8"
            )
        ),
    )
    inventory_manifest = cast(
        dict[str, object],
        json.loads(
            (info.run_dir / "stages" / "inventory" / "stage.json").read_text(
                encoding="utf-8"
            )
        ),
    )
    assert cast(str, carving_manifest["started_at"]) <= cast(
        str, profile_manifest["started_at"]
    )
    assert cast(str, profile_manifest["started_at"]) <= cast(
        str, inventory_manifest["started_at"]
    )
