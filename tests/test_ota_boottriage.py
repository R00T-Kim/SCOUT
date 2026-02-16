from __future__ import annotations

import gzip
import json
import struct
from pathlib import Path
from typing import cast

from aiedge.ota_boottriage import OtaBootTriageStage
from aiedge.run import analyze_run, create_run
from aiedge.stage import StageContext


def _ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    logs_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


def _newc_entry(path: str, mode: int, data: bytes) -> bytes:
    name = path.encode("utf-8") + b"\x00"
    header = (
        b"070701"
        + f"{0:08x}".encode("ascii")
        + f"{mode:08x}".encode("ascii")
        + f"{0:08x}".encode("ascii")
        + f"{0:08x}".encode("ascii")
        + f"{1:08x}".encode("ascii")
        + f"{0:08x}".encode("ascii")
        + f"{len(data):08x}".encode("ascii")
        + f"{0:08x}".encode("ascii")
        + f"{0:08x}".encode("ascii")
        + f"{0:08x}".encode("ascii")
        + f"{0:08x}".encode("ascii")
        + f"{len(name):08x}".encode("ascii")
        + f"{0:08x}".encode("ascii")
    )
    out = bytearray(header)
    out.extend(name)
    while len(out) % 4 != 0:
        out.append(0)
    out.extend(data)
    while len(out) % 4 != 0:
        out.append(0)
    return bytes(out)


def _cpio_archive(entries: list[tuple[str, int, bytes]]) -> bytes:
    out = bytearray()
    for path, mode, data in entries:
        out.extend(_newc_entry(path, mode, data))
    out.extend(_newc_entry("TRAILER!!!", 0, b""))
    return bytes(out)


def _boot_img_v0(
    *, ramdisk: bytes, header_version: int = 0, page_size: int = 4096
) -> bytes:
    kernel_size = 2048
    hdr = bytearray(1632)
    hdr[:8] = b"ANDROID!"
    struct.pack_into("<I", hdr, 8, kernel_size)
    struct.pack_into("<I", hdr, 16, len(ramdisk))
    struct.pack_into("<I", hdr, 36, page_size)
    struct.pack_into("<I", hdr, 40, header_version)
    hdr[48 : 48 + 16] = b"bootimg-test\x00"
    hdr[64 : 64 + len(b"console=ttyS0")] = b"console=ttyS0"

    kernel_off = page_size
    kernel_end = kernel_off + ((kernel_size + page_size - 1) // page_size) * page_size
    ramdisk_off = kernel_end
    blob = bytearray(ramdisk_off + len(ramdisk))
    blob[: len(hdr)] = hdr
    blob[ramdisk_off : ramdisk_off + len(ramdisk)] = ramdisk
    return bytes(blob)


def test_ota_boottriage_extracts_ramdisk_and_init_evidence(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    parts = ctx.run_dir / "stages" / "ota" / "partitions"
    parts.mkdir(parents=True)

    ramdisk = gzip.compress(
        _cpio_archive(
            [
                ("init.rc", 0o100644, b"on boot\n"),
                ("init.recovery.qcom.rc", 0o100644, b"service adbd /sbin/adbd\n"),
                ("sbin", 0o040755, b""),
                ("sbin/recovery", 0o100755, b"#!/bin/sh\n"),
            ]
        )
    )
    _ = (parts / "boot.img").write_bytes(_boot_img_v0(ramdisk=ramdisk))
    _ = (parts / "recovery.img").write_bytes(_boot_img_v0(ramdisk=ramdisk))

    out = OtaBootTriageStage().run(ctx)
    assert out.status == "ok"

    stage_dir = ctx.run_dir / "stages" / "ota" / "boottriage"
    boot_doc = cast(
        dict[str, object], json.loads((stage_dir / "boot.json").read_text())
    )
    recovery_doc = cast(
        dict[str, object], json.loads((stage_dir / "recovery.json").read_text())
    )
    assert boot_doc.get("status") == "ok"
    assert recovery_doc.get("status") == "ok"

    evidence = cast(list[object], boot_doc.get("evidence"))
    evidence_paths = {
        cast(dict[str, object], x).get("path")
        for x in evidence
        if isinstance(x, dict)
        and isinstance(cast(dict[str, object], x).get("path"), str)
    }
    assert "stages/ota/boottriage/boot_ramdisk/init.rc" in evidence_paths
    assert "stages/ota/boottriage/boot_ramdisk/init.recovery.qcom.rc" in evidence_paths


def test_ota_boottriage_skips_when_partition_missing(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    parts = ctx.run_dir / "stages" / "ota" / "partitions"
    parts.mkdir(parents=True)
    _ = (parts / "boot.img").write_bytes(b"ANDROID!" + b"\x00" * 8192)

    out = OtaBootTriageStage().run(ctx)
    assert out.status == "skipped"

    stage_dir = ctx.run_dir / "stages" / "ota" / "boottriage"
    assert (stage_dir / "boot.json").is_file()
    assert (stage_dir / "recovery.json").is_file()
    recovery_doc = cast(
        dict[str, object], json.loads((stage_dir / "recovery.json").read_text())
    )
    assert recovery_doc.get("status") == "skipped"


def test_ota_boottriage_marks_unsupported_header_partial(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    parts = ctx.run_dir / "stages" / "ota" / "partitions"
    parts.mkdir(parents=True)

    ramdisk = gzip.compress(_cpio_archive([("init.rc", 0o100644, b"x")]))
    _ = (parts / "boot.img").write_bytes(
        _boot_img_v0(ramdisk=ramdisk, header_version=4)
    )
    _ = (parts / "recovery.img").write_bytes(_boot_img_v0(ramdisk=ramdisk))

    out = OtaBootTriageStage().run(ctx)
    assert out.status == "partial"

    stage_dir = ctx.run_dir / "stages" / "ota" / "boottriage"
    boot_doc = cast(
        dict[str, object], json.loads((stage_dir / "boot.json").read_text())
    )
    limits = cast(list[object], boot_doc.get("limitations"))
    assert any("unsupported boot image header_version" in str(x) for x in limits)


def test_analyze_run_writes_ota_boottriage_report_section(tmp_path: Path) -> None:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")

    info = create_run(
        str(fw),
        case_id="case-ota-boottriage",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    _ = analyze_run(info, time_budget_s=0, no_llm=True)

    stage_dir = info.run_dir / "stages" / "ota" / "boottriage"
    assert (stage_dir / "boot.json").is_file()
    assert (stage_dir / "recovery.json").is_file()

    report_obj = cast(
        dict[str, object],
        json.loads(
            (info.run_dir / "report" / "report.json").read_text(encoding="utf-8")
        ),
    )
    assert "ota_boottriage" in report_obj
