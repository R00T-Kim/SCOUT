from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import cast

import pytest

from aiedge.stage import StageContext
from aiedge.structure import StructureStage


def _ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    input_dir = run_dir / "input"
    logs_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    input_dir.mkdir(parents=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


def _u32be(x: int) -> bytes:
    return int(x).to_bytes(4, "big", signed=False)


def _dtb_blob(*, totalsize: int) -> bytes:
    if totalsize < 40:
        raise ValueError("totalsize must be >= 40")
    header = b"".join(
        [
            _u32be(0xD00DFEED),
            _u32be(totalsize),
            _u32be(0x38),
            _u32be(0x60 if totalsize >= 0x64 else 0x38),
            _u32be(0x28),
            _u32be(17),
            _u32be(16),
            _u32be(0),
            _u32be(0),
            _u32be(0),
        ]
    )
    return header + (b"\x00" * (totalsize - len(header)))


def test_structure_discovers_from_binwalk_log_and_extracts(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    fw = ctx.run_dir / "input" / "firmware.bin"
    dtb = _dtb_blob(totalsize=128)
    off = 64
    blob = (b"A" * off) + dtb + (b"B" * 32)
    _ = fw.write_bytes(blob)

    binwalk_log = ctx.run_dir / "stages" / "extraction" / "binwalk.log"
    binwalk_log.parent.mkdir(parents=True)
    _ = binwalk_log.write_text(
        "DECIMAL       HEXADECIMAL     DESCRIPTION\n"
        + f"{off}          0x{off:x}           Flattened device tree, size: 128 bytes\n",
        encoding="utf-8",
    )

    outcome = StructureStage(firmware_path=fw).run(ctx)
    assert outcome.status in ("ok", "partial")

    stage_dir = ctx.run_dir / "stages" / "structure"
    assert (stage_dir / "structure.json").is_file()
    assert (stage_dir / "dtb").is_dir()

    dtbs = list((stage_dir / "dtb").glob("*.dtb"))
    assert len(dtbs) == 1
    assert dtbs[0].read_bytes()[:4] == b"\xd0\r\xfe\xed"
    assert len(dtbs[0].read_bytes()) == 128

    rep = cast(
        dict[str, object],
        json.loads((stage_dir / "structure.json").read_text(encoding="utf-8")),
    )
    assert rep.get("dtbs")
    ev = rep.get("evidence")
    assert isinstance(ev, list) and ev


def test_structure_fallback_magic_scan_extracts(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    fw = ctx.run_dir / "input" / "firmware.bin"
    dtb = _dtb_blob(totalsize=96)
    off = 17
    _ = fw.write_bytes((b"Z" * off) + dtb + (b"Z" * 10))

    outcome = StructureStage(firmware_path=fw, max_scan_bytes=4096).run(ctx)
    assert outcome.status in ("ok", "partial")

    stage_dir = ctx.run_dir / "stages" / "structure"
    dtbs = list((stage_dir / "dtb").glob("*.dtb"))
    assert len(dtbs) == 1
    assert len(dtbs[0].read_bytes()) == 96


def test_structure_magic_scan_does_not_break_on_multi_chunk_file(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    fw = ctx.run_dir / "input" / "firmware.bin"

    dtb = _dtb_blob(totalsize=64)
    off = (1024 * 1024) + 123
    blob = (b"Q" * off) + dtb + (b"R" * 10)
    _ = fw.write_bytes(blob)

    outcome = StructureStage(
        firmware_path=fw,
        max_scan_bytes=off + len(dtb) + 1,
    ).run(ctx)
    assert outcome.status in ("ok", "partial")

    stage_dir = ctx.run_dir / "stages" / "structure"
    dtbs = list((stage_dir / "dtb").glob("*.dtb"))
    assert len(dtbs) == 1
    assert len(dtbs[0].read_bytes()) == 64


def test_structure_bootargs_prefers_fdtget(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ctx = _ctx(tmp_path)
    fw = ctx.run_dir / "input" / "firmware.bin"
    dtb = _dtb_blob(totalsize=128)
    _ = fw.write_bytes(dtb + (b"X" * 32))

    def _fake_which(name: str) -> str:
        return f"/fake/{name}"

    monkeypatch.setattr("aiedge.structure.shutil.which", _fake_which)

    def _fake_run(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        if argv and argv[0].endswith("fdtget"):
            out = "console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=squashfs ubi.mtd=3\n"
            return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")
        if argv and argv[0].endswith("dtc"):
            out_idx = argv.index("-o") + 1
            dts_path = Path(argv[out_idx])
            _ = dts_path.write_text(
                '/dts-v1/;\n/ { chosen { bootargs = "root=/dev/mtdblock3"; }; };\n',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="unhandled")

    monkeypatch.setattr("aiedge.structure.subprocess.run", _fake_run)

    outcome = StructureStage(firmware_path=fw).run(ctx)
    assert outcome.status in ("ok", "partial")

    stage_dir = ctx.run_dir / "stages" / "structure"
    rep = cast(
        dict[str, object],
        json.loads((stage_dir / "structure.json").read_text(encoding="utf-8")),
    )
    bootargs = cast(dict[str, object], rep.get("bootargs"))
    raw = bootargs.get("raw")
    assert isinstance(raw, list)
    raw_list = cast(list[object], raw)
    assert all(isinstance(x, str) for x in raw_list)
    assert any("console=ttyS0" in x for x in cast(list[str], raw_list))
    terms = cast(dict[str, object], bootargs.get("terms"))
    console_vals = terms.get("console")
    root_vals = terms.get("root")
    assert isinstance(console_vals, list)
    assert isinstance(root_vals, list)
    assert "ttyS0,115200" in console_vals
    assert "/dev/mtdblock3" in root_vals


def test_structure_bootargs_falls_back_to_firmware_string_scan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ctx = _ctx(tmp_path)
    fw = ctx.run_dir / "input" / "firmware.bin"
    dtb = _dtb_blob(totalsize=128)
    off = 64
    boot = b"\x00console=ttyS0,115200 mtdparts=spi_nand.0:1M@0(foo) root=/dev/mtdblock3 rootfstype=squashfs\x00"
    _ = fw.write_bytes((b"A" * off) + dtb + (b"B" * 32) + boot)

    binwalk_log = ctx.run_dir / "stages" / "extraction" / "binwalk.log"
    binwalk_log.parent.mkdir(parents=True)
    _ = binwalk_log.write_text(
        "DECIMAL       HEXADECIMAL     DESCRIPTION\n"
        + f"{off}          0x{off:x}           Flattened device tree, size: 128 bytes\n",
        encoding="utf-8",
    )

    monkeypatch.setattr("aiedge.structure.shutil.which", lambda name: "")

    outcome = StructureStage(firmware_path=fw).run(ctx)
    assert outcome.status in ("ok", "partial")

    stage_dir = ctx.run_dir / "stages" / "structure"
    rep = cast(
        dict[str, object],
        json.loads((stage_dir / "structure.json").read_text(encoding="utf-8")),
    )
    bootargs = cast(dict[str, object], rep.get("bootargs"))
    terms = cast(dict[str, object], bootargs.get("terms"))
    mtdparts_vals = terms.get("mtdparts")
    assert isinstance(mtdparts_vals, list)
    assert "spi_nand.0:1M@0(foo)" in mtdparts_vals
