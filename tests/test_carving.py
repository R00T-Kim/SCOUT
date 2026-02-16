from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import cast

import pytest

from aiedge.carving import CarvingStage
from aiedge.stage import StageContext


def _ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    input_dir = run_dir / "input"
    logs_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    input_dir.mkdir(parents=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


def test_carving_infers_partitions_carves_and_extracts_squashfs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ctx = _ctx(tmp_path)
    fw = ctx.run_dir / "input" / "firmware.bin"

    part0 = b"A" * 4096
    part1 = b"hsqs" + (b"B" * (4096 - 4))
    part2 = b"C" * 2048
    _ = fw.write_bytes(part0 + part1 + part2)

    structure_dir = ctx.run_dir / "stages" / "structure"
    structure_dir.mkdir(parents=True)
    structure_json = structure_dir / "structure.json"
    mtd = "flash0:4k(boot),4k(../rootfs),-(data)"
    _ = structure_json.write_text(
        json.dumps(
            {
                "status": "ok",
                "bootargs": {"raw": [], "terms": {"mtdparts": [mtd]}},
                "dtbs": [],
                "limitations": [],
                "evidence": [],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    def _fake_which(name: str) -> str | None:
        if name == "unsquashfs":
            return "/fake/unsquashfs"
        return None

    monkeypatch.setattr("aiedge.carving.shutil.which", _fake_which)

    def _fake_run(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        if argv and argv[0].endswith("unsquashfs") and "-s" in argv:
            return subprocess.CompletedProcess(argv, 0, stdout="stats\n", stderr="")
        if argv and argv[0].endswith("unsquashfs") and "-d" in argv:
            d_idx = argv.index("-d") + 1
            root_dir = Path(argv[d_idx])
            (root_dir / "etc").mkdir(parents=True, exist_ok=True)
            _ = (root_dir / "etc" / "passwd").write_text("root:x:0:0\n")
            return subprocess.CompletedProcess(argv, 0, stdout="ok\n", stderr="")
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="unhandled")

    monkeypatch.setattr("aiedge.carving.subprocess.run", _fake_run)

    outcome = CarvingStage(firmware_path=fw, max_total_bytes=1024 * 1024).run(ctx)
    assert outcome.status == "ok"

    stage_dir = ctx.run_dir / "stages" / "carving"
    assert (stage_dir / "partitions.json").is_file()
    assert (stage_dir / "roots.json").is_file()

    blobs = list((stage_dir / "blobs").glob("*.bin"))
    assert blobs

    rep = cast(
        dict[str, object],
        json.loads((stage_dir / "partitions.json").read_text(encoding="utf-8")),
    )
    parts_any = rep.get("partitions")
    assert isinstance(parts_any, list)
    parts = cast(list[object], parts_any)
    assert parts

    has_rootfs_blob = False
    for p_any in parts:
        if not isinstance(p_any, dict):
            continue
        p = cast(dict[str, object], p_any)
        blob_rel = p.get("blob")
        if not isinstance(blob_rel, str):
            continue
        if "rootfs" in blob_rel:
            has_rootfs_blob = True
            blob_path = ctx.run_dir / blob_rel
            assert blob_path.is_file()
            assert blob_path.read_bytes()[:4] == b"hsqs"
    assert has_rootfs_blob

    roots_rep = cast(
        dict[str, object],
        json.loads((stage_dir / "roots.json").read_text(encoding="utf-8")),
    )
    roots_any = roots_rep.get("roots")
    assert isinstance(roots_any, list)
    roots = cast(list[object], roots_any)
    assert any(isinstance(x, str) and "stages/carving/roots" in x for x in roots)


def test_carving_falls_back_to_signature_scan_without_structure(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    fw = ctx.run_dir / "input" / "firmware.bin"
    off = 123
    _ = fw.write_bytes((b"Z" * off) + b"UBI#" + (b"K" * 4096))

    outcome = CarvingStage(
        firmware_path=fw,
        max_signature_scan_bytes=4096,
        evidence_slice_bytes=1024,
        max_total_bytes=4096,
    ).run(ctx)
    assert outcome.status == "ok"

    stage_dir = ctx.run_dir / "stages" / "carving"
    assert (stage_dir / "partitions.json").is_file()
    assert (stage_dir / "roots.json").is_file()

    evidence_files = list((stage_dir / "evidence").glob("*.bin"))
    assert evidence_files
    assert any(p.read_bytes()[:4] == b"UBI#" for p in evidence_files)

    rep = cast(
        dict[str, object],
        json.loads((stage_dir / "partitions.json").read_text(encoding="utf-8")),
    )
    parts_any = rep.get("partitions")
    assert isinstance(parts_any, list)
    assert parts_any == []

    roots_rep = cast(
        dict[str, object],
        json.loads((stage_dir / "roots.json").read_text(encoding="utf-8")),
    )
    assert roots_rep.get("roots") == []


def test_carving_respects_total_byte_cap(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    fw = ctx.run_dir / "input" / "firmware.bin"
    _ = fw.write_bytes(b"A" * 1024 + b"B" * 1024 + b"C" * 1024)

    structure_dir = ctx.run_dir / "stages" / "structure"
    structure_dir.mkdir(parents=True)
    structure_json = structure_dir / "structure.json"
    mtd = "flash0:1k(a),1k(b),1k(c)"
    _ = structure_json.write_text(
        json.dumps(
            {
                "status": "ok",
                "bootargs": {"raw": [], "terms": {"mtdparts": [mtd]}},
                "dtbs": [],
                "limitations": [],
                "evidence": [],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    cap = 1500
    outcome = CarvingStage(firmware_path=fw, max_total_bytes=cap).run(ctx)
    assert outcome.status == "ok"

    stage_dir = ctx.run_dir / "stages" / "carving"
    blobs = list((stage_dir / "blobs").glob("*.bin"))
    assert blobs

    total = sum(p.stat().st_size for p in blobs)
    assert total <= cap
    bytes_written_any = outcome.details.get("bytes_written")
    assert isinstance(bytes_written_any, int)
    assert bytes_written_any <= cap
