from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import cast

from aiedge.run import analyze_run, create_run
from aiedge.stage import Stage, StageContext, StageOutcome


def _ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    logs_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


def _write_sparse_magic(path: Path) -> None:
    _ = path.write_bytes(bytes.fromhex("3aff26ed"))


def _write_ext4_magic(path: Path) -> None:
    buf = bytearray(1024 + 56 + 2)
    buf[1024 + 56 : 1024 + 56 + 2] = bytes.fromhex("53ef")
    _ = path.write_bytes(bytes(buf))


def _run_ota_fs_stage(ctx: StageContext) -> StageOutcome:
    mod = importlib.import_module("aiedge.ota_fs")
    cls = cast(type[Stage], getattr(mod, "OtaFsStage"))
    return cls().run(ctx)


def test_ota_fs_detects_sparse_ext4_and_unknown(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    parts = ctx.run_dir / "stages" / "ota" / "partitions"
    parts.mkdir(parents=True)

    _write_sparse_magic(parts / "system.img")
    _write_ext4_magic(parts / "vendor.img")
    _ = (parts / "product.img").write_bytes(b"not-a-known-fs")

    out = _run_ota_fs_stage(ctx)
    assert out.status == "ok"

    fs_path = ctx.run_dir / "stages" / "ota" / "fs.json"
    doc = cast(dict[str, object], json.loads(fs_path.read_text(encoding="utf-8")))
    parts_obj = cast(dict[str, object], doc["partitions"])

    assert cast(dict[str, object], parts_obj["system"])["type"] == "android_sparse"
    assert cast(dict[str, object], parts_obj["vendor"])["type"] == "ext4_raw"
    assert cast(dict[str, object], parts_obj["product"])["type"] == "unknown"


def test_ota_fs_handles_missing_images_gracefully(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    parts = ctx.run_dir / "stages" / "ota" / "partitions"
    parts.mkdir(parents=True)

    _write_sparse_magic(parts / "system.img")

    out = _run_ota_fs_stage(ctx)
    assert out.status == "partial"
    assert any("vendor.img" in x for x in out.limitations)
    assert any("product.img" in x for x in out.limitations)

    fs_path = ctx.run_dir / "stages" / "ota" / "fs.json"
    doc = cast(dict[str, object], json.loads(fs_path.read_text(encoding="utf-8")))
    parts_obj = cast(dict[str, object], doc["partitions"])
    assert cast(dict[str, object], parts_obj["vendor"])["exists"] is False
    assert cast(dict[str, object], parts_obj["product"])["exists"] is False


def test_analyze_run_writes_ota_fs_json(tmp_path: Path) -> None:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")

    info = create_run(
        str(fw),
        case_id="case-ota-fs",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    _ = analyze_run(info, time_budget_s=0, no_llm=True)

    fs_path = info.run_dir / "stages" / "ota" / "fs.json"
    assert fs_path.is_file()

    report_obj = cast(
        dict[str, object],
        json.loads(
            (info.run_dir / "report" / "report.json").read_text(encoding="utf-8")
        ),
    )
    assert "ota_fs" in report_obj
