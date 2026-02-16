from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import cast

import pytest

from aiedge.ota import OtaStage, discover_ota_candidates
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


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    with io.BytesIO() as bio:
        with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, data in entries.items():
                zf.writestr(name, data)
        return bio.getvalue()


def test_ota_stage_discovers_direct_payload_and_writes_artifact(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    fw = ctx.run_dir / "input" / "firmware.bin"
    _ = fw.write_bytes(_zip_bytes({"payload.bin": b"A" * 32}))

    out = OtaStage(fw, source_input_path="update.zip").run(ctx)
    assert out.status == "ok"

    ota_json = ctx.run_dir / "stages" / "ota" / "ota.json"
    assert ota_json.is_file()

    obj = cast(dict[str, object], json.loads(ota_json.read_text(encoding="utf-8")))
    chosen = cast(dict[str, object], obj["chosen"])
    assert chosen["archive_path"] == "<root>"
    assert chosen["payload_bin_path"] == "payload.bin"
    assert chosen["payload_bin_size"] == 32


def test_ota_discovery_finds_nested_zip_payload_streaming(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inner = _zip_bytes({"payload.bin": b"B" * 11})
    top = tmp_path / "update.zip"
    _ = top.write_bytes(_zip_bytes({"BYDUpdatePackage/UpdateFull.zip": inner}))

    def _forbid_read(
        _self: zipfile.ZipFile, name: object, *_args: object, **_kwargs: object
    ) -> bytes:
        raise AssertionError(f"ZipFile.read must not be used for nested scan: {name!r}")

    monkeypatch.setattr(zipfile.ZipFile, "read", _forbid_read)

    rep = discover_ota_candidates(top)
    chosen = cast(dict[str, object], rep["chosen"])
    assert chosen["archive_path"] == "BYDUpdatePackage/UpdateFull.zip"
    assert chosen["payload_bin_path"] == "payload.bin"
    assert chosen["payload_bin_size"] == 11


def test_ota_discovery_finds_multi_depth_nested_payload_streaming(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inner2 = _zip_bytes({"payload.bin": b"C" * 13})
    inner1 = _zip_bytes({"middle/update.zip": inner2})
    top = tmp_path / "update.zip"
    _ = top.write_bytes(_zip_bytes({"BYDUpdatePackage/UpdateFull.zip": inner1}))

    def _forbid_read(
        _self: zipfile.ZipFile, name: object, *_args: object, **_kwargs: object
    ) -> bytes:
        raise AssertionError(f"ZipFile.read must not be used for nested scan: {name!r}")

    monkeypatch.setattr(zipfile.ZipFile, "read", _forbid_read)

    rep = discover_ota_candidates(top)
    chosen = cast(dict[str, object], rep["chosen"])
    assert (
        chosen["archive_path"] == "BYDUpdatePackage/UpdateFull.zip!/middle/update.zip"
    )
    assert chosen["payload_bin_path"] == "payload.bin"
    assert chosen["payload_bin_size"] == 13


def test_ota_discovery_selects_largest_payload_deterministically(
    tmp_path: Path,
) -> None:
    small = _zip_bytes({"payload.bin": b"S" * 10})
    large = _zip_bytes({"payload.bin": b"L" * 80})
    top = tmp_path / "update.zip"
    _ = top.write_bytes(
        _zip_bytes(
            {
                "folder/a.zip": small,
                "folder/b.zip": large,
            }
        )
    )

    rep = discover_ota_candidates(top)
    candidates = cast(list[dict[str, object]], rep["candidates"])
    assert candidates[0]["archive_path"] == "folder/b.zip"
    assert candidates[1]["archive_path"] == "folder/a.zip"

    chosen = cast(dict[str, object], rep["chosen"])
    assert chosen["archive_path"] == "folder/b.zip"
    assert chosen["payload_bin_size"] == 80


def test_ota_discovery_rejects_zip_slip_members(tmp_path: Path) -> None:
    top = tmp_path / "update.zip"
    _ = top.write_bytes(_zip_bytes({"../payload.bin": b"X" * 7}))

    rep = discover_ota_candidates(top)
    assert rep["chosen"] is None
    refusals = cast(list[str], rep["refusal_reasons"])
    assert any("zip-slip path rejected" in x for x in refusals)
