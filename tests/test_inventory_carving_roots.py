from __future__ import annotations

import json
import os
from errno import EACCES
from pathlib import Path
from typing import cast

import pytest

import aiedge.inventory as inventory_mod
from aiedge.inventory import InventoryStage
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


def _read_inventory(path: Path) -> dict[str, object]:
    raw = cast(object, json.loads(path.read_text(encoding="utf-8")))
    assert isinstance(raw, dict)
    return cast(dict[str, object], raw)


def test_inventory_uses_carving_roots_when_extraction_missing(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)

    root_dir = ctx.run_dir / "stages" / "carving" / "roots" / "root0"
    (root_dir / "etc").mkdir(parents=True)
    _ = (root_dir / "etc" / "passwd").write_text("root:x:0:0\n")

    roots_json = ctx.run_dir / "stages" / "carving" / "roots.json"
    roots_json.parent.mkdir(parents=True, exist_ok=True)
    _ = roots_json.write_text(
        json.dumps({"roots": ["stages/carving/roots/root0"]}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    outcome = InventoryStage().run(ctx)
    assert outcome.status == "ok"

    inv_path = ctx.run_dir / "stages" / "inventory" / "inventory.json"
    assert inv_path.is_file()
    inv = _read_inventory(inv_path)
    assert inv.get("status") == "ok"

    roots_obj = inv.get("roots")
    assert isinstance(roots_obj, list)
    roots = cast(list[object], roots_obj)
    assert roots and roots[0] == "stages/carving/roots/root0"


def test_inventory_orders_carving_roots_before_extraction_roots(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)

    carving_root = ctx.run_dir / "stages" / "carving" / "roots" / "root0"
    (carving_root / "etc").mkdir(parents=True)
    _ = (carving_root / "etc" / "passwd").write_text("root:x:0:0\n")
    roots_json = ctx.run_dir / "stages" / "carving" / "roots.json"
    roots_json.parent.mkdir(parents=True, exist_ok=True)
    _ = roots_json.write_text(
        json.dumps({"roots": ["stages/carving/roots/root0"]}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    extracted_root = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "fs-root"
    )
    (extracted_root / "etc").mkdir(parents=True)
    _ = (extracted_root / "etc" / "passwd").write_text("root:x:0:0\n")

    outcome = InventoryStage().run(ctx)
    assert outcome.status == "ok"

    inv_path = ctx.run_dir / "stages" / "inventory" / "inventory.json"
    inv = _read_inventory(inv_path)
    roots_obj = inv.get("roots")
    assert isinstance(roots_obj, list)
    roots = cast(list[object], roots_obj)

    assert roots[0] == "stages/carving/roots/root0"
    assert any(isinstance(item, str) and "stages/extraction" in item for item in roots)


def test_inventory_ignores_invalid_carving_roots_json(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)

    roots_json = ctx.run_dir / "stages" / "carving" / "roots.json"
    roots_json.parent.mkdir(parents=True, exist_ok=True)
    _ = roots_json.write_text("not-json\n", encoding="utf-8")

    extracted_root = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "fs-root"
    )
    (extracted_root / "etc").mkdir(parents=True)
    _ = (extracted_root / "etc" / "passwd").write_text("root:x:0:0\n")

    outcome = InventoryStage().run(ctx)
    assert outcome.status == "ok"
    assert any("carving roots.json" in x for x in outcome.limitations)


def test_inventory_falls_back_when_ota_roots_have_no_files(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)

    carving_root = ctx.run_dir / "stages" / "carving" / "roots" / "root0"
    (carving_root / "etc").mkdir(parents=True)
    _ = (carving_root / "etc" / "passwd").write_text("root:x:0:0\n")
    carving_roots_json = ctx.run_dir / "stages" / "carving" / "roots.json"
    carving_roots_json.parent.mkdir(parents=True, exist_ok=True)
    _ = carving_roots_json.write_text(
        json.dumps({"roots": ["stages/carving/roots/root0"]}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    ota_root = ctx.run_dir / "stages" / "ota" / "roots" / "root0"
    ota_root.mkdir(parents=True)
    ota_roots_json = ctx.run_dir / "stages" / "ota" / "roots.json"
    ota_roots_json.parent.mkdir(parents=True, exist_ok=True)
    _ = ota_roots_json.write_text(
        json.dumps({"roots": ["stages/ota/roots/root0"]}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    outcome = InventoryStage().run(ctx)
    assert outcome.status == "ok"
    assert any(
        "OTA roots are present but contain no files" in x for x in outcome.limitations
    )

    inv_path = ctx.run_dir / "stages" / "inventory" / "inventory.json"
    inv = _read_inventory(inv_path)
    roots_obj = inv.get("roots")
    assert isinstance(roots_obj, list)
    roots = cast(list[object], roots_obj)
    assert roots and roots[0] == "stages/carving/roots/root0"


def test_inventory_prefers_ota_roots_when_they_have_files(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)

    carving_root = ctx.run_dir / "stages" / "carving" / "roots" / "root0"
    (carving_root / "etc").mkdir(parents=True)
    _ = (carving_root / "etc" / "passwd").write_text("root:x:0:0\n")
    carving_roots_json = ctx.run_dir / "stages" / "carving" / "roots.json"
    carving_roots_json.parent.mkdir(parents=True, exist_ok=True)
    _ = carving_roots_json.write_text(
        json.dumps({"roots": ["stages/carving/roots/root0"]}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    ota_root = ctx.run_dir / "stages" / "ota" / "roots" / "root0"
    (ota_root / "etc").mkdir(parents=True)
    _ = (ota_root / "etc" / "passwd").write_text("root:x:0:0\n")
    ota_roots_json = ctx.run_dir / "stages" / "ota" / "roots.json"
    ota_roots_json.parent.mkdir(parents=True, exist_ok=True)
    _ = ota_roots_json.write_text(
        json.dumps({"roots": ["stages/ota/roots/root0"]}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    outcome = InventoryStage().run(ctx)
    assert outcome.status == "ok"

    inv_path = ctx.run_dir / "stages" / "inventory" / "inventory.json"
    inv = _read_inventory(inv_path)
    roots_obj = inv.get("roots")
    assert isinstance(roots_obj, list)
    roots = cast(list[object], roots_obj)
    assert roots and roots[0] == "stages/ota/roots/root0"
    assert "stages/carving/roots/root0" not in roots


def test_inventory_handles_broken_symlink_in_extracted_tree(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)

    extracted_root = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "fs-root"
    )
    etc_dir = extracted_root / "etc"
    etc_dir.mkdir(parents=True)
    _ = (etc_dir / "passwd").write_text("root:x:0:0\n")
    (etc_dir / "broken-link").symlink_to(etc_dir / "missing-target")

    outcome = InventoryStage().run(ctx)
    assert outcome.status == "ok"

    inv_path = ctx.run_dir / "stages" / "inventory" / "inventory.json"
    inv = _read_inventory(inv_path)
    assert inv.get("status") == "ok"

    summary_obj = inv.get("summary")
    assert isinstance(summary_obj, dict)
    summary = cast(dict[str, object], summary_obj)
    assert summary.get("files") == 1


def test_inventory_permission_denied_dir_is_best_effort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path)

    extracted_root = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "fs-root"
    )
    etc_dir = extracted_root / "etc"
    blocked_dir = extracted_root / "secret"
    etc_dir.mkdir(parents=True)
    blocked_dir.mkdir(parents=True)
    _ = (etc_dir / "passwd").write_text("root:x:0:0\n", encoding="utf-8")
    _ = (blocked_dir / "private.txt").write_text("do-not-read\n", encoding="utf-8")

    blocked_dir.chmod(0)
    real_scandir = os.scandir

    def _scandir_with_perm_denied(path: object):
        path_s = os.fspath(cast(os.PathLike[str] | str, path))
        if Path(path_s) == blocked_dir:
            raise PermissionError(EACCES, "Permission denied", str(blocked_dir))
        return real_scandir(path_s)

    monkeypatch.setattr(os, "scandir", _scandir_with_perm_denied)
    try:
        outcome = InventoryStage().run(ctx)
    finally:
        blocked_dir.chmod(0o700)

    assert outcome.status in {"partial", "ok"}
    assert outcome.status != "failed"

    inv_path = ctx.run_dir / "stages" / "inventory" / "inventory.json"
    assert inv_path.is_file()
    inv = _read_inventory(inv_path)

    assert inv.get("status") in {"partial", "ok"}
    errors_obj = inv.get("errors")
    assert isinstance(errors_obj, list)
    errors = cast(list[object], errors_obj)
    assert errors

    perm_errors: list[dict[str, object]] = []
    for item in errors:
        if not isinstance(item, dict):
            continue
        item_d = cast(dict[str, object], item)
        if item_d.get("op") == "scandir" and item_d.get("errno") == EACCES:
            perm_errors.append(item_d)
    assert perm_errors
    assert all(
        isinstance(item.get("path"), str)
        and not cast(str, item.get("path")).startswith("/")
        for item in perm_errors
    )
    assert all(
        isinstance(item.get("error"), str)
        and "/home/" not in cast(str, item.get("error"))
        and not cast(str, item.get("error")).startswith("/")
        for item in perm_errors
    )

    coverage_obj = inv.get("coverage_metrics")
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
        assert key in coverage


def test_inventory_no_roots_still_writes_string_hits(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)

    outcome = InventoryStage().run(ctx)
    assert outcome.status == "partial"

    inv_path = ctx.run_dir / "stages" / "inventory" / "inventory.json"
    string_hits_path = ctx.run_dir / "stages" / "inventory" / "string_hits.json"
    assert inv_path.is_file()
    assert string_hits_path.is_file()

    string_hits = cast(
        dict[str, object], json.loads(string_hits_path.read_text(encoding="utf-8"))
    )
    counts_obj = string_hits.get("counts")
    assert isinstance(counts_obj, dict)
    counts = cast(dict[str, object], counts_obj)
    assert counts == {
        "credential_words": 0,
        "email": 0,
        "ipv4": 0,
        "url": 0,
    }
    samples_obj = string_hits.get("samples")
    assert isinstance(samples_obj, list)
    assert samples_obj == []


def test_inventory_exception_recovery_still_writes_string_hits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path)

    def _raise_runtime_error(_: Path) -> tuple[list[Path], list[str]]:
        raise RuntimeError(f"boom at {ctx.run_dir}/outside")

    monkeypatch.setattr(inventory_mod, "_load_ota_roots", _raise_runtime_error)

    outcome = InventoryStage().run(ctx)
    assert outcome.status == "partial"

    inv_path = ctx.run_dir / "stages" / "inventory" / "inventory.json"
    string_hits_path = ctx.run_dir / "stages" / "inventory" / "string_hits.json"
    assert inv_path.is_file()
    assert string_hits_path.is_file()

    inv = _read_inventory(inv_path)
    assert inv.get("reason") == "inventory_recovered_from_exception"
    errors_obj = inv.get("errors")
    assert isinstance(errors_obj, list)
    errors = cast(list[object], errors_obj)
    assert errors
    for err in errors:
        assert isinstance(err, dict)
        err_d = cast(dict[str, object], err)
        path_obj = err_d.get("path")
        assert isinstance(path_obj, str)
        assert not path_obj.startswith("/")
        error_obj = err_d.get("error")
        assert isinstance(error_obj, str)
        assert "/home/" not in error_obj
        assert not error_obj.startswith("/")
