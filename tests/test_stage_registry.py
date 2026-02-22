from __future__ import annotations

from pathlib import Path

from aiedge.attack_surface import AttackSurfaceStage
from aiedge.endpoints import EndpointsStage
from aiedge.extraction import ExtractionStage
from aiedge.inventory import InventoryStage
from aiedge.stage_registry import stage_factories


class _Info:
    def __init__(
        self,
        firmware_dest: Path,
        manifest_path: Path | None = None,
        *,
        input_size_bytes: int = 0,
    ) -> None:
        self._firmware_dest = firmware_dest
        self._manifest_path = manifest_path
        self._input_size_bytes = int(input_size_bytes)

    @property
    def firmware_dest(self) -> Path:
        return self._firmware_dest

    @property
    def manifest_path(self) -> Path | None:
        return self._manifest_path

    @property
    def input_size_bytes(self) -> int:
        return self._input_size_bytes


def test_attack_surface_stage_factory_uses_env_overrides(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("AIEDGE_ATTACK_SURFACE_MAX_ITEMS", "1234")
    monkeypatch.setenv("AIEDGE_ATTACK_SURFACE_MAX_UNKNOWNS", "987")

    factory = stage_factories()["attack_surface"]
    stage = factory(_Info(tmp_path / "fw.bin"), None, lambda: 3600.0, False)

    assert isinstance(stage, AttackSurfaceStage)
    assert stage.max_items == 1234
    assert stage.max_unknowns == 987


def test_attack_surface_stage_factory_clamps_invalid_env_values(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("AIEDGE_ATTACK_SURFACE_MAX_ITEMS", "bad")
    monkeypatch.setenv("AIEDGE_ATTACK_SURFACE_MAX_UNKNOWNS", "999999")

    factory = stage_factories()["attack_surface"]
    stage = factory(_Info(tmp_path / "fw.bin"), None, lambda: 3600.0, False)

    assert isinstance(stage, AttackSurfaceStage)
    assert stage.max_items == 500
    assert stage.max_unknowns == 10000


def test_extraction_stage_factory_loads_rootfs_path_from_manifest(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "manifest.json"
    rootfs = tmp_path / "pre_extracted_rootfs"
    _ = rootfs.mkdir(parents=True, exist_ok=True)
    _ = manifest_path.write_text(
        (
            "{\n"
            '  "rootfs_input_path": "'
            + str(rootfs.resolve())
            + '"\n'
            "}\n"
        ),
        encoding="utf-8",
    )

    factory = stage_factories()["extraction"]
    stage = factory(
        _Info(tmp_path / "fw.bin", manifest_path),
        None,
        lambda: 3600.0,
        False,
    )

    assert isinstance(stage, ExtractionStage)
    assert stage.provided_rootfs_dir == rootfs.resolve()


def test_inventory_and_endpoints_factories_use_manifest_scan_limits(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "manifest.json"
    _ = manifest_path.write_text(
        (
            "{\n"
            '  "scan_limits": {\n'
            '    "max_files": 7777,\n'
            '    "max_matches": 22222\n'
            "  }\n"
            "}\n"
        ),
        encoding="utf-8",
    )

    info = _Info(tmp_path / "fw.bin", manifest_path, input_size_bytes=8 * 1024 * 1024)
    inv_stage = stage_factories()["inventory"](info, None, lambda: 3600.0, False)
    endpoints_stage = stage_factories()["endpoints"](info, None, lambda: 3600.0, False)

    assert isinstance(inv_stage, InventoryStage)
    assert inv_stage.string_scan_max_files == 7777
    assert inv_stage.string_scan_max_total_matches == 22222

    assert isinstance(endpoints_stage, EndpointsStage)
    assert endpoints_stage.max_files == 7777
    assert endpoints_stage.max_total_matches == 22222


def test_inventory_and_endpoints_factories_auto_scale_from_input_size(
    tmp_path: Path,
) -> None:
    info = _Info(tmp_path / "fw.bin", None, input_size_bytes=200 * 1024 * 1024)
    inv_stage = stage_factories()["inventory"](info, None, lambda: 3600.0, False)
    endpoints_stage = stage_factories()["endpoints"](info, None, lambda: 3600.0, False)

    assert isinstance(inv_stage, InventoryStage)
    assert inv_stage.string_scan_max_files == 12000
    assert inv_stage.string_scan_max_total_matches == 30000

    assert isinstance(endpoints_stage, EndpointsStage)
    assert endpoints_stage.max_files == 12000
    assert endpoints_stage.max_total_matches == 30000
