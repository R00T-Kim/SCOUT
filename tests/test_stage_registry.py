from __future__ import annotations

from pathlib import Path

from aiedge.attack_surface import AttackSurfaceStage
from aiedge.stage_registry import stage_factories


class _Info:
    def __init__(self, firmware_dest: Path) -> None:
        self._firmware_dest = firmware_dest

    @property
    def firmware_dest(self) -> Path:
        return self._firmware_dest


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
