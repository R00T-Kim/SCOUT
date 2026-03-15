"""Tests for symlink containment guards preventing host FS leakage."""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def _make_run_dir(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    return run_dir


class TestRelToRunDir:
    def test_path_inside_run_dir(self, tmp_path: Path) -> None:
        from aiedge.extraction import _rel_to_run_dir
        run_dir = _make_run_dir(tmp_path)
        inner = run_dir / "stages" / "extraction"
        inner.mkdir(parents=True)
        result = _rel_to_run_dir(run_dir, inner)
        assert result == "stages/extraction"

    def test_path_outside_run_dir_returns_sentinel(self, tmp_path: Path) -> None:
        from aiedge.extraction import _rel_to_run_dir
        run_dir = _make_run_dir(tmp_path)
        outside = tmp_path / "other"
        outside.mkdir()
        result = _rel_to_run_dir(run_dir, outside)
        assert result == "<outside_run_dir>"

    def test_symlink_escaping_run_dir_returns_sentinel(self, tmp_path: Path) -> None:
        from aiedge.extraction import _rel_to_run_dir
        run_dir = _make_run_dir(tmp_path)
        outside = tmp_path / "host_etc"
        outside.mkdir()
        link = run_dir / "etc_link"
        link.symlink_to(outside)
        result = _rel_to_run_dir(run_dir, link)
        assert result == "<outside_run_dir>"


class TestFirmwareProfileContainment:
    def test_probe_is_dir_rejects_absolute_symlink(self, tmp_path: Path) -> None:
        from aiedge.firmware_profile import _probe_is_dir
        run_dir = _make_run_dir(tmp_path)
        outside = tmp_path / "host_dir"
        outside.mkdir()
        link = run_dir / "escape_link"
        link.symlink_to(outside)
        errors: list[dict] = []
        limitations: list[str] = []
        assert _probe_is_dir(link, run_dir=run_dir, errors=errors, limitations=limitations, op="test") is False

    def test_probe_is_dir_accepts_internal_symlink(self, tmp_path: Path) -> None:
        from aiedge.firmware_profile import _probe_is_dir
        run_dir = _make_run_dir(tmp_path)
        target = run_dir / "real_dir"
        target.mkdir()
        link = run_dir / "internal_link"
        link.symlink_to(target)
        errors: list[dict] = []
        limitations: list[str] = []
        assert _probe_is_dir(link, run_dir=run_dir, errors=errors, limitations=limitations, op="test") is True

    def test_find_rootfs_rejects_symlinked_etc(self, tmp_path: Path) -> None:
        from aiedge.firmware_profile import _find_rootfs_candidates
        run_dir = _make_run_dir(tmp_path)
        extracted = run_dir / "stages" / "extraction" / "_fw.extracted"
        fake_root = extracted / "rootfs"
        fake_root.mkdir(parents=True)
        # etc is a symlink to outside run_dir
        outside_etc = tmp_path / "host_etc"
        outside_etc.mkdir()
        (fake_root / "etc").symlink_to(outside_etc)
        (fake_root / "bin").mkdir()
        errors: list[dict] = []
        limitations: list[str] = []
        candidates = _find_rootfs_candidates(extracted, run_dir, errors=errors, limitations=limitations)
        # The fake_root should NOT be a candidate because etc resolves outside run_dir
        assert len(candidates) == 0


class TestInventoryContainment:
    def test_resolve_or_record_rejects_outside_path(self, tmp_path: Path) -> None:
        from aiedge.inventory import _resolve_or_record
        run_dir = _make_run_dir(tmp_path)
        outside = tmp_path / "host_file"
        outside.touch()
        link = run_dir / "escape"
        link.symlink_to(outside)
        errors: list[dict] = []
        result = _resolve_or_record(run_dir=run_dir, path=link, errors=errors, op="test")
        assert result is None

    def test_is_dir_safe_rejects_absolute_symlink(self, tmp_path: Path) -> None:
        from aiedge.inventory import _find_rootfs_candidates
        run_dir = _make_run_dir(tmp_path)
        extracted = run_dir / "stages" / "extraction" / "_fw.extracted"
        # Use a name that does NOT end with "rootfs" or "-root" to avoid
        # the name-based fallback in looks_like_rootfs().
        fake_root = extracted / "firmware_fs"
        fake_root.mkdir(parents=True)
        outside_etc = tmp_path / "host_etc"
        outside_etc.mkdir()
        (fake_root / "etc").symlink_to(outside_etc)
        (fake_root / "bin").mkdir()
        errors: list[dict] = []
        candidates, _ = _find_rootfs_candidates(extracted, run_dir=run_dir, errors=errors)
        # etc resolves outside run_dir so is_dir_safe rejects it;
        # without etc the directory does not look like a rootfs.
        assert len(candidates) == 0
