"""Tests for path_safety.py — security-critical path containment and hashing."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aiedge.path_safety import (
    assert_under_dir,
    rel_to_run_dir,
    sha256_file,
    sha256_text,
)
from aiedge.policy import AIEdgePolicyViolation


# ---------------------------------------------------------------------------
# assert_under_dir
# ---------------------------------------------------------------------------

def test_valid_path_inside_dir(tmp_path: Path):
    """Normal case: target is inside base_dir."""
    target = tmp_path / "stages" / "inventory" / "output.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.touch()
    # Should not raise
    assert_under_dir(tmp_path, target)


def test_path_traversal_blocked(tmp_path: Path):
    """.. traversal must be blocked."""
    target = tmp_path / "stages" / ".." / ".." / "etc" / "passwd"
    with pytest.raises(AIEdgePolicyViolation):
        assert_under_dir(tmp_path, target)


def test_absolute_escape_blocked(tmp_path: Path):
    """Absolute path outside base_dir must be blocked."""
    with pytest.raises(AIEdgePolicyViolation):
        assert_under_dir(tmp_path, Path("/etc/passwd"))


def test_symlink_escape_blocked(tmp_path: Path):
    """Symlink pointing outside base_dir must be blocked."""
    outside = tmp_path.parent / "outside_target"
    outside.mkdir(exist_ok=True)
    link = tmp_path / "sneaky_link"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Cannot create symlinks in this environment")
    with pytest.raises(AIEdgePolicyViolation):
        assert_under_dir(tmp_path, link / "evil.txt")


def test_nested_deep_path_allowed(tmp_path: Path):
    """Deeply nested paths within base_dir should be fine."""
    target = tmp_path / "a" / "b" / "c" / "d" / "e" / "file.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.touch()
    assert_under_dir(tmp_path, target)


def test_base_dir_itself_allowed(tmp_path: Path):
    """Target equal to base_dir should be allowed (is_relative_to self)."""
    assert_under_dir(tmp_path, tmp_path)


def test_relative_path_resolved(tmp_path: Path):
    """Relative components like ./foo should resolve correctly."""
    target = tmp_path / "." / "stages" / "output.json"
    (tmp_path / "stages").mkdir(exist_ok=True)
    (tmp_path / "stages" / "output.json").touch()
    assert_under_dir(tmp_path, target)


# ---------------------------------------------------------------------------
# rel_to_run_dir
# ---------------------------------------------------------------------------

def test_rel_to_run_dir_normal(tmp_path: Path):
    target = tmp_path / "stages" / "inventory" / "stage.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.touch()
    result = rel_to_run_dir(tmp_path, target)
    assert result == os.path.join("stages", "inventory", "stage.json")


def test_rel_to_run_dir_outside_returns_absolute(tmp_path: Path):
    outside = Path("/tmp/not_inside_run")
    result = rel_to_run_dir(tmp_path, outside)
    # Should return the absolute path string, not crash
    assert "/" in result


# ---------------------------------------------------------------------------
# sha256_file
# ---------------------------------------------------------------------------

def test_sha256_file_deterministic(tmp_path: Path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"hello world")
    h1 = sha256_file(f)
    h2 = sha256_file(f)
    assert h1 == h2
    assert len(h1) == 64  # hex SHA-256


def test_sha256_file_known_value(tmp_path: Path):
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    # SHA-256 of empty string
    assert sha256_file(f) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_sha256_file_different_content(tmp_path: Path):
    f1 = tmp_path / "a.bin"
    f2 = tmp_path / "b.bin"
    f1.write_bytes(b"aaa")
    f2.write_bytes(b"bbb")
    assert sha256_file(f1) != sha256_file(f2)


# ---------------------------------------------------------------------------
# sha256_text
# ---------------------------------------------------------------------------

def test_sha256_text_deterministic():
    assert sha256_text("hello") == sha256_text("hello")
    assert len(sha256_text("hello")) == 64


def test_sha256_text_empty():
    assert sha256_text("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_sha256_text_unicode():
    """Non-ASCII text should hash without errors."""
    result = sha256_text("한글 테스트 🔒")
    assert len(result) == 64


def test_sha256_text_different_inputs():
    assert sha256_text("abc") != sha256_text("def")
