"""firmware_diff.py — Firmware version comparison module for SCOUT.

Compares two analysis runs (old vs. new firmware) and produces three
diff artefacts:

- filesystem_diff.json  — added / removed / modified / permission-changed files
- binary_diff.json      — hardening posture changes for ELF binaries
- security_posture_diff.json — security-relevant config-file line changes

All paths in artefacts are relative to their respective run directory.
Output is fully deterministic (sorted keys, sorted file lists).
"""

from __future__ import annotations

import difflib
import json
import os
import stat
from pathlib import Path
from typing import Any

from .path_safety import assert_under_dir, sha256_file
from .policy import AIEdgePolicyViolation

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_FILES = 10_000
_MAX_CONFIG_FILES = 50
_MAX_CONFIG_LINES = 100

_CONFIG_EXTENSIONS = {".conf", ".ini", ".json", ".xml", ".cfg"}

_SECURITY_KEYWORDS = {
    "password",
    "secret",
    "key",
    "auth",
    "token",
    "ssl",
    "tls",
    "allow",
    "deny",
    "root",
    "admin",
    "permit",
    "cipher",
    "certificate",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _write_json(path: Path, obj: Any) -> None:
    payload = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    path.write_text(payload, encoding="utf-8")


def _is_binary_file(path: Path) -> bool:
    """Return True if the first 512 bytes contain a null byte."""
    try:
        with path.open("rb") as fh:
            chunk = fh.read(512)
        return b"\x00" in chunk
    except OSError:
        return True


def _file_mode_octal(st_mode: int) -> str:
    """Return a 4-digit octal permission string, e.g. '0755'."""
    return oct(stat.S_IMODE(st_mode))[2:].zfill(4)


def _find_rootfs(run_dir: Path) -> Path | None:
    """Locate the extracted rootfs directory inside a run directory.

    Searches ``stages/extraction/`` for any directory whose name starts with
    ``rootfs``, falling back to any subdirectory that contains at least one of
    the canonical Unix top-level directory names.
    """
    extraction_dir = run_dir / "stages" / "extraction"
    if extraction_dir.is_dir():
        # Primary: explicit rootfs* prefix
        candidates = sorted(
            p for p in extraction_dir.iterdir()
            if p.is_dir() and p.name.startswith("rootfs")
        )
        if candidates:
            return candidates[0]
        # Fallback: any dir that looks like a Unix root
        unix_top = {"bin", "etc", "lib", "usr", "var", "sbin"}
        for candidate in sorted(extraction_dir.iterdir()):
            if not candidate.is_dir():
                continue
            children = {p.name for p in candidate.iterdir() if p.is_dir()}
            if children & unix_top:
                return candidate
    return None


def _walk_rootfs(rootfs: Path) -> dict[str, dict[str, Any]]:
    """Walk *rootfs* and return a mapping of relative-path → file metadata.

    Metadata keys: ``abs`` (Path), ``size`` (int), ``mode`` (str).
    Symlinks are skipped; only regular files are included.
    Capped at _MAX_FILES entries.
    """
    result: dict[str, dict[str, Any]] = {}
    for dirpath, _dirs, filenames in os.walk(rootfs, followlinks=False):
        for fname in filenames:
            abs_path = Path(dirpath) / fname
            if not abs_path.is_file() or abs_path.is_symlink():
                continue
            try:
                st = abs_path.stat()
            except OSError:
                continue
            rel = str(abs_path.relative_to(rootfs))
            result[rel] = {
                "abs": abs_path,
                "size": st.st_size,
                "mode": _file_mode_octal(st.st_mode),
            }
            if len(result) >= _MAX_FILES:
                return result
    return result


# ---------------------------------------------------------------------------
# 1. Filesystem diff
# ---------------------------------------------------------------------------


def _build_filesystem_diff(
    old_rootfs: Path | None,
    new_rootfs: Path | None,
    output_dir: Path,
    limitations: list[str],
) -> dict[str, Any]:
    """Produce filesystem_diff.json and return the parsed dict."""

    out_path = output_dir / "filesystem_diff.json"
    assert_under_dir(output_dir, out_path)

    if old_rootfs is None or new_rootfs is None:
        result: dict[str, Any] = {
            "schema_version": "firmware-diff-v1",
            "added": [],
            "removed": [],
            "modified": [],
            "permissions_changed": [],
            "summary": {
                "added": 0,
                "modified": 0,
                "permissions_changed": 0,
                "removed": 0,
                "total_new": 0,
                "total_old": 0,
            },
            "limitations": sorted(set(limitations)),
        }
        _write_json(out_path, result)
        return result

    old_files = _walk_rootfs(old_rootfs)
    new_files = _walk_rootfs(new_rootfs)

    old_keys = set(old_files)
    new_keys = set(new_files)

    added: list[dict[str, Any]] = []
    for rel in sorted(new_keys - old_keys):
        meta = new_files[rel]
        added.append({"mode": meta["mode"], "path": rel, "size": meta["size"]})

    removed: list[dict[str, Any]] = []
    for rel in sorted(old_keys - new_keys):
        meta = old_files[rel]
        removed.append({"path": rel, "size": meta["size"]})

    modified: list[dict[str, Any]] = []
    permissions_changed: list[dict[str, Any]] = []

    for rel in sorted(old_keys & new_keys):
        old_m = old_files[rel]
        new_m = new_files[rel]
        mode_changed = old_m["mode"] != new_m["mode"]

        # Compute hashes only when sizes differ or we need to check content
        old_sha = sha256_file(old_m["abs"])
        new_sha = sha256_file(new_m["abs"])
        content_changed = old_sha != new_sha

        if content_changed:
            entry: dict[str, Any] = {
                "new_sha256": new_sha,
                "new_size": new_m["size"],
                "old_sha256": old_sha,
                "old_size": old_m["size"],
                "path": rel,
            }
            if mode_changed:
                entry["new_mode"] = new_m["mode"]
                entry["old_mode"] = old_m["mode"]
            modified.append(entry)
        elif mode_changed:
            permissions_changed.append(
                {
                    "new_mode": new_m["mode"],
                    "old_mode": old_m["mode"],
                    "path": rel,
                }
            )

    result = {
        "schema_version": "firmware-diff-v1",
        "added": added,
        "removed": removed,
        "modified": modified,
        "permissions_changed": permissions_changed,
        "summary": {
            "added": len(added),
            "modified": len(modified),
            "permissions_changed": len(permissions_changed),
            "removed": len(removed),
            "total_new": len(new_files),
            "total_old": len(old_files),
        },
        "limitations": sorted(set(limitations)),
    }
    _write_json(out_path, result)
    return result


# ---------------------------------------------------------------------------
# 2. Binary hardening diff
# ---------------------------------------------------------------------------


def _load_binary_analysis(run_dir: Path) -> dict[str, dict[str, Any]]:
    """Load ``stages/inventory/binary_analysis.json`` from *run_dir*.

    Returns a mapping of relative-path → hardening dict.  Returns empty dict
    on any read or parse error.
    """
    path = run_dir / "stages" / "inventory" / "binary_analysis.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    mapping: dict[str, dict[str, Any]] = {}
    # Support two common shapes:
    #   { "binaries": [ { "path": "...", "nx": true, ... } ] }
    #   { "path": { "nx": true, ... }, ... }
    if isinstance(data, dict):
        binaries = data.get("binaries")
        if isinstance(binaries, list):
            for entry in binaries:
                if isinstance(entry, dict) and "path" in entry:
                    mapping[entry["path"]] = entry
        else:
            # Top-level keys are paths
            for k, v in data.items():
                if isinstance(v, dict):
                    mapping[k] = v
    return mapping


_HARDENING_FIELDS = ("canary", "nx", "pie", "relro", "stripped")


def _build_binary_diff(
    old_run_dir: Path,
    new_run_dir: Path,
    fs_diff: dict[str, Any],
    output_dir: Path,
    limitations: list[str],
) -> dict[str, Any]:
    """Produce binary_diff.json and return the parsed dict."""

    out_path = output_dir / "binary_diff.json"
    assert_under_dir(output_dir, out_path)

    old_ba = _load_binary_analysis(old_run_dir)
    new_ba = _load_binary_analysis(new_run_dir)

    if not old_ba and not new_ba:
        lims = list(limitations) + [
            "binary_analysis.json not found in either run; binary diff skipped"
        ]
        result: dict[str, Any] = {
            "schema_version": "binary-diff-v1",
            "changes": [],
            "improvements": 0,
            "limitations": sorted(set(lims)),
            "regressions": 0,
        }
        _write_json(out_path, result)
        return result

    # Gather paths that changed content (from filesystem diff)
    modified_paths: set[str] = {
        entry["path"] for entry in fs_diff.get("modified", [])
    }

    changes: list[dict[str, Any]] = []
    total_regressions = 0
    total_improvements = 0

    # Union of all binary paths present in either analysis
    all_paths = sorted(set(old_ba) | set(new_ba))
    for rel in all_paths:
        if rel not in modified_paths and rel in old_ba and rel in new_ba:
            # Not a modified file, skip unless we still want to track it
            pass  # only compare entries present in both when content changed

        old_entry = old_ba.get(rel, {})
        new_entry = new_ba.get(rel, {})

        if not old_entry or not new_entry:
            # Binary added or removed — skip hardening comparison
            continue
        if rel not in modified_paths:
            # Only compare ELF hardening for binaries that actually changed
            continue

        hardening_changes: dict[str, Any] = {}
        file_regressions = 0
        file_improvements = 0

        for field in _HARDENING_FIELDS:
            old_val = old_entry.get(field)
            new_val = new_entry.get(field)
            if old_val == new_val:
                change_label = "unchanged"
            elif _is_hardening_regression(field, old_val, new_val):
                change_label = "regression"
                file_regressions += 1
            else:
                change_label = "improved"
                file_improvements += 1
            hardening_changes[field] = {
                "change": change_label,
                "new": new_val,
                "old": old_val,
            }

        old_size = old_entry.get("size", old_entry.get("size_bytes", 0)) or 0
        new_size = new_entry.get("size", new_entry.get("size_bytes", 0)) or 0

        changes.append(
            {
                "binary": rel,
                "hardening_changes": hardening_changes,
                "regressions": file_regressions,
                "improvements": file_improvements,
                "size_change": new_size - old_size,
            }
        )
        total_regressions += file_regressions
        total_improvements += file_improvements

    # Sort deterministically
    changes.sort(key=lambda x: x["binary"])

    result = {
        "schema_version": "binary-diff-v1",
        "changes": changes,
        "improvements": total_improvements,
        "limitations": sorted(set(limitations)),
        "regressions": total_regressions,
    }
    _write_json(out_path, result)
    return result


def _is_hardening_regression(
    field: str, old_val: Any, new_val: Any
) -> bool:
    """Return True if the transition old_val → new_val is a security regression."""
    if old_val is None or new_val is None:
        return False
    if field == "relro":
        # full > partial > none
        rank = {"full": 2, "partial": 1, "none": 0}
        return rank.get(str(new_val), 0) < rank.get(str(old_val), 0)
    if field == "stripped":
        # stripped=True is not a security regression per se — neutral
        return False
    # For boolean fields (nx, pie, canary): True is protected → False is regression
    if isinstance(old_val, bool) and isinstance(new_val, bool):
        return old_val is True and new_val is False
    return False


# ---------------------------------------------------------------------------
# 3. Config / security posture diff
# ---------------------------------------------------------------------------


def _read_text_lines(path: Path) -> list[str] | None:
    """Read text lines from *path*, returning None on error or binary file."""
    if _is_binary_file(path):
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        return text.splitlines(keepends=True)
    except OSError:
        return None


def _security_relevant_lines(diff_lines: list[str]) -> list[dict[str, str]]:
    """Return lines from a unified diff that contain security keywords."""
    hits: list[dict[str, str]] = []
    for line in diff_lines:
        if not line.startswith(("+", "-")):
            continue
        lower = line.lower()
        for kw in _SECURITY_KEYWORDS:
            if kw in lower:
                hits.append({"keyword": kw, "line": line.rstrip("\n")})
                break  # one hit per line
    return hits


def _build_security_posture_diff(
    old_rootfs: Path | None,
    new_rootfs: Path | None,
    fs_diff: dict[str, Any],
    output_dir: Path,
    limitations: list[str],
) -> dict[str, Any]:
    """Produce security_posture_diff.json and return the parsed dict."""

    out_path = output_dir / "security_posture_diff.json"
    assert_under_dir(output_dir, out_path)

    config_changes: list[dict[str, Any]] = []
    regressions: list[dict[str, Any]] = []

    # Permission regressions on sensitive paths
    sensitive_suffixes = ("shadow", "passwd", "sudoers", "shadow-", "gshadow")
    for entry in fs_diff.get("permissions_changed", []):
        rel = entry["path"]
        basename = Path(rel).name
        if any(basename == s or rel.endswith("/" + s) for s in sensitive_suffixes):
            regressions.append(
                {
                    "detail": f"{entry['old_mode']} \u2192 {entry['new_mode']}",
                    "file": rel,
                    "type": "permissions_changed",
                }
            )

    if old_rootfs is None or new_rootfs is None:
        lims = list(limitations)
        result: dict[str, Any] = {
            "schema_version": "security-posture-diff-v1",
            "config_changes": config_changes,
            "limitations": sorted(set(lims)),
            "regressions": regressions,
        }
        _write_json(out_path, result)
        return result

    # Collect modified config files
    modified_paths: list[str] = [
        entry["path"]
        for entry in fs_diff.get("modified", [])
        if Path(entry["path"]).suffix in _CONFIG_EXTENSIONS
    ]

    # Also check added config files as security-relevant (new attack surface)
    added_paths: list[str] = [
        entry["path"]
        for entry in fs_diff.get("added", [])
        if Path(entry["path"]).suffix in _CONFIG_EXTENSIONS
    ]

    # Sort by size descending (largest configs first), cap at _MAX_CONFIG_FILES
    def _size_key(rel: str) -> int:
        p = new_rootfs / rel
        try:
            return p.stat().st_size
        except OSError:
            return 0

    modified_paths.sort(key=_size_key, reverse=True)
    modified_paths = modified_paths[:_MAX_CONFIG_FILES]

    for rel in modified_paths:
        old_path = old_rootfs / rel
        new_path = new_rootfs / rel
        old_lines = _read_text_lines(old_path) if old_path.is_file() else []
        new_lines = _read_text_lines(new_path) if new_path.is_file() else []
        if old_lines is None or new_lines is None:
            continue

        diff_lines = list(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile=f"old/{rel}",
                tofile=f"new/{rel}",
                n=0,
            )
        )
        # Cap diff output
        diff_lines = diff_lines[:_MAX_CONFIG_LINES]

        sec_lines = _security_relevant_lines(diff_lines)
        total_changed = sum(
            1 for ln in diff_lines if ln.startswith(("+", "-"))
            and not ln.startswith(("+++", "---"))
        )

        if not sec_lines and total_changed == 0:
            continue

        config_changes.append(
            {
                "file": rel,
                "security_relevant_lines": sec_lines,
                "total_lines_changed": total_changed,
            }
        )

    # Sort deterministically
    config_changes.sort(key=lambda x: x["file"])
    regressions.sort(key=lambda x: (x["file"], x["type"]))

    result = {
        "schema_version": "security-posture-diff-v1",
        "config_changes": config_changes,
        "limitations": sorted(set(limitations)),
        "regressions": regressions,
    }
    _write_json(out_path, result)
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compare_firmware_runs(
    old_run_dir: Path,
    new_run_dir: Path,
    output_dir: Path,
) -> dict[str, Any]:
    """Compare two firmware analysis runs and generate diff reports.

    Args:
        old_run_dir: Path to the older run directory.
        new_run_dir: Path to the newer run directory.
        output_dir: Path to write diff artefacts.

    Returns:
        Summary dict with diff statistics and artefact paths.

    Raises:
        AIEdgePolicyViolation: If *output_dir* is not contained within a
            safe parent or path traversal is attempted.
    """
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    # Validate output paths stay under output_dir
    for artefact_name in (
        "filesystem_diff.json",
        "binary_diff.json",
        "security_posture_diff.json",
    ):
        assert_under_dir(output_dir, output_dir / artefact_name)

    limitations: list[str] = []

    # Locate rootfs directories
    old_rootfs = _find_rootfs(old_run_dir)
    new_rootfs = _find_rootfs(new_run_dir)

    if old_rootfs is None:
        limitations.append(
            f"rootfs not found in old run: {old_run_dir}/stages/extraction/"
        )
    if new_rootfs is None:
        limitations.append(
            f"rootfs not found in new run: {new_run_dir}/stages/extraction/"
        )

    # --- Phase 1: filesystem diff ---
    fs_diff = _build_filesystem_diff(
        old_rootfs, new_rootfs, output_dir, list(limitations)
    )

    # --- Phase 2: binary hardening diff ---
    bin_diff = _build_binary_diff(
        old_run_dir, new_run_dir, fs_diff, output_dir, list(limitations)
    )

    # --- Phase 3: config / security posture diff ---
    sec_diff = _build_security_posture_diff(
        old_rootfs, new_rootfs, fs_diff, output_dir, list(limitations)
    )

    summary: dict[str, Any] = {
        "artefacts": {
            "binary_diff": str(output_dir / "binary_diff.json"),
            "filesystem_diff": str(output_dir / "filesystem_diff.json"),
            "security_posture_diff": str(output_dir / "security_posture_diff.json"),
        },
        "binary_hardening": {
            "changes": len(bin_diff.get("changes", [])),
            "improvements": bin_diff.get("improvements", 0),
            "regressions": bin_diff.get("regressions", 0),
        },
        "filesystem": fs_diff.get("summary", {}),
        "limitations": sorted(set(limitations)),
        "old_run_dir": str(old_run_dir),
        "new_run_dir": str(new_run_dir),
        "security_posture": {
            "config_files_changed": len(sec_diff.get("config_changes", [])),
            "regressions": len(sec_diff.get("regressions", [])),
        },
    }
    return summary
