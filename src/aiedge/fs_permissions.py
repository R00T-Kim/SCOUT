from __future__ import annotations

"""fs_permissions.py — Filesystem permission auditing for firmware rootfs.

Scans extracted firmware rootfs directories for permission-based security
issues: world-writable files/directories, SUID/SGID binaries, and sensitive
files with overly permissive modes.

Usage::

    from .fs_permissions import analyze_fs_permissions
"""

import json
import os
import re
import stat
from pathlib import Path

from .path_safety import assert_under_dir, sha256_file, sha256_text
from .policy import AIEdgePolicyViolation  # noqa: F401 (re-exported via import)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_ROOTFS_ROOTS = 3
_MAX_FILES_PER_ROOTFS = 10_000

# SUID binaries considered safe in typical embedded/Linux firmware.
# Anything with SUID *not* in this set is flagged as unexpected.
_KNOWN_SAFE_SUID: frozenset[str] = frozenset(
    [
        "su",
        "sudo",
        "ping",
        "ping6",
        "passwd",
        "mount",
        "umount",
        "busybox",
        "newgrp",
        "chsh",
        "chfn",
        "gpasswd",
        "wall",
        "write",
        "at",
        "crontab",
        "ssh",
        "ssh-agent",
        "pkexec",
        "unix_chkpwd",
        "Xorg",
        "Xwayland",
        "screen",
    ]
)

# Patterns that, when found in a filename, indicate a private key file.
# We verify actual content for the PEM header before flagging.
_PRIVKEY_SUFFIXES: tuple[str, ...] = (".key", ".pem", ".p12", ".pfx", ".der")
_PRIVKEY_CONTENT_RE = re.compile(
    rb"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----",
    re.IGNORECASE,
)

# Sensitive filenames/patterns for per-file permission checks.
# Tuples of (regex-on-rootfs-relative-path, check_callable_name)
_SENSITIVE_PATH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^etc/shadow"), "shadow"),
    (re.compile(r"^etc/passwd$"), "passwd"),
    (re.compile(r"^etc/ssh/"), "ssh_config"),
    (re.compile(r"(?:^|/)\.ssh/"), "ssh_config"),
    (re.compile(r"(?:^|/)\.htpasswd$"), "htpasswd"),
    (re.compile(r"(?:^|/)\.htaccess$"), "htaccess"),
]

# Octal mode format helper
def _fmt_mode(mode: int) -> str:
    """Return zero-padded 4-digit octal mode string, e.g. '0755'."""
    return f"{stat.S_IMODE(mode):04o}"


# ---------------------------------------------------------------------------
# Rootfs-relative path helper
# ---------------------------------------------------------------------------

def _rootfs_rel(rootfs: Path, path: Path) -> str:
    try:
        return str(path.relative_to(rootfs))
    except Exception:
        return str(path)


# ---------------------------------------------------------------------------
# Evidence reference builder
# ---------------------------------------------------------------------------

def _evidence_ref_for_path(path: Path) -> str:
    """Return sha256 evidence ref for *path*.

    Tries to hash file contents; falls back to hashing the path string
    (e.g. for symlinks or permission-denied files).
    """
    try:
        if path.is_file() and not path.is_symlink():
            return f"sha256:{sha256_file(path)}"
    except OSError:
        pass
    return f"sha256:{sha256_text(str(path))}"


# ---------------------------------------------------------------------------
# Sensitive file checks
# ---------------------------------------------------------------------------

def _check_shadow(rootfs_rel_path: str, st: os.stat_result) -> str | None:
    """Return issue type string if /etc/shadow* has wrong permissions, else None."""
    mode = stat.S_IMODE(st.st_mode)
    # Should be 0640 or stricter (0600, 0000).  Flag if group or other can read.
    if mode & 0o044:
        return "shadow_readable"
    return None


def _check_passwd(rootfs_rel_path: str, st: os.stat_result) -> str | None:
    """Return issue type if /etc/passwd is writable by non-root, else None."""
    mode = stat.S_IMODE(st.st_mode)
    # Flag if group-writable or world-writable
    if mode & 0o022:
        return "passwd_writable"
    return None


def _check_ssh_config(rootfs_rel_path: str, st: os.stat_result) -> str | None:
    """Return issue type if SSH config/key files have loose permissions."""
    mode = stat.S_IMODE(st.st_mode)
    # Other-readable is the main concern for SSH files
    if mode & 0o004:
        return "ssh_config_loose_perms"
    return None


def _check_htpasswd(rootfs_rel_path: str, st: os.stat_result) -> str | None:
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o004:
        return "htpasswd_readable_by_other"
    return None


def _check_htaccess(rootfs_rel_path: str, st: os.stat_result) -> str | None:
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o004:
        return "htaccess_readable_by_other"
    return None


_SENSITIVE_CHECKERS: dict[str, object] = {
    "shadow": _check_shadow,
    "passwd": _check_passwd,
    "ssh_config": _check_ssh_config,
    "htpasswd": _check_htpasswd,
    "htaccess": _check_htaccess,
}

_SENSITIVE_SEVERITY: dict[str, str] = {
    "shadow_readable": "high",
    "passwd_writable": "high",
    "ssh_config_loose_perms": "medium",
    "htpasswd_readable_by_other": "medium",
    "htaccess_readable_by_other": "medium",
}


def _check_privkey_content(path: Path) -> bool:
    """Return True if *path* looks like a PEM private key file."""
    try:
        raw = path.read_bytes()
        # Only read first 4 KB to avoid loading large files
        return bool(_PRIVKEY_CONTENT_RE.search(raw[:4096]))
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Issue list builder helpers
# ---------------------------------------------------------------------------

def _make_issue(
    issue_type: str,
    severity: str,
    file_path: str,
    details: dict[str, object],
    evidence_ref: str,
) -> dict[str, object]:
    return {
        "type": issue_type,
        "severity": severity,
        "file_path": file_path,
        "details": {k: details[k] for k in sorted(details)},
        "evidence_ref": evidence_ref,
    }


# ---------------------------------------------------------------------------
# Main walk logic
# ---------------------------------------------------------------------------

def _scan_rootfs(
    rootfs: Path,
    run_dir: Path,
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]], int, list[str]]:
    """Walk *rootfs* and collect permission issues.

    Returns:
        (issues, suid_binaries, sgid_binaries, files_inspected, limitations)
    """
    issues: list[dict[str, object]] = []
    suid_binaries: list[dict[str, object]] = []
    sgid_binaries: list[dict[str, object]] = []
    limitations: list[str] = []
    files_inspected = 0

    # Track parent-directory sticky bits so we can exclude world-writable files
    # inside sticky directories from being flagged (e.g. /tmp).
    sticky_dirs: set[str] = set()

    # We use os.walk with topdown=True to be able to collect sticky dirs before
    # descending into their children.
    for dirpath_str, dirnames, filenames in os.walk(str(rootfs), topdown=True, followlinks=False):
        dirpath = Path(dirpath_str)

        # Check this directory itself
        try:
            dir_st = os.lstat(dirpath_str)
            dir_mode = stat.S_IMODE(dir_st.st_mode)
            rel = _rootfs_rel(rootfs, dirpath)
            is_sticky = bool(dir_mode & stat.S_ISVTX)

            if is_sticky:
                sticky_dirs.add(dirpath_str)

            if stat.S_ISDIR(dir_st.st_mode) and (dir_mode & 0o002) and not is_sticky:
                ev = f"sha256:{sha256_text(rel)}"
                issues.append(_make_issue(
                    "world_writable_directory",
                    "medium",
                    rel,
                    {
                        "group": str(dir_st.st_gid),
                        "mode": _fmt_mode(dir_st.st_mode),
                        "owner": str(dir_st.st_uid),
                    },
                    ev,
                ))
        except OSError as exc:
            limitations.append(f"lstat error on dir {dirpath_str}: {exc}")

        # Check all files in this directory
        for fname in filenames:
            if files_inspected >= _MAX_FILES_PER_ROOTFS:
                limitations.append(
                    f"file inspection limit reached ({_MAX_FILES_PER_ROOTFS}); "
                    "scan truncated"
                )
                # Stop descending by clearing dirnames in-place
                dirnames[:] = []
                return issues, suid_binaries, sgid_binaries, files_inspected, limitations

            fpath = dirpath / fname
            try:
                st = os.lstat(str(fpath))
            except OSError as exc:
                limitations.append(f"lstat error on {fpath}: {exc}")
                continue

            files_inspected += 1
            mode = stat.S_IMODE(st.st_mode)
            is_symlink = stat.S_ISLNK(st.st_mode)
            is_reg = stat.S_ISREG(st.st_mode)
            rel = _rootfs_rel(rootfs, fpath)
            ev = _evidence_ref_for_path(fpath)

            # --- Broken SUID/SGID symlink ---
            if is_symlink and (mode & (stat.S_ISUID | stat.S_ISGID)):
                try:
                    target = os.readlink(str(fpath))
                    resolved = (dirpath / target).resolve()
                    if not resolved.exists():
                        issues.append(_make_issue(
                            "orphaned_suid_sgid",
                            "low",
                            rel,
                            {
                                "mode": _fmt_mode(st.st_mode),
                                "symlink_target": target,
                            },
                            ev,
                        ))
                except OSError:
                    pass

            # Skip symlinks for further checks (use lstat, no follow)
            if is_symlink:
                continue

            # --- World-writable regular file ---
            if is_reg and (mode & 0o002):
                parent_is_sticky = dirpath_str in sticky_dirs
                if not parent_is_sticky:
                    issues.append(_make_issue(
                        "world_writable_file",
                        "medium",
                        rel,
                        {
                            "group": str(st.st_gid),
                            "mode": _fmt_mode(st.st_mode),
                            "owner": str(st.st_uid),
                        },
                        ev,
                    ))

            # --- SUID binaries ---
            if is_reg and (mode & stat.S_ISUID):
                binary_name = fpath.name
                entry: dict[str, object] = {
                    "file_path": rel,
                    "mode": _fmt_mode(st.st_mode),
                    "owner": str(st.st_uid),
                }
                suid_binaries.append(entry)
                if binary_name not in _KNOWN_SAFE_SUID:
                    issues.append(_make_issue(
                        "suid_binary_unexpected",
                        "medium",
                        rel,
                        {
                            "mode": _fmt_mode(st.st_mode),
                            "owner": str(st.st_uid),
                        },
                        ev,
                    ))

            # --- SGID binaries ---
            if is_reg and (mode & stat.S_ISGID):
                entry = {
                    "file_path": rel,
                    "mode": _fmt_mode(st.st_mode),
                    "owner": str(st.st_uid),
                }
                sgid_binaries.append(entry)
                issues.append(_make_issue(
                    "sgid_binary",
                    "low",
                    rel,
                    {
                        "mode": _fmt_mode(st.st_mode),
                        "owner": str(st.st_uid),
                    },
                    ev,
                ))

            # --- Sensitive file checks ---
            for pattern, checker_name in _SENSITIVE_PATH_PATTERNS:
                if pattern.search(rel):
                    checker = _SENSITIVE_CHECKERS.get(checker_name)
                    if checker is None:
                        continue
                    issue_type = checker(rel, st)  # type: ignore[operator]
                    if issue_type:
                        severity = _SENSITIVE_SEVERITY.get(issue_type, "medium")
                        issues.append(_make_issue(
                            issue_type,
                            severity,
                            rel,
                            {
                                "group": str(st.st_gid),
                                "mode": _fmt_mode(st.st_mode),
                                "owner": str(st.st_uid),
                            },
                            ev,
                        ))
                    break  # Only apply first matching pattern per file

            # --- Private key files ---
            if is_reg and fpath.suffix.lower() in _PRIVKEY_SUFFIXES:
                if mode & 0o004:  # other-readable
                    if _check_privkey_content(fpath):
                        issues.append(_make_issue(
                            "private_key_readable_by_other",
                            "high",
                            rel,
                            {
                                "group": str(st.st_gid),
                                "mode": _fmt_mode(st.st_mode),
                                "owner": str(st.st_uid),
                            },
                            ev,
                        ))

        # Sort dirnames for deterministic traversal order
        dirnames.sort()

    return issues, suid_binaries, sgid_binaries, files_inspected, limitations


# ---------------------------------------------------------------------------
# Summary builder
# ---------------------------------------------------------------------------

def _build_summary(issues: list[dict[str, object]]) -> dict[str, int]:
    counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0, "info": 0, "total_issues": 0}
    for issue in issues:
        sev = str(issue.get("severity", "info"))
        if sev in counts:
            counts[sev] += 1
        counts["total_issues"] += 1
    return counts


def _build_ww_stats(issues: list[dict[str, object]]) -> dict[str, int]:
    files = sum(1 for i in issues if i["type"] == "world_writable_file")
    directories = sum(1 for i in issues if i["type"] == "world_writable_directory")
    return {"directories": directories, "files": files}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_fs_permissions(
    rootfs_dirs: list[Path],
    run_dir: Path,
    stage_dir: Path,
) -> dict[str, object]:
    """Audit filesystem permissions in firmware rootfs.

    Walks up to *_MAX_ROOTFS_ROOTS* rootfs directories looking for:
    - World-writable files and directories (without sticky bit)
    - SUID binaries, flagging unexpected ones
    - SGID binaries
    - Sensitive files (/etc/shadow, /etc/passwd, SSH keys, .htpasswd, .htaccess)
      with incorrect permissions
    - Private key files readable by others
    - Orphaned SUID/SGID symlinks

    Args:
        rootfs_dirs: Candidate rootfs root directories to scan (max 3 used).
        run_dir:     Pipeline run directory (used for path safety checks).
        stage_dir:   Directory where ``fs_permissions.json`` is written.

    Returns:
        Parsed fs_permissions dict (also written to stage_dir/fs_permissions.json).
    """
    all_issues: list[dict[str, object]] = []
    all_suid: list[dict[str, object]] = []
    all_sgid: list[dict[str, object]] = []
    all_limitations: list[str] = []
    total_files_inspected = 0

    roots_to_scan = rootfs_dirs[:_MAX_ROOTFS_ROOTS]
    if len(rootfs_dirs) > _MAX_ROOTFS_ROOTS:
        all_limitations.append(
            f"only first {_MAX_ROOTFS_ROOTS} rootfs roots scanned "
            f"({len(rootfs_dirs)} provided)"
        )

    for rootfs in roots_to_scan:
        if not rootfs.is_dir():
            all_limitations.append(f"rootfs not a directory: {rootfs}")
            continue

        try:
            issues, suid_bins, sgid_bins, n_files, lims = _scan_rootfs(rootfs, run_dir)
        except Exception as exc:
            all_limitations.append(f"scan error for rootfs {rootfs}: {exc}")
            continue

        all_issues.extend(issues)
        all_suid.extend(suid_bins)
        all_sgid.extend(sgid_bins)
        total_files_inspected += n_files
        all_limitations.extend(lims)

        # SquashFS note: world-writable bits on read-only FS are artefacts of
        # how SquashFS stores permissions and may not reflect runtime state.
        # We still report them but add an informational note.
        squashfs_marker = rootfs / ".squashfs_extracted"
        # Some extractors place a marker; also check the parent dirname pattern.
        rootfs_str = str(rootfs)
        if "squash" in rootfs_str.lower() or squashfs_marker.exists():
            all_limitations.append(
                "rootfs may be SquashFS-extracted: world-writable bits reflect "
                "stored permissions and may not indicate runtime writability"
            )

    # De-duplicate issues (same type + file_path from multiple rootfs roots)
    seen_issue_keys: set[tuple[str, str]] = set()
    deduped_issues: list[dict[str, object]] = []
    for issue in all_issues:
        key = (str(issue["type"]), str(issue["file_path"]))
        if key not in seen_issue_keys:
            seen_issue_keys.add(key)
            deduped_issues.append(issue)

    # De-duplicate SUID/SGID lists
    seen_suid: set[str] = set()
    deduped_suid: list[dict[str, object]] = []
    for entry in all_suid:
        fp = str(entry["file_path"])
        if fp not in seen_suid:
            seen_suid.add(fp)
            deduped_suid.append(entry)

    seen_sgid: set[str] = set()
    deduped_sgid: list[dict[str, object]] = []
    for entry in all_sgid:
        fp = str(entry["file_path"])
        if fp not in seen_sgid:
            seen_sgid.add(fp)
            deduped_sgid.append(entry)

    # Sort for determinism
    sorted_issues = sorted(
        deduped_issues,
        key=lambda i: (
            {"high": 0, "medium": 1, "low": 2, "info": 3}.get(str(i["severity"]), 4),
            str(i["type"]),
            str(i["file_path"]),
        ),
    )
    sorted_suid = sorted(deduped_suid, key=lambda e: str(e["file_path"]))
    sorted_sgid = sorted(deduped_sgid, key=lambda e: str(e["file_path"]))

    sensitive_file_issues = sum(
        1
        for i in sorted_issues
        if i["type"] in {
            "shadow_readable",
            "passwd_writable",
            "ssh_config_loose_perms",
            "htpasswd_readable_by_other",
            "htaccess_readable_by_other",
            "private_key_readable_by_other",
        }
    )

    result: dict[str, object] = {
        "schema_version": "fs-permissions-v1",
        "files_inspected": total_files_inspected,
        "issues": sorted_issues,
        "sgid_binaries": sorted_sgid,
        "suid_binaries": sorted_suid,
        "sensitive_file_issues": sensitive_file_issues,
        "summary": _build_summary(sorted_issues),
        "world_writable": _build_ww_stats(sorted_issues),
        "limitations": sorted(set(all_limitations)),
    }

    out_path = stage_dir / "fs_permissions.json"
    assert_under_dir(run_dir, out_path)
    out_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return result
