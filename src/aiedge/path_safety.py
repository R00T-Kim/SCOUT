"""path_safety.py — Shared path containment and hashing utilities.

Provides canonical implementations of path-safety and hashing helpers used
across all pipeline stage modules.  Centralising them here eliminates the
copy-pasted ``_assert_under_dir`` / ``_sha256_file`` pattern that previously
appeared in every stage file.

Usage::

    from .path_safety import assert_under_dir, rel_to_run_dir, sha256_file, sha256_text
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .policy import AIEdgePolicyViolation


def assert_under_dir(base_dir: Path, target: Path) -> None:
    """Raise :class:`~aiedge.policy.AIEdgePolicyViolation` if *target* is not
    contained within *base_dir*.

    Both paths are resolved before comparison so symlinks and relative
    components cannot be used to escape the run directory.

    Args:
        base_dir: The directory that *target* must be located inside (usually
            the run directory).
        target: The path to validate before writing.

    Raises:
        AIEdgePolicyViolation: When *target* resolves to a location outside
            *base_dir*.
    """
    base = base_dir.resolve()
    resolved = target.resolve()
    if not resolved.is_relative_to(base):
        raise AIEdgePolicyViolation(
            f"Refusing to write outside run dir: target={resolved} base={base}"
        )


def rel_to_run_dir(run_dir: Path, path: Path) -> str:
    """Return *path* expressed relative to *run_dir* as a string.

    Falls back to the stringified absolute path when *path* does not sit
    inside *run_dir* (e.g. during tests with temporary directories).

    Args:
        run_dir: Root of the current analysis run.
        path: Absolute path to an artifact inside the run.

    Returns:
        A POSIX-style relative path string, or the absolute path string when
        relativisation fails.
    """
    try:
        return str(path.resolve().relative_to(run_dir.resolve()))
    except Exception:
        return str(path)


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    """Return the hex-encoded SHA-256 digest of *path*.

    Reads the file in *chunk_size* chunks to keep memory usage bounded for
    large firmware images.

    Args:
        path: Path to the file to hash.
        chunk_size: Read buffer size in bytes (default 1 MiB).

    Returns:
        Lowercase hexadecimal SHA-256 digest string.
    """
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    """Return the hex-encoded SHA-256 digest of *text* encoded as UTF-8.

    Args:
        text: Arbitrary Unicode string to hash.

    Returns:
        Lowercase hexadecimal SHA-256 digest string.
    """
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
