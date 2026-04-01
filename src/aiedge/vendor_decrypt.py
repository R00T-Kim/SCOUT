"""vendor_decrypt.py — Vendor-specific firmware decryption helpers.

Currently supports:
- D-Link SHRS (AES-128-CBC encrypted firmware, magic 0x53485253)
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
from pathlib import Path

from .path_safety import assert_under_dir

_LOG = logging.getLogger(__name__)

# D-Link SHRS constants
_SHRS_MAGIC = b"SHRS"
_SHRS_HEADER_SIZE = 0x6DC  # bytes to skip before encrypted body
_DLINK_AES_KEY = "c05fbf1936c99429ce2a0781f08d6ad8"
_DLINK_AES_IV = "67c6697351ff4aec29cdbaabf2fbe346"


def detect_shrs(fw: Path) -> bool:
    """Return True if *fw* starts with the SHRS magic bytes (D-Link AES firmware)."""
    try:
        with fw.open("rb") as fh:
            return fh.read(4) == _SHRS_MAGIC
    except OSError:
        return False


def decrypt_shrs(fw: Path, out_dir: Path) -> Path | None:
    """Decrypt a D-Link SHRS-encrypted firmware image.

    Skips the SHRS header (``_SHRS_HEADER_SIZE`` bytes) then decrypts the
    remaining body with AES-128-CBC using the known D-Link key/IV via the
    ``openssl`` CLI.

    Args:
        fw: Path to the encrypted firmware file.
        out_dir: Directory where the decrypted output will be written.
            The output file is placed inside this directory and validated
            with :func:`~aiedge.path_safety.assert_under_dir`.

    Returns:
        Path to the decrypted file on success, ``None`` on failure.
    """
    import shutil

    if not shutil.which("openssl"):
        _LOG.warning("openssl not found; cannot decrypt SHRS firmware")
        return None

    out_path = out_dir / f"{fw.stem}_decrypted{fw.suffix}"
    assert_under_dir(out_dir, out_path)

    # Write the encrypted body (skip the SHRS header) to a temp file so we
    # can pass it directly to openssl without a shell pipeline.
    try:
        with fw.open("rb") as fh:
            fh.seek(_SHRS_HEADER_SIZE)
            body = fh.read()
    except OSError as exc:
        _LOG.warning("Failed to read SHRS firmware body: %s", exc)
        return None

    if not body:
        _LOG.warning("SHRS firmware body is empty after header skip")
        return None

    with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tmp:
        tmp_path = Path(tmp.name)
        tmp.write(body)

    try:
        result = subprocess.run(
            [
                "openssl", "enc", "-d", "-aes-128-cbc",
                "-K", _DLINK_AES_KEY,
                "-iv", _DLINK_AES_IV,
                "-in", str(tmp_path),
                "-out", str(out_path),
                "-nopad",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        _LOG.warning("openssl timed out decrypting SHRS firmware")
        tmp_path.unlink(missing_ok=True)
        return None
    except OSError as exc:
        _LOG.warning("openssl exec failed: %s", exc)
        tmp_path.unlink(missing_ok=True)
        return None
    finally:
        tmp_path.unlink(missing_ok=True)

    if result.returncode != 0:
        _LOG.warning(
            "openssl returned %d decrypting SHRS firmware: %s",
            result.returncode,
            result.stderr.strip(),
        )
        out_path.unlink(missing_ok=True)
        return None

    if not out_path.exists() or out_path.stat().st_size == 0:
        _LOG.warning("openssl produced empty output for SHRS firmware")
        out_path.unlink(missing_ok=True)
        return None

    return out_path


def try_vendor_decrypt(fw: Path, out_dir: Path) -> tuple[Path | None, str]:
    """Attempt all known vendor decryption schemes against *fw*.

    Args:
        fw: Firmware path to inspect and potentially decrypt.
        out_dir: Directory for decrypted output artifacts.

    Returns:
        A tuple ``(decrypted_path, log_message)``.  ``decrypted_path`` is
        ``None`` when no scheme matched or all attempts failed.
    """
    if detect_shrs(fw):
        result = decrypt_shrs(fw, out_dir)
        if result is not None:
            return result, "D-Link SHRS AES-128-CBC"
        return None, "D-Link SHRS detected but decryption failed"

    return None, "no vendor decryption scheme matched"
