from __future__ import annotations

import base64
import hashlib
import io
import zipfile
from pathlib import Path

import pytest

from aiedge.ota import OtaDiscoveryLimits
from aiedge.ota_payload import (
    extract_payload_and_properties,
    verify_payload_file_hash,
)


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    with io.BytesIO() as bio:
        with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, data in entries.items():
                zf.writestr(name, data)
        return bio.getvalue()


def test_extract_payload_from_direct_update_zip(tmp_path: Path) -> None:
    fw = tmp_path / "update.zip"
    payload = b"P" * 41
    props = b"FILE_HASH=not-used\n"
    _ = fw.write_bytes(
        _zip_bytes(
            {
                "payload.bin": payload,
                "payload_properties.txt": props,
            }
        )
    )

    input_dir = tmp_path / "run" / "stages" / "ota" / "input"
    input_dir.mkdir(parents=True)
    update_zip_path, payload_path, payload_props_text = extract_payload_and_properties(
        firmware_zip_path=fw,
        archive_chain=[],
        payload_member_path="payload.bin",
        input_dir=input_dir,
        limits=OtaDiscoveryLimits(),
    )

    assert update_zip_path.read_bytes() == fw.read_bytes()
    assert payload_path.read_bytes() == payload
    assert payload_props_text is not None
    assert "FILE_HASH=not-used" in payload_props_text


def test_extract_payload_from_nested_update_zip_streaming(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"NESTED" * 11
    inner = _zip_bytes(
        {
            "payload.bin": payload,
            "payload_properties.txt": b"k=v\n",
        }
    )
    fw = tmp_path / "update.zip"
    _ = fw.write_bytes(_zip_bytes({"BYDUpdatePackage/UpdateFull.zip": inner}))

    def _forbid_read(
        _self: zipfile.ZipFile, name: object, *_args: object, **_kwargs: object
    ) -> bytes:
        raise AssertionError(
            f"ZipFile.read must not be used for nested extraction: {name!r}"
        )

    monkeypatch.setattr(zipfile.ZipFile, "read", _forbid_read)

    input_dir = tmp_path / "run" / "stages" / "ota" / "input"
    input_dir.mkdir(parents=True)
    update_zip_path, payload_path, payload_props_text = extract_payload_and_properties(
        firmware_zip_path=fw,
        archive_chain=["BYDUpdatePackage/UpdateFull.zip"],
        payload_member_path="payload.bin",
        input_dir=input_dir,
        limits=OtaDiscoveryLimits(),
    )

    assert update_zip_path.read_bytes() == inner
    assert payload_path.read_bytes() == payload
    assert payload_props_text is not None
    assert "k=v" in payload_props_text


def test_extract_payload_from_two_level_nested_chain_streaming(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"CHAINED" * 9
    inner2 = _zip_bytes(
        {
            "payload.bin": payload,
            "payload_properties.txt": b"chain=2\n",
        }
    )
    inner1 = _zip_bytes({"middle/update.zip": inner2})
    fw = tmp_path / "update.zip"
    _ = fw.write_bytes(_zip_bytes({"BYDUpdatePackage/UpdateFull.zip": inner1}))

    def _forbid_read(
        _self: zipfile.ZipFile, name: object, *_args: object, **_kwargs: object
    ) -> bytes:
        raise AssertionError(
            f"ZipFile.read must not be used for nested extraction: {name!r}"
        )

    monkeypatch.setattr(zipfile.ZipFile, "read", _forbid_read)

    input_dir = tmp_path / "run" / "stages" / "ota" / "input"
    input_dir.mkdir(parents=True)
    update_zip_path, payload_path, payload_props_text = extract_payload_and_properties(
        firmware_zip_path=fw,
        archive_chain=["BYDUpdatePackage/UpdateFull.zip", "middle/update.zip"],
        payload_member_path="payload.bin",
        input_dir=input_dir,
        limits=OtaDiscoveryLimits(),
    )

    assert update_zip_path.read_bytes() == inner2
    assert payload_path.read_bytes() == payload
    assert payload_props_text is not None
    assert "chain=2" in payload_props_text


def test_verify_payload_file_hash_matches_and_mismatch(tmp_path: Path) -> None:
    payload_path = tmp_path / "payload.bin"
    payload = b"HASHME" * 9
    _ = payload_path.write_bytes(payload)

    expected_b64 = base64.b64encode(hashlib.sha256(payload).digest()).decode("ascii")
    ok = verify_payload_file_hash(payload_path, f"FILE_HASH={expected_b64}\n")
    assert ok["file_hash_present"] is True
    assert ok["file_hash_matches"] is True
    assert ok["file_hash_error"] == ""

    bad = verify_payload_file_hash(payload_path, "FILE_HASH=not-base64***\n")
    assert bad["file_hash_present"] is True
    assert bad["file_hash_matches"] is None
    assert isinstance(bad["file_hash_error"], str)
    assert "invalid FILE_HASH base64" in bad["file_hash_error"]
