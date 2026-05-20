from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from scripts import fetch_pair_firmware


def _write_manifest(path: Path) -> None:
    payload = {
        "schema_version": "pair-eval-v1",
        "pairs": [
            {
                "pair_id": "demo-pair",
                "vendor": "demo",
                "model": "demo-router",
                "cve_id": "CVE-2099-0001",
                "vulnerable": {
                    "firmware_path": "aiedge-inputs/demo/vuln.bin",
                    "sha256": "00" * 32,
                    "source_url": "https://example.invalid/vuln.bin",
                },
                "patched": {
                    "firmware_path": "aiedge-inputs/demo/patched.bin",
                    "sha256": "11" * 32,
                    "source_url": "https://example.invalid/patched.bin",
                },
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_fetch_pair_firmware_dry_run_reports_destinations(tmp_path: Path, capsys) -> None:
    manifest = tmp_path / "pairs.json"
    _write_manifest(manifest)

    rc = fetch_pair_firmware.main([
        "--pairs",
        str(manifest),
        "--pair-id",
        "demo-pair",
        "--dest-root",
        str(tmp_path),
        "--dry-run",
    ])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    pair = cast(dict[str, object], payload["pairs"][0])
    assert pair["pair_id"] == "demo-pair"
    sides = cast(list[dict[str, object]], pair["sides"])
    assert {side["status"] for side in sides} == {"planned"}
    assert sides[0]["destination"] == str((tmp_path / "aiedge-inputs/demo/vuln.bin").resolve())


def test_fetch_pair_firmware_verify_existing_rejects_sha_mismatch(tmp_path: Path, capsys) -> None:
    manifest = tmp_path / "pairs.json"
    _write_manifest(manifest)
    (tmp_path / "aiedge-inputs/demo").mkdir(parents=True)
    (tmp_path / "aiedge-inputs/demo/vuln.bin").write_bytes(b"not-zero")
    (tmp_path / "aiedge-inputs/demo/patched.bin").write_bytes(b"not-one")

    rc = fetch_pair_firmware.main([
        "--pairs",
        str(manifest),
        "--pair-id",
        "demo-pair",
        "--dest-root",
        str(tmp_path),
    ])

    assert rc == 47
    payload = json.loads(capsys.readouterr().out)
    pair = cast(dict[str, object], payload["pairs"][0])
    assert pair["status"] == "failed"
    assert {side["status"] for side in cast(list[dict[str, object]], pair["sides"])} == {"sha256_mismatch"}
