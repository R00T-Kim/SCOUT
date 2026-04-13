"""Tests for sbom.py inventory schema compatibility fix.

Covers:

1. ``_collect_so_files_from_inventory`` walking inventory roots on disk when
    the current inventory schema (post-v2.x) omits ``file_list``.
2. ``_collect_so_files_from_inventory`` legacy fallback when ``file_list`` is
    still present (pre-v2.x schema).
3. ``_detect_from_binary_analysis`` reading printable strings directly from
    the binary file when the inventory entry lacks a ``string_hits`` field.
4. ``_extract_ascii_runs`` behaviour on mixed bytes.
5. End-to-end ``SbomStage.run`` on a synthetic rootfs — verifies that a
    firmware with only ``roots`` + ``hits``-style ``binary_analysis`` (no
    ``file_list``, no per-entry ``string_hits``) still produces components.

These tests guard against regressions of the silent schema mismatch that
caused Netgear R7000 SBOMs to report 0 components despite having 2,412
binaries and 259 ``.so*`` files in the extracted rootfs.
"""

from __future__ import annotations

import json
from pathlib import Path

from aiedge.sbom import (
    SbomStage,
    _collect_so_files_from_inventory,
    _ComponentRegistry,
    _detect_from_binary_analysis,
    _extract_ascii_runs,
)
from aiedge.stage import StageContext

# ---------------------------------------------------------------------------
# _extract_ascii_runs
# ---------------------------------------------------------------------------


class TestExtractAsciiRuns:
    def test_all_printable(self) -> None:
        data = b"hello world"
        out = _extract_ascii_runs(data)
        assert out == "hello world"

    def test_mixed_binary_drops_short_runs(self) -> None:
        data = b"short\x00\x01usable_run_here\x00also_a_run"
        out = _extract_ascii_runs(data, min_len=6)
        assert "usable_run_here" in out
        assert "also_a_run" in out
        assert "short" not in out

    def test_empty_input(self) -> None:
        assert _extract_ascii_runs(b"") == ""

    def test_min_len_respected(self) -> None:
        data = b"abcd\x00xyz\x00longer_string"
        out = _extract_ascii_runs(data, min_len=6)
        assert "longer_string" in out
        assert "abcd" not in out
        assert "xyz" not in out


# ---------------------------------------------------------------------------
# _collect_so_files_from_inventory
# ---------------------------------------------------------------------------


class TestCollectSoFilesFromInventory:
    def _make_root_with_libs(self, run_dir: Path, rel: str) -> None:
        root = run_dir / rel
        (root / "usr" / "lib").mkdir(parents=True, exist_ok=True)
        for name in ("libz.so.1", "libc.so.6", "libssl.so.1.0.0", "not_a_lib.txt"):
            (root / "usr" / "lib" / name).write_bytes(b"\x7fELF stub")

    def test_walks_roots_on_disk_when_file_list_absent(
        self, scout_stage_ctx: StageContext
    ) -> None:
        ctx = scout_stage_ctx
        rel_root = "stages/extraction/_firmware.bin.extracted/squashfs-root"
        self._make_root_with_libs(ctx.run_dir, rel_root)
        inventory = {"roots": [rel_root]}

        result = _collect_so_files_from_inventory(inventory, run_dir=ctx.run_dir)

        assert any("libz.so.1" in p for p in result)
        assert any("libc.so.6" in p for p in result)
        assert any("libssl.so.1.0.0" in p for p in result)
        assert not any("not_a_lib.txt" in p for p in result)

    def test_legacy_file_list_preserved(self, scout_stage_ctx: StageContext) -> None:
        ctx = scout_stage_ctx
        inventory = {
            "file_list": [
                "stages/extraction/_firmware.bin.extracted/squashfs-root/lib/libcrypto.so.1.1",
                "stages/extraction/_firmware.bin.extracted/squashfs-root/etc/hosts",
            ],
            "roots": [],
        }
        result = _collect_so_files_from_inventory(inventory, run_dir=ctx.run_dir)
        assert len(result) == 1
        assert "libcrypto.so.1.1" in result[0]

    def test_missing_run_dir_returns_empty(self) -> None:
        inventory = {"roots": ["stages/extraction/anything"]}
        assert _collect_so_files_from_inventory(inventory, run_dir=None) == []

    def test_absolute_root_path_rejected(self, scout_stage_ctx: StageContext) -> None:
        ctx = scout_stage_ctx
        inventory = {"roots": ["/etc"]}
        assert _collect_so_files_from_inventory(inventory, run_dir=ctx.run_dir) == []

    def test_nonexistent_root_skipped(self, scout_stage_ctx: StageContext) -> None:
        ctx = scout_stage_ctx
        inventory = {"roots": ["stages/extraction/_firmware.bin.extracted/missing"]}
        assert _collect_so_files_from_inventory(inventory, run_dir=ctx.run_dir) == []


# ---------------------------------------------------------------------------
# _detect_from_binary_analysis
# ---------------------------------------------------------------------------


class TestDetectFromBinaryAnalysis:
    def _write_curl_stub(self, run_dir: Path, rel: str) -> None:
        p = run_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        # Pad with a few printable strings including a curl version banner
        # that matches the curl pattern in _BINARY_PATTERNS.
        body = (
            b"some prefix padding\x00"
            + b"Usage: curl [options] <url>\x00"
            + b"libcurl/7.36.0 OpenSSL/1.0.2\x00"
            + b"\x01\x02\x03"
        )
        p.write_bytes(body)

    def test_entry_with_string_hits_uses_legacy_path(
        self, scout_stage_ctx: StageContext
    ) -> None:
        ctx = scout_stage_ctx
        registry = _ComponentRegistry()
        entries = [
            {
                "path": "stages/extraction/_firmware.bin.extracted/squashfs-root/bin/curl",
                "string_hits": ["libcurl/7.36.0 OpenSSL/1.0.2"],
            }
        ]
        added = _detect_from_binary_analysis(entries, registry, run_dir=ctx.run_dir)
        assert added >= 1
        assert any(c.name == "curl" for c in registry.components())

    def test_entry_without_string_hits_reads_binary(
        self, scout_stage_ctx: StageContext
    ) -> None:
        ctx = scout_stage_ctx
        rel = "stages/extraction/_firmware.bin.extracted/squashfs-root/usr/bin/curl"
        self._write_curl_stub(ctx.run_dir, rel)
        registry = _ComponentRegistry()
        entries = [
            {
                "path": rel,
                "arch": "arm-32",
                "matched_symbols": ["strcpy", "system"],
            }
        ]
        added = _detect_from_binary_analysis(entries, registry, run_dir=ctx.run_dir)
        assert added >= 1
        curl = next((c for c in registry.components() if c.name == "curl"), None)
        assert curl is not None
        assert curl.version.startswith("7.36")
        assert curl.detection_method == "binary_string"

    def test_missing_run_dir_falls_back_gracefully(
        self, scout_stage_ctx: StageContext
    ) -> None:
        registry = _ComponentRegistry()
        entries = [
            {
                "path": "stages/extraction/anything/bin/curl",
                "arch": "arm-32",
            }
        ]
        added = _detect_from_binary_analysis(entries, registry, run_dir=None)
        assert added == 0

    def test_absolute_path_rejected(self, scout_stage_ctx: StageContext) -> None:
        ctx = scout_stage_ctx
        registry = _ComponentRegistry()
        entries = [{"path": "/etc/hostname"}]
        _detect_from_binary_analysis(entries, registry, run_dir=ctx.run_dir)
        assert len(registry.components()) == 0


# ---------------------------------------------------------------------------
# Integration: SbomStage end-to-end
# ---------------------------------------------------------------------------


class TestSbomStageWithCurrentInventorySchema:
    def _seed_run(self, ctx: StageContext) -> None:
        run_dir = ctx.run_dir
        rel_root = "stages/extraction/_firmware.bin.extracted/squashfs-root"
        root = run_dir / rel_root
        (root / "usr" / "lib").mkdir(parents=True, exist_ok=True)
        (root / "usr" / "bin").mkdir(parents=True, exist_ok=True)

        # .so files for the so_filename pass
        (root / "usr" / "lib" / "libssl.so.1.0.0").write_bytes(b"\x7fELF stub")
        (root / "usr" / "lib" / "libz.so.1").write_bytes(b"\x7fELF stub")

        # A curl binary that binary_string pass can introspect
        curl_bytes = (
            b"curl cli padding\x00"
            + b"libcurl/7.36.0 OpenSSL/1.0.2l zlib/1.2.8\x00"
            + b"\x00\x01\x02"
        )
        (root / "usr" / "bin" / "curl").write_bytes(curl_bytes)

        inv_dir = run_dir / "stages" / "inventory"
        inv_dir.mkdir(parents=True, exist_ok=True)
        inventory = {
            "status": "ok",
            "roots": [rel_root],
            "extracted_dir": "stages/extraction/_firmware.bin.extracted",
            "summary": {
                "binaries": 1,
                "files": 3,
                "roots_scanned": 1,
                "risky_binary_hits": 0,
                "configs": 0,
                "string_hits": 0,
            },
        }
        (inv_dir / "inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
        (inv_dir / "binary_analysis.json").write_text(
            json.dumps(
                {
                    "hits": [
                        {
                            "path": f"{rel_root}/usr/bin/curl",
                            "arch": "arm-32",
                            "matched_symbols": ["strcpy"],
                            "hardening": {},
                            "ipc_indicators": {},
                            "sample_sha256": "stub",
                            "symbol_details": [],
                            "symbol_source": "dynstr",
                        }
                    ],
                    "note": "Best-effort scan",
                    "summary": {"binaries_scanned": 1},
                }
            ),
            encoding="utf-8",
        )

        # Minimal firmware_profile so kernel detection pass can no-op cleanly
        fp_dir = run_dir / "stages" / "firmware_profile"
        fp_dir.mkdir(parents=True, exist_ok=True)
        (fp_dir / "firmware_profile.json").write_text(
            json.dumps({"schema_version": "firmware-profile-v1"}),
            encoding="utf-8",
        )

    def test_sbom_finds_components_from_current_schema(
        self, scout_stage_ctx: StageContext
    ) -> None:
        ctx = scout_stage_ctx
        self._seed_run(ctx)
        stage = SbomStage(
            run_dir=ctx.run_dir,
            case_id="test",
            remaining_budget_s=lambda: 600.0,
            no_llm=True,
        )
        outcome = stage.run(ctx)
        assert outcome.status == "ok", (outcome.status, outcome.limitations)

        sbom = json.loads(
            (ctx.run_dir / "stages" / "sbom" / "sbom.json").read_text(encoding="utf-8")
        )
        components = sbom.get("components", [])
        # curl from binary_string + openssl/libz from so_filename
        names = {c.get("name") for c in components}
        assert "curl" in names
        assert len(components) >= 2
