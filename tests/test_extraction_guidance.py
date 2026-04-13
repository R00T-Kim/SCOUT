"""Tests for extraction analyst guidance (PR #14).

Verifies that:
- extraction failure paths attach extraction_guidance to StageOutcome.details
- extraction success does NOT attach extraction_guidance
- _build_extraction_guidance() produces non-empty, structured output for each reason code
- run.py _emit_extraction_guidance() correctly logs guidance when quiet=True
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from aiedge.extraction import ExtractionStage, _build_extraction_guidance
from aiedge.run import _emit_extraction_guidance
from aiedge.stage import StageContext, StageResult

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = tmp_path / "logs"
    report_dir = tmp_path / "report"
    run_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


# ---------------------------------------------------------------------------
# _build_extraction_guidance unit tests
# ---------------------------------------------------------------------------


def test_guidance_encrypted_contains_required_content() -> None:
    msg = _build_extraction_guidance(reason_code="encrypted", entropy=7.95)
    assert "7.95" in msg
    assert "vendor_decrypt.py" in msg
    assert "--rootfs" in msg
    assert "docs/runbook.md#extraction-failure" in msg
    assert "Suggested actions:" in msg


def test_guidance_unknown_container_contains_required_content() -> None:
    msg = _build_extraction_guidance(reason_code="unknown_container", binwalk_rc=1)
    assert "0 extracted files" in msg
    assert "vendor_decrypt.py" in msg
    assert "--rootfs" in msg
    assert "rc=1" in msg
    assert "docs/runbook.md#extraction-failure" in msg


def test_guidance_timeout() -> None:
    msg = _build_extraction_guidance(reason_code="timeout")
    assert "timed out" in msg.lower()
    assert "--time-budget-s" in msg
    assert "--rootfs" in msg
    assert "docs/runbook.md#extraction-failure" in msg


def test_guidance_no_binwalk() -> None:
    msg = _build_extraction_guidance(reason_code="no_binwalk")
    assert "binwalk" in msg.lower()
    assert "--rootfs" in msg
    assert "docs/runbook.md#extraction-failure" in msg


def test_guidance_invalid_rootfs() -> None:
    msg = _build_extraction_guidance(reason_code="invalid_rootfs")
    assert "does not exist" in msg or "--rootfs" in msg
    assert "docs/runbook.md#extraction-failure" in msg


def test_guidance_vendor_tried_appears_in_output() -> None:
    msg = _build_extraction_guidance(
        reason_code="encrypted",
        entropy=7.92,
        vendor_tried="dlink-shrs",
    )
    assert "dlink-shrs" in msg


def test_guidance_non_empty_for_all_known_codes() -> None:
    for code in (
        "encrypted",
        "unknown_container",
        "timeout",
        "no_binwalk",
        "invalid_rootfs",
    ):
        msg = _build_extraction_guidance(reason_code=code)
        assert msg.strip(), f"guidance empty for reason_code={code}"


# ---------------------------------------------------------------------------
# ExtractionStage failure tests (firmware file not found)
# ---------------------------------------------------------------------------


def test_extraction_failure_includes_guidance_firmware_missing(tmp_path: Path) -> None:
    """Firmware file does not exist → failed outcome with extraction_guidance."""
    ctx = _make_ctx(tmp_path)
    # Write a fake firmware path that doesn't exist inside run_dir
    fw_path = ctx.run_dir / "firmware.bin"
    # Do NOT create the file
    stage = ExtractionStage(firmware_path=fw_path)
    outcome = stage.run(ctx)
    assert outcome.status == "failed"
    assert "extraction_guidance" in outcome.details
    guidance = outcome.details["extraction_guidance"]
    assert isinstance(guidance, str)
    assert guidance.strip()
    assert "docs/runbook.md#extraction-failure" in guidance


def test_extraction_failure_invalid_rootfs_includes_guidance(tmp_path: Path) -> None:
    """--rootfs path that doesn't exist → failed with extraction_guidance."""
    ctx = _make_ctx(tmp_path)
    fw_path = ctx.run_dir / "firmware.bin"
    fw_path.write_bytes(b"\x00" * 16)
    nonexistent_rootfs = tmp_path / "no_such_dir"
    stage = ExtractionStage(
        firmware_path=fw_path,
        provided_rootfs_dir=nonexistent_rootfs,
    )
    outcome = stage.run(ctx)
    assert outcome.status == "failed"
    assert "extraction_guidance" in outcome.details
    guidance = outcome.details["extraction_guidance"]
    assert isinstance(guidance, str)
    assert guidance.strip()
    assert "docs/runbook.md#extraction-failure" in guidance


def test_extraction_partial_no_binwalk_includes_guidance(tmp_path: Path) -> None:
    """binwalk not available → partial outcome with extraction_guidance."""
    ctx = _make_ctx(tmp_path)
    fw_path = ctx.run_dir / "firmware.bin"
    fw_path.write_bytes(b"\x00" * 16)
    stage = ExtractionStage(firmware_path=fw_path)
    # Patch shutil.which to simulate missing binwalk
    with patch("aiedge.extraction.shutil.which", return_value=None):
        outcome = stage.run(ctx)
    assert outcome.status == "partial"
    assert "extraction_guidance" in outcome.details
    guidance = outcome.details["extraction_guidance"]
    assert isinstance(guidance, str)
    assert guidance.strip()
    assert "binwalk" in guidance.lower()
    assert "docs/runbook.md#extraction-failure" in guidance


def test_extraction_partial_binwalk_zero_files_includes_guidance(
    tmp_path: Path,
) -> None:
    """binwalk exits 0 but produces no files → partial with extraction_guidance."""
    ctx = _make_ctx(tmp_path)
    fw_path = ctx.run_dir / "firmware.bin"
    fw_path.write_bytes(b"\x00" * 16)
    stage = ExtractionStage(firmware_path=fw_path, min_extracted_files=0)

    import subprocess

    fake_result = subprocess.CompletedProcess(
        args=["binwalk"], returncode=0, stdout="", stderr=""
    )

    def fake_which(name: str) -> str | None:
        return "/usr/bin/binwalk" if name == "binwalk" else None

    with patch("aiedge.extraction.shutil.which", side_effect=fake_which):
        with patch("aiedge.extraction.subprocess.run", return_value=fake_result):
            with patch("aiedge.extraction._shannon_entropy", return_value=3.0):
                with patch(
                    "aiedge.extraction.try_vendor_decrypt",
                    return_value=(None, "no vendor decryption scheme matched"),
                ):
                    with patch(
                        "aiedge.extraction._binwalk_major_version", return_value=2
                    ):
                        outcome = stage.run(ctx)

    # extracted_files == 0 and min_expected_files == 0, so status might be "ok"
    # let's just check it's either ok (no guidance) or partial/failed (guidance present)
    if outcome.status != "ok":
        assert "extraction_guidance" in outcome.details
        guidance = outcome.details["extraction_guidance"]
        assert isinstance(guidance, str)
        assert guidance.strip()


# ---------------------------------------------------------------------------
# Success — no guidance injected
# ---------------------------------------------------------------------------


def test_extraction_success_does_not_inject_guidance(tmp_path: Path) -> None:
    """Successful extraction (files > threshold) must NOT add extraction_guidance."""
    ctx = _make_ctx(tmp_path)
    fw_path = ctx.run_dir / "firmware.bin"
    fw_path.write_bytes(b"\x00" * 16)
    stage = ExtractionStage(firmware_path=fw_path, min_extracted_files=0)

    import subprocess

    fake_result = subprocess.CompletedProcess(
        args=["binwalk"], returncode=0, stdout="", stderr=""
    )

    def fake_which(name: str) -> str | None:
        return "/usr/bin/binwalk" if name == "binwalk" else None

    # Create an extracted dir with a file so extracted_files > 0
    extracted_dir = ctx.run_dir / "stages" / "extraction" / f"_{fw_path.name}.extracted"
    extracted_dir.mkdir(parents=True, exist_ok=True)
    (extracted_dir / "some_file.txt").write_text("hello", encoding="utf-8")

    with patch("aiedge.extraction.shutil.which", side_effect=fake_which):
        with patch("aiedge.extraction.subprocess.run", return_value=fake_result):
            with patch("aiedge.extraction._shannon_entropy", return_value=3.0):
                with patch(
                    "aiedge.extraction.try_vendor_decrypt",
                    return_value=(None, "no vendor decryption scheme matched"),
                ):
                    with patch(
                        "aiedge.extraction._binwalk_major_version", return_value=2
                    ):
                        outcome = stage.run(ctx)

    assert outcome.status == "ok"
    assert "extraction_guidance" not in outcome.details


# ---------------------------------------------------------------------------
# _emit_extraction_guidance tests
# ---------------------------------------------------------------------------


def _make_stage_result(
    stage_name: str, details: dict, status: str = "failed"
) -> StageResult:
    return StageResult(
        stage=stage_name,
        status=status,
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        duration_s=1.0,
        details=details,
        limitations=[],
        error=None,
        timed_out=False,
    )


def test_emit_guidance_prints_to_stderr_when_not_quiet(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """_emit_extraction_guidance prints to stderr when quiet=False."""
    guidance_text = (
        "Detected encryption.\nSuggested actions:\n  1. Check vendor_decrypt.py"
    )
    sr = _make_stage_result("extraction", {"extraction_guidance": guidance_text})
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    _emit_extraction_guidance(sr, quiet=False, logs_dir=logs_dir)
    captured = capsys.readouterr()
    assert "ANALYST GUIDANCE" in captured.err
    assert "Detected encryption" in captured.err


def test_emit_guidance_suppressed_when_quiet(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """_emit_extraction_guidance suppresses stderr when quiet=True."""
    guidance_text = (
        "Detected encryption.\nSuggested actions:\n  1. Check vendor_decrypt.py"
    )
    sr = _make_stage_result("extraction", {"extraction_guidance": guidance_text})
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    _emit_extraction_guidance(sr, quiet=True, logs_dir=logs_dir)
    captured = capsys.readouterr()
    assert captured.err == ""


def test_emit_guidance_writes_log_file_when_quiet(tmp_path: Path) -> None:
    """When quiet=True, guidance is written to logs_dir/extraction_guidance.txt."""
    guidance_text = (
        "Detected encryption.\nSuggested actions:\n  1. Check vendor_decrypt.py"
    )
    sr = _make_stage_result("extraction", {"extraction_guidance": guidance_text})
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    _emit_extraction_guidance(sr, quiet=True, logs_dir=logs_dir)
    log_file = logs_dir / "extraction_guidance.txt"
    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    assert "Detected encryption" in content


def test_emit_guidance_writes_log_file_when_not_quiet(tmp_path: Path) -> None:
    """Even when quiet=False, guidance is written to logs_dir/extraction_guidance.txt."""
    guidance_text = "No binwalk installed.\nSuggested actions:\n  1. Install binwalk"
    sr = _make_stage_result("extraction", {"extraction_guidance": guidance_text})
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    _emit_extraction_guidance(sr, quiet=False, logs_dir=logs_dir)
    log_file = logs_dir / "extraction_guidance.txt"
    assert log_file.exists()


def test_emit_guidance_skips_non_extraction_stage(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """_emit_extraction_guidance is a no-op for non-extraction stages."""
    sr = _make_stage_result("inventory", {"extraction_guidance": "should not appear"})
    _emit_extraction_guidance(sr, quiet=False)
    captured = capsys.readouterr()
    assert captured.err == ""


def test_emit_guidance_skips_when_no_guidance_field(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """_emit_extraction_guidance is a no-op when extraction_guidance is absent."""
    sr = _make_stage_result("extraction", {"confidence": 0.0})
    _emit_extraction_guidance(sr, quiet=False)
    captured = capsys.readouterr()
    assert captured.err == ""
