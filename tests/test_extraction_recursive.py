from __future__ import annotations

import subprocess
from pathlib import Path

from aiedge.extraction import _recursive_nested_extraction


def test_recursive_nested_extraction_skips_when_extracted_dir_missing(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    stage_dir = run_dir / "stages" / "extraction"
    stage_dir.mkdir(parents=True, exist_ok=True)
    log_path = stage_dir / "binwalk.log"
    _ = log_path.write_text("", encoding="utf-8")
    fw = run_dir / "input" / "firmware.bin"
    fw.parent.mkdir(parents=True, exist_ok=True)
    _ = fw.write_bytes(b"FW")

    details, limits, evidence = _recursive_nested_extraction(
        run_dir=run_dir,
        stage_dir=stage_dir,
        extracted_dir=stage_dir / "_firmware.bin.extracted",
        firmware_path=fw,
        log_path=log_path,
        timeout_s=30.0,
    )

    assert details.get("attempted") is False
    assert details.get("reason") == "missing_extracted_dir"
    assert limits == []
    assert evidence == []


def test_recursive_nested_extraction_reports_missing_optional_tools(
    tmp_path: Path, monkeypatch
) -> None:
    run_dir = tmp_path / "run"
    stage_dir = run_dir / "stages" / "extraction"
    extracted_dir = stage_dir / "_firmware.bin.extracted"
    extracted_dir.mkdir(parents=True, exist_ok=True)
    log_path = stage_dir / "binwalk.log"
    _ = log_path.write_text("", encoding="utf-8")
    fw = run_dir / "input" / "firmware.bin"
    fw.parent.mkdir(parents=True, exist_ok=True)
    _ = fw.write_bytes(b"FW")

    _ = (extracted_dir / "blob.ubi").write_bytes(b"UBI#....")
    _ = (extracted_dir / "blob.squashfs").write_bytes(b"hsqs....")

    monkeypatch.setattr(
        "aiedge.extraction.shutil.which",
        lambda name: None,
    )

    details, limits, _ = _recursive_nested_extraction(
        run_dir=run_dir,
        stage_dir=stage_dir,
        extracted_dir=extracted_dir,
        firmware_path=fw,
        log_path=log_path,
        timeout_s=30.0,
    )

    assert details.get("attempted") is True
    assert int(details.get("ubi_candidate_count", 0)) >= 1
    assert int(details.get("squashfs_candidate_count", 0)) >= 1
    assert any("ubireader_extract_images is unavailable" in x for x in limits)
    assert any("unsquashfs is unavailable" in x for x in limits)


def test_recursive_nested_extraction_uses_ubireader_and_unsquashfs(
    tmp_path: Path, monkeypatch
) -> None:
    run_dir = tmp_path / "run"
    stage_dir = run_dir / "stages" / "extraction"
    extracted_dir = stage_dir / "_firmware.bin.extracted"
    extracted_dir.mkdir(parents=True, exist_ok=True)
    log_path = stage_dir / "binwalk.log"
    _ = log_path.write_text("", encoding="utf-8")
    fw = run_dir / "input" / "firmware.bin"
    fw.parent.mkdir(parents=True, exist_ok=True)
    _ = fw.write_bytes(b"FW")

    _ = (extracted_dir / "blob.ubi").write_bytes(b"UBI#....")

    def fake_which(name: str) -> str | None:
        if name == "ubireader_extract_images":
            return "/fake/ubireader_extract_images"
        if name == "unsquashfs":
            return "/fake/unsquashfs"
        return None

    def fake_run(
        argv: list[str],
        *,
        cwd: str | None = None,
        text: bool = True,
        capture_output: bool = True,
        check: bool = False,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        _ = cwd, text, capture_output, check, timeout
        if argv[0].endswith("ubireader_extract_images"):
            out_dir = Path(argv[2])
            out_dir.mkdir(parents=True, exist_ok=True)
            _ = (out_dir / "volume.squashfs").write_bytes(b"hsqs....")
            return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")
        if argv[0].endswith("unsquashfs"):
            out_dir = Path(argv[2])
            out_dir.mkdir(parents=True, exist_ok=True)
            _ = (out_dir / "etc").mkdir(parents=True, exist_ok=True)
            _ = (out_dir / "etc" / "passwd").write_text("root:x:0:0\n", encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")
        raise AssertionError(f"unexpected argv: {argv}")

    monkeypatch.setattr("aiedge.extraction.shutil.which", fake_which)
    monkeypatch.setattr("aiedge.extraction.subprocess.run", fake_run)

    details, limits, evidence = _recursive_nested_extraction(
        run_dir=run_dir,
        stage_dir=stage_dir,
        extracted_dir=extracted_dir,
        firmware_path=fw,
        log_path=log_path,
        timeout_s=30.0,
    )

    assert details.get("attempted") is True
    assert int(details.get("ubi_extract_ok", 0)) == 1
    assert int(details.get("squashfs_extract_ok", 0)) >= 1
    assert limits == []
    assert any(
        "stages/extraction/_firmware.bin.extracted/__recursive_squashfs/" in str(ev.get("path", ""))
        for ev in evidence
    )
