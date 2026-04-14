from __future__ import annotations

import subprocess
from pathlib import Path

from aiedge import extraction
from aiedge.run import create_run, run_subset


def test_run_subset_extraction_uses_copied_firmware_with_relative_runs_root(
    tmp_path: Path, monkeypatch
) -> None:
    firmware = tmp_path / "sample.bin"
    firmware.write_bytes(b"FAKEFIRMWARE")

    monkeypatch.chdir(tmp_path)

    info = create_run(
        str(firmware),
        case_id="relative-runs-root",
        ack_authorization=True,
        runs_root=Path("relative-runs"),
    )

    seen: dict[str, Path] = {}

    monkeypatch.setattr(
        extraction.shutil,
        "which",
        lambda cmd: "/usr/bin/binwalk" if cmd == "binwalk" else None,
    )
    monkeypatch.setattr(extraction, "_binwalk_major_version", lambda _path: 2)
    monkeypatch.setattr(
        extraction,
        "try_vendor_decrypt",
        lambda fw, stage_dir: (None, "no vendor decryption scheme matched"),
    )
    monkeypatch.setattr(
        extraction,
        "_recursive_nested_extraction",
        lambda **_kwargs: ({"attempted": False}, [], []),
    )

    def fake_run(
        argv: list[str],
        *,
        cwd: str,
        text: bool,
        capture_output: bool,
        check: bool,
        timeout: float | None,
    ) -> subprocess.CompletedProcess[str]:
        assert text is True
        assert capture_output is True
        assert check is False
        assert timeout is not None

        firmware_arg = Path(argv[-1])
        seen["firmware_arg"] = firmware_arg
        seen["cwd"] = Path(cwd)

        assert firmware_arg.is_absolute()
        assert firmware_arg == info.firmware_dest.resolve()
        assert firmware_arg.is_file()

        extracted_dir = Path(cwd) / f"_{firmware_arg.name}.extracted"
        extracted_dir.mkdir(parents=True, exist_ok=True)
        for idx in range(50):
            (extracted_dir / f"file-{idx}.txt").write_text("ok", encoding="utf-8")

        return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

    monkeypatch.setattr(extraction.subprocess, "run", fake_run)

    rep = run_subset(info, ["extraction"], time_budget_s=5, no_llm=True)

    stage = next(result for result in rep.stage_results if result.stage == "extraction")
    assert stage.status == "ok"
    assert seen["firmware_arg"] == info.firmware_dest.resolve()
    assert seen["cwd"] == info.run_dir / "stages" / "extraction"
