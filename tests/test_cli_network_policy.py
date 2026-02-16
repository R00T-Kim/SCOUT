from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aiedge.__main__ import main


def test_analyze_cli_open_egress_records_manifest_override(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")

    rc = main(
        [
            "analyze",
            str(fw),
            "--case-id",
            "case-cli",
            "--ack-authorization",
            "--time-budget-s",
            "0",
            "--open-egress",
            "--egress-allow",
            "example.com",
        ]
    )

    assert rc in (0, 10)
    out = capsys.readouterr().out.strip()
    run_dir = Path(out)
    manifest = cast(
        dict[str, object],
        json.loads((run_dir / "manifest.json").read_text(encoding="utf-8")),
    )
    policy = cast(dict[str, object], manifest["network_policy"])

    assert policy["internet_egress"] == {
        "mode": "open",
        "allowlist": ["example.com"],
    }
    assert policy["override_open_egress"] is True
    assert policy["warnings"] == ["open_egress enabled"]


def test_analyze_cli_no_llm_writes_skipped_llm_section(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")

    rc = main(
        [
            "analyze",
            str(fw),
            "--case-id",
            "case-cli-no-llm",
            "--ack-authorization",
            "--time-budget-s",
            "0",
            "--no-llm",
        ]
    )

    assert rc in (0, 10)
    out = capsys.readouterr().out.strip()
    run_dir = Path(out)
    report = cast(
        dict[str, object],
        json.loads((run_dir / "report" / "report.json").read_text(encoding="utf-8")),
    )
    llm = cast(dict[str, object], report["llm"])

    assert llm["driver"] == "codex"
    assert llm["status"] == "skipped"
    assert llm["reason"] == "disabled by --no-llm"
    assert cast(dict[str, object], llm["probe"]) == {
        "version_ok": False,
        "version_out": "skipped",
        "help_ok": False,
        "help_out": "skipped",
    }
