from __future__ import annotations
# pyright: reportMissingImports=false, reportUnknownMemberType=false, reportUnknownArgumentType=false

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import pytest

import aiedge.codex_probe as codex_probe
from aiedge.run import analyze_run, create_run


def test_probe_codex_cli_skips_when_codex_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        args: Sequence[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        _ = args
        _ = kwargs
        raise FileNotFoundError("codex")

    monkeypatch.setattr(codex_probe.subprocess, "run", fake_run)

    out = cast(dict[str, object], codex_probe.probe_codex_cli(timeout_s=0.1))
    assert out["driver"] == "codex"
    assert out["status"] == "skipped"
    assert "not installed" in cast(str, out["reason"])

    probe = cast(dict[str, object], out["probe"])
    assert probe["version_ok"] is False
    assert probe["help_ok"] is False


def test_probe_codex_cli_skips_when_auth_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(
        args: Sequence[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        if args[1] == "--version":
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="codex 1.2.3"
            )
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="help")

    monkeypatch.setattr(codex_probe.subprocess, "run", fake_run)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))

    out = cast(dict[str, object], codex_probe.probe_codex_cli(timeout_s=0.1))
    assert out["status"] == "available"
    probe = cast(dict[str, object], out["probe"])
    assert probe["auth_cache_present"] is False
    assert "note" in out


def test_probe_codex_cli_available_when_auth_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir(parents=True)
    _ = (codex_home / "auth.json").write_text("{}", encoding="utf-8")

    def fake_run(
        args: Sequence[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        if args[1] == "--version":
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="codex 1.2.3"
            )
        return subprocess.CompletedProcess(
            args=args, returncode=0, stdout="usage: codex"
        )

    monkeypatch.setattr(codex_probe.subprocess, "run", fake_run)
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    out = cast(dict[str, object], codex_probe.probe_codex_cli(timeout_s=0.1))
    assert out["driver"] == "codex"
    assert out["status"] == "available"
    assert "reason" not in out

    probe = cast(dict[str, object], out["probe"])
    assert probe["auth_cache_present"] is True


def test_analyze_run_writes_deterministic_llm_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_llm = {
        "driver": "codex",
        "status": "skipped",
        "probe": {
            "version_ok": False,
            "version_out": "missing",
            "help_ok": False,
            "help_out": "missing",
        },
        "reason": "Codex CLI is not installed",
    }
    monkeypatch.setattr("aiedge.codex_probe.probe_codex_cli", lambda: fake_llm)

    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")
    info = create_run(
        str(fw),
        case_id="case-codex",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    _ = analyze_run(info, time_budget_s=0)

    report = cast(
        dict[str, object],
        json.loads(info.report_json_path.read_text(encoding="utf-8")),
    )
    assert report["llm"] == fake_llm


def test_analyze_run_no_llm_writes_skipped_with_probe_placeholders(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode_probe() -> dict[str, object]:
        raise AssertionError("probe should not run when --no-llm is set")

    monkeypatch.setattr("aiedge.codex_probe.probe_codex_cli", explode_probe)

    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")
    info = create_run(
        str(fw),
        case_id="case-no-llm",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    _ = analyze_run(info, time_budget_s=0, no_llm=True)

    report = cast(
        dict[str, object],
        json.loads(info.report_json_path.read_text(encoding="utf-8")),
    )
    llm = cast(dict[str, object], report["llm"])
    assert llm["driver"] == "codex"
    assert llm["status"] == "skipped"
    assert llm["reason"] == "disabled by --no-llm"

    probe = cast(dict[str, object], llm["probe"])
    assert probe == {
        "version_ok": False,
        "version_out": "skipped",
        "help_ok": False,
        "help_out": "skipped",
    }
