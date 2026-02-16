from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest

from aiedge.run import analyze_run, create_run
from aiedge.stage import StageContext
from aiedge.tooling import ToolingStage


def _ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    logs_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


def test_tooling_stage_writes_tools_json_and_partial_when_tools_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path)

    def fake_which(_name: str) -> str | None:
        return None

    monkeypatch.setattr("aiedge.tooling.shutil.which", fake_which)

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        if args[:3] == [sys.executable, "-m", "ubidump"]:
            return subprocess.CompletedProcess(
                args=args,
                returncode=1,
                stdout="",
                stderr="No module named ubidump\n",
            )
        raise AssertionError(f"unexpected subprocess args: {args}")

    monkeypatch.setattr("aiedge.tooling.subprocess.run", fake_run)

    out = ToolingStage(timeout_s=0.1, max_output_chars=64).run(ctx)
    assert out.status == "partial"
    assert out.details.get("missing_required_tools") == [
        "dtc",
        "fdtget",
        "fdtdump",
        "binwalk",
        "unsquashfs",
        "docker",
    ]
    assert out.details.get("missing_optional_tools") == ["lzop", "ubidump"]

    tools_path = ctx.run_dir / "stages" / "tooling" / "tools.json"
    assert tools_path.is_file()

    evidence_any = out.details.get("evidence")
    assert isinstance(evidence_any, list)
    evidence = cast(list[object], evidence_any)
    paths: list[str] = []
    for ev_any in evidence:
        assert isinstance(ev_any, dict)
        p = cast(dict[str, object], ev_any).get("path")
        assert isinstance(p, str)
        paths.append(p)
    assert "stages/tooling/tools.json" in paths


def test_analyze_run_writes_stages_tooling_tools_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")

    info = create_run(
        str(fw),
        case_id="case-tooling",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    tool_paths = {
        "dtc": "/fake/bin/dtc",
        "fdtget": "/fake/bin/fdtget",
        "fdtdump": "/fake/bin/fdtdump",
        "binwalk": None,
        "unsquashfs": "/fake/bin/unsquashfs",
        "lzop": None,
        "docker": None,
        "ubidump": None,
    }

    def fake_which(name: str) -> str | None:
        return tool_paths.get(name)

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        if args == ["/fake/bin/dtc", "-v"]:
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout="",
                stderr="Device Tree Compiler version 1.6.0\n",
            )
        if args == ["/fake/bin/fdtget", "--version"]:
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout="fdtget version 1.6.0\n",
                stderr="",
            )
        if args == ["/fake/bin/fdtdump", "--version"]:
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout="fdtdump 1.6.0\n",
                stderr="",
            )
        if args == ["/fake/bin/unsquashfs", "-version"]:
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout="unsquashfs version 4.5\n",
                stderr="",
            )
        if args[:3] == [sys.executable, "-m", "ubidump"]:
            return subprocess.CompletedProcess(
                args=args,
                returncode=1,
                stdout="",
                stderr="No module named ubidump\n",
            )
        raise AssertionError(f"unexpected subprocess args: {args}")

    monkeypatch.setattr("aiedge.tooling.shutil.which", fake_which)
    monkeypatch.setattr("aiedge.tooling.subprocess.run", fake_run)

    _ = analyze_run(info, time_budget_s=0, no_llm=True)

    tools_path = info.run_dir / "stages" / "tooling" / "tools.json"
    assert tools_path.is_file()

    tools = cast(dict[str, object], json.loads(tools_path.read_text(encoding="utf-8")))
    required = {
        "dtc",
        "fdtget",
        "fdtdump",
        "binwalk",
        "unsquashfs",
        "lzop",
        "docker",
        "ubidump",
    }
    assert required.issubset(set(tools.keys()))

    for k in sorted(required):
        entry_any = tools.get(k)
        assert isinstance(entry_any, dict)
        entry = cast(dict[str, object], entry_any)
        assert set(entry.keys()) == {
            "required",
            "available",
            "version",
            "argv",
            "timeout_s",
            "exit_code",
            "stdout",
            "stderr",
        }
        assert isinstance(entry["required"], bool)
        assert isinstance(entry["available"], bool)
        assert isinstance(entry["version"], str)
        assert isinstance(entry["argv"], list)
        assert isinstance(entry["timeout_s"], (int, float))
        assert entry["exit_code"] is None or isinstance(entry["exit_code"], int)
        assert isinstance(entry["stdout"], str)
        assert isinstance(entry["stderr"], str)


def test_tooling_stage_optional_missing_keeps_status_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path)

    tool_paths = {
        "dtc": "/fake/bin/dtc",
        "fdtget": "/fake/bin/fdtget",
        "fdtdump": "/fake/bin/fdtdump",
        "binwalk": "/fake/bin/binwalk",
        "unsquashfs": "/fake/bin/unsquashfs",
        "lzop": None,
        "docker": "/fake/bin/docker",
        "ubidump": None,
    }

    def fake_which(name: str) -> str | None:
        return tool_paths.get(name)

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        if args == ["/fake/bin/dtc", "-v"]:
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="", stderr="dtc 1.6.0\n"
            )
        if args == ["/fake/bin/fdtget", "--version"]:
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="fdtget 1.6.0\n", stderr=""
            )
        if args == ["/fake/bin/fdtdump", "--version"]:
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="fdtdump 1.6.0\n", stderr=""
            )
        if args == ["/fake/bin/binwalk", "--version"]:
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="binwalk 2.3.4\n", stderr=""
            )
        if args == ["/fake/bin/unsquashfs", "-version"]:
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="unsquashfs 4.5\n", stderr=""
            )
        if args == ["/fake/bin/docker", "--version"]:
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="Docker version 26.1.1\n", stderr=""
            )
        if args[:3] == [sys.executable, "-m", "ubidump"]:
            return subprocess.CompletedProcess(
                args=args,
                returncode=1,
                stdout="",
                stderr="No module named ubidump\n",
            )
        raise AssertionError(f"unexpected subprocess args: {args}")

    monkeypatch.setattr("aiedge.tooling.shutil.which", fake_which)
    monkeypatch.setattr("aiedge.tooling.subprocess.run", fake_run)

    out = ToolingStage(timeout_s=0.1, max_output_chars=64).run(ctx)
    assert out.status == "ok"
    assert out.details.get("missing_required_tools") == []
    assert out.details.get("missing_optional_tools") == ["lzop", "ubidump"]
    assert out.details.get("missing_tools") == ["lzop", "ubidump"]
