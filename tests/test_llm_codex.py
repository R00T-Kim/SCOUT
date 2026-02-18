from __future__ import annotations
# pyright: reportMissingImports=false

import json
import os
from pathlib import Path
from typing import cast

import pytest

from aiedge.llm_codex import PROMPT_TEMPLATE_VERSION
from aiedge.run import analyze_run, create_run


def _write_fake_codex(
    path: Path, *, exec_exit: int, exec_stdout: str, exec_stderr: str
) -> None:
    script = "\n".join(
        [
            "#!/usr/bin/env python3",
            "import sys",
            "args = sys.argv[1:]",
            "if args and args[0] == '--version':",
            "    print('codex 9.9.9')",
            "    raise SystemExit(0)",
            "if args and args[0] == '--help':",
            "    print('usage: codex')",
            "    raise SystemExit(0)",
            "if args and args[0] == 'exec':",
            f"    sys.stdout.write({exec_stdout!r})",
            f"    sys.stderr.write({exec_stderr!r})",
            f"    raise SystemExit({exec_exit})",
            "raise SystemExit(2)",
            "",
        ]
    )
    _ = path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def _write_fake_codex_requires_skip_git_repo_check(path: Path) -> None:
    script = "\n".join(
        [
            "#!/usr/bin/env python3",
            "import sys",
            "args = sys.argv[1:]",
            "if args and args[0] == '--version':",
            "    print('codex 9.9.9')",
            "    raise SystemExit(0)",
            "if args and args[0] == '--help':",
            "    print('usage: codex')",
            "    raise SystemExit(0)",
            "if args and args[0] == 'exec':",
            "    if '--skip-git-repo-check' not in args:",
            "        sys.stderr.write('Not inside a trusted directory and --skip-git-repo-check was not specified.\\n')",
            "        raise SystemExit(3)",
            "    sys.stdout.write('SUMMARY_OK\\n')",
            "    raise SystemExit(0)",
            "raise SystemExit(2)",
            "",
        ]
    )
    _ = path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def test_analyze_run_executes_codex_and_writes_llm_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True)
    _write_fake_codex(
        fake_bin / "codex",
        exec_exit=0,
        exec_stdout="SUMMARY_OK\n",
        exec_stderr="",
    )

    codex_home = tmp_path / "codex-home"
    codex_home.mkdir(parents=True)
    _ = (codex_home / "auth.json").write_text("{}", encoding="utf-8")

    monkeypatch.setenv("PATH", str(fake_bin) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")
    info = create_run(
        str(fw),
        case_id="case-llm-log",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    _ = analyze_run(info, time_budget_s=0)

    report = cast(
        dict[str, object],
        json.loads(info.report_json_path.read_text(encoding="utf-8")),
    )
    llm = cast(dict[str, object], report["llm"])
    assert llm["status"] == "ok"
    summary_any = llm.get("summary")
    assert isinstance(summary_any, dict)
    summary = cast(dict[str, object], summary_any)
    assert summary.get("path") == "stages/llm/summary.md"
    assert summary.get("chars") == len("SUMMARY_OK\n")

    llm_summary_path = info.run_dir / "stages" / "llm" / "summary.md"
    assert llm_summary_path.is_file()
    assert llm_summary_path.read_text(encoding="utf-8") == "SUMMARY_OK\n"

    llm_log_path = info.run_dir / "stages" / "llm" / "llm.log"
    assert llm_log_path.is_file()
    llm_log = cast(
        dict[str, object], json.loads(llm_log_path.read_text(encoding="utf-8"))
    )

    assert llm_log["prompt_template_version"] == PROMPT_TEMPLATE_VERSION
    redaction = cast(dict[str, object], llm_log["input_redaction_summary"])
    excluded = cast(list[object], redaction["excluded"])
    assert "raw firmware bytes" in excluded

    argv = cast(list[object], llm_log["executed_argv"])
    assert argv[0] == "codex"
    assert argv[1] == "exec"
    assert llm_log["exit_code"] == 0
    assert "SUMMARY_OK" in cast(str, llm_log["stdout"])

    input_preview = cast(dict[str, object], llm_log["input_preview"])
    assert set(input_preview) == {
        "overview",
        "extraction_summary",
        "inventory_summary",
        "emulation",
        "findings",
    }


def test_analyze_run_codex_exec_login_failure_is_logged_and_nonfatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True)
    _write_fake_codex(
        fake_bin / "codex",
        exec_exit=7,
        exec_stdout="",
        exec_stderr="please login first\n",
    )

    codex_home = tmp_path / "codex-home"
    codex_home.mkdir(parents=True)
    _ = (codex_home / "auth.json").write_text("{}", encoding="utf-8")

    monkeypatch.setenv("PATH", str(fake_bin) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")
    info = create_run(
        str(fw),
        case_id="case-llm-login-fail",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    _ = analyze_run(info, time_budget_s=0)

    report = cast(
        dict[str, object],
        json.loads(info.report_json_path.read_text(encoding="utf-8")),
    )
    llm = cast(dict[str, object], report["llm"])
    assert llm["status"] == "skipped"
    assert "logged in" in cast(str, llm["reason"])

    llm_log_path = info.run_dir / "stages" / "llm" / "llm.log"
    assert llm_log_path.is_file()
    llm_log = cast(
        dict[str, object], json.loads(llm_log_path.read_text(encoding="utf-8"))
    )
    assert llm_log["exit_code"] == 7
    assert "login" in cast(str, llm_log["stderr"])


def test_analyze_run_codex_exec_success_without_stdout_is_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True)
    _write_fake_codex(
        fake_bin / "codex",
        exec_exit=0,
        exec_stdout="",
        exec_stderr="",
    )

    codex_home = tmp_path / "codex-home"
    codex_home.mkdir(parents=True)
    _ = (codex_home / "auth.json").write_text("{}", encoding="utf-8")

    monkeypatch.setenv("PATH", str(fake_bin) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")
    info = create_run(
        str(fw),
        case_id="case-llm-empty-stdout",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    _ = analyze_run(info, time_budget_s=0)

    report = cast(
        dict[str, object],
        json.loads(info.report_json_path.read_text(encoding="utf-8")),
    )
    llm = cast(dict[str, object], report["llm"])
    assert llm["status"] == "ok"
    assert "summary" not in llm
    assert not (info.run_dir / "stages" / "llm" / "summary.md").exists()


def test_analyze_run_retries_codex_exec_with_skip_git_repo_check_when_untrusted_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True)
    _write_fake_codex_requires_skip_git_repo_check(fake_bin / "codex")

    monkeypatch.setenv("PATH", str(fake_bin) + os.pathsep + os.environ.get("PATH", ""))

    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")
    info = create_run(
        str(fw),
        case_id="case-llm-untrusted",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    _ = analyze_run(info, time_budget_s=0)

    report = cast(
        dict[str, object],
        json.loads(info.report_json_path.read_text(encoding="utf-8")),
    )
    llm = cast(dict[str, object], report["llm"])
    assert llm["status"] == "ok"

    llm_log_path = info.run_dir / "stages" / "llm" / "llm.log"
    llm_log = cast(
        dict[str, object], json.loads(llm_log_path.read_text(encoding="utf-8"))
    )
    attempts = cast(list[object], llm_log["attempts"])
    assert len(attempts) == 2
    argv2 = cast(dict[str, object], attempts[1])["argv"]
    assert "--skip-git-repo-check" in cast(list[object], argv2)
