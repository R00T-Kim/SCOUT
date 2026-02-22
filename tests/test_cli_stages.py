from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from typing import cast

import pytest

import aiedge.run as run_mod
from aiedge.__main__ import main


def _write_firmware(tmp_path: Path) -> Path:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")
    return fw


def test_analyze_cli_with_stages_calls_run_subset(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    fw = _write_firmware(tmp_path)
    calls: dict[str, object] = {}

    def fake_run_subset(
        info: run_mod.RunInfo,
        stage_names: list[str],
        *,
        time_budget_s: int,
        no_llm: bool,
    ) -> object:
        calls["run_id"] = info.run_id
        calls["stage_names"] = stage_names
        calls["time_budget_s"] = time_budget_s
        calls["no_llm"] = no_llm
        return SimpleNamespace(status="ok")

    def fail_analyze_run(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("analyze_run should not be called when --stages is set")

    monkeypatch.setattr(run_mod, "run_subset", fake_run_subset)
    monkeypatch.setattr(run_mod, "analyze_run", fail_analyze_run)

    rc = main(
        [
            "analyze",
            str(fw),
            "--case-id",
            "case-stages",
            "--ack-authorization",
            "--no-llm",
            "--stages",
            " tooling, structure ",
        ]
    )

    assert rc == 0
    run_dir = Path(capsys.readouterr().out.strip())
    assert run_dir.is_dir()
    assert run_dir.parent == tmp_path / "aiedge-runs"
    assert calls["stage_names"] == ["tooling", "structure"]
    assert calls["time_budget_s"] == 3600
    assert calls["no_llm"] is True


def test_analyze_cli_without_stages_calls_analyze_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    fw = _write_firmware(tmp_path)
    calls: dict[str, object] = {}

    def fake_analyze_run(
        info: run_mod.RunInfo,
        *,
        time_budget_s: int,
        no_llm: bool,
        force_retriage: bool,
    ) -> str:
        calls["run_id"] = info.run_id
        calls["time_budget_s"] = time_budget_s
        calls["no_llm"] = no_llm
        calls["force_retriage"] = force_retriage
        return "ok"

    def fail_run_subset(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("run_subset should not be called when --stages is omitted")

    monkeypatch.setattr(run_mod, "analyze_run", fake_analyze_run)
    monkeypatch.setattr(run_mod, "run_subset", fail_run_subset)

    rc = main(
        [
            "analyze",
            str(fw),
            "--case-id",
            "case-default",
            "--ack-authorization",
            "--no-llm",
        ]
    )

    assert rc == 0
    run_dir = Path(capsys.readouterr().out.strip())
    assert run_dir.is_dir()
    assert run_dir.parent == tmp_path / "aiedge-runs"
    assert calls["time_budget_s"] == 3600
    assert calls["no_llm"] is True
    assert calls["force_retriage"] is False


def test_analyze_cli_rootfs_writes_manifest_marker(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    fw = _write_firmware(tmp_path)
    rootfs_dir = tmp_path / "rootfs"
    (rootfs_dir / "etc").mkdir(parents=True)
    _ = (rootfs_dir / "etc" / "passwd").write_text("root:x:0:0\n", encoding="utf-8")
    calls: dict[str, object] = {}

    def fake_analyze_run(
        info: run_mod.RunInfo,
        *,
        time_budget_s: int,
        no_llm: bool,
        force_retriage: bool,
    ) -> str:
        manifest = cast(
            dict[str, object],
            json.loads(info.manifest_path.read_text(encoding="utf-8")),
        )
        calls["rootfs_input_path"] = manifest.get("rootfs_input_path")
        calls["time_budget_s"] = time_budget_s
        calls["no_llm"] = no_llm
        calls["force_retriage"] = force_retriage
        return "ok"

    monkeypatch.setattr(run_mod, "analyze_run", fake_analyze_run)

    rc = main(
        [
            "analyze",
            str(fw),
            "--case-id",
            "case-rootfs-marker",
            "--ack-authorization",
            "--rootfs",
            str(rootfs_dir),
            "--no-llm",
        ]
    )

    assert rc == 0
    _ = Path(capsys.readouterr().out.strip())
    assert calls["rootfs_input_path"] == str(rootfs_dir.resolve())
    assert calls["time_budget_s"] == 3600
    assert calls["no_llm"] is True
    assert calls["force_retriage"] is False


def test_analyze_cli_rejects_missing_rootfs_dir(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    fw = _write_firmware(tmp_path)
    missing = tmp_path / "missing-rootfs"

    rc = main(
        [
            "analyze",
            str(fw),
            "--case-id",
            "case-missing-rootfs",
            "--ack-authorization",
            "--rootfs",
            str(missing),
        ]
    )

    captured = capsys.readouterr()
    assert rc == 20
    assert captured.out == ""
    assert "Pre-extracted rootfs directory not found" in captured.err


def test_analyze_cli_stages_rejects_empty_list(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    fw = _write_firmware(tmp_path)

    rc = main(
        [
            "analyze",
            str(fw),
            "--case-id",
            "case-empty-stages",
            "--ack-authorization",
            "--stages",
            " , , ",
        ]
    )

    captured = capsys.readouterr()
    assert rc == 20
    assert captured.out == ""
    assert "Invalid --stages value" in captured.err


def test_analyze_cli_force_retriage_flag_is_forwarded(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    fw = _write_firmware(tmp_path)
    calls: dict[str, object] = {}

    def fake_analyze_run(
        _info: run_mod.RunInfo,
        *,
        time_budget_s: int,
        no_llm: bool,
        force_retriage: bool,
    ) -> str:
        calls["time_budget_s"] = time_budget_s
        calls["no_llm"] = no_llm
        calls["force_retriage"] = force_retriage
        return "ok"

    monkeypatch.setattr(run_mod, "analyze_run", fake_analyze_run)

    rc = main(
        [
            "analyze",
            str(fw),
            "--case-id",
            "case-force-retriage",
            "--ack-authorization",
            "--no-llm",
            "--force-retriage",
        ]
    )
    assert rc == 0
    _ = Path(capsys.readouterr().out.strip())
    assert calls["time_budget_s"] == 3600
    assert calls["no_llm"] is True
    assert calls["force_retriage"] is True


def test_analyze_cli_stages_unknown_name_returns_clean_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    fw = _write_firmware(tmp_path)

    def fake_run_subset(*_args: object, **_kwargs: object) -> object:
        raise ValueError("Unknown stage 'nope'. Valid stage names: tooling")

    monkeypatch.setattr(run_mod, "run_subset", fake_run_subset)

    rc = main(
        [
            "analyze",
            str(fw),
            "--case-id",
            "case-unknown-stage",
            "--ack-authorization",
            "--stages",
            "tooling,nope",
        ]
    )

    captured = capsys.readouterr()
    assert rc == 20
    assert captured.out == ""
    assert captured.err.strip() == "Unknown stage 'nope'. Valid stage names: tooling"


def test_analyze_cli_stages_findings_name_returns_integrated_step_hint(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    fw = _write_firmware(tmp_path)

    def fake_run_subset(*_args: object, **_kwargs: object) -> object:
        raise ValueError(
            "Unknown stage 'findings'. findings are produced by the integrated run_findings() step during full analyze/analyze-8mb execution (artifacts: stages/findings/*.json)."
        )

    monkeypatch.setattr(run_mod, "run_subset", fake_run_subset)

    rc = main(
        [
            "analyze",
            str(fw),
            "--case-id",
            "case-findings-stage",
            "--ack-authorization",
            "--stages",
            "findings",
        ]
    )

    captured = capsys.readouterr()
    assert rc == 20
    assert captured.out == ""
    assert "Unknown stage 'findings'." in captured.err
    assert "integrated run_findings() step" in captured.err


def test_analyze_cli_stages_partial_status_returns_10(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    fw = _write_firmware(tmp_path)

    def fake_run_subset(*_args: object, **_kwargs: object) -> object:
        return SimpleNamespace(status="partial")

    monkeypatch.setattr(run_mod, "run_subset", fake_run_subset)

    rc = main(
        [
            "analyze",
            str(fw),
            "--case-id",
            "case-partial",
            "--ack-authorization",
            "--stages",
            "tooling",
        ]
    )

    out = capsys.readouterr().out.strip()
    assert rc == 10
    assert Path(out).is_dir()


def test_analyze_cli_require_ref_md_missing_fails_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    fw = _write_firmware(tmp_path)

    rc = main(
        [
            "analyze",
            str(fw),
            "--case-id",
            "case-ref-required-missing",
            "--ack-authorization",
            "--require-ref-md",
            "--no-llm",
        ]
    )

    captured = capsys.readouterr()
    assert rc == 20
    assert "REF_MD_REQUIRED_MISSING" in captured.err


def test_analyze_cli_ref_md_hash_recorded_in_manifest_and_report(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    fw = _write_firmware(tmp_path)
    ref_md = tmp_path / "ref.md"
    _ = ref_md.write_text("governed context\n", encoding="utf-8")
    expected_sha = hashlib.sha256(ref_md.read_bytes()).hexdigest()

    def fake_analyze_run(
        _info: run_mod.RunInfo,
        *,
        time_budget_s: int,
        no_llm: bool,
        force_retriage: bool,
    ) -> str:
        _ = time_budget_s, no_llm, force_retriage
        return "ok"

    monkeypatch.setattr(run_mod, "analyze_run", fake_analyze_run)

    rc = main(
        [
            "analyze",
            str(fw),
            "--case-id",
            "case-ref-recorded",
            "--ack-authorization",
            "--ref-md",
            str(ref_md),
            "--require-ref-md",
            "--no-llm",
        ]
    )
    assert rc == 0

    run_dir = Path(capsys.readouterr().out.strip())
    manifest = cast(
        dict[str, object],
        json.loads((run_dir / "manifest.json").read_text(encoding="utf-8")),
    )
    report = cast(
        dict[str, object],
        json.loads((run_dir / "report" / "report.json").read_text(encoding="utf-8")),
    )
    expected_path = str(ref_md.resolve())

    assert manifest["ref_md_path"] == expected_path
    assert manifest["ref_md_sha256"] == expected_sha
    overview = cast(dict[str, object], report["overview"])
    assert overview["ref_md_path"] == expected_path
    assert overview["ref_md_sha256"] == expected_sha


def test_cli_stages_reuse_existing_run_increments_attempt_history(
    tmp_path: Path,
) -> None:
    fw = _write_firmware(tmp_path)
    src_root = Path(__file__).resolve().parents[1] / "src"
    env = dict(os.environ)
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(src_root)
        if not existing_pythonpath
        else str(src_root) + os.pathsep + existing_pythonpath
    )

    first = subprocess.run(
        [
            sys.executable,
            "-m",
            "aiedge",
            "analyze",
            str(fw),
            "--case-id",
            "case-rerun",
            "--ack-authorization",
            "--stages",
            "tooling",
            "--no-llm",
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert first.returncode in (0, 10), first.stderr
    run_dir = Path(first.stdout.strip())
    assert run_dir.is_dir()
    attempt_1 = run_dir / "stages" / "tooling" / "attempts" / "attempt-1" / "stage.json"
    assert attempt_1.is_file()

    second = subprocess.run(
        [
            sys.executable,
            "-m",
            "aiedge",
            "stages",
            str(run_dir),
            "--stages",
            "tooling",
            "--no-llm",
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert second.returncode in (0, 10), second.stderr
    assert Path(second.stdout.strip()) == run_dir
    attempt_2 = run_dir / "stages" / "tooling" / "attempts" / "attempt-2" / "stage.json"
    assert attempt_2.is_file()
