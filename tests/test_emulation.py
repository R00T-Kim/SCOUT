# pyright: reportMissingImports=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import cast

import pytest

from aiedge.emulation import EmulationStage
from aiedge.run import analyze_run, create_run
from aiedge.stage import StageContext


def _ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    logs_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


def test_emulation_stage_writes_log_when_no_rootfs(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    out = EmulationStage().run(ctx)

    log_path = ctx.run_dir / "stages" / "emulation" / "emulation.log"
    assert out.status == "partial"
    assert out.details.get("reason") == "no extracted rootfs candidates"
    assert log_path.is_file()
    log_text = log_path.read_text(encoding="utf-8")
    assert "attempted_command:" in log_text
    assert "--- stdout ---" in log_text
    assert "--- stderr ---" in log_text
    assert "failure_reason:" in log_text


def test_emulation_stage_partial_when_docker_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path)
    rootfs = ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "etc"
    rootfs.mkdir(parents=True)
    _ = (rootfs / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\n", encoding="utf-8"
    )

    monkeypatch.setattr("aiedge.emulation.shutil.which", lambda _name: None)

    out = EmulationStage().run(ctx)
    log_path = ctx.run_dir / "stages" / "emulation" / "emulation.log"

    assert out.status == "partial"
    assert out.details.get("reason") == "docker not installed"
    assert log_path.is_file()
    assert "docker not installed" in log_path.read_text(encoding="utf-8")


def test_pipeline_continues_when_emulation_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")

    info = create_run(
        str(fw),
        case_id="case-emu",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    extracted_root = (
        info.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "etc"
    )
    extracted_root.mkdir(parents=True)
    _ = (extracted_root / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\n", encoding="utf-8"
    )

    monkeypatch.setattr("aiedge.emulation.shutil.which", lambda _name: None)

    status = analyze_run(info, time_budget_s=5, no_llm=True)
    assert status == "partial"

    rep = cast(
        dict[str, object],
        json.loads(info.report_json_path.read_text(encoding="utf-8")),
    )
    emulation = rep.get("emulation")
    assert isinstance(emulation, dict)
    emu = cast(dict[str, object], emulation)
    assert emu.get("status") == "partial"
    assert emu.get("reason") == "docker not installed"

    emu_log = info.run_dir / "stages" / "emulation" / "emulation.log"
    assert emu_log.is_file()


def test_emulation_stage_partial_when_docker_permission_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path)
    rootfs = ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "etc"
    rootfs.mkdir(parents=True)
    _ = (rootfs / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\n", encoding="utf-8"
    )

    monkeypatch.setattr(
        "aiedge.emulation.shutil.which", lambda _name: "/usr/bin/docker"
    )

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        if args[:3] == ["/usr/bin/docker", "image", "inspect"]:
            return subprocess.CompletedProcess(
                args=args,
                returncode=1,
                stdout="[]\n",
                stderr="permission denied while trying to connect to the docker API at unix:///var/run/docker.sock\n",
            )
        raise AssertionError(f"unexpected docker command: {args}")

    monkeypatch.setattr("aiedge.emulation.subprocess.run", fake_run)

    out = EmulationStage().run(ctx)
    assert out.status == "partial"
    assert out.details.get("reason") == "docker permission denied"


def test_emulation_stage_uses_restricted_docker_run_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path)
    rootfs = ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "etc"
    rootfs.mkdir(parents=True)
    _ = (rootfs / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\n", encoding="utf-8"
    )

    monkeypatch.setattr(
        "aiedge.emulation.shutil.which", lambda _name: "/usr/bin/docker"
    )

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        if args[:3] == ["/usr/bin/docker", "image", "inspect"]:
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout="[]\n",
                stderr="",
            )
        if args[:2] == ["/usr/bin/docker", "run"]:
            joined = " ".join(args)
            assert "--network none" in joined
            assert "--read-only" in joined
            assert "--cap-drop=ALL" in joined
            assert "--security-opt no-new-privileges" in joined
            assert "--tmpfs /tmp:rw,nosuid,noexec,size=64m" in joined
            assert "--pull=never" in joined
            assert "--pids-limit" in args
            assert "--cpus" in args
            assert "--memory" in args
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout="ok\n",
                stderr="",
            )
        raise AssertionError(f"unexpected docker command: {args}")

    monkeypatch.setattr("aiedge.emulation.subprocess.run", fake_run)

    out = EmulationStage().run(ctx)
    assert out.status == "ok"


def test_runtime_docker_network_none_blocks_outbound_dns() -> None:
    docker_bin = shutil.which("docker")
    if docker_bin is None:
        pytest.skip("docker not installed")

    inspect_res = subprocess.run(
        [docker_bin, "image", "inspect", "alpine:3.23"],
        text=True,
        capture_output=True,
        check=False,
    )
    if inspect_res.returncode != 0:
        pytest.skip("alpine:3.23 image unavailable for runtime isolation check")

    try:
        res = subprocess.run(
            [
                docker_bin,
                "run",
                "--rm",
                "--network",
                "none",
                "--pull=never",
                "alpine:3.23",
                "sh",
                "-lc",
                'RES_OPTIONS="attempts:1 timeout:1" getent hosts example.com >/dev/null 2>&1; code="$?"; [ "$code" -ne 0 ] && [ "$(wc -l </proc/net/route)" -eq 1 ]',
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        pytest.skip("docker run timed out during runtime isolation check")
    except OSError as exc:
        pytest.skip(f"docker run failed during runtime isolation check: {exc}")

    assert res.returncode == 0, (
        "docker --network none did not enforce expected isolation behavior; "
        f"stdout={res.stdout!r} stderr={res.stderr!r}"
    )
