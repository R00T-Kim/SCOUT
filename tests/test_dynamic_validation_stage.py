from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import cast

import pytest

import aiedge.dynamic_validation as dv
from aiedge.dynamic_validation import DynamicValidationStage
from aiedge.run import create_run, run_subset
from aiedge.stage import StageContext


def _ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    input_dir = run_dir / "input"
    logs_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    input_dir.mkdir(parents=True)
    _ = (input_dir / "firmware.bin").write_bytes(b"firmware")
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


class _Sock:
    def close(self) -> None:
        return


class _HTTPResp:
    status: int = 200

    def __init__(self) -> None:
        self.headers: dict[str, str] = {"Server": "fixture"}

    def __enter__(self) -> _HTTPResp:
        return self

    def __exit__(self, _t: object, _v: object, _tb: object) -> None:
        return

    def read(self, _n: int) -> bytes:
        return b"ok"


def _fake_urlopen(*args: object, **kwargs: object) -> _HTTPResp:
    _ = args, kwargs
    return _HTTPResp()


def test_dynamic_validation_uses_firmae_target_ip_and_sanitized_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    firmae_root = tmp_path / "FirmAE"
    scratch_root = firmae_root / "scratch"
    scratch_root.mkdir(parents=True)
    _ = (firmae_root / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")

    def fake_which(name: str) -> str | None:
        mapping = {
            "sudo": "/usr/bin/sudo",
            "git": "/usr/bin/git",
            "tcpdump": "/usr/sbin/tcpdump",
            "iptables-save": "/usr/sbin/iptables-save",
            "ip6tables-save": "/usr/sbin/ip6tables-save",
            "nft": "/usr/sbin/nft",
            "ip": "/usr/sbin/ip",
        }
        return mapping.get(name)

    def fake_run(
        argv: list[str], *, timeout_s: float | None, cwd: Path | None = None
    ) -> dv.CommandResult:
        _ = timeout_s
        cmd = " ".join(argv)
        if "run.sh" in cmd:
            assert argv[0] == "/usr/bin/sudo"
            assert argv[1] == "-n"
            assert argv[3] == "-c"
            assert argv[4] == "auto"
            assert len(argv) == 6
            assert cwd == firmae_root

            run_scratch = scratch_root / "777"
            run_scratch.mkdir(parents=True, exist_ok=True)
            _ = (run_scratch / "ip").write_text("192.0.2.10\n", encoding="utf-8")
            _ = (run_scratch / "ping").write_text("true\n", encoding="utf-8")
            _ = (run_scratch / "web").write_text("true\n", encoding="utf-8")
            _ = (run_scratch / "result").write_text("true\n", encoding="utf-8")
            return dv.CommandResult(
                argv=argv,
                returncode=0,
                stdout="[IID] 777\n",
                stderr="",
                timed_out=False,
                error=None,
            )

        if argv[:3] == ["git", "-C", str(firmae_root)]:
            out = "abcd1234\n" if "rev-parse" in argv else "v1\n"
            return dv.CommandResult(
                argv=argv,
                returncode=0,
                stdout=out,
                stderr="",
                timed_out=False,
                error=None,
            )

        if "tcpdump" in cmd:
            if "-w" in argv:
                idx = argv.index("-w")
                if idx + 1 < len(argv):
                    pcap_path = Path(argv[idx + 1])
                    pcap_path.parent.mkdir(parents=True, exist_ok=True)
                    _ = pcap_path.write_bytes(
                        struct.pack(
                            "<IHHIIII",
                            0xA1B2C3D4,
                            2,
                            4,
                            0,
                            0,
                            65535,
                            1,
                        )
                    )
            return dv.CommandResult(
                argv=argv,
                returncode=0,
                stdout="",
                stderr="",
                timed_out=False,
                error=None,
            )

        return dv.CommandResult(
            argv=argv,
            returncode=0,
            stdout="ok\n",
            stderr="",
            timed_out=False,
            error=None,
        )

    def fake_connect(addr: tuple[str, int], timeout: float) -> _Sock:
        _ = timeout
        ip, port = addr
        assert ip == "192.0.2.10"
        if port in {80, 22}:
            return _Sock()
        raise OSError("closed")

    monkeypatch.setattr("aiedge.dynamic_validation.shutil.which", fake_which)
    monkeypatch.setattr(dv, "_run_command", fake_run)
    monkeypatch.setattr(
        "aiedge.dynamic_validation.socket.create_connection", fake_connect
    )
    monkeypatch.setattr("aiedge.dynamic_validation.url_request.urlopen", _fake_urlopen)
    monkeypatch.setitem(
        __import__(
            "aiedge.stage_registry", fromlist=["_STAGE_FACTORIES"]
        )._STAGE_FACTORIES,
        "dynamic_validation",
        lambda info, source_input_path, remaining_s, no_llm: DynamicValidationStage(
            firmae_root=str(tmp_path / "FirmAE")
        ),
    )

    out = DynamicValidationStage(firmae_root=str(firmae_root), max_retries=2).run(ctx)
    stage_dir = ctx.run_dir / "stages" / "dynamic_validation"

    assert out.status == "ok"
    interfaces = cast(
        dict[str, object],
        json.loads((stage_dir / "network" / "interfaces.json").read_text("utf-8")),
    )
    assert interfaces["iid"] == "777"
    assert interfaces["interfaces"] == [{"ifname": "target", "ipv4": ["192.0.2.10"]}]

    ports = cast(
        dict[str, object],
        json.loads((stage_dir / "network" / "ports.json").read_text("utf-8")),
    )
    assert ports["target_ip"] == "192.0.2.10"
    open_ports = cast(list[object], ports["open_ports"])
    assert 80 in open_ports
    assert 22 in open_ports

    summary_text = (stage_dir / "dynamic_validation.json").read_text("utf-8")
    assert "/home/" not in summary_text
    assert "dynamic_validation.pcap" in summary_text
    assert "192.0.2.10" in summary_text


def test_dynamic_validation_marks_sudo_nopasswd_required(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    firmae_root = tmp_path / "FirmAE"
    firmae_root.mkdir(parents=True)
    _ = (firmae_root / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")

    def fake_which(name: str) -> str | None:
        mapping = {
            "sudo": "/usr/bin/sudo",
            "git": "/usr/bin/git",
            "ip": "/usr/sbin/ip",
            "tcpdump": "/usr/sbin/tcpdump",
        }
        return mapping.get(name)

    def fake_run(
        argv: list[str], *, timeout_s: float | None, cwd: Path | None = None
    ) -> dv.CommandResult:
        _ = timeout_s, cwd
        if "run.sh" in " ".join(argv):
            return dv.CommandResult(
                argv=argv,
                returncode=1,
                stdout="",
                stderr="sudo: a password is required\n",
                timed_out=False,
                error=None,
            )
        return dv.CommandResult(
            argv=argv,
            returncode=1,
            stdout="",
            stderr="fail\n",
            timed_out=False,
            error=None,
        )

    monkeypatch.setattr("aiedge.dynamic_validation.shutil.which", fake_which)
    monkeypatch.setattr(dv, "_run_command", fake_run)

    out = DynamicValidationStage(firmae_root=str(firmae_root), max_retries=1).run(ctx)
    assert out.status == "partial"
    assert "sudo_nopasswd_required" in out.limitations


def test_dynamic_validation_uses_env_privileged_runner_for_boot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    firmae_root = tmp_path / "FirmAE"
    firmae_root.mkdir(parents=True)
    _ = (firmae_root / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setenv("AIEDGE_PRIV_RUNNER", "privrun --")
    seen_boot_argv: list[list[str]] = []

    def fake_which(name: str) -> str | None:
        mapping = {
            "sudo": "/usr/bin/sudo",
            "privrun": "/usr/local/bin/privrun",
            "git": "/usr/bin/git",
        }
        return mapping.get(name)

    def fake_run(
        argv: list[str], *, timeout_s: float | None, cwd: Path | None = None
    ) -> dv.CommandResult:
        _ = timeout_s, cwd
        if "run.sh" in " ".join(argv):
            seen_boot_argv.append(list(argv))
            return dv.CommandResult(
                argv=argv,
                returncode=1,
                stdout="",
                stderr="boot failed\n",
                timed_out=False,
                error=None,
            )
        return dv.CommandResult(
            argv=argv,
            returncode=1,
            stdout="",
            stderr="missing\n",
            timed_out=False,
            error=None,
        )

    monkeypatch.setattr("aiedge.dynamic_validation.shutil.which", fake_which)
    monkeypatch.setattr(dv, "_run_command", fake_run)

    out = DynamicValidationStage(firmae_root=str(firmae_root), max_retries=1).run(ctx)
    assert out.status == "partial"
    assert seen_boot_argv
    assert seen_boot_argv[0][:2] == ["privrun", "--"]
    assert "/usr/bin/sudo" not in seen_boot_argv[0][:2]
    details = cast(dict[str, object], out.details)
    priv_any = details.get("privileged_executor")
    assert isinstance(priv_any, dict)
    priv = cast(dict[str, object], priv_any)
    assert priv.get("mode") == "runner"


def test_dynamic_validation_invalid_env_privileged_runner_falls_back_to_sudo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    firmae_root = tmp_path / "FirmAE"
    firmae_root.mkdir(parents=True)
    _ = (firmae_root / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setenv("AIEDGE_PRIV_RUNNER", "missing-priv-runner --")
    seen_boot_argv: list[list[str]] = []

    def fake_which(name: str) -> str | None:
        mapping = {
            "sudo": "/usr/bin/sudo",
            "git": "/usr/bin/git",
        }
        return mapping.get(name)

    def fake_run(
        argv: list[str], *, timeout_s: float | None, cwd: Path | None = None
    ) -> dv.CommandResult:
        _ = timeout_s, cwd
        if "run.sh" in " ".join(argv):
            seen_boot_argv.append(list(argv))
            return dv.CommandResult(
                argv=argv,
                returncode=1,
                stdout="",
                stderr="boot failed\n",
                timed_out=False,
                error=None,
            )
        return dv.CommandResult(
            argv=argv,
            returncode=1,
            stdout="",
            stderr="missing\n",
            timed_out=False,
            error=None,
        )

    monkeypatch.setattr("aiedge.dynamic_validation.shutil.which", fake_which)
    monkeypatch.setattr(dv, "_run_command", fake_run)

    out = DynamicValidationStage(firmae_root=str(firmae_root), max_retries=1).run(ctx)
    assert out.status == "partial"
    assert seen_boot_argv
    assert seen_boot_argv[0][:2] == ["/usr/bin/sudo", "-n"]
    assert "privileged_runner_unavailable" in out.limitations


def test_dynamic_validation_resolves_relative_runner_path_from_run_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    firmae_root = tmp_path / "FirmAE"
    runner_bin = ctx.run_dir / "tools" / "priv-runner"
    runner_bin.parent.mkdir(parents=True)
    _ = runner_bin.write_text("#!/bin/sh\n", encoding="utf-8")
    runner_bin.chmod(0o700)
    firmae_root.mkdir(parents=True)
    _ = (firmae_root / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setenv("AIEDGE_PRIV_RUNNER", "tools/priv-runner --")
    seen_boot_argv: list[list[str]] = []

    def fake_which(name: str) -> str | None:
        mapping = {
            "git": "/usr/bin/git",
            "ip": "/usr/sbin/ip",
        }
        return mapping.get(name)

    def fake_run(
        argv: list[str], *, timeout_s: float | None, cwd: Path | None = None
    ) -> dv.CommandResult:
        _ = timeout_s, cwd
        if "run.sh" in " ".join(argv):
            seen_boot_argv.append(list(argv))
            return dv.CommandResult(
                argv=argv,
                returncode=1,
                stdout="",
                stderr="boot failed\n",
                timed_out=False,
                error=None,
            )
        return dv.CommandResult(
            argv=argv,
            returncode=1,
            stdout="",
            stderr="missing\n",
            timed_out=False,
            error=None,
        )

    monkeypatch.setattr("aiedge.dynamic_validation.shutil.which", fake_which)
    monkeypatch.setattr(dv, "_run_command", fake_run)

    out = DynamicValidationStage(firmae_root=str(firmae_root), max_retries=1).run(ctx)
    assert out.status == "partial"
    assert seen_boot_argv
    assert seen_boot_argv[0][0] == str(runner_bin)
    assert seen_boot_argv[0][1] == "--"
    details = cast(dict[str, object], out.details)
    priv_any = details.get("privileged_executor")
    assert isinstance(priv_any, dict)
    priv = cast(dict[str, object], priv_any)
    assert priv.get("mode") == "runner"
    assert "privileged_runner_unavailable" not in out.limitations


def test_dynamic_validation_marks_sudo_execution_blocked_without_boot_flaky(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    firmae_root = tmp_path / "FirmAE"
    firmae_root.mkdir(parents=True)
    _ = (firmae_root / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")

    def fake_which(name: str) -> str | None:
        mapping = {
            "sudo": "/usr/bin/sudo",
            "git": "/usr/bin/git",
            "ip": "/usr/sbin/ip",
            "tcpdump": "/usr/sbin/tcpdump",
        }
        return mapping.get(name)

    def fake_run(
        argv: list[str], *, timeout_s: float | None, cwd: Path | None = None
    ) -> dv.CommandResult:
        _ = timeout_s, cwd
        if "run.sh" in " ".join(argv):
            return dv.CommandResult(
                argv=argv,
                returncode=1,
                stdout="",
                stderr='sudo: The "no new privileges" flag is set.\n',
                timed_out=False,
                error=None,
            )
        return dv.CommandResult(
            argv=argv,
            returncode=1,
            stdout="",
            stderr="fail\n",
            timed_out=False,
            error=None,
        )

    monkeypatch.setattr("aiedge.dynamic_validation.shutil.which", fake_which)
    monkeypatch.setattr(dv, "_run_command", fake_run)

    out = DynamicValidationStage(firmae_root=str(firmae_root), max_retries=1).run(ctx)
    assert out.status == "partial"
    assert "sudo_execution_blocked" in out.limitations
    assert "boot_flaky" not in out.limitations


def test_run_subset_dynamic_validation_writes_stage_and_report_section(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")
    info = create_run(
        str(fw),
        case_id="case-dynamic-validation",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    scratch_root = tmp_path / "FirmAE" / "scratch"
    scratch_root.mkdir(parents=True)

    def fake_which(name: str) -> str | None:
        mapping = {
            "sudo": "/usr/bin/sudo",
            "git": "/usr/bin/git",
            "tcpdump": "/usr/sbin/tcpdump",
            "iptables-save": "/usr/sbin/iptables-save",
            "ip6tables-save": "/usr/sbin/ip6tables-save",
            "nft": "/usr/sbin/nft",
            "ip": "/usr/sbin/ip",
        }
        return mapping.get(name)

    def fake_run(
        argv: list[str], *, timeout_s: float | None, cwd: Path | None = None
    ) -> dv.CommandResult:
        _ = timeout_s
        if "run.sh" in " ".join(argv):
            assert cwd == tmp_path / "FirmAE"
            run_scratch = scratch_root / "222"
            run_scratch.mkdir(parents=True, exist_ok=True)
            _ = (run_scratch / "ip").write_text("198.51.100.8\n", encoding="utf-8")
            _ = (run_scratch / "ping").write_text("true\n", encoding="utf-8")
            _ = (run_scratch / "web").write_text("false\n", encoding="utf-8")
            _ = (run_scratch / "result").write_text("false\n", encoding="utf-8")
            return dv.CommandResult(
                argv=argv,
                returncode=0,
                stdout="[IID] 222\n",
                stderr="",
                timed_out=False,
                error=None,
            )
        return dv.CommandResult(
            argv=argv,
            returncode=0,
            stdout="",
            stderr="",
            timed_out=False,
            error=None,
        )

    def fake_connect(addr: tuple[str, int], timeout: float) -> _Sock:
        _ = timeout
        ip, port = addr
        assert ip == "198.51.100.8"
        if port == 80:
            return _Sock()
        raise OSError("closed")

    monkeypatch.setattr("aiedge.dynamic_validation.shutil.which", fake_which)
    monkeypatch.setattr(dv, "_run_command", fake_run)
    monkeypatch.setattr(
        "aiedge.dynamic_validation.socket.create_connection", fake_connect
    )
    monkeypatch.setattr("aiedge.dynamic_validation.url_request.urlopen", _fake_urlopen)
    monkeypatch.setitem(
        __import__(
            "aiedge.stage_registry", fromlist=["_STAGE_FACTORIES"]
        )._STAGE_FACTORIES,
        "dynamic_validation",
        lambda info, source_input_path, remaining_s, no_llm: DynamicValidationStage(
            firmae_root=str(tmp_path / "FirmAE")
        ),
    )

    rep = run_subset(
        info,
        ["dynamic_validation"],
        time_budget_s=5,
        no_llm=True,
    )
    assert [r.stage for r in rep.stage_results] == ["dynamic_validation"]

    stage_manifest = info.run_dir / "stages" / "dynamic_validation" / "stage.json"
    assert stage_manifest.is_file()

    report = cast(
        dict[str, object],
        json.loads(info.report_json_path.read_text(encoding="utf-8")),
    )
    dv_report_any = report.get("dynamic_validation")
    assert isinstance(dv_report_any, dict)
    dv_report = cast(dict[str, object], dv_report_any)
    assert dv_report.get("status") in {"ok", "partial"}
    assert dv_report.get("dynamic_scope") in {"full_system", "single_binary"}
    assessment_any = report.get("exploit_assessment")
    assert isinstance(assessment_any, dict)
    assessment = cast(dict[str, object], assessment_any)
    assert assessment.get("profile") in {"analysis", "exploit"}


def test_dynamic_validation_placeholder_pcap_has_valid_header(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    firmae_root = tmp_path / "FirmAE"
    firmae_root.mkdir(parents=True, exist_ok=True)

    def fake_which(name: str) -> str | None:
        if name == "git":
            return "/usr/bin/git"
        return None

    monkeypatch.setattr("aiedge.dynamic_validation.shutil.which", fake_which)

    out = DynamicValidationStage(firmae_root=str(firmae_root), max_retries=1).run(ctx)
    assert out.status == "partial"

    pcap_path = ctx.run_dir / "stages" / "dynamic_validation" / "pcap" / "dynamic_validation.pcap"
    assert pcap_path.is_file()
    raw = pcap_path.read_bytes()
    assert len(raw) >= 24
    magic = struct.unpack_from("<I", raw, 0)[0]
    assert magic in (0xA1B2C3D4, 0xD4C3B2A1)
