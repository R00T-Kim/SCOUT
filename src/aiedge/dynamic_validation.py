from __future__ import annotations

import json
import re
import shutil
import socket
import ssl
import subprocess
from dataclasses import dataclass
from http.client import HTTPResponse
from pathlib import Path
from typing import cast
from urllib import error as url_error
from urllib import request as url_request

from .policy import AIEdgePolicyViolation
from .schema import JsonValue
from .stage import StageContext, StageOutcome

_ABS_PATH_TOKEN_RE = re.compile(r"(?P<path>/[^\s\"'`]+)")
_IID_RE = re.compile(r"\[IID\]\s*([0-9]+)")
_ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def _assert_under_dir(base_dir: Path, target: Path) -> None:
    base = base_dir.resolve()
    resolved = target.resolve()
    if not resolved.is_relative_to(base):
        raise AIEdgePolicyViolation(
            f"Refusing to write outside run dir: target={resolved} base={base}"
        )


def _rel_to_run_dir(run_dir: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(run_dir.resolve()))
    except Exception:
        return str(path)


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _sanitize_string_paths(text: str, *, run_dir: Path) -> str:
    run_resolved = run_dir.resolve()

    def repl(match: re.Match[str]) -> str:
        token = match.group("path")
        p = Path(token)
        if not p.is_absolute() or token == "/":
            return token
        try:
            rel = p.resolve().relative_to(run_resolved)
            return rel.as_posix()
        except Exception:
            return p.name if p.name else "<abs-path>"

    return _ABS_PATH_TOKEN_RE.sub(repl, text)


def _sanitize_argv_for_output(argv: list[str], *, run_dir: Path) -> list[str]:
    out: list[str] = []
    run_resolved = run_dir.resolve()
    for token in argv:
        p = Path(token)
        if p.is_absolute():
            try:
                out.append(
                    str(p.resolve().relative_to(run_resolved)).replace("\\", "/")
                )
            except Exception:
                out.append(p.name if p.name else "<abs-path>")
        else:
            out.append(token)
    return out


def _write_json(path: Path, payload: dict[str, JsonValue]) -> None:
    _ = path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


@dataclass(frozen=True)
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    error: str | None


def _run_command(
    argv: list[str],
    *,
    timeout_s: float | None,
    cwd: Path | None = None,
) -> CommandResult:
    try:
        cp = subprocess.run(
            argv,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_s,
            cwd=str(cwd) if cwd is not None else None,
        )
        return CommandResult(
            argv=list(argv),
            returncode=int(cp.returncode),
            stdout=cp.stdout or "",
            stderr=cp.stderr or "",
            timed_out=False,
            error=None,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            argv=list(argv),
            returncode=124,
            stdout=exc.stdout if isinstance(exc.stdout, str) else "",
            stderr=exc.stderr if isinstance(exc.stderr, str) else "",
            timed_out=True,
            error=f"timeout after {timeout_s}s",
        )
    except Exception as exc:
        return CommandResult(
            argv=list(argv),
            returncode=1,
            stdout="",
            stderr="",
            timed_out=False,
            error=f"{type(exc).__name__}: {exc}",
        )


def _as_jsonable_command_result(
    res: CommandResult, *, run_dir: Path
) -> dict[str, JsonValue]:
    return {
        "argv": cast(
            list[JsonValue],
            cast(
                list[object], _sanitize_argv_for_output(list(res.argv), run_dir=run_dir)
            ),
        ),
        "returncode": int(res.returncode),
        "stdout": _sanitize_string_paths(res.stdout, run_dir=run_dir),
        "stderr": _sanitize_string_paths(res.stderr, run_dir=run_dir),
        "timed_out": bool(res.timed_out),
        "error": _sanitize_string_paths(res.error or "", run_dir=run_dir),
    }


def _list_scratch_dirs(scratch_root: Path) -> dict[str, float]:
    out: dict[str, float] = {}
    if not scratch_root.is_dir():
        return out
    for child in scratch_root.iterdir():
        if not child.is_dir() or not child.name.isdigit():
            continue
        try:
            out[child.name] = float(child.stat().st_mtime)
        except OSError:
            continue
    return out


def _newest_scratch_iid(
    before: dict[str, float], scratch_root: Path, hint: str | None
) -> str | None:
    after = _list_scratch_dirs(scratch_root)
    if hint and hint in after:
        return hint

    candidates: list[tuple[str, float]] = []
    for iid, mtime in after.items():
        prev = before.get(iid)
        if prev is None or mtime > prev:
            candidates.append((iid, mtime))

    if candidates:
        candidates.sort(key=lambda pair: pair[1], reverse=True)
        return candidates[0][0]

    if after:
        return sorted(after.items(), key=lambda pair: pair[1], reverse=True)[0][0]
    return None


def _read_text(path: Path) -> str:
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return ""


def _read_target_from_scratch(
    *,
    scratch_root: Path,
    iid: str,
) -> tuple[dict[str, JsonValue], str | None]:
    scratch_dir = scratch_root / iid
    ip = _read_text(scratch_dir / "ip")

    ip_num_s = _read_text(scratch_dir / "ip_num")
    if (not ip) and ip_num_s.isdigit():
        for idx in range(int(ip_num_s)):
            ip_n = _read_text(scratch_dir / f"ip.{idx}")
            if ip_n:
                ip = ip_n
                break

    ping = _read_text(scratch_dir / "ping").lower() == "true"
    web = _read_text(scratch_dir / "web").lower() == "true"
    result = _read_text(scratch_dir / "result").lower()

    state: dict[str, JsonValue] = {
        "iid": iid,
        "scratch_dir": str(Path("scratch") / iid),
        "ip": ip,
        "ping": ping,
        "web": web,
        "result": result,
    }
    return state, (ip if ip else None)


def _collect_interfaces_from_target(
    *,
    target_ip: str | None,
    iid: str | None,
) -> tuple[dict[str, JsonValue], list[str]]:
    limitations: list[str] = []
    if not target_ip:
        limitations.append("target_ip_missing")
        return {
            "status": "partial",
            "iid": iid or "",
            "interfaces": cast(list[JsonValue], cast(list[object], [])),
            "reason": "target_ip_unavailable",
        }, limitations

    return {
        "status": "ok",
        "iid": iid or "",
        "interfaces": cast(
            list[JsonValue],
            cast(list[object], [{"ifname": "target", "ipv4": [target_ip]}]),
        ),
    }, limitations


def _probe_target_ports(
    *,
    target_ip: str | None,
    timeout_s: float,
) -> tuple[dict[str, JsonValue], list[str]]:
    limitations: list[str] = []
    probe_ports = [80, 443, 22, 23, 8080, 8443]
    if not target_ip:
        limitations.append("target_ip_missing")
        return {
            "status": "partial",
            "target_ip": "",
            "ports": cast(list[JsonValue], cast(list[object], [])),
            "open_ports": cast(list[JsonValue], cast(list[object], [])),
            "reason": "target_ip_unavailable",
        }, limitations

    probed: list[dict[str, JsonValue]] = []
    open_ports: list[int] = []
    for port in probe_ports:
        state = "closed"
        error = ""
        sock: socket.socket | None = None
        try:
            sock = socket.create_connection(
                (target_ip, int(port)), timeout=float(timeout_s)
            )
            state = "open"
            open_ports.append(int(port))
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
        probed.append(
            {
                "proto": "tcp",
                "port": int(port),
                "state": state,
                "error": error,
            }
        )

    return {
        "status": "ok",
        "target_ip": target_ip,
        "ports": cast(list[JsonValue], cast(list[object], probed)),
        "open_ports": cast(list[JsonValue], cast(list[object], open_ports)),
    }, limitations


def _run_http_probes(
    *,
    target_ip: str | None,
    open_ports: list[int],
    timeout_s: float,
) -> tuple[dict[str, JsonValue], list[str]]:
    if not target_ip:
        return cast(dict[str, JsonValue], {}), ["target_ip_missing"]

    http_candidates = [p for p in open_ports if p in (80, 443, 8080, 8443)]
    if not http_candidates:
        return cast(dict[str, JsonValue], {}), []

    insecure_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    insecure_ctx.check_hostname = False
    insecure_ctx.verify_mode = ssl.CERT_NONE
    reqs: list[dict[str, JsonValue]] = []
    for port in sorted(set(http_candidates)):
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{target_ip}:{port}/"
        status_code = 0
        body_sample = ""
        headers: dict[str, str] = {}
        err = ""
        try:
            req = url_request.Request(url=url, method="GET")
            with cast(
                HTTPResponse,
                url_request.urlopen(
                    req,
                    timeout=float(timeout_s),
                    context=insecure_ctx if scheme == "https" else None,
                ),
            ) as resp:
                status_code = int(resp.status)
                header_items = list(resp.getheaders())[:20]
                headers = {str(k): str(v) for k, v in header_items}
                body_sample = resp.read(256).decode("utf-8", errors="replace")
        except url_error.HTTPError as exc:
            status_code = int(exc.code)
            err = f"HTTPError:{exc.code}"
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"

        reqs.append(
            {
                "target": f"{target_ip}:{port}",
                "url": url,
                "status_code": int(status_code),
                "headers": cast(dict[str, JsonValue], headers),
                "body_sample": body_sample,
                "error": err,
            }
        )

    return {
        "target_ip": target_ip,
        "targets": cast(
            list[JsonValue],
            cast(
                list[object],
                [f"{target_ip}:{int(p)}" for p in sorted(set(http_candidates))],
            ),
        ),
        "requests": cast(list[JsonValue], cast(list[object], reqs)),
    }, []


def _capture_firewall_snapshot(
    *,
    run_dir: Path,
    snapshot_path: Path,
    timeout_s: float,
) -> tuple[list[str], list[dict[str, JsonValue]]]:
    limitations: list[str] = []
    sections: list[str] = []
    command_results: list[dict[str, JsonValue]] = []

    sudo_bin = shutil.which("sudo")
    candidates: list[tuple[str, list[str], bool]] = [
        ("iptables_save", ["iptables-save"], True),
        ("ip6tables_save", ["ip6tables-save"], True),
        ("nft_ruleset", ["nft", "list", "ruleset"], True),
        ("ip_route", ["ip", "route", "show"], False),
        ("ip6_route", ["ip", "-6", "route", "show"], False),
    ]

    for label, cmd, use_sudo in candidates:
        cmd_bin = shutil.which(cmd[0])
        if not cmd_bin:
            sections.append(f"### {label}\nMISSING: {cmd[0]}\n")
            command_results.append(
                {
                    "label": label,
                    "argv": cast(list[JsonValue], cast(list[object], cmd)),
                    "returncode": 127,
                    "error": "binary_missing",
                }
            )
            if use_sudo:
                limitations.append("firewall_snapshot_incomplete")
            continue

        argv = [cmd_bin] + cmd[1:]
        if use_sudo:
            if not sudo_bin:
                limitations.extend(
                    ["sudo_nopasswd_required", "firewall_snapshot_incomplete"]
                )
                sections.append(f"### {label}\nSKIP: sudo unavailable\n")
                continue
            argv = [sudo_bin, "-n"] + argv

        res = _run_command(argv, timeout_s=timeout_s)
        command_results.append(
            {
                "label": label,
                **_as_jsonable_command_result(res, run_dir=run_dir),
            }
        )
        sections.append(
            "\n".join(
                [
                    f"### {label}",
                    "command: "
                    + " ".join(_sanitize_argv_for_output(argv, run_dir=run_dir)),
                    f"returncode: {res.returncode}",
                    "--- stdout ---",
                    _sanitize_string_paths(res.stdout, run_dir=run_dir),
                    "--- stderr ---",
                    _sanitize_string_paths(res.stderr, run_dir=run_dir),
                    f"error: {_sanitize_string_paths(res.error or '', run_dir=run_dir)}",
                    "",
                ]
            )
        )
        if use_sudo and (res.returncode != 0 or res.timed_out):
            limitations.extend(
                ["sudo_nopasswd_required", "firewall_snapshot_incomplete"]
            )

    _ = snapshot_path.write_text("\n".join(sections), encoding="utf-8")
    return sorted(set(limitations)), command_results


def _capture_pcap(
    *,
    run_dir: Path,
    pcap_path: Path,
    timeout_s: float,
) -> tuple[list[str], dict[str, JsonValue]]:
    limitations: list[str] = []
    tcpdump_bin = shutil.which("tcpdump")
    sudo_bin = shutil.which("sudo")

    if not tcpdump_bin or not sudo_bin:
        _ = pcap_path.write_bytes(b"")
        limitations.append("pcap_placeholder")
        if not sudo_bin:
            limitations.append("sudo_nopasswd_required")
        return sorted(set(limitations)), {
            "status": "placeholder",
            "reason": "tcpdump_or_sudo_missing",
            "argv": cast(list[JsonValue], cast(list[object], [])),
        }

    argv = [
        sudo_bin,
        "-n",
        tcpdump_bin,
        "-i",
        "any",
        "-n",
        "-U",
        "-w",
        str(pcap_path),
        "-c",
        "1",
    ]
    res = _run_command(argv, timeout_s=timeout_s)
    if res.returncode != 0:
        limitations.append("sudo_nopasswd_required")
    if res.returncode != 0 and not pcap_path.exists():
        _ = pcap_path.write_bytes(b"")
        limitations.append("pcap_placeholder")

    status = (
        "captured"
        if pcap_path.exists() and pcap_path.stat().st_size > 0
        else "placeholder"
    )
    details = {
        "status": status,
        **_as_jsonable_command_result(res, run_dir=run_dir),
    }
    return sorted(set(limitations)), details


def _scan_roots_for_binary(
    roots: list[Path], max_candidates: int = 2000
) -> Path | None:
    wanted_names = {"busybox", "sh", "lighttpd", "httpd", "boa", "cgi-bin"}
    inspected = 0
    for root in roots:
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            inspected += 1
            if inspected > max_candidates:
                return None
            if path.name in wanted_names or path.name.endswith(".cgi"):
                return path
    return None


def _resolve_run_relative_dir(run_dir: Path, rel_path: str) -> Path | None:
    p = (run_dir / rel_path).resolve()
    if not p.is_relative_to(run_dir.resolve()):
        return None
    if not p.is_dir():
        return None
    return p


def _read_inventory_roots(run_dir: Path) -> list[Path]:
    inv_path = run_dir / "stages" / "inventory" / "inventory.json"
    if not inv_path.is_file():
        return []
    try:
        raw = cast(object, json.loads(inv_path.read_text(encoding="utf-8")))
    except Exception:
        return []
    if not isinstance(raw, dict):
        return []
    inv = cast(dict[str, object], raw)

    roots: list[Path] = []
    roots_any = inv.get("roots")
    if isinstance(roots_any, list):
        for item in cast(list[object], roots_any):
            if isinstance(item, str) and item:
                p = _resolve_run_relative_dir(run_dir, item)
                if isinstance(p, Path):
                    roots.append(p)
    extracted_any = inv.get("extracted_dir")
    if isinstance(extracted_any, str) and extracted_any:
        p2 = _resolve_run_relative_dir(run_dir, extracted_any)
        if isinstance(p2, Path):
            roots.append(p2)

    uniq: list[Path] = []
    seen: set[str] = set()
    for p in roots:
        key = str(p.resolve())
        if key in seen:
            continue
        seen.add(key)
        uniq.append(p)
    return uniq


def _read_profile_arch(run_dir: Path) -> str | None:
    profile_path = run_dir / "stages" / "firmware_profile" / "firmware_profile.json"
    if not profile_path.is_file():
        return None
    try:
        raw = cast(object, json.loads(profile_path.read_text(encoding="utf-8")))
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None
    arch_hints_any = cast(dict[str, object], raw).get("arch_hints")
    if not isinstance(arch_hints_any, dict):
        return None
    arch_any = cast(dict[str, object], arch_hints_any).get("arch")
    if isinstance(arch_any, str) and arch_any:
        return arch_any.lower()
    return None


def _qemu_binary_for_arch(arch: str | None) -> str | None:
    if not arch:
        return None
    arch_l = arch.lower()
    if "mips" in arch_l:
        return shutil.which("qemu-mips-static") or shutil.which("qemu-mipsel-static")
    if "arm" in arch_l:
        return shutil.which("qemu-arm-static") or shutil.which("qemu-aarch64-static")
    if "x86_64" in arch_l or "amd64" in arch_l:
        return shutil.which("qemu-x86_64-static")
    if "i386" in arch_l or "x86" in arch_l:
        return shutil.which("qemu-i386-static")
    return None


def _run_qemu_user_fallback(
    *,
    run_dir: Path,
    fallback_dir: Path,
    roots: list[Path],
    timeout_s: float,
) -> tuple[dict[str, JsonValue], list[str]]:
    limitations: list[str] = []
    arch = _read_profile_arch(run_dir)
    qemu_bin = _qemu_binary_for_arch(arch)
    selected = _scan_roots_for_binary(roots)

    log_path = fallback_dir / "qemu_user.log"
    proof_path = fallback_dir / "proof.json"
    argv_path = fallback_dir / "argv.json"

    run_result: dict[str, JsonValue]
    if not qemu_bin or not selected:
        msg = "fallback unavailable: qemu binary or target binary missing"
        _ = log_path.write_text(msg + "\n", encoding="utf-8")
        _write_json(
            proof_path,
            {
                "status": "partial",
                "reason": msg,
                "dynamic_scope": "single_binary",
            },
        )
        _write_json(
            argv_path,
            {
                "argv": cast(list[JsonValue], cast(list[object], [])),
                "input_mode": "none",
            },
        )
        limitations.append("qemu_user_fallback_unavailable")
        run_result = {
            "status": "partial",
            "reason": msg,
            "argv": cast(list[JsonValue], cast(list[object], [])),
        }
    else:
        argv = [qemu_bin, str(selected), "--help"]
        res = _run_command(argv, timeout_s=timeout_s)
        safe_argv = _sanitize_argv_for_output(argv, run_dir=run_dir)
        _ = log_path.write_text(
            "\n".join(
                [
                    "command: " + " ".join(safe_argv),
                    f"returncode: {res.returncode}",
                    "--- stdout ---",
                    _sanitize_string_paths(res.stdout, run_dir=run_dir),
                    "--- stderr ---",
                    _sanitize_string_paths(res.stderr, run_dir=run_dir),
                    f"error: {_sanitize_string_paths(res.error or '', run_dir=run_dir)}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        _write_json(
            proof_path,
            {
                "status": "ok" if res.returncode == 0 else "partial",
                "dynamic_scope": "single_binary",
                "returncode": int(res.returncode),
                "timed_out": bool(res.timed_out),
                "stdout_sample": _sanitize_string_paths(
                    (res.stdout or "")[:512], run_dir=run_dir
                ),
                "stderr_sample": _sanitize_string_paths(
                    (res.stderr or "")[:512], run_dir=run_dir
                ),
                "error": _sanitize_string_paths(res.error or "", run_dir=run_dir),
            },
        )
        _write_json(
            argv_path,
            {
                "argv": cast(list[JsonValue], cast(list[object], safe_argv)),
                "input_mode": "argv_help",
            },
        )
        if res.returncode != 0:
            limitations.append("qemu_user_fallback_failed")
        run_result = {
            "status": "ok" if res.returncode == 0 else "partial",
            "argv": cast(list[JsonValue], cast(list[object], safe_argv)),
            "returncode": int(res.returncode),
            "timed_out": bool(res.timed_out),
            "error": _sanitize_string_paths(res.error or "", run_dir=run_dir),
        }

    return {
        "dynamic_scope": "single_binary",
        "log": _rel_to_run_dir(run_dir, log_path),
        "proof": _rel_to_run_dir(run_dir, proof_path),
        "argv": _rel_to_run_dir(run_dir, argv_path),
        "result": run_result,
    }, limitations


def _detect_firmae_version(firmae_root: Path) -> dict[str, JsonValue]:
    out: dict[str, JsonValue] = {
        "firmae_root": "firmae_present" if firmae_root.is_dir() else "",
        "git_commit": "",
        "git_describe": "",
    }
    if not firmae_root.is_dir():
        return out
    rev = _run_command(
        ["git", "-C", str(firmae_root), "rev-parse", "HEAD"], timeout_s=5
    )
    desc = _run_command(
        ["git", "-C", str(firmae_root), "describe", "--always", "--dirty"], timeout_s=5
    )
    out["git_commit"] = (rev.stdout or "").strip() if rev.returncode == 0 else ""
    out["git_describe"] = (desc.stdout or "").strip() if desc.returncode == 0 else ""
    return out


def _collect_tool_versions() -> dict[str, JsonValue]:
    out: dict[str, JsonValue] = {}
    for key, cmd in (
        ("ip", ["ip", "-V"]),
        ("tcpdump", ["tcpdump", "--version"]),
        ("sudo", ["sudo", "-V"]),
    ):
        bin_path = shutil.which(cmd[0])
        if not bin_path:
            out[key] = "missing"
            continue
        res = _run_command([bin_path] + cmd[1:], timeout_s=5)
        lines = ((res.stdout or "") + "\n" + (res.stderr or "")).strip().splitlines()
        out[key] = lines[0] if lines else "unknown"
    return out


@dataclass(frozen=True)
class DynamicValidationStage:
    firmae_root: str = "/home/rootk1m/FirmAE"
    boot_timeout_s: float = 480.0
    probe_timeout_s: float = 3.0
    capture_timeout_s: float = 10.0
    max_retries: int = 2

    @property
    def name(self) -> str:
        return "dynamic_validation"

    def run(self, ctx: StageContext) -> StageOutcome:
        stage_dir = ctx.run_dir / "stages" / "dynamic_validation"
        _assert_under_dir(ctx.run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)

        firmae_dir = stage_dir / "firmae"
        qemu_user_dir = stage_dir / "qemu_user"
        network_dir = stage_dir / "network"
        probes_dir = stage_dir / "probes"
        isolation_dir = stage_dir / "isolation"
        pcap_dir = stage_dir / "pcap"
        for p in (
            firmae_dir,
            qemu_user_dir,
            network_dir,
            probes_dir,
            isolation_dir,
            pcap_dir,
        ):
            _assert_under_dir(ctx.run_dir, p)
            p.mkdir(parents=True, exist_ok=True)

        boot_log_path = firmae_dir / "boot.log"
        interfaces_path = network_dir / "interfaces.json"
        ports_path = network_dir / "ports.json"
        http_path = probes_dir / "http.json"
        snapshot_path = isolation_dir / "firewall_snapshot.txt"
        pcap_path = pcap_dir / "dynamic_validation.pcap"
        summary_path = stage_dir / "dynamic_validation.json"

        firmware_path = ctx.run_dir / "input" / "firmware.bin"
        roots = _read_inventory_roots(ctx.run_dir)
        limitations: list[str] = []

        evidence: list[dict[str, JsonValue]] = [
            {"path": _rel_to_run_dir(ctx.run_dir, boot_log_path)},
            {"path": _rel_to_run_dir(ctx.run_dir, interfaces_path)},
            {"path": _rel_to_run_dir(ctx.run_dir, ports_path)},
            {"path": _rel_to_run_dir(ctx.run_dir, http_path)},
            {"path": _rel_to_run_dir(ctx.run_dir, snapshot_path)},
            {"path": _rel_to_run_dir(ctx.run_dir, pcap_path)},
        ]

        firmae_root = Path(self.firmae_root)
        run_sh = firmae_root / "run.sh"
        scratch_root = firmae_root / "scratch"
        sudo_bin = shutil.which("sudo")
        attempt_count = max(1, int(self.max_retries))

        boot_attempts: list[dict[str, JsonValue]] = []
        boot_lines: list[str] = []
        boot_success = False
        saw_timeout = False
        target_ip: str | None = None
        target_iid: str | None = None
        scratch_state: dict[str, JsonValue] = {}

        for attempt in range(1, attempt_count + 1):
            if not run_sh.is_file():
                limitations.append("boot_flaky")
                boot_attempts.append(
                    {
                        "attempt": attempt,
                        "returncode": 127,
                        "timed_out": False,
                        "error": "run_sh_missing",
                    }
                )
                break

            if not sudo_bin:
                limitations.extend(["boot_flaky", "sudo_nopasswd_required"])
                boot_attempts.append(
                    {
                        "attempt": attempt,
                        "returncode": 127,
                        "timed_out": False,
                        "error": "sudo_missing",
                    }
                )
                break

            before = _list_scratch_dirs(scratch_root)
            argv = [sudo_bin, "-n", str(run_sh), "-c", "auto", str(firmware_path)]
            res = _run_command(
                argv, timeout_s=float(self.boot_timeout_s), cwd=firmae_root
            )
            saw_timeout = saw_timeout or res.timed_out

            out_text = _strip_ansi((res.stdout or "") + "\n" + (res.stderr or ""))
            iid_match = _IID_RE.search(out_text)
            iid_hint = iid_match.group(1) if iid_match else None
            iid = _newest_scratch_iid(before, scratch_root, iid_hint)
            state, ip = (
                _read_target_from_scratch(scratch_root=scratch_root, iid=iid)
                if iid
                else ({}, None)
            )

            if iid and ip:
                target_iid = iid
                target_ip = ip
                scratch_state = state

            safe_argv = _sanitize_argv_for_output(argv, run_dir=ctx.run_dir)
            boot_attempts.append(
                {
                    "attempt": attempt,
                    "iid": iid or "",
                    "target_ip": ip or "",
                    "returncode": int(res.returncode),
                    "timed_out": bool(res.timed_out),
                    "error": _sanitize_string_paths(
                        res.error or "", run_dir=ctx.run_dir
                    ),
                }
            )
            boot_lines.append(
                "\n".join(
                    [
                        f"attempt={attempt}",
                        "command: " + " ".join(safe_argv),
                        f"returncode: {res.returncode}",
                        f"iid: {iid or ''}",
                        f"target_ip: {ip or ''}",
                        "--- stdout ---",
                        _sanitize_string_paths(
                            _strip_ansi(res.stdout), run_dir=ctx.run_dir
                        ),
                        "--- stderr ---",
                        _sanitize_string_paths(
                            _strip_ansi(res.stderr), run_dir=ctx.run_dir
                        ),
                        "",
                    ]
                )
            )

            stderr_l = (res.stderr or "").lower()
            if (
                "password" in stderr_l
                or "a password is required" in stderr_l
                or "no tty present" in stderr_l
                or "sudo" in stderr_l
                and "askpass" in stderr_l
            ):
                limitations.append("sudo_nopasswd_required")

            if res.returncode == 0 and ip:
                boot_success = True
                break

        _ = boot_log_path.write_text("\n".join(boot_lines), encoding="utf-8")

        if not boot_success:
            limitations.append("boot_timeout" if saw_timeout else "boot_flaky")

        interfaces_payload, interface_limits = _collect_interfaces_from_target(
            target_ip=target_ip,
            iid=target_iid,
        )
        limitations.extend(interface_limits)
        _write_json(interfaces_path, interfaces_payload)

        ports_payload, port_limits = _probe_target_ports(
            target_ip=target_ip,
            timeout_s=float(self.probe_timeout_s),
        )
        limitations.extend(port_limits)
        _write_json(ports_path, ports_payload)

        open_ports: list[int] = []
        open_any = ports_payload.get("open_ports")
        if isinstance(open_any, list):
            open_ports = [int(x) for x in open_any if isinstance(x, int)]

        http_payload, http_limits = _run_http_probes(
            target_ip=target_ip,
            open_ports=open_ports,
            timeout_s=float(self.probe_timeout_s),
        )
        limitations.extend(http_limits)
        _write_json(
            http_path, http_payload if http_payload else cast(dict[str, JsonValue], {})
        )

        snapshot_limits, snapshot_commands = _capture_firewall_snapshot(
            run_dir=ctx.run_dir,
            snapshot_path=snapshot_path,
            timeout_s=float(self.capture_timeout_s),
        )
        limitations.extend(snapshot_limits)

        pcap_limits, pcap_capture = _capture_pcap(
            run_dir=ctx.run_dir,
            pcap_path=pcap_path,
            timeout_s=float(self.capture_timeout_s),
        )
        limitations.extend(pcap_limits)

        network_unstable = boot_success and not target_ip
        if network_unstable:
            limitations.extend(["boot_flaky", "network_unstable"])

        dynamic_scope: str
        fallback_payload: dict[str, JsonValue] | None = None
        if (not boot_success) or network_unstable:
            fallback_payload, fallback_limits = _run_qemu_user_fallback(
                run_dir=ctx.run_dir,
                fallback_dir=qemu_user_dir,
                roots=roots,
                timeout_s=float(self.capture_timeout_s),
            )
            limitations.extend(fallback_limits)
            dynamic_scope = "single_binary"
            evidence.append(
                {
                    "path": cast(str, fallback_payload.get("log", "")),
                    "note": "qemu_user_fallback",
                }
            )
        else:
            dynamic_scope = "full_system"

        versions: dict[str, JsonValue] = {
            "firmae": cast(JsonValue, _detect_firmae_version(firmae_root)),
            "tools": cast(JsonValue, _collect_tool_versions()),
        }

        summary_doc: dict[str, JsonValue] = {
            "schema_version": "1.0",
            "status": "ok"
            if dynamic_scope == "full_system" and not limitations
            else "partial",
            "dynamic_scope": dynamic_scope,
            "target": {
                "iid": target_iid or "",
                "ip": target_ip or "",
                "scratch_state": scratch_state,
            },
            "boot": {
                "attempts": cast(list[JsonValue], cast(list[object], boot_attempts)),
                "log": _rel_to_run_dir(ctx.run_dir, boot_log_path),
                "success": bool(boot_success),
            },
            "network": {
                "interfaces": _rel_to_run_dir(ctx.run_dir, interfaces_path),
                "ports": _rel_to_run_dir(ctx.run_dir, ports_path),
            },
            "probes": {"http": _rel_to_run_dir(ctx.run_dir, http_path)},
            "isolation": {
                "firewall_snapshot": _rel_to_run_dir(ctx.run_dir, snapshot_path),
                "firewall_commands": cast(
                    list[JsonValue], cast(list[object], snapshot_commands)
                ),
                "pcap": _rel_to_run_dir(ctx.run_dir, pcap_path),
                "pcap_capture": pcap_capture,
            },
            "versions": versions,
            "limitations": cast(
                list[JsonValue], cast(list[object], sorted(set(limitations)))
            ),
        }
        if fallback_payload is not None:
            summary_doc["fallback"] = fallback_payload

        _write_json(summary_path, summary_doc)
        evidence.append({"path": _rel_to_run_dir(ctx.run_dir, summary_path)})

        details: dict[str, JsonValue] = {
            "dynamic_scope": dynamic_scope,
            "summary": _rel_to_run_dir(ctx.run_dir, summary_path),
            "target_iid": target_iid or "",
            "target_ip": target_ip or "",
            "evidence": cast(list[JsonValue], cast(list[object], evidence)),
            "boot_attempts": cast(list[JsonValue], cast(list[object], boot_attempts)),
            "pcap": _rel_to_run_dir(ctx.run_dir, pcap_path),
        }

        status = (
            "ok" if not limitations and dynamic_scope == "full_system" else "partial"
        )
        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
