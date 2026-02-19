from __future__ import annotations

from collections.abc import Iterable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
import errno

import json
import os
import re
import shlex
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import time
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
_QEMU_ATTEMPT_ARGS: tuple[tuple[str, ...], ...] = (
    ("--help",),
    ("-h",),
    ("-V",),
    ("--version",),
    ("help",),
    ("-v",),
)
_QEMU_MAX_BINARY_CANDIDATES = 12
_QEMU_MAX_ATTEMPTS = 18
_QEMU_MAX_SCAN_FILES = 800


def _write_minimal_pcap(path: Path, *, linktype: int = 1) -> None:
    """Write a valid pcap global header with zero packets.

    This keeps downstream network-isolation parsers deterministic even when
    capture tooling is unavailable.
    """
    header = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,  # magic
        2,  # major
        4,  # minor
        0,  # thiszone
        0,  # sigfigs
        65535,  # snaplen
        int(linktype),  # network linktype (1=Ethernet)
    )
    _ = path.write_bytes(header)


def _iter_sorted_stable(values: Iterable[str]) -> list[str]:
    return sorted(set(values), key=lambda item: item.lower())


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


def _looks_like_qemu_success_output(stdout: str, stderr: str, code: int) -> bool:
    if code == 0:
        return True

    text = (stdout or "").lower() + "\n" + (stderr or "").lower()
    if "command not found" in text or "no such file" in text:
        return False
    if "invalid option" in text or "unknown option" in text:
        return False
    if "not enough arguments" in text:
        return False
    return (
        "usage:" in text
        or "options:" in text
        or "help:" in text
        or "help options" in text
        or "qemu" in text
    )


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


@dataclass(frozen=True)
class PrivilegedExecutor:
    mode: str
    source: str
    prefix: tuple[str, ...]
    sudo_bin: str | None


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


def _resolve_privileged_executor(*, run_dir: Path) -> tuple[PrivilegedExecutor, list[str]]:
    limitations: list[str] = []
    sudo_bin = shutil.which("sudo")

    runner_raw = os.environ.get("AIEDGE_PRIV_RUNNER", "").strip()
    if runner_raw:
        try:
            parsed = shlex.split(runner_raw)
        except ValueError:
            parsed = []
            limitations.append("privileged_runner_invalid_config")

        if parsed:
            runner_bin = parsed[0]
            if "/" in runner_bin:
                runner_candidates: list[Path] = []
                runner_path = Path(runner_bin).expanduser()
                if runner_path.is_absolute():
                    runner_candidates.append(runner_path)
                else:
                    runner_candidates.extend(
                        [
                            Path.cwd() / runner_path,
                            run_dir / runner_path,
                            Path(__file__).resolve().parents[2] / runner_path,
                        ]
                    )
                runner_candidates.extend(
                    run_dir.parents[i] / runner_path
                    for i in range(1, len(run_dir.parents))
                )
                runner_bin_path: Path | None = None
                seen_paths: set[str] = set()
                for candidate in runner_candidates:
                    candidate_key = str(candidate)
                    if candidate_key in seen_paths:
                        continue
                    seen_paths.add(candidate_key)
                    if candidate.is_file():
                        runner_bin_path = candidate
                        break

                runner_valid = runner_bin_path is not None
                if not runner_valid:
                    limitations.append("privileged_runner_unavailable")
                else:
                    parsed = [str(runner_bin_path)] + parsed[1:]
            else:
                runner_valid = shutil.which(runner_bin) is not None
            if runner_valid:
                return (
                    PrivilegedExecutor(
                        mode="runner",
                        source="env:AIEDGE_PRIV_RUNNER",
                        prefix=tuple(parsed),
                        sudo_bin=sudo_bin,
                    ),
                    limitations,
                )
            limitations.append("privileged_runner_unavailable")
        else:
            limitations.append("privileged_runner_invalid_config")

    if sudo_bin:
        return (
            PrivilegedExecutor(
                mode="sudo",
                source="system:sudo",
                prefix=(sudo_bin, "-n"),
                sudo_bin=sudo_bin,
            ),
            limitations,
        )

    limitations.append("privileged_executor_missing")
    return (
        PrivilegedExecutor(
            mode="none",
            source="none",
            prefix=tuple(),
            sudo_bin=None,
        ),
        limitations,
    )


def _build_privileged_argv(
    cmd_argv: list[str], *, executor: PrivilegedExecutor
) -> list[str] | None:
    if executor.mode in {"sudo", "runner"} and executor.prefix:
        return list(executor.prefix) + list(cmd_argv)
    return None


def _record_privilege_failure_limitations(
    *,
    limitations: list[str],
    executor: PrivilegedExecutor,
    stderr: str,
    error: str | None,
) -> None:
    text = f"{stderr}\n{error or ''}".lower()
    if not text:
        return

    if "no new privileges" in text or "operation not permitted" in text:
        limitations.append("sudo_execution_blocked")

    if (
        "password" in text
        or "a password is required" in text
        or "no tty present" in text
        or ("sudo" in text and "askpass" in text)
    ):
        limitations.append("sudo_nopasswd_required")

    if executor.mode == "runner":
        if (
            "permission denied" in text
            or "not permitted" in text
            or "not found" in text
            or "no such file" in text
            or "failed to execute" in text
        ):
            limitations.append("privileged_runner_failed")


def _privileged_executor_payload(
    *, executor: PrivilegedExecutor, run_dir: Path
) -> dict[str, JsonValue]:
    return {
        "mode": executor.mode,
        "source": executor.source,
        "prefix": cast(
            list[JsonValue],
            cast(
                list[object],
                _sanitize_argv_for_output(list(executor.prefix), run_dir=run_dir),
            ),
        ),
    }


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


_BASE_PROBE_PORTS: tuple[int, ...] = (
    22,
    23,
    53,
    67,
    68,
    80,
    81,
    123,
    161,
    443,
    5000,
    7000,
    7547,
    8080,
    8081,
    8443,
    8888,
)

_SERVICE_PORT_HINTS: dict[str, tuple[int, ...]] = {
    "dropbear": (22,),
    "sshd": (22,),
    "ssh": (22,),
    "telnetd": (23,),
    "telnet": (23,),
    "uhttpd": (80, 443),
    "httpd": (80, 443),
    "nginx": (80, 443),
    "lighttpd": (80, 443),
    "boa": (80,),
    "mini_httpd": (80,),
    "rpcd": (80, 443, 8080),
    "dnsmasq": (53, 67),
    "named": (53,),
    "odhcpd": (67, 547),
    "ntpd": (123,),
    "snmpd": (161,),
    "upnpd": (1900,),
    "miniupnpd": (1900,),
    "tftpd": (69,),
    "ftpd": (21,),
    "proftpd": (21,),
}


def _safe_load_json_object(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        obj_any = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return {}
    if not isinstance(obj_any, dict):
        return {}
    return cast(dict[str, object], obj_any)


def _collect_static_port_hints(*, run_dir: Path) -> tuple[list[int], list[str]]:
    hints: set[int] = set(_BASE_PROBE_PORTS)
    sources: list[str] = []

    inv_obj = _safe_load_json_object(run_dir / "stages" / "inventory" / "inventory.json")
    service_candidates_any = inv_obj.get("service_candidates")
    if isinstance(service_candidates_any, list):
        for item_any in cast(list[object], service_candidates_any):
            if not isinstance(item_any, dict):
                continue
            item = cast(dict[str, object], item_any)
            name = str(item.get("name", "")).strip().lower()
            if not name:
                continue
            matched = False
            for token, ports in _SERVICE_PORT_HINTS.items():
                if token in name:
                    hints.update(int(p) for p in ports)
                    matched = True
            if matched:
                sources.append(f"service:{name}")

    endpoints_obj = _safe_load_json_object(run_dir / "stages" / "endpoints" / "endpoints.json")
    endpoints_any = endpoints_obj.get("endpoints")
    if isinstance(endpoints_any, list):
        for endpoint_any in cast(list[object], endpoints_any):
            if not isinstance(endpoint_any, dict):
                continue
            endpoint = cast(dict[str, object], endpoint_any)
            value = str(endpoint.get("value", "")).strip()
            if not value:
                continue
            # URL with explicit port
            match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/:]+:(\d{1,5})\b", value)
            if match:
                port = int(match.group(1))
                if 1 <= port <= 65535:
                    hints.add(port)
                    sources.append(f"endpoint:{port}")
                continue
            # host:port style literal
            match = re.match(r"^[a-zA-Z0-9_.:\-\[\]]+:(\d{1,5})$", value)
            if match:
                port = int(match.group(1))
                if 1 <= port <= 65535:
                    hints.add(port)
                    sources.append(f"endpoint:{port}")

    ordered_hints = sorted({p for p in hints if 1 <= p <= 65535})
    ordered_sources = sorted(set(sources))
    return ordered_hints, ordered_sources


def _derive_portscan_config(*, timeout_s: float) -> tuple[float, int, float, int, int, int]:
    connect_timeout = min(0.35, max(0.08, float(timeout_s) / 12.0))
    workers_default = 384
    budget_default_s = 90.0
    range_start_default = 1
    range_end_default = 65535

    workers_env = os.environ.get("AIEDGE_PORTSCAN_WORKERS", "").strip()
    budget_env = os.environ.get("AIEDGE_PORTSCAN_BUDGET_S", "").strip()
    range_start_env = os.environ.get("AIEDGE_PORTSCAN_START", "").strip()
    range_end_env = os.environ.get("AIEDGE_PORTSCAN_END", "").strip()
    timeout_env = os.environ.get("AIEDGE_PORTSCAN_CONNECT_TIMEOUT_S", "").strip()
    top_k_env = os.environ.get("AIEDGE_PORTSCAN_TOP_K", "").strip()

    workers = workers_default
    if workers_env.isdigit():
        workers = max(32, min(1024, int(workers_env)))

    budget_s = budget_default_s
    try:
        if budget_env:
            budget_s = max(15.0, min(600.0, float(budget_env)))
    except Exception:
        budget_s = budget_default_s

    try:
        if timeout_env:
            connect_timeout = max(0.03, min(2.0, float(timeout_env)))
    except Exception:
        pass

    top_k = 1000
    if top_k_env:
        try:
            top_k = max(0, min(65_535, int(top_k_env)))
        except Exception:
            top_k = 1000

    range_start = range_start_default
    range_end = range_end_default
    if range_start_env.isdigit():
        range_start = max(1, min(65535, int(range_start_env)))
    if range_end_env.isdigit():
        range_end = max(1, min(65535, int(range_end_env)))
    if range_start > range_end:
        range_start, range_end = range_end, range_start

    return connect_timeout, workers, budget_s, range_start, range_end, int(top_k)


def _iter_port_scan_plan(
    *,
    prioritized: list[int],
    top_k_ports: int,
    range_start: int,
    range_end: int,
) -> Iterable[int]:
    seen: set[int] = set()
    for port in prioritized:
        if not (range_start <= int(port) <= range_end):
            continue
        p = int(port)
        if p in seen:
            continue
        seen.add(p)
        yield p

    top_limit = max(0, int(top_k_ports))
    if top_limit > 0:
        for port in range(range_start, range_end + 1):
            if port in seen:
                continue
            if len(seen) - len(prioritized) >= top_limit:
                break
            seen.add(port)
            yield port

    for port in range(range_start, range_end + 1):
        if port in seen:
            continue
        seen.add(port)
        yield port


def _scan_single_tcp_port(*, target_ip: str, port: int, timeout_s: float) -> tuple[int, str, str]:
    sock: object | None = None
    try:
        # keep socket.create_connection for compatibility with tests/monkeypatching
        # and consistent behavior across platforms.
        sock = socket.create_connection((target_ip, int(port)), float(timeout_s))
        return int(port), "open", ""
    except socket.timeout:
        return int(port), "filtered", "TimeoutError: timed out"
    except OSError as exc:
        err_no = exc.errno
        if err_no in (
            errno.ETIMEDOUT,
            errno.EHOSTUNREACH,
            errno.ENETUNREACH,
            errno.EHOSTDOWN,
            errno.ENETDOWN,
        ):
            return int(port), "filtered", f"OSError[{err_no}]: {exc.strerror or exc}"
        if err_no in (errno.ECONNREFUSED,):
            return int(port), "closed", f"OSError[{err_no}]: {exc.strerror or exc}"

        # Some environments/tests raise OSError without errno for closed ports.
        message = str(exc).strip().lower()
        if err_no is None and message in {"closed", "connection refused"}:
            return int(port), "closed", f"OSError: {exc}"
        return int(port), "error", f"OSError[{err_no}]: {exc.strerror or exc}"
    except Exception as exc:
        return int(port), "error", f"{type(exc).__name__}: {exc}"
    finally:
        if sock is not None:
            close_fn = getattr(sock, "close", None)
            if callable(close_fn):
                try:
                    close_fn()
                except Exception:
                    pass


def _probe_target_ports(
    *,
    run_dir: Path,
    target_ip: str | None,
    timeout_s: float,
) -> tuple[dict[str, JsonValue], list[str]]:
    limitations: list[str] = []
    if not target_ip:
        limitations.append("target_ip_missing")
        return {
            "status": "partial",
            "target_ip": "",
            "ports": cast(list[JsonValue], cast(list[object], [])),
            "open_ports": cast(list[JsonValue], cast(list[object], [])),
            "reason": "target_ip_unavailable",
        }, limitations

    hint_ports, hint_sources = _collect_static_port_hints(run_dir=run_dir)
    connect_timeout_s, workers, budget_s, range_start, range_end, top_k_ports = (
        _derive_portscan_config(
        timeout_s=timeout_s
    )
    )
    plan_iter = _iter_port_scan_plan(
        prioritized=hint_ports,
        top_k_ports=top_k_ports,
        range_start=range_start,
        range_end=range_end,
    )

    scan_started = time.monotonic()
    budget_deadline = scan_started + float(budget_s)
    queue_depth = max(64, int(workers * 2))
    inflight: dict[Future[tuple[int, str, str]], int] = {}
    budget_hit = False
    plan_exhausted = False

    scanned_total = 0
    state_counts: dict[str, int] = {"open": 0, "closed": 0, "filtered": 0, "error": 0}
    open_ports: list[int] = []
    open_rows: list[dict[str, JsonValue]] = []
    sample_rows: list[dict[str, JsonValue]] = []

    with ThreadPoolExecutor(max_workers=int(workers)) as executor:
        while True:
            now = time.monotonic()
            if now >= budget_deadline:
                budget_hit = True

            while (not budget_hit) and len(inflight) < queue_depth:
                try:
                    port = next(plan_iter)
                except StopIteration:
                    plan_exhausted = True
                    break
                future = executor.submit(
                    _scan_single_tcp_port,
                    target_ip=target_ip,
                    port=int(port),
                    timeout_s=float(connect_timeout_s),
                )
                inflight[future] = int(port)

            if not inflight:
                if plan_exhausted or budget_hit:
                    break
                continue

            done, _pending = wait(
                set(inflight.keys()),
                timeout=0.1,
                return_when=FIRST_COMPLETED,
            )
            if not done:
                if budget_hit:
                    # deadline reached; stop submitting and wait for in-flight to drain
                    continue
                continue

            for future in done:
                _ = inflight.pop(future, None)
                try:
                    port, state, error = future.result()
                except Exception as exc:
                    state = "error"
                    error = f"{type(exc).__name__}: {exc}"
                    port = -1
                if port <= 0:
                    continue
                scanned_total += 1
                if state not in state_counts:
                    state = "error"
                state_counts[state] = state_counts.get(state, 0) + 1

                row = {
                    "proto": "tcp",
                    "port": int(port),
                    "state": state,
                    "error": error,
                }
                if state == "open":
                    open_ports.append(int(port))
                    open_rows.append(row)
                elif len(sample_rows) < 64:
                    sample_rows.append(row)

            if plan_exhausted and not inflight:
                break

    total_ports = max(1, (range_end - range_start + 1))
    coverage_pct = round((float(scanned_total) / float(total_ports)) * 100.0, 2)
    duration_s = round(max(0.0, time.monotonic() - scan_started), 3)
    if budget_hit and not plan_exhausted:
        limitations.append("port_scan_budget_exceeded")

    serialized_ports = open_rows + sample_rows[:32]
    open_unique = sorted({int(p) for p in open_ports if int(p) > 0})
    status = "ok" if (not limitations and plan_exhausted) else "partial"

    payload: dict[str, JsonValue] = {
        "status": status,
        "target_ip": target_ip,
        "scan_strategy": "adaptive_full_range_tcp",
        "scan_range": cast(list[JsonValue], cast(list[object], [int(range_start), int(range_end)])),
        "scan_top_k": int(top_k_ports),
        "scan_connect_timeout_s": float(connect_timeout_s),
        "scan_budget_s": float(budget_s),
        "scan_workers": int(workers),
        "hint_ports": cast(list[JsonValue], cast(list[object], hint_ports[:48])),
        "hint_sources": cast(list[JsonValue], cast(list[object], hint_sources[:48])),
        "ports": cast(list[JsonValue], cast(list[object], serialized_ports)),
        "open_ports": cast(list[JsonValue], cast(list[object], open_unique)),
        "summary": cast(
            JsonValue,
            {
                "scanned": int(scanned_total),
                "range_total": int(total_ports),
                "coverage_pct": float(coverage_pct),
                "open": int(state_counts.get("open", 0)),
                "closed": int(state_counts.get("closed", 0)),
                "filtered": int(state_counts.get("filtered", 0)),
                "error": int(state_counts.get("error", 0)),
                "budget_hit": bool(budget_hit and not plan_exhausted),
                "duration_s": float(duration_s),
            },
        ),
    }
    if budget_hit and not plan_exhausted:
        payload["reason"] = "scan_budget_reached_before_full_range_complete"
    return payload, limitations


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
    privileged_executor: PrivilegedExecutor,
) -> tuple[list[str], list[dict[str, JsonValue]]]:
    limitations: list[str] = []
    sections: list[str] = []
    command_results: list[dict[str, JsonValue]] = []

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
            wrapped = _build_privileged_argv(argv, executor=privileged_executor)
            if wrapped is None:
                limitations.extend(
                    [
                        "privileged_executor_missing",
                        "sudo_nopasswd_required",
                        "firewall_snapshot_incomplete",
                    ]
                )
                sections.append(
                    f"### {label}\nSKIP: privileged executor unavailable\n"
                )
                continue
            argv = wrapped

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
            limitations.append("firewall_snapshot_incomplete")
            _record_privilege_failure_limitations(
                limitations=limitations,
                executor=privileged_executor,
                stderr=res.stderr,
                error=res.error,
            )

    _ = snapshot_path.write_text("\n".join(sections), encoding="utf-8")
    return sorted(set(limitations)), command_results


def _capture_pcap(
    *,
    run_dir: Path,
    pcap_path: Path,
    timeout_s: float,
    privileged_executor: PrivilegedExecutor,
) -> tuple[list[str], dict[str, JsonValue]]:
    limitations: list[str] = []
    tcpdump_bin = shutil.which("tcpdump")
    cmd_argv: list[str] = []
    wrapped_argv: list[str] | None = None

    if not tcpdump_bin:
        _write_minimal_pcap(pcap_path, linktype=1)
        limitations.append("pcap_placeholder")
        return sorted(set(limitations)), {
            "status": "placeholder",
            "reason": "tcpdump_missing",
            "argv": cast(list[JsonValue], cast(list[object], [])),
        }

    cmd_argv = [
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
    wrapped_argv = _build_privileged_argv(cmd_argv, executor=privileged_executor)
    if wrapped_argv is None:
        _write_minimal_pcap(pcap_path, linktype=1)
        limitations.extend(
            ["pcap_placeholder", "privileged_executor_missing", "sudo_nopasswd_required"]
        )
        return sorted(set(limitations)), {
            "status": "placeholder",
            "reason": "privileged_executor_missing",
            "argv": cast(list[JsonValue], cast(list[object], [])),
        }

    res = _run_command(wrapped_argv, timeout_s=timeout_s)
    if res.returncode != 0:
        _record_privilege_failure_limitations(
            limitations=limitations,
            executor=privileged_executor,
            stderr=res.stderr,
            error=res.error,
        )
    if res.returncode != 0 and not pcap_path.exists():
        _write_minimal_pcap(pcap_path, linktype=1)
        limitations.append("pcap_placeholder")

    if (
        (not pcap_path.exists())
        or (pcap_path.is_file() and pcap_path.stat().st_size < 24)
    ):
        _write_minimal_pcap(pcap_path, linktype=1)
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


def _is_executable_file(path: Path) -> bool:
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode) and (mode & stat.S_IXUSR != 0)


def _looks_like_binary_file(path: Path) -> bool:
    if _is_executable_file(path):
        return True
    return path.suffix.lower() in {".bin", ".elf", ".out", ".exe", ".so", ".a", ".o"}


def _scan_roots_for_binary(
    roots: list[Path],
    max_candidates: int = _QEMU_MAX_BINARY_CANDIDATES,
    max_scan_files: int = _QEMU_MAX_SCAN_FILES,
) -> list[Path]:
    max_binary_candidates = max(1, int(max_candidates))
    wanted_names = {
        "busybox",
        "sh",
        "bash",
        "ash",
        "dash",
        "dropbear",
        "sshd",
        "lighttpd",
        "httpd",
        "boa",
        "nginx",
        "dnsmasq",
        "curl",
        "wget",
        "curl",
        "uci",
        "ubnt",  # ubnt-specific helper naming
        "cgi-bin",
    }
    priority_suffixes = {".cgi"}
    executable_names = {
        "dropbear",
        "sshd",
        "lighttpd",
        "httpd",
        "boa",
        "nginx",
        "dnsmasq",
        "busybox",
        "curl",
        "wget",
        "nc",
        "ncat",
        "tmux",
        "iptables",
        "ip",
        "ip6tables",
    }

    ranked: list[tuple[int, Path]] = []
    fallback_paths: list[tuple[int, Path]] = []
    seen: set[str] = set()
    inspected = 0

    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if inspected >= max_scan_files:
                break
            if not path.is_file():
                continue
            inspected += 1

            try:
                rel = str(path.resolve().relative_to(root.resolve()))
            except Exception:
                rel = path.name
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)

            if not _looks_like_binary_file(path):
                continue

            name = path.name
            name_low = name.lower()
            score = 0
            if name_low in wanted_names:
                score += 260
            if any(name_low.endswith(suffix) for suffix in priority_suffixes):
                score += 220
            if any(segment in rel.lower() for segment in ("/sbin/", "/bin/", "/usr/sbin/", "/usr/bin/")):
                score += 90
            if name_low in executable_names:
                score += 110
            if name_low.startswith(("ubnt-", "vyatta-", "wireguard")):
                score += 100
            if name_low.startswith(("dhcp", "http", "ssh", "dropbear", "nginx", "lighttpd")):
                score += 80
            if path.suffix.lower() == ".cgi":
                score += 70

            target = path.resolve()
            if score > 0:
                ranked.append((score, target))
            else:
                fallback_paths.append((10, target))

    ranked.sort(key=lambda item: (item[0], str(item[1])), reverse=True)
    final_candidates: list[Path] = []
    for _, candidate in ranked:
        if len(final_candidates) >= _QEMU_MAX_BINARY_CANDIDATES:
            break
        if candidate in final_candidates:
            continue
        final_candidates.append(candidate)

    if len(final_candidates) < _QEMU_MAX_BINARY_CANDIDATES and fallback_paths:
        fallback_paths.sort(key=lambda item: (item[0], str(item[1])), reverse=True)
        for _, fallback in fallback_paths:
            if len(final_candidates) >= _QEMU_MAX_BINARY_CANDIDATES:
                break
            if fallback in final_candidates:
                continue
            final_candidates.append(fallback)

    return final_candidates


def _qemu_dynamic_scope(candidate_count: int) -> str:
    if candidate_count <= 1:
        return "single_binary"
    return "single_binary_multi_binary"


def _safe_rel_path(path: Path, *, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except Exception:
        return path.as_posix()


def _extract_binary_stem(path: Path) -> str:
    stem = path.name
    if not stem:
        return "<unknown>"
    return stem


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
    candidates = _scan_roots_for_binary(roots)

    attempt_limit = max(1, int(_QEMU_MAX_ATTEMPTS))

    log_path = fallback_dir / "qemu_user.log"
    proof_path = fallback_dir / "proof.json"
    argv_path = fallback_dir / "argv.json"

    attempt_records: list[dict[str, JsonValue]] = []
    dynamic_scope = _qemu_dynamic_scope(len(candidates))
    if not qemu_bin:
        missing_reason = "qemu user-static binary missing for firmware architecture"
        _ = log_path.write_text(f"{missing_reason}\n", encoding="utf-8")
        _write_json(
            proof_path,
            {
                "status": "partial",
                "reason": missing_reason,
                "dynamic_scope": dynamic_scope,
                "candidate_count": int(len(candidates)),
                "attempts": cast(list[JsonValue], cast(list[object], [])),
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
        return {
            "dynamic_scope": dynamic_scope,
            "log": _rel_to_run_dir(run_dir, log_path),
            "proof": _rel_to_run_dir(run_dir, proof_path),
            "argv": _rel_to_run_dir(run_dir, argv_path),
            "result": {
                "status": "partial",
                "reason": missing_reason,
                "argv": cast(list[JsonValue], cast(list[object], [])),
            },
        }, limitations

    if not candidates:
        missing_reason = "fallback target binary candidates unavailable"
        _ = log_path.write_text(f"{missing_reason}\n", encoding="utf-8")
        _write_json(
            proof_path,
            {
                "status": "partial",
                "reason": missing_reason,
                "dynamic_scope": dynamic_scope,
                "candidate_count": 0,
                "attempts": cast(list[JsonValue], cast(list[object], [])),
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
        return {
            "dynamic_scope": dynamic_scope,
            "log": _rel_to_run_dir(run_dir, log_path),
            "proof": _rel_to_run_dir(run_dir, proof_path),
            "argv": _rel_to_run_dir(run_dir, argv_path),
            "result": {
                "status": "partial",
                "reason": missing_reason,
                "argv": cast(list[JsonValue], cast(list[object], [])),
            },
        }, limitations

    best_attempt: dict[str, JsonValue] | None = None
    fallback_succeeded = False

    for candidate_index, selected in enumerate(candidates, start=1):
        if len(attempt_records) >= attempt_limit:
            break
        candidate_rel = _safe_rel_path(selected, base=run_dir)
        for attempt_args in _QEMU_ATTEMPT_ARGS:
            if len(attempt_records) >= attempt_limit:
                break
            argv = [qemu_bin, str(selected)] + list(attempt_args)
            res = _run_command(argv, timeout_s=timeout_s)
            safe_argv = _sanitize_argv_for_output(argv, run_dir=run_dir)
            attempt_record: dict[str, JsonValue] = {
                "index": len(attempt_records) + 1,
                "candidate": candidate_index,
                "candidate_path": candidate_rel,
                "argv": cast(list[JsonValue], cast(list[object], safe_argv)),
                "attempt_args": cast(list[JsonValue], cast(list[object], list(attempt_args))),
                "returncode": int(res.returncode),
                "timed_out": bool(res.timed_out),
                "success": _looks_like_qemu_success_output(
                    res.stdout, res.stderr, int(res.returncode)
                ),
                "stdout_sample": _sanitize_string_paths(
                    (res.stdout or "")[:380], run_dir=run_dir
                ),
                "stderr_sample": _sanitize_string_paths(
                    (res.stderr or "")[:380], run_dir=run_dir
                ),
                "error": _sanitize_string_paths(res.error or "", run_dir=run_dir),
            }
            attempt_records.append(attempt_record)

            if bool(attempt_record["success"]):
                fallback_succeeded = True
                best_attempt = attempt_record
                break

            if not res.timed_out and int(res.returncode) in {126, 127}:
                limitations.append("qemu_user_fallback_binary_exec_failed")

        if fallback_succeeded:
            break

    proof_status = "ok" if fallback_succeeded else "partial"
    if best_attempt is None and attempt_records:
        best_attempt = cast(dict[str, JsonValue], attempt_records[0])

    log_lines: list[str] = ["qemu_user_fallback attempts:"]
    for entry in attempt_records:
        entry_argv = cast(
            list[object],
            entry.get("argv", cast(list[JsonValue], cast(list[object], []))),
        )
        entry_attempt_args = cast(
            list[object],
            entry.get("attempt_args", cast(list[JsonValue], cast(list[object], []))),
        )
        log_lines.extend(
            [
                f"[#{entry.get('index', '')}] candidate={entry.get('candidate', '')} "
                f"args={entry_attempt_args} rc={entry.get('returncode', 'unknown')} "
                f"success={entry.get('success', False)}",
                "  command: "
                + " ".join(cast(list[str], entry_argv))
                if isinstance(entry_argv, list)
                else "  command: <missing>",
                "  stdout: " + cast(str, entry.get("stdout_sample", "")),
                "  stderr: " + cast(str, entry.get("stderr_sample", "")),
                "",
            ]
        )
    _ = log_path.write_text("\n".join(log_lines), encoding="utf-8")

    _write_json(
        proof_path,
        {
            "status": proof_status,
            "reason": "qemu_user_fallback_attempted" if fallback_succeeded else "qemu_user_fallback_failed",
            "dynamic_scope": dynamic_scope,
            "candidate_count": int(len(candidates)),
            "attempts": cast(list[JsonValue], cast(list[object], attempt_records)),
            "best_attempt": cast(
                dict[str, JsonValue],
                best_attempt if isinstance(best_attempt, dict) else {},
            ),
        },
    )
    if isinstance(best_attempt, dict):
        best_argv = cast(
            list[object],
            best_attempt.get("argv", cast(list[JsonValue], cast(list[object], []))),
        )
        argv_path_payload = {
            "argv": cast(
                list[JsonValue],
                best_argv if isinstance(best_argv, list) else cast(list[object], []),
            )
        }
        argv_input_mode = "argv_probe"
    else:
        argv_path_payload = {"argv": cast(list[JsonValue], cast(list[object], []))}
        argv_input_mode = "none"
    _write_json(
        argv_path,
        {
            **argv_path_payload,
            "input_mode": argv_input_mode,
        },
    )
    if not fallback_succeeded:
        limitations.append("qemu_user_fallback_failed")

    best_attempt_argv = cast(
        list[object],
        best_attempt.get("argv", cast(list[JsonValue], cast(list[object], [])))
        if isinstance(best_attempt, dict)
        else cast(list[JsonValue], cast(list[object], [])),
    )
    run_result = {
        "status": proof_status,
        "argv": cast(
            list[JsonValue],
            cast(
                list[object],
                best_attempt_argv if isinstance(best_attempt_argv, list) else [],
            ),
        ),
        "returncode": int(best_attempt.get("returncode", -1))
        if isinstance(best_attempt, dict)
        else -1,
        "timed_out": bool(best_attempt.get("timed_out", False))
        if isinstance(best_attempt, dict)
        else False,
        "error": _sanitize_string_paths(
            str(best_attempt.get("error", "")) if isinstance(best_attempt, dict) else "",
            run_dir=run_dir,
        ),
    }

    return {
        "dynamic_scope": dynamic_scope,
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
        privileged_executor, privileged_limits = _resolve_privileged_executor(
            run_dir=ctx.run_dir
        )
        limitations.extend(privileged_limits)

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
        attempt_count = max(1, int(self.max_retries))

        boot_attempts: list[dict[str, JsonValue]] = []
        boot_lines: list[str] = []
        boot_success = False
        saw_timeout = False
        boot_attempted = False
        boot_blocked = False
        target_ip: str | None = None
        target_iid: str | None = None
        scratch_state: dict[str, JsonValue] = {}

        for attempt in range(1, attempt_count + 1):
            if not run_sh.is_file():
                limitations.append("boot_unavailable_run_sh_missing")
                boot_blocked = True
                boot_attempts.append(
                    {
                        "attempt": attempt,
                        "returncode": 127,
                        "timed_out": False,
                        "error": "run_sh_missing",
                    }
                )
                break

            boot_cmd = [str(run_sh), "-c", "auto", str(firmware_path)]
            argv = _build_privileged_argv(
                boot_cmd, executor=privileged_executor
            )
            if argv is None:
                limitations.extend(
                    [
                        "boot_unavailable_sudo_missing",
                        "boot_unavailable_privileged_executor_missing",
                        "sudo_nopasswd_required",
                    ]
                )
                boot_blocked = True
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
            boot_attempted = True
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
            sudo_auth_blocked = (
                "password" in stderr_l
                or "a password is required" in stderr_l
                or "no tty present" in stderr_l
                or ("sudo" in stderr_l and "askpass" in stderr_l)
            )
            sudo_exec_blocked = "sudo" in stderr_l and (
                "no new privileges" in stderr_l
                or "operation not permitted" in stderr_l
            )
            if sudo_auth_blocked:
                limitations.append("sudo_nopasswd_required")
                boot_blocked = True
            if sudo_exec_blocked:
                limitations.append("sudo_execution_blocked")
                boot_blocked = True
            if res.returncode != 0:
                _record_privilege_failure_limitations(
                    limitations=limitations,
                    executor=privileged_executor,
                    stderr=res.stderr,
                    error=res.error,
                )
                if privileged_executor.mode == "runner" and (
                    (res.error or "").strip()
                    or "permission denied" in stderr_l
                    or "operation not permitted" in stderr_l
                    or "not found" in stderr_l
                    or "no such file" in stderr_l
                ):
                    boot_blocked = True

            if res.returncode == 0 and ip:
                boot_success = True
                break

        _ = boot_log_path.write_text("\n".join(boot_lines), encoding="utf-8")

        if not boot_success and boot_attempted and not boot_blocked:
            limitations.append("boot_timeout" if saw_timeout else "boot_flaky")

        interfaces_payload, interface_limits = _collect_interfaces_from_target(
            target_ip=target_ip,
            iid=target_iid,
        )
        limitations.extend(interface_limits)
        _write_json(interfaces_path, interfaces_payload)

        ports_payload, port_limits = _probe_target_ports(
            run_dir=ctx.run_dir,
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
            privileged_executor=privileged_executor,
        )
        limitations.extend(snapshot_limits)

        pcap_limits, pcap_capture = _capture_pcap(
            run_dir=ctx.run_dir,
            pcap_path=pcap_path,
            timeout_s=float(self.capture_timeout_s),
            privileged_executor=privileged_executor,
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
            dynamic_scope = cast(
                str,
                fallback_payload.get("dynamic_scope", "single_binary"),
            )
            if not dynamic_scope:
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
            "privileged_executor": _privileged_executor_payload(
                executor=privileged_executor,
                run_dir=ctx.run_dir,
            ),
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
            "privileged_executor": _privileged_executor_payload(
                executor=privileged_executor,
                run_dir=ctx.run_dir,
            ),
        }

        status = (
            "ok" if not limitations and dynamic_scope == "full_system" else "partial"
        )
        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
