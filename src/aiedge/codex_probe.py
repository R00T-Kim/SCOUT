from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .llm_codex import load_llm_gate_fixture
from .schema import JsonValue


@dataclass(frozen=True)
class _ProbeCommandResult:
    ok: bool
    out: str
    executable_missing: bool = False


def _combine_output(proc: subprocess.CompletedProcess[str]) -> str:
    parts: list[str] = []
    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    if stdout:
        parts.append(stdout)
    if stderr:
        parts.append(stderr)
    return "\n".join(parts)


def _run_codex_command(
    args: list[str], *, timeout_s: float, env: dict[str, str]
) -> _ProbeCommandResult:
    try:
        proc = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            stdin=subprocess.DEVNULL,
            env=env,
        )
    except FileNotFoundError:
        return _ProbeCommandResult(
            ok=False,
            out="codex executable not found in PATH",
            executable_missing=True,
        )
    except subprocess.TimeoutExpired:
        return _ProbeCommandResult(
            ok=False,
            out=f"timed out after {timeout_s:.1f}s",
        )

    out = _combine_output(proc)
    if not out:
        out = f"exit code {proc.returncode}"
    return _ProbeCommandResult(ok=(proc.returncode == 0), out=out)


def _codex_auth_path(env: dict[str, str]) -> Path:
    codex_home = env.get("CODEX_HOME")
    if codex_home:
        return Path(codex_home) / "auth.json"
    return Path.home() / ".codex" / "auth.json"


def probe_codex_cli(*, timeout_s: float = 2.0) -> dict[str, JsonValue]:
    env = dict(os.environ)
    version = _run_codex_command(["codex", "--version"], timeout_s=timeout_s, env=env)
    help_result = _run_codex_command(["codex", "--help"], timeout_s=timeout_s, env=env)

    auth_path = _codex_auth_path(env)
    auth_present = auth_path.is_file()

    llm: dict[str, JsonValue] = {
        "driver": "codex",
        "status": "available",
        "probe": {
            "version_ok": version.ok,
            "version_out": version.out,
            "help_ok": help_result.ok,
            "help_out": help_result.out,
            "auth_cache_path": str(auth_path),
            "auth_cache_present": auth_present,
        },
    }

    if version.executable_missing or help_result.executable_missing:
        llm["status"] = "skipped"
        llm["reason"] = (
            "Codex CLI is not installed or not on PATH; install Codex CLI to enable LLM analysis."
        )
        return llm

    if not version.ok or not help_result.ok:
        llm["status"] = "skipped"
        llm["reason"] = (
            "Codex CLI probe failed; verify `codex --version` and `codex --help` run successfully."
        )

    if llm.get("status") == "available" and not auth_present:
        llm["note"] = (
            "Codex auth cache file is missing; credentials may be stored in OS keyring. "
            "`codex exec` will still be attempted and will report a login error if not authenticated."
        )

    return llm


def resolve_llm_gate_input(
    *,
    fixture_path: Path | None,
    run_dir: Path,
    report: dict[str, JsonValue],
) -> tuple[dict[str, object] | None, str | None]:
    _ = run_dir
    _ = report
    if fixture_path is None:
        return None, None
    payload = load_llm_gate_fixture(fixture_path)
    return payload, f"fixture:{fixture_path.resolve()}"
