"""Unified LLM CLI driver abstraction.

Consolidates the repeated codex-exec subprocess pattern from
llm_synthesis, exploit_autopoc, and llm_codex into a single module.
"""
from __future__ import annotations

import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

ModelTier = Literal["haiku", "sonnet", "opus"]


@dataclass(frozen=True)
class LLMDriverResult:
    """Outcome of a single LLM CLI invocation (with retries)."""

    status: str  # "ok"|"skipped"|"timeout"|"error"|"nonzero_exit"|"missing_cli"
    stdout: str
    stderr: str
    argv: list[str]
    attempts: list[dict[str, object]]
    returncode: int
    usage: dict[str, int] | None = None


class LLMDriver(Protocol):
    """Structural protocol every LLM backend must satisfy."""

    @property
    def name(self) -> str: ...

    def available(self) -> bool: ...

    def execute(
        self,
        *,
        prompt: str,
        run_dir: Path,
        timeout_s: float,
        max_attempts: int = 3,
        retryable_tokens: tuple[str, ...] = (),
        model_tier: ModelTier = "sonnet",
    ) -> LLMDriverResult: ...


class CodexCLIDriver:
    """Wraps ``codex exec --ephemeral`` with retry / fallback logic."""

    @property
    def name(self) -> str:
        return "codex"

    def available(self) -> bool:
        return shutil.which("codex") is not None

    def execute(
        self,
        *,
        prompt: str,
        run_dir: Path,
        timeout_s: float,
        max_attempts: int = 3,
        retryable_tokens: tuple[str, ...] = (),
        model_tier: ModelTier = "sonnet",
    ) -> LLMDriverResult:
        if not self.available():
            return LLMDriverResult(
                status="missing_cli",
                stdout="",
                stderr="codex executable not found",
                argv=[],
                attempts=[],
                returncode=-1,
            )

        base_argv = [
            "codex",
            "exec",
            "--ephemeral",
            "-s",
            "read-only",
            "-C",
            str(run_dir),
        ]
        argv = base_argv + [prompt]
        attempts: list[dict[str, object]] = []

        def _exec_once(cmd: list[str]) -> subprocess.CompletedProcess[str]:
            cp = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                stdin=subprocess.DEVNULL,
            )
            attempts.append(
                {
                    "argv": list(cmd),
                    "returncode": int(cp.returncode),
                    "stdout": cp.stdout or "",
                    "stderr": cp.stderr or "",
                }
            )
            return cp

        cp: subprocess.CompletedProcess[str] | None = None
        use_skip_git_repo_check = False

        for attempt_idx in range(max(1, max_attempts)):
            cmd = (
                base_argv + ["--skip-git-repo-check", prompt]
                if use_skip_git_repo_check
                else list(argv)
            )
            try:
                cp = _exec_once(cmd)
            except subprocess.TimeoutExpired as exc:
                attempts.append(
                    {
                        "argv": list(cmd),
                        "returncode": -1,
                        "stdout": (exc.stdout if isinstance(exc.stdout, str) else "") or "",
                        "stderr": (exc.stderr if isinstance(exc.stderr, str) else "") or "",
                        "exception": "TimeoutExpired",
                    }
                )
                if attempt_idx + 1 < max_attempts:
                    continue
                return LLMDriverResult(
                    status="timeout",
                    stdout=(exc.stdout if isinstance(exc.stdout, str) else "") or "",
                    stderr=(exc.stderr if isinstance(exc.stderr, str) else "") or "",
                    argv=list(cmd),
                    attempts=attempts,
                    returncode=-1,
                )
            except FileNotFoundError:
                return LLMDriverResult(
                    status="missing_cli",
                    stdout="",
                    stderr="codex executable not found",
                    argv=list(cmd),
                    attempts=attempts,
                    returncode=-1,
                )
            except Exception as exc:
                return LLMDriverResult(
                    status="error",
                    stdout="",
                    stderr=f"{type(exc).__name__}: {exc}",
                    argv=list(cmd),
                    attempts=attempts,
                    returncode=-1,
                )

            stderr_lc = (cp.stderr or "").lower()
            if cp.returncode == 0:
                break

            if "skip-git-repo-check" in stderr_lc and not use_skip_git_repo_check:
                use_skip_git_repo_check = True
                continue

            if retryable_tokens and any(
                token in stderr_lc for token in retryable_tokens
            ):
                continue

            break

        if cp is None:
            return LLMDriverResult(
                status="error",
                stdout="",
                stderr="codex execution did not produce a process result",
                argv=list(argv),
                attempts=attempts,
                returncode=-1,
            )

        status = "ok" if cp.returncode == 0 else "nonzero_exit"
        return LLMDriverResult(
            status=status,
            stdout=cp.stdout or "",
            stderr=cp.stderr or "",
            argv=list(attempts[-1]["argv"]) if attempts else list(argv),
            attempts=attempts,
            returncode=int(cp.returncode),
        )


class ClaudeAPIDriver:
    """Direct Claude API driver via urllib (no SDK needed)."""

    _MODEL_MAP: dict[str, str] = {
        "haiku": "claude-haiku-4-5-20251001",
        "sonnet": "claude-sonnet-4-6-20250827",
        "opus": "claude-opus-4-6-20250826",
    }

    _RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 529})

    @property
    def name(self) -> str:
        return "claude"

    def available(self) -> bool:
        return bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())

    def execute(
        self,
        *,
        prompt: str,
        run_dir: Path,
        timeout_s: float,
        max_attempts: int = 3,
        retryable_tokens: tuple[str, ...] = (),
        model_tier: ModelTier = "sonnet",
    ) -> LLMDriverResult:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not api_key:
            return LLMDriverResult(
                status="missing_cli",
                stdout="",
                stderr="ANTHROPIC_API_KEY not set",
                argv=[],
                attempts=[],
                returncode=-1,
            )

        model = self._MODEL_MAP.get(model_tier, self._MODEL_MAP["sonnet"])
        url = "https://api.anthropic.com/v1/messages"
        payload = json.dumps({
            "model": model,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }).encode("utf-8")
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        attempts: list[dict[str, object]] = []
        argv = [f"POST {url}", f"model={model}"]

        for attempt_idx in range(max(1, max_attempts)):
            attempt_record: dict[str, object] = {"attempt": attempt_idx + 1, "model": model}
            try:
                req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
                ctx = ssl.create_default_context()
                with urllib.request.urlopen(req, timeout=timeout_s, context=ctx) as resp:
                    raw = resp.read().decode("utf-8")
                    attempt_record["returncode"] = 0
                    attempt_record["raw_response_len"] = len(raw)
                    attempts.append(attempt_record)
                    data = json.loads(raw)
                    content_blocks = data.get("content", [])
                    stdout = ""
                    for block in content_blocks:
                        if isinstance(block, dict) and block.get("type") == "text":
                            stdout += block.get("text", "")
                    usage_raw = data.get("usage", {})
                    usage: dict[str, int] | None = None
                    if usage_raw:
                        usage = {
                            "input_tokens": int(usage_raw.get("input_tokens", 0)),
                            "output_tokens": int(usage_raw.get("output_tokens", 0)),
                        }
                    return LLMDriverResult(
                        status="ok",
                        stdout=stdout,
                        stderr="",
                        argv=argv,
                        attempts=attempts,
                        returncode=0,
                        usage=usage,
                    )
            except urllib.error.HTTPError as exc:
                status_code = exc.code
                attempt_record["returncode"] = status_code
                try:
                    err_body = exc.read().decode("utf-8", errors="replace")
                except Exception:
                    err_body = ""
                attempt_record["stderr"] = err_body
                attempts.append(attempt_record)
                if status_code in self._RETRYABLE_STATUS and attempt_idx + 1 < max_attempts:
                    backoff = 2 ** attempt_idx
                    time.sleep(backoff)
                    continue
                return LLMDriverResult(
                    status="error",
                    stdout="",
                    stderr=f"HTTP {status_code}: {err_body[:500]}",
                    argv=argv,
                    attempts=attempts,
                    returncode=status_code,
                )
            except TimeoutError as exc:
                attempt_record["returncode"] = -1
                attempt_record["exception"] = "TimeoutError"
                attempts.append(attempt_record)
                if attempt_idx + 1 < max_attempts:
                    continue
                return LLMDriverResult(
                    status="timeout",
                    stdout="",
                    stderr=f"Request timed out after {timeout_s}s: {exc}",
                    argv=argv,
                    attempts=attempts,
                    returncode=-1,
                )
            except (ssl.SSLError, urllib.error.URLError, OSError) as exc:
                attempt_record["returncode"] = -1
                attempt_record["exception"] = type(exc).__name__
                attempt_record["stderr"] = str(exc)
                attempts.append(attempt_record)
                if attempt_idx + 1 < max_attempts:
                    time.sleep(2 ** attempt_idx)
                    continue
                return LLMDriverResult(
                    status="error",
                    stdout="",
                    stderr=f"{type(exc).__name__}: {exc}",
                    argv=argv,
                    attempts=attempts,
                    returncode=-1,
                )
            except Exception as exc:
                attempt_record["returncode"] = -1
                attempt_record["exception"] = type(exc).__name__
                attempt_record["stderr"] = str(exc)
                attempts.append(attempt_record)
                return LLMDriverResult(
                    status="error",
                    stdout="",
                    stderr=f"{type(exc).__name__}: {exc}",
                    argv=argv,
                    attempts=attempts,
                    returncode=-1,
                )

        # Should not be reached
        return LLMDriverResult(
            status="error",
            stdout="",
            stderr="ClaudeAPIDriver: exhausted attempts without result",
            argv=argv,
            attempts=attempts,
            returncode=-1,
        )


class OllamaDriver:
    """Local Ollama LLM server driver."""

    _TIER_DEFAULTS: dict[str, str] = {
        "haiku": "llama3.2:1b",
        "sonnet": "llama3.2:3b",
        "opus": "llama3.1:8b",
    }

    @property
    def name(self) -> str:
        return "ollama"

    def _base_url(self) -> str:
        return os.environ.get("AIEDGE_OLLAMA_URL", "http://localhost:11434").rstrip("/")

    def _model_for_tier(self, tier: ModelTier) -> str:
        env_key = f"AIEDGE_OLLAMA_MODEL_{tier.upper()}"
        return os.environ.get(env_key, self._TIER_DEFAULTS.get(tier, "llama3.2:3b"))

    def available(self) -> bool:
        url = f"{self._base_url()}/api/tags"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            return False

    def execute(
        self,
        *,
        prompt: str,
        run_dir: Path,
        timeout_s: float,
        max_attempts: int = 3,
        retryable_tokens: tuple[str, ...] = (),
        model_tier: ModelTier = "sonnet",
    ) -> LLMDriverResult:
        model = self._model_for_tier(model_tier)
        url = f"{self._base_url()}/api/generate"
        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
        }).encode("utf-8")
        headers = {"content-type": "application/json"}
        argv = [f"POST {url}", f"model={model}"]
        attempts: list[dict[str, object]] = []

        for attempt_idx in range(max(1, max_attempts)):
            attempt_record: dict[str, object] = {"attempt": attempt_idx + 1, "model": model}
            try:
                req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                    raw = resp.read().decode("utf-8")
                    attempt_record["returncode"] = 0
                    attempts.append(attempt_record)
                    data = json.loads(raw)
                    stdout = data.get("response", "")
                    return LLMDriverResult(
                        status="ok",
                        stdout=stdout,
                        stderr="",
                        argv=argv,
                        attempts=attempts,
                        returncode=0,
                    )
            except urllib.error.HTTPError as exc:
                status_code = exc.code
                attempt_record["returncode"] = status_code
                try:
                    err_body = exc.read().decode("utf-8", errors="replace")
                except Exception:
                    err_body = ""
                attempt_record["stderr"] = err_body
                attempts.append(attempt_record)
                if attempt_idx + 1 < max_attempts:
                    time.sleep(2 ** attempt_idx)
                    continue
                return LLMDriverResult(
                    status="error",
                    stdout="",
                    stderr=f"HTTP {status_code}: {err_body[:500]}",
                    argv=argv,
                    attempts=attempts,
                    returncode=status_code,
                )
            except TimeoutError as exc:
                attempt_record["returncode"] = -1
                attempt_record["exception"] = "TimeoutError"
                attempts.append(attempt_record)
                if attempt_idx + 1 < max_attempts:
                    continue
                return LLMDriverResult(
                    status="timeout",
                    stdout="",
                    stderr=f"Request timed out after {timeout_s}s: {exc}",
                    argv=argv,
                    attempts=attempts,
                    returncode=-1,
                )
            except (urllib.error.URLError, OSError) as exc:
                attempt_record["returncode"] = -1
                attempt_record["exception"] = type(exc).__name__
                attempt_record["stderr"] = str(exc)
                attempts.append(attempt_record)
                if attempt_idx + 1 < max_attempts:
                    time.sleep(2 ** attempt_idx)
                    continue
                return LLMDriverResult(
                    status="error",
                    stdout="",
                    stderr=f"{type(exc).__name__}: {exc}",
                    argv=argv,
                    attempts=attempts,
                    returncode=-1,
                )
            except Exception as exc:
                attempt_record["returncode"] = -1
                attempt_record["exception"] = type(exc).__name__
                attempt_record["stderr"] = str(exc)
                attempts.append(attempt_record)
                return LLMDriverResult(
                    status="error",
                    stdout="",
                    stderr=f"{type(exc).__name__}: {exc}",
                    argv=argv,
                    attempts=attempts,
                    returncode=-1,
                )

        return LLMDriverResult(
            status="error",
            stdout="",
            stderr="OllamaDriver: exhausted attempts without result",
            argv=argv,
            attempts=attempts,
            returncode=-1,
        )


class ClaudeCodeCLIDriver:
    """Wraps ``claude -p`` CLI with OAuth auth (no API key needed)."""

    _TIER_MAP: dict[str, str] = {
        "haiku": "haiku",
        "sonnet": "sonnet",
        "opus": "opus",
    }

    @property
    def name(self) -> str:
        return "claude-code"

    def available(self) -> bool:
        return shutil.which("claude") is not None

    def execute(
        self,
        *,
        prompt: str,
        run_dir: Path,
        timeout_s: float,
        max_attempts: int = 3,
        retryable_tokens: tuple[str, ...] = (),
        model_tier: ModelTier = "sonnet",
    ) -> LLMDriverResult:
        if not self.available():
            return LLMDriverResult(
                status="missing_cli",
                stdout="",
                stderr="claude executable not found",
                argv=[],
                attempts=[],
                returncode=-1,
            )

        model_alias = self._TIER_MAP.get(model_tier, "sonnet")
        base_argv = [
            "claude",
            "-p",
            "--model", model_alias,
            "--output-format", "text",
            "--no-session-persistence",
            "--dangerously-skip-permissions",
        ]
        argv = base_argv + [prompt]
        attempts: list[dict[str, object]] = []

        for attempt_idx in range(max(1, max_attempts)):
            try:
                cp = subprocess.run(
                    argv,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout_s,
                    stdin=subprocess.DEVNULL,
                )
                attempts.append({
                    "argv": list(argv),
                    "returncode": int(cp.returncode),
                    "stdout": cp.stdout or "",
                    "stderr": cp.stderr or "",
                })
            except subprocess.TimeoutExpired as exc:
                attempts.append({
                    "argv": list(argv),
                    "returncode": -1,
                    "stdout": (exc.stdout if isinstance(exc.stdout, str) else "") or "",
                    "stderr": (exc.stderr if isinstance(exc.stderr, str) else "") or "",
                    "exception": "TimeoutExpired",
                })
                if attempt_idx + 1 < max_attempts:
                    continue
                return LLMDriverResult(
                    status="timeout",
                    stdout="",
                    stderr=f"claude CLI timed out after {timeout_s}s",
                    argv=list(argv),
                    attempts=attempts,
                    returncode=-1,
                )
            except FileNotFoundError:
                return LLMDriverResult(
                    status="missing_cli",
                    stdout="",
                    stderr="claude executable not found",
                    argv=list(argv),
                    attempts=attempts,
                    returncode=-1,
                )
            except Exception as exc:
                return LLMDriverResult(
                    status="error",
                    stdout="",
                    stderr=f"{type(exc).__name__}: {exc}",
                    argv=list(argv),
                    attempts=attempts,
                    returncode=-1,
                )

            if cp.returncode == 0:
                return LLMDriverResult(
                    status="ok",
                    stdout=cp.stdout or "",
                    stderr=cp.stderr or "",
                    argv=list(argv),
                    attempts=attempts,
                    returncode=0,
                )

            stderr_lc = (cp.stderr or "").lower()
            if retryable_tokens and any(
                token in stderr_lc for token in retryable_tokens
            ):
                time.sleep(2 ** attempt_idx)
                continue

            if "overloaded" in stderr_lc or "rate" in stderr_lc:
                time.sleep(2 ** attempt_idx)
                continue

            return LLMDriverResult(
                status="nonzero_exit",
                stdout=cp.stdout or "",
                stderr=cp.stderr or "",
                argv=list(argv),
                attempts=attempts,
                returncode=int(cp.returncode),
            )

        last = attempts[-1] if attempts else {}
        return LLMDriverResult(
            status="error",
            stdout=str(last.get("stdout", "")),
            stderr=str(last.get("stderr", "exhausted attempts")),
            argv=list(argv),
            attempts=attempts,
            returncode=-1,
        )


_KNOWN_LLM_DRIVERS = frozenset({"codex", "claude", "claude-code", "ollama"})


def resolve_driver() -> LLMDriver:
    """Return the configured LLM driver (default: codex)."""
    driver_name = os.environ.get("AIEDGE_LLM_DRIVER", "codex").strip().lower()
    if driver_name == "claude":
        return ClaudeAPIDriver()
    if driver_name == "claude-code":
        return ClaudeCodeCLIDriver()
    if driver_name == "ollama":
        return OllamaDriver()
    if driver_name not in _KNOWN_LLM_DRIVERS:
        sys.stderr.write(
            f"[AIEDGE] WARNING: unrecognized AIEDGE_LLM_DRIVER={driver_name!r}, "
            f"falling back to codex. Valid drivers: {sorted(_KNOWN_LLM_DRIVERS)}\n"
        )
    return CodexCLIDriver()  # default fallback
