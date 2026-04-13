"""LLM driver conformance suite (PR #5).

Verifies that all 4 drivers correctly forward system_prompt and temperature,
and report failures via the documented classification (quota_exhausted,
driver_unavailable, driver_nonzero_exit).

Externally-facing claim: 'SCOUT supports system_prompt and temperature on all
4 driver backends (Codex CLI, Claude API, Claude Code CLI, Ollama).'
This file is the test that backs that claim.

Known gaps (documented, not fixed here):
- CodexCLIDriver: temperature parameter is accepted but silently dropped.
  The CLI has no temperature flag; prepend-style prompts are the only
  mechanism, and temperature cannot be encoded there.
- ClaudeCodeCLIDriver: same situation — temperature is accepted but not
  forwarded. The `claude -p` CLI exposes no temperature flag.
"""

from __future__ import annotations

import inspect
import json
import subprocess
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aiedge.llm_driver import (
    ClaudeAPIDriver,
    ClaudeCodeCLIDriver,
    CodexCLIDriver,
    LLMDriverResult,
    OllamaDriver,
    classify_llm_failure,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fake_subprocess_cp(
    returncode: int, stdout: str = "", stderr: str = ""
) -> MagicMock:
    cp = MagicMock(spec=subprocess.CompletedProcess)
    cp.returncode = returncode
    cp.stdout = stdout
    cp.stderr = stderr
    return cp


class _FakeHTTPResponse:
    """Minimal context-manager HTTP response for urlopen mocking."""

    def __init__(self, body: bytes, status: int = 200) -> None:
        self._body = body
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, *args: object) -> None:
        pass


# ---------------------------------------------------------------------------
# CodexCLIDriver
# ---------------------------------------------------------------------------


class TestCodexCLIDriverConformance:
    """CodexCLIDriver wraps ``codex exec --ephemeral``.

    system_prompt is prepended as '[System instructions]\\n...' because the
    CLI has no native system field.  temperature is accepted by the Protocol
    signature but silently dropped (no CLI flag available).
    """

    def test_system_prompt_prepended_in_argv(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """system_prompt must appear verbatim inside the prompt argument."""
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/codex")
        captured: dict[str, object] = {}

        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            captured["cmd"] = cmd
            return _make_fake_subprocess_cp(0, stdout='{"ok": true}')

        monkeypatch.setattr("subprocess.run", fake_run)

        driver = CodexCLIDriver()
        driver.execute(
            prompt="analyse binary",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
            system_prompt="You are a security expert. Output only JSON.",
        )

        cmd = captured["cmd"]
        assert isinstance(cmd, list)
        full_prompt = cmd[-1]
        assert "You are a security expert" in full_prompt
        assert "[System instructions]" in full_prompt
        assert "[User prompt]" in full_prompt
        assert "analyse binary" in full_prompt

    def test_system_prompt_empty_not_prepended(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Empty system_prompt must not inject sentinel markers."""
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/codex")
        captured: dict[str, object] = {}

        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            captured["cmd"] = cmd
            return _make_fake_subprocess_cp(0, stdout="output")

        monkeypatch.setattr("subprocess.run", fake_run)

        driver = CodexCLIDriver()
        driver.execute(
            prompt="plain prompt",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
            system_prompt="",
        )

        cmd = captured["cmd"]
        assert isinstance(cmd, list)
        full_prompt = cmd[-1]
        assert "[System instructions]" not in full_prompt
        assert full_prompt == "plain prompt"

    def test_temperature_silently_dropped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """temperature is accepted (Protocol compliance) but has no CLI mapping.

        Verify it does NOT raise and does NOT appear as a literal string in
        the command — the driver must not try to stringify it into the argv.
        """
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/codex")
        captured: dict[str, object] = {}

        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            captured["cmd"] = cmd
            return _make_fake_subprocess_cp(0, stdout="output")

        monkeypatch.setattr("subprocess.run", fake_run)

        driver = CodexCLIDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
            temperature=0.7,
        )

        # Must succeed despite unsupported temperature
        assert result.status == "ok"
        cmd = captured["cmd"]
        assert isinstance(cmd, list)
        # temperature value must not appear as a raw flag in argv
        assert "--temperature" not in cmd
        assert "-t" not in cmd

    def test_quota_exhausted_classified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/codex")
        monkeypatch.setattr(
            "subprocess.run",
            lambda *a, **kw: _make_fake_subprocess_cp(
                1,
                stdout="You've hit your limit · resets 12am (Asia/Seoul)\n",
                stderr="",
            ),
        )

        driver = CodexCLIDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
        )

        bucket, _ = classify_llm_failure(result)
        assert bucket == "quota_exhausted"

    def test_nonzero_exit_classified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/codex")
        monkeypatch.setattr(
            "subprocess.run",
            lambda *a, **kw: _make_fake_subprocess_cp(1, stderr="internal error"),
        )

        driver = CodexCLIDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
        )

        assert result.status == "nonzero_exit"
        bucket, _ = classify_llm_failure(result)
        assert bucket == "driver_nonzero_exit"

    def test_timeout_classified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/codex")

        def fake_run(*args: object, **kwargs: object) -> None:
            raise subprocess.TimeoutExpired(cmd=["codex"], timeout=5.0)

        monkeypatch.setattr("subprocess.run", fake_run)

        driver = CodexCLIDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=5.0,
            max_attempts=1,
        )

        assert result.status == "timeout"
        bucket, _ = classify_llm_failure(result)
        assert bucket == "timeout"

    def test_missing_cli_classified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: None)

        driver = CodexCLIDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
        )

        assert result.status == "missing_cli"
        bucket, _ = classify_llm_failure(result)
        assert bucket == "driver_unavailable"


# ---------------------------------------------------------------------------
# ClaudeAPIDriver
# ---------------------------------------------------------------------------


class TestClaudeAPIDriverConformance:
    """ClaudeAPIDriver POSTs to api.anthropic.com/v1/messages.

    system_prompt -> body['system'] (omitted when empty).
    temperature   -> body['temperature'] (omitted when None).
    """

    def _make_urlopen(self, captured: dict[str, object], response_body: bytes):
        """Return a fake urlopen that records the request and returns body."""

        def fake_urlopen(
            req: object, timeout: float, context: object
        ) -> _FakeHTTPResponse:
            captured["url"] = getattr(req, "full_url", None)
            captured["data"] = getattr(req, "data", None)
            captured["headers"] = dict(getattr(req, "headers", {}))
            return _FakeHTTPResponse(response_body)

        return fake_urlopen

    def _ok_response(self, text: str = "response text") -> bytes:
        return json.dumps(
            {
                "content": [{"type": "text", "text": text}],
                "usage": {"input_tokens": 10, "output_tokens": 5},
            }
        ).encode("utf-8")

    def test_system_prompt_in_request_body(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """system_prompt must be placed in body['system']."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-abc")
        captured: dict[str, object] = {}
        monkeypatch.setattr(
            "aiedge.llm_driver.urllib.request.urlopen",
            self._make_urlopen(captured, self._ok_response()),
        )

        driver = ClaudeAPIDriver()
        result = driver.execute(
            prompt="user message",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
            system_prompt="You are a strict JSON emitter.",
        )

        assert result.status == "ok"
        body = json.loads(captured["data"])  # type: ignore[arg-type]
        assert "system" in body
        assert body["system"] == "You are a strict JSON emitter."

    def test_system_prompt_absent_when_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Empty system_prompt must not produce a 'system' key at all."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-abc")
        captured: dict[str, object] = {}
        monkeypatch.setattr(
            "aiedge.llm_driver.urllib.request.urlopen",
            self._make_urlopen(captured, self._ok_response()),
        )

        driver = ClaudeAPIDriver()
        driver.execute(
            prompt="user message",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
            system_prompt="",
        )

        body = json.loads(captured["data"])  # type: ignore[arg-type]
        assert "system" not in body

    def test_temperature_in_request_body(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """temperature must be forwarded as body['temperature']."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-abc")
        captured: dict[str, object] = {}
        monkeypatch.setattr(
            "aiedge.llm_driver.urllib.request.urlopen",
            self._make_urlopen(captured, self._ok_response()),
        )

        driver = ClaudeAPIDriver()
        result = driver.execute(
            prompt="user message",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
            temperature=0.3,
        )

        assert result.status == "ok"
        body = json.loads(captured["data"])  # type: ignore[arg-type]
        assert "temperature" in body
        assert body["temperature"] == pytest.approx(0.3)

    def test_temperature_absent_when_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """temperature=None must not produce a 'temperature' key."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-abc")
        captured: dict[str, object] = {}
        monkeypatch.setattr(
            "aiedge.llm_driver.urllib.request.urlopen",
            self._make_urlopen(captured, self._ok_response()),
        )

        driver = ClaudeAPIDriver()
        driver.execute(
            prompt="user message",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
            temperature=None,
        )

        body = json.loads(captured["data"])  # type: ignore[arg-type]
        assert "temperature" not in body

    def test_model_tier_maps_to_correct_model_string(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """model_tier='haiku' must map to the haiku model ID."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-abc")
        captured: dict[str, object] = {}
        monkeypatch.setattr(
            "aiedge.llm_driver.urllib.request.urlopen",
            self._make_urlopen(captured, self._ok_response()),
        )

        driver = ClaudeAPIDriver()
        driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
            model_tier="haiku",
        )

        body = json.loads(captured["data"])  # type: ignore[arg-type]
        assert "haiku" in body["model"].lower()

    def test_missing_api_key_returns_missing_cli(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        driver = ClaudeAPIDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
        )

        assert result.status == "missing_cli"
        bucket, _ = classify_llm_failure(result)
        assert bucket == "driver_unavailable"

    def test_429_rate_limit_retries_and_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """HTTP 429 is in _RETRYABLE_STATUS; after exhausting retries status='error'."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-abc")
        # Patch time.sleep to avoid actual delays
        monkeypatch.setattr("aiedge.llm_driver.time.sleep", lambda _: None)
        call_count = 0

        def fake_urlopen(*args: object, **kwargs: object) -> None:
            nonlocal call_count
            call_count += 1
            raise urllib.error.HTTPError(
                url="https://api.anthropic.com/v1/messages",
                code=429,
                msg="Too Many Requests",
                hdrs={},  # type: ignore[arg-type]
                fp=None,
            )

        monkeypatch.setattr("aiedge.llm_driver.urllib.request.urlopen", fake_urlopen)

        driver = ClaudeAPIDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=2,
        )

        assert result.status == "error"
        assert "429" in result.stderr
        assert call_count == 2  # all attempts exhausted

    def test_4xx_non_retryable_fails_immediately(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """HTTP 400 is not retryable; must fail on first attempt."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-abc")
        call_count = 0

        def fake_urlopen(*args: object, **kwargs: object) -> None:
            nonlocal call_count
            call_count += 1
            raise urllib.error.HTTPError(
                url="https://api.anthropic.com/v1/messages",
                code=400,
                msg="Bad Request",
                hdrs={},  # type: ignore[arg-type]
                fp=None,
            )

        monkeypatch.setattr("aiedge.llm_driver.urllib.request.urlopen", fake_urlopen)

        driver = ClaudeAPIDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=3,
        )

        assert result.status == "error"
        assert "400" in result.stderr
        assert call_count == 1

    def test_network_error_classified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """URLError (connection refused) must retry then return status='error'."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-abc")
        monkeypatch.setattr("aiedge.llm_driver.time.sleep", lambda _: None)

        def fake_urlopen(*args: object, **kwargs: object) -> None:
            raise urllib.error.URLError(reason="[Errno 111] Connection refused")

        monkeypatch.setattr("aiedge.llm_driver.urllib.request.urlopen", fake_urlopen)

        driver = ClaudeAPIDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=5.0,
            max_attempts=1,
        )

        assert result.status == "error"
        assert "URLError" in result.stderr or "Connection refused" in result.stderr

    def test_usage_tokens_captured(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Usage token counts must be propagated into LLMDriverResult.usage."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-abc")
        captured: dict[str, object] = {}
        monkeypatch.setattr(
            "aiedge.llm_driver.urllib.request.urlopen",
            self._make_urlopen(
                captured,
                json.dumps(
                    {
                        "content": [{"type": "text", "text": "hello"}],
                        "usage": {"input_tokens": 42, "output_tokens": 7},
                    }
                ).encode("utf-8"),
            ),
        )

        driver = ClaudeAPIDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
        )

        assert result.status == "ok"
        assert result.usage is not None
        assert result.usage["input_tokens"] == 42
        assert result.usage["output_tokens"] == 7


# ---------------------------------------------------------------------------
# OllamaDriver
# ---------------------------------------------------------------------------


class TestOllamaDriverConformance:
    """OllamaDriver POSTs to /api/generate.

    system_prompt -> body['system'] (omitted when empty).
    temperature   -> body['options']['temperature'] (omitted when None).
    """

    def _make_urlopen(self, captured: dict[str, object], response_body: bytes):
        def fake_urlopen(req: object, timeout: float) -> _FakeHTTPResponse:
            captured["url"] = getattr(req, "full_url", None)
            captured["data"] = getattr(req, "data", None)
            return _FakeHTTPResponse(response_body)

        return fake_urlopen

    def _ok_response(self, text: str = "model output") -> bytes:
        return json.dumps({"response": text, "done": True}).encode("utf-8")

    def test_system_prompt_in_payload(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """system_prompt must appear as body['system']."""
        monkeypatch.setenv("AIEDGE_OLLAMA_URL", "http://localhost:11434")
        captured: dict[str, object] = {}
        monkeypatch.setattr(
            "aiedge.llm_driver.urllib.request.urlopen",
            self._make_urlopen(captured, self._ok_response()),
        )

        driver = OllamaDriver()
        result = driver.execute(
            prompt="scan firmware",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
            system_prompt="Return only valid JSON arrays.",
        )

        assert result.status == "ok"
        body = json.loads(captured["data"])  # type: ignore[arg-type]
        assert "system" in body
        assert body["system"] == "Return only valid JSON arrays."

    def test_system_prompt_absent_when_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AIEDGE_OLLAMA_URL", "http://localhost:11434")
        captured: dict[str, object] = {}
        monkeypatch.setattr(
            "aiedge.llm_driver.urllib.request.urlopen",
            self._make_urlopen(captured, self._ok_response()),
        )

        driver = OllamaDriver()
        driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
            system_prompt="",
        )

        body = json.loads(captured["data"])  # type: ignore[arg-type]
        assert "system" not in body

    def test_temperature_in_options(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """temperature must appear as body['options']['temperature']."""
        monkeypatch.setenv("AIEDGE_OLLAMA_URL", "http://localhost:11434")
        captured: dict[str, object] = {}
        monkeypatch.setattr(
            "aiedge.llm_driver.urllib.request.urlopen",
            self._make_urlopen(captured, self._ok_response()),
        )

        driver = OllamaDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
            temperature=0.1,
        )

        assert result.status == "ok"
        body = json.loads(captured["data"])  # type: ignore[arg-type]
        assert "options" in body
        assert body["options"]["temperature"] == pytest.approx(0.1)

    def test_temperature_absent_when_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AIEDGE_OLLAMA_URL", "http://localhost:11434")
        captured: dict[str, object] = {}
        monkeypatch.setattr(
            "aiedge.llm_driver.urllib.request.urlopen",
            self._make_urlopen(captured, self._ok_response()),
        )

        driver = OllamaDriver()
        driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
            temperature=None,
        )

        body = json.loads(captured["data"])  # type: ignore[arg-type]
        assert "options" not in body

    def test_custom_base_url_used(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """AIEDGE_OLLAMA_URL must control the target endpoint."""
        monkeypatch.setenv("AIEDGE_OLLAMA_URL", "http://gpu-box:11434")
        captured: dict[str, object] = {}
        monkeypatch.setattr(
            "aiedge.llm_driver.urllib.request.urlopen",
            self._make_urlopen(captured, self._ok_response()),
        )

        driver = OllamaDriver()
        driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
        )

        assert captured["url"] is not None
        assert "gpu-box:11434" in str(captured["url"])

    def test_connection_refused_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """URLError (connection refused) must return status='error' after retries."""
        monkeypatch.setenv("AIEDGE_OLLAMA_URL", "http://localhost:11434")
        monkeypatch.setattr("aiedge.llm_driver.time.sleep", lambda _: None)

        def fake_urlopen(*args: object, **kwargs: object) -> None:
            raise urllib.error.URLError(reason="[Errno 111] Connection refused")

        monkeypatch.setattr("aiedge.llm_driver.urllib.request.urlopen", fake_urlopen)

        driver = OllamaDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=5.0,
            max_attempts=1,
        )

        assert result.status == "error"
        assert "URLError" in result.stderr or "Connection refused" in result.stderr

    def test_http_error_retries_then_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """HTTPError on Ollama should retry then report status='error'."""
        monkeypatch.setenv("AIEDGE_OLLAMA_URL", "http://localhost:11434")
        monkeypatch.setattr("aiedge.llm_driver.time.sleep", lambda _: None)
        call_count = 0

        def fake_urlopen(*args: object, **kwargs: object) -> None:
            nonlocal call_count
            call_count += 1
            raise urllib.error.HTTPError(
                url="http://localhost:11434/api/generate",
                code=503,
                msg="Service Unavailable",
                hdrs={},  # type: ignore[arg-type]
                fp=None,
            )

        monkeypatch.setattr("aiedge.llm_driver.urllib.request.urlopen", fake_urlopen)

        driver = OllamaDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=5.0,
            max_attempts=2,
        )

        assert result.status == "error"
        assert "503" in result.stderr
        assert call_count == 2

    def test_stream_false_in_payload(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """stream must be False to get a single JSON response (not NDJSON)."""
        monkeypatch.setenv("AIEDGE_OLLAMA_URL", "http://localhost:11434")
        captured: dict[str, object] = {}
        monkeypatch.setattr(
            "aiedge.llm_driver.urllib.request.urlopen",
            self._make_urlopen(captured, self._ok_response()),
        )

        driver = OllamaDriver()
        driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
        )

        body = json.loads(captured["data"])  # type: ignore[arg-type]
        assert body["stream"] is False


# ---------------------------------------------------------------------------
# ClaudeCodeCLIDriver
# ---------------------------------------------------------------------------


class TestClaudeCodeCLIDriverConformance:
    """ClaudeCodeCLIDriver wraps ``claude -p --model <tier>``.

    system_prompt is prepended as '[System instructions]\\n...' (no CLI flag).
    temperature is accepted by the Protocol but silently dropped.
    """

    def test_system_prompt_prepended_in_argv(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """system_prompt must appear in the final prompt argument."""
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/claude")
        captured: dict[str, object] = {}

        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            captured["cmd"] = cmd
            return _make_fake_subprocess_cp(0, stdout="analysis result")

        monkeypatch.setattr("subprocess.run", fake_run)

        driver = ClaudeCodeCLIDriver()
        result = driver.execute(
            prompt="find vulnerabilities",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
            system_prompt="You are a firmware security analyst.",
        )

        assert result.status == "ok"
        cmd = captured["cmd"]
        assert isinstance(cmd, list)
        full_prompt = cmd[-1]
        assert "You are a firmware security analyst." in full_prompt
        assert "[System instructions]" in full_prompt
        assert "[User prompt]" in full_prompt
        assert "find vulnerabilities" in full_prompt

    def test_system_prompt_empty_not_prepended(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/claude")
        captured: dict[str, object] = {}

        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            captured["cmd"] = cmd
            return _make_fake_subprocess_cp(0, stdout="output")

        monkeypatch.setattr("subprocess.run", fake_run)

        driver = ClaudeCodeCLIDriver()
        driver.execute(
            prompt="bare prompt",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
            system_prompt="",
        )

        cmd = captured["cmd"]
        assert isinstance(cmd, list)
        full_prompt = cmd[-1]
        assert "[System instructions]" not in full_prompt
        assert full_prompt == "bare prompt"

    def test_model_tier_flag_in_argv(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--model flag must reflect the requested tier alias."""
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/claude")
        captured: dict[str, object] = {}

        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            captured["cmd"] = cmd
            return _make_fake_subprocess_cp(0, stdout="ok")

        monkeypatch.setattr("subprocess.run", fake_run)

        driver = ClaudeCodeCLIDriver()
        driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
            model_tier="haiku",
        )

        cmd = captured["cmd"]
        assert isinstance(cmd, list)
        model_idx = cmd.index("--model") + 1
        assert cmd[model_idx] == "haiku"

    def test_temperature_silently_dropped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """temperature is accepted (Protocol compliance) but has no CLI mapping.

        The driver must not raise and must not inject a raw temperature flag.
        """
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/claude")
        captured: dict[str, object] = {}

        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            captured["cmd"] = cmd
            return _make_fake_subprocess_cp(0, stdout="output")

        monkeypatch.setattr("subprocess.run", fake_run)

        driver = ClaudeCodeCLIDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
            temperature=0.9,
        )

        assert result.status == "ok"
        cmd = captured["cmd"]
        assert isinstance(cmd, list)
        assert "--temperature" not in cmd
        assert "-t" not in cmd

    def test_quota_exhausted_classified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/claude")
        monkeypatch.setattr(
            "subprocess.run",
            lambda *a, **kw: _make_fake_subprocess_cp(
                1,
                stdout="You've hit your limit · resets 12am (Asia/Seoul)\n",
                stderr="",
            ),
        )

        driver = ClaudeCodeCLIDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
        )

        bucket, _ = classify_llm_failure(result)
        assert bucket == "quota_exhausted"

    def test_nonzero_exit_classified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/claude")
        monkeypatch.setattr(
            "subprocess.run",
            lambda *a, **kw: _make_fake_subprocess_cp(1, stderr="auth failure"),
        )

        driver = ClaudeCodeCLIDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
        )

        assert result.status == "nonzero_exit"
        bucket, _ = classify_llm_failure(result)
        assert bucket == "driver_nonzero_exit"

    def test_timeout_classified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/claude")

        def fake_run(*args: object, **kwargs: object) -> None:
            raise subprocess.TimeoutExpired(cmd=["claude"], timeout=10.0)

        monkeypatch.setattr("subprocess.run", fake_run)

        driver = ClaudeCodeCLIDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=10.0,
            max_attempts=1,
        )

        assert result.status == "timeout"
        bucket, _ = classify_llm_failure(result)
        assert bucket == "timeout"

    def test_missing_cli_classified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: None)

        driver = ClaudeCodeCLIDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
        )

        assert result.status == "missing_cli"
        bucket, _ = classify_llm_failure(result)
        assert bucket == "driver_unavailable"

    def test_transient_rate_limit_retried(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Transient 429/overloaded errors in stderr trigger retry logic."""
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/claude")
        monkeypatch.setattr("aiedge.llm_driver.time.sleep", lambda _: None)
        call_count = 0

        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _make_fake_subprocess_cp(1, stderr="429 rate limit exceeded")
            return _make_fake_subprocess_cp(0, stdout="success")

        monkeypatch.setattr("subprocess.run", fake_run)

        driver = ClaudeCodeCLIDriver()
        result = driver.execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=3,
        )

        assert result.status == "ok"
        assert call_count == 2


# ---------------------------------------------------------------------------
# Cross-driver invariants
# ---------------------------------------------------------------------------


class TestCrossDriverProtocolConformance:
    """All 4 drivers must conform to the LLMDriver Protocol signature."""

    @pytest.mark.parametrize(
        "driver_class",
        [CodexCLIDriver, ClaudeAPIDriver, ClaudeCodeCLIDriver, OllamaDriver],
        ids=["codex", "claude-api", "claude-code", "ollama"],
    )
    def test_execute_signature_has_system_prompt(self, driver_class: type) -> None:
        """execute() must accept system_prompt as a keyword argument."""
        sig = inspect.signature(driver_class.execute)
        assert (
            "system_prompt" in sig.parameters
        ), f"{driver_class.__name__}.execute() missing 'system_prompt' parameter"

    @pytest.mark.parametrize(
        "driver_class",
        [CodexCLIDriver, ClaudeAPIDriver, ClaudeCodeCLIDriver, OllamaDriver],
        ids=["codex", "claude-api", "claude-code", "ollama"],
    )
    def test_execute_signature_has_temperature(self, driver_class: type) -> None:
        """execute() must accept temperature as a keyword argument."""
        sig = inspect.signature(driver_class.execute)
        assert (
            "temperature" in sig.parameters
        ), f"{driver_class.__name__}.execute() missing 'temperature' parameter"

    @pytest.mark.parametrize(
        "driver_class",
        [CodexCLIDriver, ClaudeAPIDriver, ClaudeCodeCLIDriver, OllamaDriver],
        ids=["codex", "claude-api", "claude-code", "ollama"],
    )
    def test_execute_signature_has_model_tier(self, driver_class: type) -> None:
        """execute() must accept model_tier as a keyword argument."""
        sig = inspect.signature(driver_class.execute)
        assert (
            "model_tier" in sig.parameters
        ), f"{driver_class.__name__}.execute() missing 'model_tier' parameter"

    @pytest.mark.parametrize(
        "driver_class",
        [CodexCLIDriver, ClaudeAPIDriver, ClaudeCodeCLIDriver, OllamaDriver],
        ids=["codex", "claude-api", "claude-code", "ollama"],
    )
    def test_name_property_is_string(self, driver_class: type) -> None:
        """name property must return a non-empty string."""
        driver = driver_class()
        assert isinstance(driver.name, str)
        assert len(driver.name) > 0

    @pytest.mark.parametrize(
        "driver_class",
        [CodexCLIDriver, ClaudeAPIDriver, ClaudeCodeCLIDriver, OllamaDriver],
        ids=["codex", "claude-api", "claude-code", "ollama"],
    )
    def test_available_returns_bool(
        self, driver_class: type, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """available() must return bool regardless of environment state."""
        # Ensure no real network or filesystem side-effects
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setattr(
            "aiedge.llm_driver.urllib.request.urlopen",
            lambda *a, **kw: (_ for _ in ()).throw(
                urllib.error.URLError("connection refused")
            ),
        )
        driver = driver_class()
        result = driver.available()
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# classify_llm_failure integration: all status codes
# ---------------------------------------------------------------------------


class TestClassifyLlmFailureAllBuckets:
    """Ensure every documented failure bucket is reachable."""

    def test_ok_passthrough(self) -> None:
        result = LLMDriverResult(
            status="ok", stdout="data", stderr="", argv=[], attempts=[], returncode=0
        )
        bucket, msg = classify_llm_failure(result)
        assert bucket == "ok"
        assert msg == ""

    def test_quota_from_stderr(self) -> None:
        result = LLMDriverResult(
            status="nonzero_exit",
            stdout="",
            stderr="usage limit reached",
            argv=[],
            attempts=[],
            returncode=1,
        )
        bucket, _ = classify_llm_failure(result)
        assert bucket == "quota_exhausted"

    def test_quota_keyword_quota(self) -> None:
        result = LLMDriverResult(
            status="error",
            stdout="quota exceeded",
            stderr="",
            argv=[],
            attempts=[],
            returncode=-1,
        )
        bucket, _ = classify_llm_failure(result)
        assert bucket == "quota_exhausted"

    def test_timeout_bucket(self) -> None:
        result = LLMDriverResult(
            status="timeout",
            stdout="",
            stderr="timed out",
            argv=[],
            attempts=[],
            returncode=-1,
        )
        bucket, _ = classify_llm_failure(result)
        assert bucket == "timeout"

    def test_driver_unavailable_bucket(self) -> None:
        result = LLMDriverResult(
            status="missing_cli",
            stdout="",
            stderr="not found",
            argv=[],
            attempts=[],
            returncode=-1,
        )
        bucket, _ = classify_llm_failure(result)
        assert bucket == "driver_unavailable"

    def test_driver_nonzero_exit_bucket(self) -> None:
        result = LLMDriverResult(
            status="nonzero_exit",
            stdout="",
            stderr="generic error",
            argv=[],
            attempts=[],
            returncode=2,
        )
        bucket, _ = classify_llm_failure(result)
        assert bucket == "driver_nonzero_exit"

    def test_driver_error_bucket(self) -> None:
        result = LLMDriverResult(
            status="error",
            stdout="",
            stderr="unexpected exception",
            argv=[],
            attempts=[],
            returncode=-1,
        )
        bucket, _ = classify_llm_failure(result)
        assert bucket == "driver_error"

    def test_skipped_bucket(self) -> None:
        result = LLMDriverResult(
            status="skipped",
            stdout="",
            stderr="",
            argv=[],
            attempts=[],
            returncode=0,
        )
        bucket, _ = classify_llm_failure(result)
        assert bucket == "skipped"
