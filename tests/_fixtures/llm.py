"""Generalized FakeLLMDriver for LLMDriver Protocol mocking.

Based on _FakeDriver pattern in test_llm_failure_observability.py:33-42.
Generalized to support multiple response modes, failure injection, call logging.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aiedge.llm_driver import LLMDriverResult, ModelTier


def _make_result(
    status: str,
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> LLMDriverResult:
    return LLMDriverResult(
        status=status,
        stdout=stdout,
        stderr=stderr,
        argv=[],
        attempts=[],
        returncode=returncode,
    )


_FAIL_MODE_RESULTS: dict[str, LLMDriverResult] = {
    "quota_exhausted": _make_result(
        "error",
        stderr="you've hit your limit",
        returncode=1,
    ),
    "driver_unavailable": _make_result(
        "missing_cli",
        stderr="llm driver unavailable",
        returncode=-1,
    ),
    "driver_nonzero_exit": _make_result(
        "nonzero_exit",
        stderr="llm command exited non-zero",
        returncode=1,
    ),
    "timeout": _make_result(
        "timeout",
        stderr="llm request timed out",
        returncode=-1,
    ),
}


class FakeLLMDriver:
    """Test double for LLMDriver Protocol.

    Usage::

        # Always returns default empty-ok result
        driver = FakeLLMDriver()

        # Returns a specific stdout on each call (cycles if multiple)
        driver = FakeLLMDriver(responses=[{"output": "..."}])

        # Reports unavailable
        driver = FakeLLMDriver(available=False)

        # Injects a failure mode
        driver = FakeLLMDriver(fail_mode="quota_exhausted")
        # valid fail_mode values: "quota_exhausted", "driver_unavailable",
        #                         "driver_nonzero_exit", "timeout"
    """

    @property
    def name(self) -> str:
        return "fake"

    def __init__(
        self,
        *,
        available: bool = True,
        responses: list[str] | None = None,
        fail_mode: str | None = None,
    ) -> None:
        self._available = available
        self._responses: list[str] = responses if responses is not None else []
        self._fail_mode = fail_mode
        self._call_index = 0
        self.call_log: list[dict[str, Any]] = []

    def available(self) -> bool:
        return self._available

    def execute(
        self,
        *,
        prompt: str,
        run_dir: Path,
        timeout_s: float,
        max_attempts: int = 3,
        retryable_tokens: tuple[str, ...] = (),
        model_tier: ModelTier = "sonnet",
        system_prompt: str = "",
        temperature: float | None = None,
    ) -> LLMDriverResult:
        self.call_log.append(
            {
                "prompt": prompt,
                "run_dir": run_dir,
                "timeout_s": timeout_s,
                "max_attempts": max_attempts,
                "model_tier": model_tier,
                "system_prompt": system_prompt,
                "temperature": temperature,
            }
        )

        if self._fail_mode is not None:
            if self._fail_mode in _FAIL_MODE_RESULTS:
                return _FAIL_MODE_RESULTS[self._fail_mode]
            raise ValueError(
                f"Unknown fail_mode {self._fail_mode!r}. "
                f"Valid: {sorted(_FAIL_MODE_RESULTS)}"
            )

        if self._responses:
            idx = self._call_index % len(self._responses)
            stdout = self._responses[idx]
            self._call_index += 1
        else:
            stdout = ""

        return LLMDriverResult(
            status="ok",
            stdout=stdout,
            stderr="",
            argv=[],
            attempts=[],
            returncode=0,
        )
