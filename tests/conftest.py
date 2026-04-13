"""SCOUT test fixtures (opt-in, scout_ prefix to avoid collision).

NO autouse fixtures. NO monkeypatch defaults. NO sys.path manipulation.
Existing tests must remain zero-impact.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import pytest
from _fixtures.corpora import MALFORMED_JSON_CORPUS
from _fixtures.fs import read_json, write_json
from _fixtures.llm import FakeLLMDriver
from _fixtures.stage import make_stage_ctx


@pytest.fixture
def scout_fake_llm_driver() -> FakeLLMDriver:
    """Fresh FakeLLMDriver for each test."""
    return FakeLLMDriver()


@pytest.fixture
def scout_stage_ctx(tmp_path: Path):
    """StageContext with run/logs/report dirs under tmp_path."""
    return make_stage_ctx(tmp_path)


@pytest.fixture
def scout_write_json() -> Callable[[Path, Any], None]:
    """Helper to write JSON files in tests."""
    return write_json


@pytest.fixture
def scout_read_json() -> Callable[[Path], Any]:
    """Helper to read JSON files in tests."""
    return read_json


@pytest.fixture
def scout_malformed_corpus() -> list[tuple[str, str]]:
    """Corpus of 30+ malformed LLM JSON outputs for parser testing."""
    return MALFORMED_JSON_CORPUS
