"""Smoke test for SCOUT fixture infrastructure (PR #4)."""

from __future__ import annotations

from pathlib import Path


def test_scout_fake_llm_driver_creates(scout_fake_llm_driver) -> None:
    assert scout_fake_llm_driver is not None
    assert hasattr(scout_fake_llm_driver, "available")
    assert hasattr(scout_fake_llm_driver, "execute")
    assert scout_fake_llm_driver.available() is True
    assert scout_fake_llm_driver.call_log == []


def test_scout_fake_llm_driver_logs_call(scout_fake_llm_driver, tmp_path: Path) -> None:
    result = scout_fake_llm_driver.execute(
        prompt="test prompt",
        run_dir=tmp_path,
        timeout_s=10.0,
        system_prompt="test system",
        temperature=0.0,
    )
    assert result.status == "ok"
    assert len(scout_fake_llm_driver.call_log) == 1
    entry = scout_fake_llm_driver.call_log[0]
    assert entry["prompt"] == "test prompt"
    assert entry["system_prompt"] == "test system"
    assert entry["temperature"] == 0.0


def test_scout_stage_ctx_creates_dirs(scout_stage_ctx, tmp_path: Path) -> None:
    assert scout_stage_ctx.run_dir.exists()
    assert scout_stage_ctx.logs_dir.exists()
    assert scout_stage_ctx.report_dir.exists()
    assert scout_stage_ctx.run_dir.is_relative_to(tmp_path)


def test_scout_write_read_json(
    scout_write_json, scout_read_json, tmp_path: Path
) -> None:
    target = tmp_path / "data" / "test.json"
    payload = {"key": "value", "num": 42}
    scout_write_json(target, payload)
    assert target.exists()
    loaded = scout_read_json(target)
    assert loaded == payload


def test_scout_malformed_corpus_loaded(scout_malformed_corpus) -> None:
    assert isinstance(scout_malformed_corpus, list)
    assert len(scout_malformed_corpus) >= 30
    for label, raw in scout_malformed_corpus:
        assert isinstance(label, str) and label
        assert isinstance(raw, str)
