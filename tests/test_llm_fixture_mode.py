from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aiedge.codex_probe import resolve_llm_gate_input
from aiedge.llm_codex import load_llm_gate_fixture
from aiedge.quality_policy import (
    QUALITY_GATE_LLM_INVALID,
    QUALITY_GATE_LLM_REQUIRED,
    QUALITY_GATE_LLM_VERDICT_MISS,
    QualityGateError,
)
from aiedge.schema import JsonValue


def _write_json(path: Path, payload: dict[str, object]) -> None:
    _ = path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def test_load_llm_gate_fixture_accepts_strict_valid_payload(tmp_path: Path) -> None:
    fixture_path = tmp_path / "llm_gate_fixture.json"
    _write_json(
        fixture_path,
        {
            "verdict": "pass",
            "confidence": 0.9,
            "tokens": 123,
            "evidence_refs": ["stages/llm/llm.log", "report/report.json"],
        },
    )

    payload = load_llm_gate_fixture(fixture_path)

    assert payload == {
        "verdict": "pass",
        "confidence": 0.9,
        "tokens": 123,
        "evidence_refs": ["stages/llm/llm.log", "report/report.json"],
    }


def test_load_llm_gate_fixture_missing_file_fails_closed(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"

    with pytest.raises(QualityGateError) as exc:
        _ = load_llm_gate_fixture(missing)

    assert exc.value.token == QUALITY_GATE_LLM_REQUIRED


def test_load_llm_gate_fixture_invalid_json_fails_closed(tmp_path: Path) -> None:
    fixture_path = tmp_path / "bad.json"
    _ = fixture_path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(QualityGateError) as exc:
        _ = load_llm_gate_fixture(fixture_path)

    assert exc.value.token == QUALITY_GATE_LLM_INVALID


def test_load_llm_gate_fixture_missing_verdict_fails_closed(tmp_path: Path) -> None:
    fixture_path = tmp_path / "missing-verdict.json"
    _write_json(fixture_path, {"confidence": 0.5})

    with pytest.raises(QualityGateError) as exc:
        _ = load_llm_gate_fixture(fixture_path)

    assert exc.value.token == QUALITY_GATE_LLM_VERDICT_MISS


def test_load_llm_gate_fixture_invalid_verdict_fails_closed(tmp_path: Path) -> None:
    fixture_path = tmp_path / "invalid-verdict.json"
    _write_json(fixture_path, {"verdict": "maybe"})

    with pytest.raises(QualityGateError) as exc:
        _ = load_llm_gate_fixture(fixture_path)

    assert exc.value.token == QUALITY_GATE_LLM_INVALID


def test_load_llm_gate_fixture_rejects_absolute_evidence_ref(tmp_path: Path) -> None:
    fixture_path = tmp_path / "abs-ref.json"
    _write_json(
        fixture_path,
        {
            "verdict": "pass",
            "evidence_refs": ["/tmp/absolute.log"],
        },
    )

    with pytest.raises(QualityGateError) as exc:
        _ = load_llm_gate_fixture(fixture_path)

    assert exc.value.token == QUALITY_GATE_LLM_INVALID


def test_load_llm_gate_fixture_rejects_unknown_keys(tmp_path: Path) -> None:
    fixture_path = tmp_path / "extra-key.json"
    _write_json(
        fixture_path,
        {
            "verdict": "pass",
            "unexpected": "x",
        },
    )

    with pytest.raises(QualityGateError) as exc:
        _ = load_llm_gate_fixture(fixture_path)

    assert exc.value.token == QUALITY_GATE_LLM_INVALID


def test_resolve_llm_gate_input_returns_payload_and_traceable_fixture_path(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True)

    fixture_path = tmp_path / "fixture.json"
    _write_json(fixture_path, {"verdict": "fail"})

    payload, llm_gate_path = resolve_llm_gate_input(
        fixture_path=fixture_path,
        run_dir=run_dir,
        report=cast(dict[str, JsonValue], {}),
    )

    assert payload == {"verdict": "fail"}
    assert llm_gate_path == f"fixture:{fixture_path.resolve()}"


def test_resolve_llm_gate_input_without_fixture_is_none(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True)

    payload, llm_gate_path = resolve_llm_gate_input(
        fixture_path=None,
        run_dir=run_dir,
        report=cast(dict[str, JsonValue], {}),
    )

    assert payload is None
    assert llm_gate_path is None
