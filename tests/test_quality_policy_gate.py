from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aiedge.__main__ import main
from aiedge.quality_policy import evaluate_quality_gate


def _write_json(path: Path, payload: dict[str, object]) -> None:
    _ = path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _base_metrics_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "abstain_rate": 0.2,
        "overall": {
            "precision": 0.95,
            "recall": 0.8,
            "f1": 0.87,
            "fpr": 0.05,
            "fnr": 0.2,
        },
    }


def _stderr_objects(stderr: str) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for line in stderr.splitlines():
        if not line.strip():
            continue
        obj = cast(dict[str, object], json.loads(line))
        out.append(obj)
    return out


def test_quality_gate_passes_when_thresholds_met(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    metrics_path = tmp_path / "metrics.json"
    out_path = tmp_path / "quality_gate.json"
    _write_json(metrics_path, _base_metrics_payload())

    rc = main(
        [
            "quality-gate",
            "--metrics",
            str(metrics_path),
            "--out",
            str(out_path),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 0
    assert captured.err == ""
    assert out_path.is_file()
    assert captured.out == out_path.read_text(encoding="utf-8")

    payload_any = cast(object, json.loads(captured.out))
    assert isinstance(payload_any, dict)
    payload = cast(dict[str, object], payload_any)
    assert payload["passed"] is True
    assert payload["verdict"] == "pass"
    policy_any = payload.get("policy")
    assert isinstance(policy_any, dict)
    policy = cast(dict[str, object], policy_any)
    assert policy["high_severity_false_positive_rate_proxy"] == "overall.fpr"


def test_quality_gate_fails_on_precision_floor(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = _base_metrics_payload()
    overall = cast(dict[str, object], payload["overall"])
    overall["precision"] = 0.89

    metrics_path = tmp_path / "metrics.json"
    _write_json(metrics_path, payload)

    rc = main(["quality-gate", "--metrics", str(metrics_path)])
    captured = capsys.readouterr()

    assert rc == 30
    stderr = _stderr_objects(captured.err)
    assert len(stderr) == 1
    assert stderr[0]["error_token"] == "QUALITY_GATE_THRESHOLD_MISS"
    assert stderr[0]["metric"] == "precision"
    assert stderr[0]["actual"] == 0.89
    assert stderr[0]["threshold"] == 0.9


def test_quality_gate_fails_on_abstain_ceiling(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = _base_metrics_payload()
    payload["abstain_rate"] = 0.3

    metrics_path = tmp_path / "metrics.json"
    _write_json(metrics_path, payload)

    rc = main(["quality-gate", "--metrics", str(metrics_path)])
    captured = capsys.readouterr()

    assert rc == 30
    stderr = _stderr_objects(captured.err)
    assert len(stderr) == 1
    assert stderr[0]["error_token"] == "QUALITY_GATE_THRESHOLD_MISS"
    assert stderr[0]["metric"] == "abstain_rate"
    assert stderr[0]["actual"] == 0.3
    assert stderr[0]["threshold"] == 0.25


def test_quality_gate_fails_closed_on_missing_metrics_key(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = _base_metrics_payload()
    _ = payload.pop("abstain_rate")

    metrics_path = tmp_path / "metrics.json"
    _write_json(metrics_path, payload)

    rc = main(["quality-gate", "--metrics", str(metrics_path)])
    captured = capsys.readouterr()

    assert rc == 20
    stderr = _stderr_objects(captured.err)
    assert len(stderr) == 1
    assert stderr[0]["error_token"] == "QUALITY_GATE_INVALID_METRICS"
    assert "abstain_rate" in cast(str, stderr[0]["message"])


def test_release_quality_gate_adds_confirmed_high_critical_constraint(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = _base_metrics_payload()
    overall = cast(dict[str, object], payload["overall"])
    overall["precision"] = 0.7

    metrics_path = tmp_path / "metrics.json"
    report_path = tmp_path / "report.json"
    _write_json(metrics_path, payload)
    _write_json(
        report_path,
        {
            "findings": [
                {
                    "id": "finding-1",
                    "severity": "high",
                    "disposition": "confirmed",
                }
            ]
        },
    )

    rc = main(
        [
            "release-quality-gate",
            "--metrics",
            str(metrics_path),
            "--report",
            str(report_path),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 30
    stderr = _stderr_objects(captured.err)
    tokens = {cast(str, e["error_token"]) for e in stderr}
    assert "QUALITY_GATE_THRESHOLD_MISS" in tokens
    assert "QUALITY_GATE_RELEASE_CONSTRAINT" in tokens


def test_llm_primary_fails_closed_when_llm_payload_missing() -> None:
    verdict = evaluate_quality_gate(
        metrics_payload=_base_metrics_payload(),
        metrics_path="metrics.json",
        report_payload=None,
        report_path=None,
        release_mode=False,
        llm_primary=True,
        llm_gate_payload=None,
        llm_gate_path=None,
    )

    assert verdict["passed"] is False
    assert verdict["verdict"] == "fail"
    errors = cast(list[dict[str, object]], verdict["errors"])
    assert errors[0]["error_token"] == "QUALITY_GATE_LLM_REQUIRED"


def test_llm_primary_fails_when_llm_verdict_is_fail() -> None:
    verdict = evaluate_quality_gate(
        metrics_payload=_base_metrics_payload(),
        metrics_path="metrics.json",
        report_payload=None,
        report_path=None,
        release_mode=False,
        llm_primary=True,
        llm_gate_payload={"verdict": "fail"},
        llm_gate_path="llm_gate.json",
    )

    assert verdict["passed"] is False
    assert verdict["verdict"] == "fail"
    errors = cast(list[dict[str, object]], verdict["errors"])
    assert errors[0]["error_token"] == "QUALITY_GATE_LLM_VERDICT_MISS"


def test_llm_primary_does_not_override_threshold_failures() -> None:
    payload = _base_metrics_payload()
    overall = cast(dict[str, object], payload["overall"])
    overall["precision"] = 0.7

    verdict = evaluate_quality_gate(
        metrics_payload=payload,
        metrics_path="metrics.json",
        report_payload=None,
        report_path=None,
        release_mode=False,
        llm_primary=True,
        llm_gate_payload={"verdict": "pass"},
        llm_gate_path="llm_gate.json",
    )

    assert verdict["passed"] is False
    assert verdict["verdict"] == "fail"
    errors = cast(list[dict[str, object]], verdict["errors"])
    tokens = {cast(str, err["error_token"]) for err in errors}
    assert "QUALITY_GATE_THRESHOLD_MISS" in tokens
    assert "QUALITY_GATE_LLM_VERDICT_MISS" not in tokens


def test_llm_primary_fails_when_llm_payload_malformed() -> None:
    verdict = evaluate_quality_gate(
        metrics_payload=_base_metrics_payload(),
        metrics_path="metrics.json",
        report_payload=None,
        report_path=None,
        release_mode=False,
        llm_primary=True,
        llm_gate_payload={"verdict": "maybe"},
        llm_gate_path="llm_gate.json",
    )

    assert verdict["passed"] is False
    assert verdict["verdict"] == "fail"
    errors = cast(list[dict[str, object]], verdict["errors"])
    assert errors[0]["error_token"] == "QUALITY_GATE_LLM_INVALID"


def test_release_quality_gate_llm_primary_requires_report(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    metrics_path = tmp_path / "metrics.json"
    _write_json(metrics_path, _base_metrics_payload())

    rc = main(
        [
            "release-quality-gate",
            "--metrics",
            str(metrics_path),
            "--llm-primary",
        ]
    )
    captured = capsys.readouterr()

    assert rc in (20, 30)
    stderr = _stderr_objects(captured.err)
    assert stderr
    assert stderr[0]["error_token"] == "QUALITY_GATE_LLM_REQUIRED"


@pytest.mark.parametrize(
    ("fixture_payload", "expected_token", "expected_exit"),
    [
        ({"verdict": "pass"}, None, 0),
        ({"verdict": "fail"}, "QUALITY_GATE_LLM_VERDICT_MISS", 30),
    ],
)
def test_release_quality_gate_llm_primary_uses_llm_fixture_verdict(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    fixture_payload: dict[str, object],
    expected_token: str | None,
    expected_exit: int,
) -> None:
    metrics_path = tmp_path / "metrics.json"
    report_path = tmp_path / "report.json"
    fixture_path = tmp_path / "llm_gate_fixture.json"
    _write_json(metrics_path, _base_metrics_payload())
    _write_json(report_path, {"llm": {"status": "skipped"}})
    _write_json(fixture_path, fixture_payload)

    rc = main(
        [
            "release-quality-gate",
            "--metrics",
            str(metrics_path),
            "--report",
            str(report_path),
            "--llm-primary",
            "--llm-fixture",
            str(fixture_path),
        ]
    )
    captured = capsys.readouterr()

    assert rc == expected_exit
    payload_any = cast(object, json.loads(captured.out))
    assert isinstance(payload_any, dict)
    payload = cast(dict[str, object], payload_any)
    if expected_token is None:
        assert payload["passed"] is True
    else:
        assert payload["passed"] is False
        stderr = _stderr_objects(captured.err)
        assert stderr
        assert stderr[0]["error_token"] == expected_token


def test_release_quality_gate_llm_primary_report_llm_skipped_fails(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    metrics_path = tmp_path / "metrics.json"
    report_path = tmp_path / "report.json"
    _write_json(metrics_path, _base_metrics_payload())
    _write_json(report_path, {"llm": {"status": "skipped"}})

    rc = main(
        [
            "release-quality-gate",
            "--metrics",
            str(metrics_path),
            "--report",
            str(report_path),
            "--llm-primary",
        ]
    )
    captured = capsys.readouterr()

    assert rc == 30
    stderr = _stderr_objects(captured.err)
    assert stderr
    assert stderr[0]["error_token"] == "QUALITY_GATE_LLM_VERDICT_MISS"
