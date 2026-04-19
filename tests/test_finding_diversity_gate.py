from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from aiedge.quality_policy import (
    QUALITY_GATE_DIVERSITY_MISS,
    QUALITY_GATE_INVALID_PAIR_EVAL,
    QUALITY_GATE_SCHEMA_VERSION,
    QualityGateError,
    compute_pair_eval_diversity_index,
    evaluate_pair_eval_diversity_gate,
    load_pair_eval_finding_ids,
)


def _measured(result: dict[str, object]) -> dict[str, object]:
    return cast(dict[str, object], result["measured"])


def _errors(result: dict[str, object]) -> list[dict[str, object]]:
    return cast(list[dict[str, object]], result["errors"])


def _policy(result: dict[str, object]) -> dict[str, object]:
    return cast(dict[str, object], result["policy"])


def test_diversity_index_empty_returns_zero() -> None:
    assert compute_pair_eval_diversity_index([]) == 0.0


def test_diversity_index_single_finding_is_degenerate() -> None:
    finding_ids = ["aiedge.findings.web.exec_sink_overlap"] * 14
    assert compute_pair_eval_diversity_index(finding_ids) == 1.0


def test_diversity_index_all_distinct_is_inverse_n() -> None:
    finding_ids = [f"finding_{i}" for i in range(8)]
    # Each appears exactly once, so max share = 1/8
    assert compute_pair_eval_diversity_index(finding_ids) == 0.125


def test_diversity_index_partial_share_is_max_count_over_total() -> None:
    # 3 of 'a', 1 of 'b', 1 of 'c' → max share = 3/5 = 0.6
    finding_ids = ["a", "a", "a", "b", "c"]
    assert compute_pair_eval_diversity_index(finding_ids) == 0.6


def test_evaluate_diversity_gate_passes_when_diverse() -> None:
    finding_ids = ["a", "b", "c", "d", "e"]  # max share = 0.2 < 0.5
    result = evaluate_pair_eval_diversity_gate(
        finding_ids=finding_ids,
        findings_source="test://diverse.csv",
    )
    assert result["passed"] is True
    assert result["verdict"] == "pass"
    assert _errors(result) == []
    measured = _measured(result)
    assert measured["finding_diversity_index"] == 0.2
    assert measured["sample_size"] == 5
    assert result["schema_version"] == QUALITY_GATE_SCHEMA_VERSION


def test_evaluate_diversity_gate_fails_when_degenerate() -> None:
    finding_ids = ["aiedge.findings.web.exec_sink_overlap"] * 14
    result = evaluate_pair_eval_diversity_gate(
        finding_ids=finding_ids,
        findings_source="test://degenerate.csv",
    )
    assert result["passed"] is False
    assert result["verdict"] == "fail"
    errors = _errors(result)
    assert len(errors) == 1
    err = errors[0]
    assert err["error_token"] == QUALITY_GATE_DIVERSITY_MISS
    assert err["actual"] == 1.0
    assert err["threshold"] == 0.5
    assert err["sample_size"] == 14
    assert "degenerate" in cast(str, err["message"])


def test_evaluate_diversity_gate_threshold_env_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AIEDGE_PAIR_DIVERSITY_MAX", "0.7")
    # diversity index 0.6 should now PASS under 0.7 threshold
    finding_ids = ["a", "a", "a", "b", "c"]
    result = evaluate_pair_eval_diversity_gate(
        finding_ids=finding_ids,
        findings_source="test://env.csv",
    )
    assert result["passed"] is True
    measured = _measured(result)
    assert measured["finding_diversity_index"] == 0.6
    policy = _policy(result)
    assert policy["finding_diversity_max"] == 0.7


def test_evaluate_diversity_gate_empty_sample_passes_with_zero_index() -> None:
    result = evaluate_pair_eval_diversity_gate(
        finding_ids=[],
        findings_source="test://empty.csv",
    )
    assert result["passed"] is True
    measured = _measured(result)
    assert measured["finding_diversity_index"] == 0.0
    assert measured["sample_size"] == 0


def test_load_pair_eval_finding_ids_filters_blank(tmp_path: Path) -> None:
    csv_path = tmp_path / "findings.csv"
    csv_path.write_text(
        "pair_id,side,finding_id,ground_truth\n"
        "p1,vulnerable,aiedge.findings.x,tp\n"
        "p1,patched,,tn\n"  # empty finding_id should be skipped
        "p2,vulnerable,aiedge.findings.y,fn\n"
        "p2,patched,aiedge.findings.x,fp\n",
        encoding="utf-8",
    )
    finding_ids = load_pair_eval_finding_ids(csv_path)
    assert finding_ids == [
        "aiedge.findings.x",
        "aiedge.findings.y",
        "aiedge.findings.x",
    ]


def test_load_pair_eval_finding_ids_filters_by_ground_truth(tmp_path: Path) -> None:
    csv_path = tmp_path / "findings.csv"
    csv_path.write_text(
        "pair_id,side,finding_id,ground_truth\n"
        "p1,vulnerable,aiedge.findings.x,tp\n"
        "p1,patched,aiedge.findings.x,fp\n"
        "p2,vulnerable,aiedge.findings.y,fn\n"
        "p2,patched,aiedge.findings.z,tn\n",
        encoding="utf-8",
    )
    finding_ids = load_pair_eval_finding_ids(
        csv_path, only_ground_truth=frozenset({"tp", "fp"})
    )
    assert finding_ids == ["aiedge.findings.x", "aiedge.findings.x"]


def test_load_pair_eval_finding_ids_missing_file_raises(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.csv"
    with pytest.raises(QualityGateError) as exc_info:
        load_pair_eval_finding_ids(missing)
    assert exc_info.value.token == QUALITY_GATE_INVALID_PAIR_EVAL
    assert "not found" in str(exc_info.value)


def test_local_7_baseline_is_degenerate() -> None:
    """Sanity check: the 2026-04-19 local-7 baseline maps every pair-side row to
    the same finding, so the diversity gate must classify it as fail."""
    # 14 rows = 7 pairs × 2 sides, all same finding (matches recall_0.142857 lane)
    finding_ids = ["aiedge.findings.web.exec_sink_overlap"] * 14
    result = evaluate_pair_eval_diversity_gate(
        finding_ids=finding_ids,
        findings_source="benchmark-results/pair-eval/pair_eval_findings.csv",
    )
    assert result["passed"] is False
    measured = _measured(result)
    assert measured["finding_diversity_index"] == 1.0
    assert measured["sample_size"] == 14
