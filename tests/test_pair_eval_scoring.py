from __future__ import annotations

from aiedge.pair_eval import (
    aggregate_tier_metrics,
    choose_primary_finding,
    determine_ground_truth,
    extract_target_cve_hits,
)


def test_choose_primary_finding_prefers_vulnerability_and_priority() -> None:
    payload = {
        "findings": [
            {"id": "a", "category": "pipeline_artifact", "priority_score": 0.9, "confidence": 0.9},
            {"id": "b", "category": "vulnerability", "priority_score": 0.5, "confidence": 0.7},
            {"id": "c", "category": "vulnerability", "priority_score": 0.7, "confidence": 0.6},
        ]
    }
    picked = choose_primary_finding(payload)
    assert picked is not None
    assert picked["id"] == "c"


def test_extract_target_cve_hits_filters_exact_id() -> None:
    payload = {"matches": [{"cve_id": "CVE-1"}, {"cve_id": "CVE-2"}, {"other": 1}]}
    hits = extract_target_cve_hits(payload, "CVE-2")
    assert len(hits) == 1
    assert hits[0]["cve_id"] == "CVE-2"


def test_determine_ground_truth_for_vulnerable_and_patched() -> None:
    assert determine_ground_truth("vulnerable", status="success", extraction_status="ok", target_hit=True) == "tp"
    assert determine_ground_truth("vulnerable", status="success", extraction_status="ok", target_hit=False) == "fn"
    assert determine_ground_truth("patched", status="success", extraction_status="ok", target_hit=True) == "fp"
    assert determine_ground_truth("patched", status="success", extraction_status="ok", target_hit=False) == "tn"
    assert determine_ground_truth("patched", status="partial", extraction_status="partial", target_hit=True) == "excluded"


def test_aggregate_tier_metrics_counts_by_ground_truth() -> None:
    records = [
        {"evidence_tier": "symbol_only", "ground_truth": "tp"},
        {"evidence_tier": "symbol_only", "ground_truth": "fp"},
        {"evidence_tier": "unknown", "ground_truth": "excluded"},
    ]
    metrics = aggregate_tier_metrics(records)
    assert metrics["symbol_only"]["tp"] == 1
    assert metrics["symbol_only"]["fp"] == 1
    assert metrics["unknown"]["excluded"] == 1
