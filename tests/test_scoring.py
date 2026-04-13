"""Tests for PR #15 -- detection_confidence vs priority_score separation.

Two test groups:
  1. Unit tests for ``aiedge.scoring`` (PriorityInputs + compute_priority_score).
  2. Integration tests for ``aiedge.cve_scan`` confirming the refactored
     CVE finding builder emits separate ``confidence`` and ``priority_score``
     fields with the documented semantics.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aiedge.confidence_caps import STATIC_CODE_VERIFIED_CAP
from aiedge.cve_scan import CveScanStage
from aiedge.scoring import (
    BACKPORT_PENALTY,
    PriorityInputs,
    compute_priority_score,
    priority_bucket,
    priority_inputs_to_dict,
)
from aiedge.stage import StageContext

# ---------------------------------------------------------------------------
# Section 1 -- compute_priority_score unit tests
# ---------------------------------------------------------------------------


def _pi(
    *,
    detection_confidence: float = 0.0,
    epss_score: float | None = None,
    epss_percentile: float | None = None,
    reachability: str | None = None,
    backport_present: bool = False,
    cvss_base: float | None = None,
) -> PriorityInputs:
    """PriorityInputs factory with kwargs-only and sensible defaults."""
    return PriorityInputs(
        detection_confidence=detection_confidence,
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        reachability=reachability,
        backport_present=backport_present,
        cvss_base=cvss_base,
    )


def test_priority_detection_only() -> None:
    """With only detection set, priority = detection*0.50 + reach_unknown*0.15."""
    score = compute_priority_score(_pi(detection_confidence=1.0))
    # 1.0 * 0.50 + 0.5 (unknown reach) * 0.15 = 0.50 + 0.075 = 0.575
    assert score == pytest.approx(0.575, abs=1e-9)


def test_priority_detection_zero_yields_only_reach_floor() -> None:
    """Zero detection still gets the unknown-reachability floor contribution."""
    score = compute_priority_score(_pi(detection_confidence=0.0))
    # 0.0 * 0.50 + 0.5 * 0.15 = 0.075
    assert score == pytest.approx(0.075, abs=1e-9)


def test_priority_with_high_epss_bumps_above_detection() -> None:
    """High EPSS should push priority above the detection-only baseline."""
    base = compute_priority_score(_pi(detection_confidence=0.55))
    boosted = compute_priority_score(_pi(detection_confidence=0.55, epss_score=0.9))
    # EPSS contribution: 0.9 * 0.25 = 0.225
    assert boosted > base
    assert boosted - base == pytest.approx(0.9 * 0.25, abs=1e-9)


def test_priority_with_low_reachability_lowers_priority() -> None:
    """Unreachable should pull priority down vs directly_reachable."""
    direct = compute_priority_score(
        _pi(detection_confidence=0.55, reachability="directly_reachable")
    )
    unreach = compute_priority_score(
        _pi(detection_confidence=0.55, reachability="unreachable")
    )
    assert direct > unreach
    # Difference: (1.0 - 0.2) * 0.15 = 0.12
    assert direct - unreach == pytest.approx(0.12, abs=1e-9)


def test_priority_potentially_reachable_between_direct_and_unreach() -> None:
    """potentially_reachable sits between directly_reachable and unreachable."""
    direct = compute_priority_score(
        _pi(detection_confidence=0.55, reachability="directly_reachable")
    )
    pot = compute_priority_score(
        _pi(detection_confidence=0.55, reachability="potentially_reachable")
    )
    unreach = compute_priority_score(
        _pi(detection_confidence=0.55, reachability="unreachable")
    )
    assert direct > pot > unreach


def test_priority_unknown_reachability_treated_as_default() -> None:
    """Missing/None reachability is treated identically to 'unknown'."""
    none_reach = compute_priority_score(
        _pi(detection_confidence=0.55, reachability=None)
    )
    explicit = compute_priority_score(
        _pi(detection_confidence=0.55, reachability="unknown")
    )
    assert none_reach == explicit


def test_priority_unrecognized_reachability_treated_as_unknown() -> None:
    """Unknown string values fall back to the 0.5 floor."""
    fallback = compute_priority_score(
        _pi(detection_confidence=0.55, reachability="never_seen_this")
    )
    explicit = compute_priority_score(
        _pi(detection_confidence=0.55, reachability="unknown")
    )
    assert fallback == explicit


def test_priority_backport_penalty_applied() -> None:
    """backport_present=True applies the documented BACKPORT_PENALTY (-0.20)."""
    base = compute_priority_score(
        _pi(
            detection_confidence=0.55,
            epss_score=0.5,
            reachability="directly_reachable",
            cvss_base=9.0,
            backport_present=False,
        )
    )
    with_backport = compute_priority_score(
        _pi(
            detection_confidence=0.55,
            epss_score=0.5,
            reachability="directly_reachable",
            cvss_base=9.0,
            backport_present=True,
        )
    )
    assert base - with_backport == pytest.approx(BACKPORT_PENALTY, abs=1e-9)
    assert BACKPORT_PENALTY == pytest.approx(0.20, abs=1e-9)


def test_priority_clamps_to_unit_interval_upper() -> None:
    """Score never exceeds 1.0 even with all positive signals maxed out."""
    score = compute_priority_score(
        _pi(
            detection_confidence=1.0,
            epss_score=1.0,
            reachability="directly_reachable",
            cvss_base=10.0,
            backport_present=False,
        )
    )
    # Raw: 0.5 + 0.25 + 0.15 + 0.10 = 1.0 exactly
    assert score == pytest.approx(1.0, abs=1e-9)
    assert 0.0 <= score <= 1.0


def test_priority_clamps_to_unit_interval_lower() -> None:
    """Score never drops below 0.0 even with backport on a zero-detection finding."""
    score = compute_priority_score(
        _pi(
            detection_confidence=0.0,
            epss_score=None,
            reachability="unreachable",
            cvss_base=None,
            backport_present=True,
        )
    )
    # Raw: 0 + 0 + 0.2*0.15 + 0 - 0.20 = 0.03 - 0.20 = -0.17 -> clamped to 0
    assert score == 0.0
    assert 0.0 <= score <= 1.0


def test_priority_cvss_contribution_scales_linearly() -> None:
    """A 1-point CVSS bump increases priority by 0.01 (10% weight / 10 points)."""
    low = compute_priority_score(_pi(detection_confidence=0.5, cvss_base=5.0))
    high = compute_priority_score(_pi(detection_confidence=0.5, cvss_base=6.0))
    assert high - low == pytest.approx(0.01, abs=1e-9)


def test_priority_epss_none_omits_term() -> None:
    """Missing EPSS does NOT zero-out the term; it omits it entirely.

    Verifies that a finding without EPSS data is not artificially penalized
    versus a finding with EPSS=0.0.
    """
    no_epss = compute_priority_score(_pi(detection_confidence=0.55, epss_score=None))
    zero_epss = compute_priority_score(_pi(detection_confidence=0.55, epss_score=0.0))
    # 0.0 * 0.25 = 0, so the two should be equal
    assert no_epss == pytest.approx(zero_epss, abs=1e-9)


def test_priority_inputs_serializable() -> None:
    """priority_inputs_to_dict returns a JSON-roundtrippable dict."""
    pi = _pi(
        detection_confidence=0.55,
        epss_score=0.42,
        epss_percentile=0.93,
        reachability="directly_reachable",
        backport_present=True,
        cvss_base=9.8,
    )
    d = priority_inputs_to_dict(pi)
    assert d["detection_confidence"] == 0.55
    assert d["epss_score"] == 0.42
    assert d["epss_percentile"] == 0.93
    assert d["reachability"] == "directly_reachable"
    assert d["backport_present"] is True
    assert d["cvss_base"] == 9.8

    # Roundtrip
    encoded = json.dumps(d)
    decoded = json.loads(encoded)
    assert decoded == d


def test_priority_inputs_with_none_fields_serializable() -> None:
    """None fields survive JSON roundtrip as null."""
    pi = _pi(detection_confidence=0.4)
    d = priority_inputs_to_dict(pi)
    assert d["epss_score"] is None
    assert d["epss_percentile"] is None
    assert d["reachability"] is None
    assert d["cvss_base"] is None
    assert d["backport_present"] is False
    encoded = json.dumps(d)
    decoded = json.loads(encoded)
    assert decoded == d


def test_priority_bucket_boundaries() -> None:
    """priority_bucket returns the documented labels at boundary values."""
    assert priority_bucket(0.0) == "low"
    assert priority_bucket(0.39) == "low"
    assert priority_bucket(0.40) == "medium"
    assert priority_bucket(0.59) == "medium"
    assert priority_bucket(0.60) == "high"
    assert priority_bucket(0.79) == "high"
    assert priority_bucket(0.80) == "critical"
    assert priority_bucket(1.0) == "critical"


# ---------------------------------------------------------------------------
# Section 2 -- cve_scan integration tests
# ---------------------------------------------------------------------------


def _ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    logs_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


def _read_json(path: Path) -> dict[str, object]:
    raw = cast(object, json.loads(path.read_text(encoding="utf-8")))
    assert isinstance(raw, dict)
    return cast(dict[str, object], raw)


def _make_cve_match(
    *,
    component: str,
    version: str,
    cve_id: str,
    cvss: float,
    match_conf: float,
    epss: float | None,
    epss_percentile: float | None,
    component_metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "component": component,
        "version": version,
        "cve_id": cve_id,
        "cvss_v3_score": cvss,
        "match_confidence": match_conf,
        "match_type": "exact_version",
        "description": "synthetic mock match",
        "evidence_ref": f"nvd_api:{cve_id}",
        "component_metadata": component_metadata,
        "epss": epss,
        "epss_percentile": epss_percentile,
    }


def _run_cve_stage_with_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    match: dict[str, object],
    *,
    component: dict[str, object],
    epss_entry: dict[str, object] | None = None,
) -> dict[str, object]:
    """Drive CveScanStage with one synthetic match and return the candidate dict."""
    ctx = _ctx(tmp_path)

    monkeypatch.setattr(
        "aiedge.cve_scan._load_cpe_index",
        lambda _run_dir: ([component], []),
    )
    monkeypatch.setattr(
        "aiedge.cve_scan._query_nvd_with_cache",
        lambda *args, **kwargs: {"vulnerabilities": [{"dummy": True}]},
    )
    monkeypatch.setattr(
        "aiedge.cve_scan._extract_cve_entry",
        lambda *args, **kwargs: [match],
    )
    monkeypatch.setattr(
        CveScanStage,
        "_match_known_cve_signatures",
        lambda self, _run_dir: [],
    )

    if epss_entry is None:
        monkeypatch.setattr(
            "aiedge.cve_scan._query_epss_with_cache",
            lambda *args, **kwargs: ({}, False),
        )
    else:
        cve_id = str(match["cve_id"])

        def _fake_epss(
            cve_ids: list[str],
            *,
            per_run_cache_dir: Path,
            cross_run_cache_dir: Path | None,
            run_dir: Path,
            stats: dict[str, int],
        ) -> tuple[dict[str, dict[str, object]], bool]:
            _ = (per_run_cache_dir, cross_run_cache_dir, run_dir)
            stats["epss_api_calls"] += 1
            return ({cve_id: epss_entry}, False)

        monkeypatch.setattr("aiedge.cve_scan._query_epss_with_cache", _fake_epss)

    stage = CveScanStage(
        run_dir=ctx.run_dir,
        case_id="test-case",
        remaining_budget_s=lambda: 600.0,
        no_llm=False,
    )
    out = stage.run(ctx)
    assert out.status in ("ok", "partial")

    payload = _read_json(ctx.run_dir / "stages" / "cve_scan" / "cve_matches.json")
    candidates = cast(list[object], payload["finding_candidates"])
    assert len(candidates) == 1
    candidate = candidates[0]
    assert isinstance(candidate, dict)
    return cast(dict[str, object], candidate)


def test_cve_finding_has_separate_confidence_and_priority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """High-EPSS CVE: confidence stays at static cap; priority is higher."""
    component = {
        "name": "dnsmasq",
        "version": "2.0",
        "cpe": "cpe:2.3:a:dnsmasq:dnsmasq:2.0:*:*:*:*:*:*:*",
    }
    match = _make_cve_match(
        component="dnsmasq",
        version="2.0",
        cve_id="CVE-2024-EPSSHIGH",
        cvss=9.8,
        match_conf=0.90,
        epss=0.42,
        epss_percentile=0.95,
    )
    candidate = _run_cve_stage_with_match(
        tmp_path,
        monkeypatch,
        match,
        component=component,
        epss_entry={
            "cve": "CVE-2024-EPSSHIGH",
            "epss": 0.42,
            "percentile": 0.95,
            "source": "first_epss_api",
        },
    )

    confidence = float(cast(float, candidate["confidence"]))
    priority_score = float(cast(float, candidate["priority_score"]))
    priority_inputs = cast(dict[str, object], candidate["priority_inputs"])

    # Detection confidence: capped at STATIC_CODE_VERIFIED_CAP (0.55)
    assert confidence <= STATIC_CODE_VERIFIED_CAP + 1e-9
    # _finding_confidence raw: 0.9 * 9.8/10 * 0.6 = 0.5292 (below cap)
    assert confidence == pytest.approx(0.5292, abs=1e-3)

    # Priority should reflect the EPSS boost -- higher than the raw confidence
    assert priority_score > confidence

    # priority_inputs must echo the inputs verbatim
    assert priority_inputs["detection_confidence"] == pytest.approx(
        confidence, abs=1e-9
    )
    assert priority_inputs["epss_score"] == pytest.approx(0.42, abs=1e-9)
    assert priority_inputs["epss_percentile"] == pytest.approx(0.95, abs=1e-9)
    assert priority_inputs["cvss_base"] == 9.8
    assert priority_inputs["backport_present"] is False


def test_cve_backport_lowers_priority_not_confidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Backport_present applies BACKPORT_PENALTY to priority but not confidence."""
    component = {
        "name": "busybox",
        "version": "1.0",
        "cpe": "cpe:2.3:a:busybox:busybox:1.0:*:*:*:*:*:*:*",
        "patch_revision": "5",
        "detection_method": "opkg",
    }
    match = _make_cve_match(
        component="busybox",
        version="1.0",
        cve_id="CVE-2024-BACKPORT",
        cvss=9.0,
        match_conf=0.90,
        epss=0.30,
        epss_percentile=0.85,
        component_metadata={
            "patch_revision": "5",
            "detection_method": "opkg",
        },
    )
    backport_candidate = _run_cve_stage_with_match(
        tmp_path / "backport",
        monkeypatch,
        match,
        component=component,
        epss_entry={
            "cve": "CVE-2024-BACKPORT",
            "epss": 0.30,
            "percentile": 0.85,
            "source": "first_epss_api",
        },
    )

    # Same match WITHOUT backport metadata
    component_clean = {
        "name": "busybox",
        "version": "1.0",
        "cpe": "cpe:2.3:a:busybox:busybox:1.0:*:*:*:*:*:*:*",
    }
    match_clean = _make_cve_match(
        component="busybox",
        version="1.0",
        cve_id="CVE-2024-NOBACK",
        cvss=9.0,
        match_conf=0.90,
        epss=0.30,
        epss_percentile=0.85,
        component_metadata=None,
    )
    clean_candidate = _run_cve_stage_with_match(
        tmp_path / "clean",
        monkeypatch,
        match_clean,
        component=component_clean,
        epss_entry={
            "cve": "CVE-2024-NOBACK",
            "epss": 0.30,
            "percentile": 0.85,
            "source": "first_epss_api",
        },
    )

    backport_conf = float(cast(float, backport_candidate["confidence"]))
    clean_conf = float(cast(float, clean_candidate["confidence"]))
    backport_priority = float(cast(float, backport_candidate["priority_score"]))
    clean_priority = float(cast(float, clean_candidate["priority_score"]))

    # Confidence is identical -- backport must not modify detection
    assert backport_conf == pytest.approx(clean_conf, abs=1e-9)

    # Priority is reduced by exactly BACKPORT_PENALTY (within clamp boundaries)
    assert backport_priority < clean_priority
    assert clean_priority - backport_priority == pytest.approx(
        BACKPORT_PENALTY, abs=1e-9
    )

    # priority_inputs must record the backport flag
    backport_inputs = cast(dict[str, object], backport_candidate["priority_inputs"])
    clean_inputs = cast(dict[str, object], clean_candidate["priority_inputs"])
    assert backport_inputs["backport_present"] is True
    assert clean_inputs["backport_present"] is False


def test_cve_unreachable_reduces_priority_not_confidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reachability=unreachable lowers priority_score but not confidence."""
    ctx = _ctx(tmp_path)

    # Stash a reachability.json so the cve_scan stage picks up "unreachable".
    # Schema must match _load_reachability_map: results[].component + .reachability.
    reach_dir = ctx.run_dir / "stages" / "reachability"
    reach_dir.mkdir(parents=True)
    reach_payload = {
        "results": [
            {"component": "dnsmasq", "reachability": "unreachable"},
        ]
    }
    (reach_dir / "reachability.json").write_text(
        json.dumps(reach_payload), encoding="utf-8"
    )

    component = {
        "name": "dnsmasq",
        "version": "2.0",
        "cpe": "cpe:2.3:a:dnsmasq:dnsmasq:2.0:*:*:*:*:*:*:*",
    }
    match = _make_cve_match(
        component="dnsmasq",
        version="2.0",
        cve_id="CVE-2024-UNREACH",
        cvss=9.0,
        match_conf=0.90,
        epss=0.30,
        epss_percentile=0.85,
    )

    monkeypatch.setattr(
        "aiedge.cve_scan._load_cpe_index",
        lambda _run_dir: ([component], []),
    )
    monkeypatch.setattr(
        "aiedge.cve_scan._query_nvd_with_cache",
        lambda *args, **kwargs: {"vulnerabilities": [{"dummy": True}]},
    )
    monkeypatch.setattr(
        "aiedge.cve_scan._extract_cve_entry",
        lambda *args, **kwargs: [match],
    )
    monkeypatch.setattr(
        CveScanStage,
        "_match_known_cve_signatures",
        lambda self, _run_dir: [],
    )
    monkeypatch.setattr(
        "aiedge.cve_scan._query_epss_with_cache",
        lambda *args, **kwargs: (
            {
                "CVE-2024-UNREACH": {
                    "cve": "CVE-2024-UNREACH",
                    "epss": 0.30,
                    "percentile": 0.85,
                    "source": "first_epss_api",
                }
            },
            False,
        ),
    )

    stage = CveScanStage(
        run_dir=ctx.run_dir,
        case_id="test-case",
        remaining_budget_s=lambda: 600.0,
        no_llm=False,
    )
    out = stage.run(ctx)
    assert out.status in ("ok", "partial")

    payload = _read_json(ctx.run_dir / "stages" / "cve_scan" / "cve_matches.json")
    candidates = cast(list[object], payload["finding_candidates"])
    assert len(candidates) == 1
    cand = cast(dict[str, object], candidates[0])

    confidence = float(cast(float, cand["confidence"]))
    priority_score = float(cast(float, cand["priority_score"]))
    priority_inputs = cast(dict[str, object], cand["priority_inputs"])

    # Confidence: still capped, NOT modified by reachability
    # _finding_confidence raw: 0.9 * 9.0/10 * 0.6 = 0.486
    assert confidence == pytest.approx(0.486, abs=1e-3)
    assert confidence <= STATIC_CODE_VERIFIED_CAP + 1e-9

    # priority_inputs must record the unreachable status
    assert priority_inputs["reachability"] == "unreachable"

    # Priority score should reflect the unreachable penalty:
    #   detection*0.50 + epss*0.25 + 0.2*0.15 + (cvss/10)*0.10
    # = 0.486*0.50 + 0.30*0.25 + 0.030 + 0.090
    # = 0.243 + 0.075 + 0.030 + 0.090 = 0.438
    expected_priority = (
        confidence * 0.50 + 0.30 * 0.25 + 0.20 * 0.15 + (9.0 / 10.0) * 0.10
    )
    assert priority_score == pytest.approx(expected_priority, abs=1e-3)


def test_cve_finding_priority_inputs_are_json_serializable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """priority_inputs from cve_scan survive a json.dumps roundtrip."""
    component = {
        "name": "openssl",
        "version": "1.0.0",
        "cpe": "cpe:2.3:a:openssl:openssl:1.0.0:*:*:*:*:*:*:*",
    }
    match = _make_cve_match(
        component="openssl",
        version="1.0.0",
        cve_id="CVE-2024-JSON",
        cvss=8.5,
        match_conf=0.90,
        epss=None,
        epss_percentile=None,
    )
    candidate = _run_cve_stage_with_match(
        tmp_path,
        monkeypatch,
        match,
        component=component,
        epss_entry=None,
    )

    encoded = json.dumps(candidate)
    decoded = cast(dict[str, object], json.loads(encoded))
    assert "priority_score" in decoded
    assert "priority_inputs" in decoded
    assert isinstance(decoded["priority_inputs"], dict)
