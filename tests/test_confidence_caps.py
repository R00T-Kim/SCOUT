"""Tests for confidence_caps.py — governance-critical capping logic."""

from __future__ import annotations

from aiedge.confidence_caps import (
    DECOMPILED_COLOCATED_CAP,
    EVIDENCE_LEVELS,
    PCODE_VERIFIED_CAP,
    STATIC_CODE_VERIFIED_CAP,
    STATIC_ONLY_CAP,
    SYMBOL_COOCCURRENCE_CAP,
    calibrated_confidence,
    clamp01,
    evidence_level,
)

# ---------------------------------------------------------------------------
# clamp01
# ---------------------------------------------------------------------------


def test_clamp01_within_range():
    assert clamp01(0.5) == 0.5


def test_clamp01_at_boundaries():
    assert clamp01(0.0) == 0.0
    assert clamp01(1.0) == 1.0


def test_clamp01_below_zero():
    assert clamp01(-0.5) == 0.0
    assert clamp01(-100.0) == 0.0


def test_clamp01_above_one():
    assert clamp01(1.5) == 1.0
    assert clamp01(999.0) == 1.0


# ---------------------------------------------------------------------------
# evidence_level
# ---------------------------------------------------------------------------


def test_evidence_level_no_refs_returns_L0():
    assert evidence_level("static_reference", None) == "L0"
    assert evidence_level("static_reference", []) == "L0"
    assert evidence_level("dynamic_observation", None) == "L0"


def test_evidence_level_empty_strings_ignored():
    assert evidence_level("static_reference", ["", ""]) == "L0"


def test_evidence_level_static_reference_tiers():
    assert evidence_level("static_reference", ["ref1"]) == "L1"
    assert evidence_level("static_reference", ["ref1", "ref2"]) == "L2"
    assert evidence_level("static_reference", ["ref1", "ref2", "ref3"]) == "L2"
    assert evidence_level("static_reference", ["a", "b", "c", "d"]) == "L3"


def test_evidence_level_non_static_tiers():
    assert evidence_level("dynamic_observation", ["ref1"]) == "L2"
    assert evidence_level("dynamic_observation", ["ref1", "ref2"]) == "L3"
    assert evidence_level("dynamic_observation", ["a", "b", "c", "d"]) == "L4"


def test_evidence_level_deduplicates_refs():
    # 3 refs but only 2 unique → L2 for static_reference
    assert evidence_level("static_reference", ["a", "a", "b"]) == "L2"


# ---------------------------------------------------------------------------
# calibrated_confidence — STATIC_ONLY_CAP enforcement
# ---------------------------------------------------------------------------


def test_static_only_cap_value():
    """The constant must be 0.60 — changing it affects all governance."""
    assert STATIC_ONLY_CAP == 0.60


def test_evidence_levels_tuple():
    assert EVIDENCE_LEVELS == ("L0", "L1", "L2", "L3", "L4")


def test_static_reference_capped_at_060():
    """Even with high raw confidence, static_reference cannot exceed 0.60."""
    result = calibrated_confidence(
        confidence=0.95,
        observation="static_reference",
        evidence_refs=["a", "b", "c", "d"],  # L3 → +0.0 bonus
    )
    assert result <= STATIC_ONLY_CAP


def test_static_reference_with_L0_penalty():
    """L0 applies -0.15 penalty, then capped at 0.60."""
    result = calibrated_confidence(
        confidence=0.80,
        observation="static_reference",
        evidence_refs=None,  # L0
    )
    # 0.80 - 0.15 = 0.65, then capped at 0.60
    assert result == 0.60


def test_static_reference_low_confidence_not_inflated():
    """Cap only limits from above, never inflates below."""
    result = calibrated_confidence(
        confidence=0.30,
        observation="static_reference",
        evidence_refs=["ref1"],  # L1 → -0.08
    )
    # 0.30 - 0.08 = 0.22, below cap so unchanged
    assert abs(result - 0.22) < 1e-9


def test_dynamic_observation_not_capped():
    """Non-static observations should NOT be subject to STATIC_ONLY_CAP."""
    result = calibrated_confidence(
        confidence=0.90,
        observation="dynamic_observation",
        evidence_refs=["a", "b", "c", "d"],  # L4 → +0.03
    )
    # 0.90 + 0.03 = 0.93
    assert abs(result - 0.93) < 1e-9


def test_L0_penalty_applied():
    result = calibrated_confidence(
        confidence=0.50,
        observation="dynamic_observation",
        evidence_refs=None,  # L0 → -0.15
    )
    assert abs(result - 0.35) < 1e-9


def test_L1_penalty_applied():
    result = calibrated_confidence(
        confidence=0.50,
        observation="static_reference",
        evidence_refs=["one"],  # L1 → -0.08
    )
    # 0.50 - 0.08 = 0.42, below cap
    assert abs(result - 0.42) < 1e-9


def test_L4_bonus_applied():
    result = calibrated_confidence(
        confidence=0.70,
        observation="dynamic_observation",
        evidence_refs=["a", "b", "c", "d"],  # L4 → +0.03
    )
    assert abs(result - 0.73) < 1e-9


def test_result_clamped_to_01():
    """Negative result after penalty should clamp to 0.0."""
    result = calibrated_confidence(
        confidence=0.05,
        observation="dynamic_observation",
        evidence_refs=None,  # L0 → -0.15
    )
    assert result == 0.0


def test_result_clamped_at_upper_bound():
    """Result above 1.0 after bonus should clamp to 1.0."""
    result = calibrated_confidence(
        confidence=1.0,
        observation="dynamic_observation",
        evidence_refs=["a", "b", "c", "d"],  # L4 → +0.03
    )
    assert result == 1.0


# ---------------------------------------------------------------------------
# DECOMPILED_COLOCATED_CAP (Phase 2C++.1, v2.7.2)
#
# Introduced to separate the body-text co-occurrence signal from the inline
# literal 0.50 previously used in taint_propagation. Evidence-level parity with
# SYMBOL_COOCCURRENCE, +0.05 because decompilation exposes inlined CALLs absent
# from symbol tables. Strictly below STATIC_CODE_VERIFIED — no SSA def-use
# proof. See docs/confidence_semantic_break_v2.6.md for rationale.
# ---------------------------------------------------------------------------


def test_decompiled_colocated_cap_value():
    """The constant must be 0.45 — changing it reshapes per-method confidence
    ceilings in taint_propagation.decompiled_colocated."""
    assert DECOMPILED_COLOCATED_CAP == 0.45


def test_cap_ordering_ascending():
    """Caps must form a strictly ascending evidence ladder. Any reordering
    changes the semantic meaning of confidence scores downstream (cve_scan,
    findings, priority_score)."""
    assert (
        SYMBOL_COOCCURRENCE_CAP
        < DECOMPILED_COLOCATED_CAP
        < STATIC_CODE_VERIFIED_CAP
        < STATIC_ONLY_CAP
        < PCODE_VERIFIED_CAP
    )


def test_decompiled_colocated_above_symbol_cooccurrence():
    """Inline expansion exposes CALLs absent from symbol tables, warranting a
    small bonus above SYMBOL_COOCCURRENCE (pure symbol signal only)."""
    assert DECOMPILED_COLOCATED_CAP > SYMBOL_COOCCURRENCE_CAP
    assert abs((DECOMPILED_COLOCATED_CAP - SYMBOL_COOCCURRENCE_CAP) - 0.05) < 1e-9


def test_decompiled_colocated_below_static_code_verified():
    """Body-text co-occurrence has no SSA def-use proof; must stay below the
    cap for decompiled code with LLM-verified taint traces."""
    assert DECOMPILED_COLOCATED_CAP < STATIC_CODE_VERIFIED_CAP


def test_decompiled_colocated_below_pcode_verified():
    """Body text is strictly weaker than P-code SSA dataflow confirmation."""
    assert DECOMPILED_COLOCATED_CAP < PCODE_VERIFIED_CAP


def test_taint_propagation_uses_decompiled_colocated_cap():
    """taint_propagation.py must import the shared cap rather than re-hardcode
    0.50 (the pre-v2.7.2 literal). This prevents future drift between the
    confidence_caps ladder and per-method ceilings."""
    from aiedge import taint_propagation

    assert hasattr(taint_propagation, "DECOMPILED_COLOCATED_CAP")
    assert taint_propagation.DECOMPILED_COLOCATED_CAP == DECOMPILED_COLOCATED_CAP
