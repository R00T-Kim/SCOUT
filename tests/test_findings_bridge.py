"""Tests for bridge token detection in binary strings proximity analysis."""
from __future__ import annotations


class TestClassifyBinaryToken:
    def test_identifies_bridge_sprintf(self) -> None:
        from aiedge.findings import _classify_binary_token
        result = _classify_binary_token("sprintf(")
        assert result is not None
        kind, token, _ = result
        assert kind == "bridge"
        assert token == "sprintf("

    def test_identifies_bridge_snprintf(self) -> None:
        from aiedge.findings import _classify_binary_token
        result = _classify_binary_token("snprintf(")
        assert result is not None
        assert result[0] == "bridge"

    def test_identifies_bridge_strcat(self) -> None:
        from aiedge.findings import _classify_binary_token
        result = _classify_binary_token("strcat(")
        assert result is not None
        assert result[0] == "bridge"

    def test_sink_takes_priority_over_bridge(self) -> None:
        from aiedge.findings import _classify_binary_token
        # system( is a sink, should not be classified as bridge
        result = _classify_binary_token("system(")
        assert result is not None
        assert result[0] == "sink"

    def test_non_matching_returns_none(self) -> None:
        from aiedge.findings import _classify_binary_token
        assert _classify_binary_token("hello_world") is None


class TestBinaryAnchorScore:
    def test_bridge_near_adds_015(self) -> None:
        from aiedge.findings import _binary_anchor_score
        score_without = _binary_anchor_score(near_shell=1, mid_shell=0, near_source=0, mid_source=0)
        score_with = _binary_anchor_score(near_shell=1, mid_shell=0, near_source=0, mid_source=0, near_bridge=1)
        assert score_with - score_without == pytest.approx(0.15)

    def test_bridge_mid_adds_008(self) -> None:
        from aiedge.findings import _binary_anchor_score
        score_without = _binary_anchor_score(near_shell=1, mid_shell=0, near_source=0, mid_source=0)
        score_with = _binary_anchor_score(near_shell=1, mid_shell=0, near_source=0, mid_source=0, mid_bridge=1)
        assert score_with - score_without == pytest.approx(0.08)

    def test_backward_compatible_no_bridge_params(self) -> None:
        from aiedge.findings import _binary_anchor_score
        # Calling without bridge params should produce same results as before
        score = _binary_anchor_score(near_shell=1, mid_shell=0, near_source=1, mid_source=0)
        assert score == pytest.approx(0.65)  # 0.2 + 0.25 + 0.2

    def test_isolated_sink_with_no_neighbors(self) -> None:
        from aiedge.findings import _binary_anchor_score
        score = _binary_anchor_score(near_shell=0, mid_shell=0, near_source=0, mid_source=0)
        assert score == 0.25

    def test_max_score_capped_at_085(self) -> None:
        from aiedge.findings import _binary_anchor_score
        score = _binary_anchor_score(
            near_shell=1, mid_shell=0, near_source=1, mid_source=0,
            near_bridge=1, mid_bridge=0,
        )
        # 0.2 + 0.25 + 0.2 + 0.15 = 0.80, still under cap
        assert score == pytest.approx(0.80)

    def test_all_max_hits_caps_correctly(self) -> None:
        from aiedge.findings import _binary_anchor_score
        score = _binary_anchor_score(
            near_shell=5, mid_shell=5, near_source=5, mid_source=5,
            near_bridge=5, mid_bridge=5,
        )
        assert score <= 0.85


import pytest
