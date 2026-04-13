"""Unit tests for stage_dag: STAGE_DEPS + topo_levels + validate_deps.

Covers:
* Linear / diamond / cycle / orphan / unregistered-dep topologies.
* STAGE_DEPS ↔ _STAGE_FACTORIES integrity (no drift).
* validate_deps() warning surface.
"""

from __future__ import annotations

import pytest

from aiedge.stage_dag import STAGE_DEPS, topo_levels, validate_deps
from aiedge.stage_registry import stage_factories


# ---------------------------------------------------------------------------
# topo_levels() unit cases
# ---------------------------------------------------------------------------
def test_topo_levels_linear() -> None:
    """A -> B -> C renders three singleton levels."""
    deps: dict[str, frozenset[str]] = {
        "A": frozenset(),
        "B": frozenset({"A"}),
        "C": frozenset({"B"}),
    }
    levels = topo_levels(deps, {"A", "B", "C"})
    assert levels == [["A"], ["B"], ["C"]]


def test_topo_levels_diamond() -> None:
    """A -> B, A -> C, B -> D, C -> D: B and C share one level."""
    deps: dict[str, frozenset[str]] = {
        "A": frozenset(),
        "B": frozenset({"A"}),
        "C": frozenset({"A"}),
        "D": frozenset({"B", "C"}),
    }
    levels = topo_levels(deps, {"A", "B", "C", "D"})
    assert levels[0] == ["A"]
    assert sorted(levels[1]) == ["B", "C"]
    assert levels[2] == ["D"]
    assert sum(len(lv) for lv in levels) == 4


def test_topo_levels_cycle_raises() -> None:
    """A cycle must raise ValueError with an unresolved stage list."""
    deps: dict[str, frozenset[str]] = {
        "A": frozenset({"B"}),
        "B": frozenset({"A"}),
    }
    with pytest.raises(ValueError, match="Cycle or missing dep"):
        _ = topo_levels(deps, {"A", "B"})


def test_topo_levels_orphan() -> None:
    """Disconnected (no-dep, no-children) stages still appear as a level-0 singleton."""
    deps: dict[str, frozenset[str]] = {
        "A": frozenset(),
        "B": frozenset({"A"}),
        "X": frozenset(),  # orphan
    }
    levels = topo_levels(deps, {"A", "B", "X"})
    # A and X have in-degree 0, so both land on level 0.
    assert sorted(levels[0]) == ["A", "X"]
    assert levels[1] == ["B"]


def test_topo_levels_unregistered_dep_filtered() -> None:
    """A dep outside the requested set is silently ignored (not a cycle)."""
    deps: dict[str, frozenset[str]] = {
        "A": frozenset(),
        "B": frozenset({"A", "not_requested"}),
    }
    levels = topo_levels(deps, {"A", "B"})
    assert levels == [["A"], ["B"]]


# ---------------------------------------------------------------------------
# validate_deps() cases
# ---------------------------------------------------------------------------
def test_validate_deps_unknown_stage() -> None:
    """STAGE_DEPS referencing a stage that is not in the registry must warn."""
    deps: dict[str, frozenset[str]] = {
        "A": frozenset(),
        "ghost": frozenset({"A"}),
    }
    registered = {"A"}  # 'ghost' absent on purpose
    warnings = validate_deps(deps, registered)
    assert any("unregistered stage: ghost" in w for w in warnings)


def test_validate_deps_unknown_dep_target() -> None:
    """An edge pointing at a stage absent from both registered+deps must warn."""
    deps: dict[str, frozenset[str]] = {
        "A": frozenset({"MISSING"}),
    }
    registered = {"A"}
    warnings = validate_deps(deps, registered)
    assert any("A depends on unknown stage: MISSING" in w for w in warnings)


def test_validate_deps_cycle_detection() -> None:
    """validate_deps should surface cycles as warnings (no raise)."""
    deps: dict[str, frozenset[str]] = {
        "A": frozenset({"B"}),
        "B": frozenset({"A"}),
    }
    warnings = validate_deps(deps, {"A", "B"})
    assert any("Cycle detected" in w for w in warnings)


def test_validate_deps_clean() -> None:
    """Current SCOUT STAGE_DEPS must validate cleanly against the real registry."""
    registered = set(stage_factories().keys())
    warnings = validate_deps(STAGE_DEPS, registered)
    assert warnings == [], f"STAGE_DEPS drifted from _STAGE_FACTORIES: {warnings}"


# ---------------------------------------------------------------------------
# STAGE_DEPS integrity checks (guards against silent drift)
# ---------------------------------------------------------------------------
def test_stage_deps_keys_match_factories_exact() -> None:
    """Every registered stage has an entry; no extra keys are present."""
    registered = set(stage_factories().keys())
    deps_keys = set(STAGE_DEPS.keys())
    missing_in_deps = registered - deps_keys
    extra_in_deps = deps_keys - registered
    assert not missing_in_deps, f"missing from STAGE_DEPS: {sorted(missing_in_deps)}"
    assert not extra_in_deps, f"extra in STAGE_DEPS: {sorted(extra_in_deps)}"


def test_stage_deps_excludes_findings() -> None:
    """findings runs as an integrated step and must never appear in the DAG."""
    assert "findings" not in STAGE_DEPS
    for stage, deps in STAGE_DEPS.items():
        assert (
            "findings" not in deps
        ), f"stage {stage!r} references findings in STAGE_DEPS"


def test_stage_deps_includes_exploit_gate() -> None:
    """exploit_gate is registered inline in stage_registry.py; DAG must include it."""
    assert "exploit_gate" in STAGE_DEPS
    assert "chain_construction" in STAGE_DEPS["exploit_gate"]


def test_stage_deps_ipc_chain_from_docs() -> None:
    """pipeline-architecture.md IPC chain: inventory -> endpoints -> surfaces -> graph -> attack_surface."""
    assert "inventory" in STAGE_DEPS["endpoints"]
    assert "endpoints" in STAGE_DEPS["surfaces"]
    assert "inventory" in STAGE_DEPS["surfaces"]
    assert "surfaces" in STAGE_DEPS["graph"]
    assert "endpoints" in STAGE_DEPS["graph"]
    assert "graph" in STAGE_DEPS["attack_surface"]


def test_stage_deps_topo_levels_cover_all_registered() -> None:
    """topo_levels over the full registered set visits every stage exactly once."""
    registered = set(stage_factories().keys())
    levels = topo_levels(STAGE_DEPS, registered)
    flat = [s for lvl in levels for s in lvl]
    assert sorted(flat) == sorted(registered)
    assert len(flat) == len(set(flat))  # no duplicates
