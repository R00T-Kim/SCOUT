from __future__ import annotations

"""Manual STAGE_DEPS dictionary + topological levels.

Single source of truth for stage-to-stage dependencies in SCOUT.
Used by ``run_stages_parallel()`` to compute level-wise execution batches.

STAGE_DEPS is a hand-maintained adjacency list -- every key is a stage name
registered in :data:`aiedge.stage_registry._STAGE_FACTORIES`. The ``findings``
integrated step is intentionally absent because it is not a registered stage
factory; it runs outside the parallel execution path via ``run_findings(ctx)``.

The dependency edges mirror the documented pipeline order in
``.claude/rules/pipeline-architecture.md`` (IPC chain: inventory -> endpoints
-> surfaces -> graph -> attack_surface) and the factory registration order in
``stage_registry.py``.
"""

from collections import defaultdict, deque

# -----------------------------------------------------------------------------
# STAGE_DEPS -- Kahn topological sort source-of-truth.
#
# Edge semantics: ``stage -> frozenset(deps)`` means ``stage`` may only start
# after every listed dependency has completed successfully. Frozensets are used
# so the dict itself is effectively hashable and safe to share across threads.
# -----------------------------------------------------------------------------
STAGE_DEPS: dict[str, frozenset[str]] = {
    "tooling": frozenset(),
    "ota": frozenset({"tooling"}),
    "ota_payload": frozenset({"ota"}),
    "ota_fs": frozenset({"ota_payload"}),
    "ota_roots": frozenset({"ota_fs"}),
    "ota_boottriage": frozenset({"ota_roots"}),
    "extraction": frozenset({"tooling"}),
    "firmware_lineage": frozenset({"extraction"}),
    "structure": frozenset({"extraction"}),
    "carving": frozenset({"extraction"}),
    "firmware_profile": frozenset({"extraction"}),
    "inventory": frozenset({"extraction"}),
    "ghidra_analysis": frozenset({"inventory"}),
    "semantic_classification": frozenset({"ghidra_analysis"}),
    "sbom": frozenset({"inventory"}),
    "cve_scan": frozenset({"sbom"}),
    "reachability": frozenset({"sbom", "ghidra_analysis"}),
    "endpoints": frozenset({"inventory"}),
    "surfaces": frozenset({"endpoints", "inventory"}),
    "enhanced_source": frozenset({"inventory"}),
    "csource_identification": frozenset({"surfaces", "enhanced_source"}),
    "taint_propagation": frozenset({"csource_identification", "ghidra_analysis"}),
    "fp_verification": frozenset({"taint_propagation"}),
    "adversarial_triage": frozenset({"fp_verification"}),
    "web_ui": frozenset({"endpoints"}),
    "graph": frozenset({"surfaces", "endpoints"}),
    "attribution": frozenset({"inventory"}),
    "attack_surface": frozenset({"graph", "attribution"}),
    "functional_spec": frozenset({"attack_surface"}),
    "threat_model": frozenset({"functional_spec"}),
    "llm_triage": frozenset({"adversarial_triage"}),
    "llm_synthesis": frozenset({"llm_triage", "threat_model"}),
    "emulation": frozenset({"firmware_profile"}),
    "dynamic_validation": frozenset({"emulation"}),
    "fuzzing": frozenset({"dynamic_validation"}),
    "poc_refinement": frozenset({"fuzzing", "adversarial_triage"}),
    "chain_construction": frozenset({"adversarial_triage", "graph"}),
    "exploit_gate": frozenset({"chain_construction"}),
    "exploit_chain": frozenset({"exploit_gate"}),
    "exploit_autopoc": frozenset({"exploit_chain"}),
    "poc_validation": frozenset({"exploit_autopoc"}),
    "exploit_policy": frozenset({"poc_validation"}),
}


def topo_levels(
    deps: dict[str, frozenset[str]], requested: set[str]
) -> list[list[str]]:
    """Kahn's algorithm: return level-wise groups for parallel execution.

    Each inner list contains stages that share a dependency level -- they have
    no edges between them and therefore may run concurrently. Levels are
    executed in order.

    Only edges whose source AND target are in ``requested`` are considered.
    Edges that reference a stage outside ``requested`` are silently dropped,
    which keeps the level structure consistent when users pass a subset via
    ``--stages``.

    Raises:
        ValueError: if the subgraph induced by ``requested`` contains a cycle
            or any stage that cannot be reached from a level-0 node.
    """
    in_degree: dict[str, int] = defaultdict(int)
    children: dict[str, set[str]] = defaultdict(set)

    # Ensure every requested stage appears as a key, even leaves.
    for stage in requested:
        _ = in_degree[stage]

    for stage in requested:
        for dep in deps.get(stage, frozenset()):
            if dep in requested:
                in_degree[stage] += 1
                children[dep].add(stage)

    levels: list[list[str]] = []
    ready: deque[str] = deque(sorted(s for s in requested if in_degree[s] == 0))

    while ready:
        current_level = list(ready)
        levels.append(current_level)
        ready = deque()
        for stage in current_level:
            for child in sorted(children[stage]):
                in_degree[child] -= 1
                if in_degree[child] == 0:
                    ready.append(child)

    visited = sum(len(level) for level in levels)
    if visited != len(requested):
        unresolved = requested - {s for level in levels for s in level}
        raise ValueError(f"Cycle or missing dep: {sorted(unresolved)}")

    return levels


def validate_deps(deps: dict[str, frozenset[str]], registered: set[str]) -> list[str]:
    """Validate ``deps`` against a set of registered stage names.

    Returns a list of human-readable warnings. An empty list means the graph
    is internally consistent and references only registered stages. Checks:
      * Every key in ``deps`` is registered.
      * Every dependency edge points to a registered (or at least declared)
        stage -- a dep may be declared solely as a ``deps`` key even if its
        factory is not in ``registered``, but that still emits a warning.
      * The full ``deps`` graph is acyclic.
    """
    warnings: list[str] = []
    for stage, stage_deps in deps.items():
        if stage not in registered:
            warnings.append(f"STAGE_DEPS contains unregistered stage: {stage}")
        for dep in stage_deps:
            if dep not in registered and dep not in deps:
                warnings.append(f"{stage} depends on unknown stage: {dep}")

    try:
        _ = topo_levels(deps, set(deps.keys()))
    except ValueError as exc:
        warnings.append(f"Cycle detected: {exc}")

    return warnings
