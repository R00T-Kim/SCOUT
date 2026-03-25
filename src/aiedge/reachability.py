from __future__ import annotations

"""reachability.py — CVE reachability analysis stage.

Determines whether CVE-matched components are actually reachable from the
attack surface by walking the communication graph emitted by the graph stage.

Inputs (all optional — stage degrades gracefully when missing):
    stages/cve_scan/cve_matches.json         — CVE-matched components
    stages/graph/communication_graph.json    — directed communication graph
    stages/attack_surface/attack_surface.json — network-facing endpoints
    stages/inventory/binary_analysis.json    — binary list + import symbols
    stages/surfaces/source_sink_graph.json   — source-sink paths (enrichment)

Output:
    stages/reachability/reachability.json    — per-component reachability results
    stages/reachability/stage.json           — standard stage metadata
"""

import json
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .path_safety import assert_under_dir, rel_to_run_dir, sha256_text
from .policy import AIEdgePolicyViolation
from .schema import JsonValue
from .stage import StageContext, StageOutcome

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_STAGE_NAME = "reachability"
_MAX_COMPONENTS = 200
_DIRECTLY_REACHABLE_MAX_HOPS = 2

# Node types treated as attack surface entry points
_ENTRY_NODE_TYPES = frozenset({"endpoint", "surface"})

# Reachability classification strings
_DIRECTLY_REACHABLE = "directly_reachable"
_POTENTIALLY_REACHABLE = "potentially_reachable"
_UNREACHABLE = "unreachable"
_NO_GRAPH_DATA = "no_graph_data"


# ---------------------------------------------------------------------------
# Helpers — JSON I/O
# ---------------------------------------------------------------------------


def _write_json(run_dir: Path, dest: Path, data: object) -> None:
    """Serialize *data* to *dest*, enforcing run-dir containment."""
    assert_under_dir(run_dir, dest)
    dest.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _load_json(path: Path) -> object | None:
    """Load JSON from *path*, returning None on any error."""
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def _build_adjacency(
    comm_graph: dict[str, object],
) -> tuple[dict[str, list[str]], dict[str, str]]:
    """Build a forward adjacency list and node-type map from communication_graph.

    Returns:
        adj:       node_id → list[neighbor_node_id]
        node_types: node_id → type string (e.g. "endpoint", "component", "surface")
    """
    adj: dict[str, list[str]] = {}
    node_types: dict[str, str] = {}

    nodes_any = comm_graph.get("nodes")
    if isinstance(nodes_any, list):
        for n in nodes_any:
            if not isinstance(n, dict):
                continue
            nid = str(n.get("id", ""))
            if not nid:
                continue
            node_types[nid] = str(n.get("type", "unknown"))
            adj.setdefault(nid, [])

    edges_any = comm_graph.get("edges")
    if isinstance(edges_any, list):
        for e in edges_any:
            if not isinstance(e, dict):
                continue
            src = str(e.get("source", e.get("src", "")))
            dst = str(e.get("target", e.get("dst", "")))
            if src and dst:
                adj.setdefault(src, []).append(dst)
                adj.setdefault(dst, [])  # ensure destination exists

    return adj, node_types


def _entry_nodes(node_types: dict[str, str]) -> list[str]:
    """Return all node IDs whose type is an attack surface entry point."""
    return [nid for nid, ntype in node_types.items() if ntype in _ENTRY_NODE_TYPES]


# ---------------------------------------------------------------------------
# BFS reachability
# ---------------------------------------------------------------------------


def _bfs_shortest_path(
    adj: dict[str, list[str]],
    sources: list[str],
    target: str,
) -> list[str] | None:
    """BFS from all *sources* simultaneously; return shortest path to *target*.

    Returns None if *target* is not reachable from any source.
    The returned path includes the source node and *target*.
    """
    if target in sources:
        return [target]

    visited: dict[str, str | None] = {s: None for s in sources}
    queue: deque[str] = deque(sources)

    while queue:
        node = queue.popleft()
        for neighbor in adj.get(node, []):
            if neighbor not in visited:
                visited[neighbor] = node
                if neighbor == target:
                    # Reconstruct path
                    path: list[str] = []
                    cur: str | None = neighbor
                    while cur is not None:
                        path.append(cur)
                        cur = visited[cur]
                    path.reverse()
                    return path
                queue.append(neighbor)

    return None


# ---------------------------------------------------------------------------
# Component → node matching
# ---------------------------------------------------------------------------


def _candidate_nodes(
    component_name: str,
    binary_path: str,
    adj: dict[str, list[str]],
    node_types: dict[str, str],
) -> list[str]:
    """Find graph nodes that plausibly correspond to a CVE-matched component.

    Matching strategy (in order of specificity):
    1. Exact node-id match against binary_path basename
    2. Node-id contains the component name (case-insensitive)
    3. Node label/name attribute contains the component name
    """
    comp_lower = component_name.lower()
    binary_basename = Path(binary_path).name.lower() if binary_path else ""

    candidates: list[str] = []

    for nid in adj:
        nid_lower = nid.lower()
        # Exact basename match
        if binary_basename and binary_basename in nid_lower:
            candidates.append(nid)
            continue
        # Component name substring match in node id
        if comp_lower and comp_lower in nid_lower:
            candidates.append(nid)

    # Deduplicate while preserving order
    seen: set[str] = set()
    result: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return result


# ---------------------------------------------------------------------------
# Per-component analysis
# ---------------------------------------------------------------------------


def _analyze_component(
    component_name: str,
    version: str,
    cve_ids: list[str],
    binary_path: str,
    entry_nodes: list[str],
    adj: dict[str, list[str]],
    node_types: dict[str, str],
    evidence_refs: list[str],
) -> dict[str, object]:
    """Compute reachability for one CVE-matched component."""

    target_nodes = _candidate_nodes(component_name, binary_path, adj, node_types)

    if not entry_nodes or not adj:
        return {
            "component": component_name,
            "version": version,
            "cve_ids": sorted(cve_ids),
            "reachability": _NO_GRAPH_DATA,
            "hop_count": None,
            "path": [],
            "confidence": 0.0,
            "evidence_refs": sorted(evidence_refs),
        }

    if not target_nodes:
        # Component not found in graph — treat as unreachable
        return {
            "component": component_name,
            "version": version,
            "cve_ids": sorted(cve_ids),
            "reachability": _UNREACHABLE,
            "hop_count": None,
            "path": [],
            "confidence": 0.30,
            "evidence_refs": sorted(evidence_refs),
        }

    # Try each candidate target node; keep shortest path overall
    best_path: list[str] | None = None
    for tnode in target_nodes:
        path = _bfs_shortest_path(adj, entry_nodes, tnode)
        if path is not None:
            if best_path is None or len(path) < len(best_path):
                best_path = path

    if best_path is None:
        return {
            "component": component_name,
            "version": version,
            "cve_ids": sorted(cve_ids),
            "reachability": _UNREACHABLE,
            "hop_count": None,
            "path": [],
            "confidence": 0.40,
            "evidence_refs": sorted(evidence_refs),
        }

    # hop_count = number of edges = len(path) - 1
    hop_count = len(best_path) - 1

    if hop_count <= _DIRECTLY_REACHABLE_MAX_HOPS:
        reachability = _DIRECTLY_REACHABLE
        # Confidence reflects that graph data may be incomplete; cap conservatively
        confidence = 0.65
    else:
        reachability = _POTENTIALLY_REACHABLE
        confidence = 0.50

    return {
        "component": component_name,
        "version": version,
        "cve_ids": sorted(cve_ids),
        "reachability": reachability,
        "hop_count": hop_count,
        "path": best_path,
        "confidence": confidence,
        "evidence_refs": sorted(evidence_refs),
    }


# ---------------------------------------------------------------------------
# Input loaders
# ---------------------------------------------------------------------------


def _load_cve_matches(
    run_dir: Path,
) -> tuple[list[dict[str, object]], list[str]]:
    """Load cve_matches.json; return (matches_list, limitations)."""
    path = run_dir / "stages" / "cve_scan" / "cve_matches.json"
    limitations: list[str] = []

    if not path.exists():
        return [], ["cve_scan/cve_matches.json not found; reachability skipped"]

    raw = _load_json(path)
    if not isinstance(raw, dict):
        limitations.append("cve_matches.json: unexpected format")
        return [], limitations

    matches_any = raw.get("matches")
    if not isinstance(matches_any, list):
        limitations.append("cve_matches.json: 'matches' field missing or not a list")
        return [], limitations

    matches: list[dict[str, object]] = []
    for item in matches_any:
        if isinstance(item, dict):
            matches.append(cast(dict[str, object], item))

    return matches, limitations


def _load_comm_graph(
    run_dir: Path,
) -> tuple[dict[str, object] | None, list[str]]:
    """Load communication_graph.json; return (graph_dict, limitations)."""
    path = run_dir / "stages" / "graph" / "communication_graph.json"
    limitations: list[str] = []

    if not path.exists():
        limitations.append("graph/communication_graph.json not found; graph-based reachability unavailable")
        return None, limitations

    raw = _load_json(path)
    if not isinstance(raw, dict):
        limitations.append("communication_graph.json: unexpected format")
        return None, limitations

    return cast(dict[str, object], raw), limitations


def _load_attack_surface(
    run_dir: Path,
) -> tuple[list[str], list[str]]:
    """Extract network-facing endpoint names from attack_surface.json.

    Returns (endpoint_names, limitations).
    """
    path = run_dir / "stages" / "attack_surface" / "attack_surface.json"
    limitations: list[str] = []

    if not path.exists():
        return [], ["attack_surface/attack_surface.json not found"]

    raw = _load_json(path)
    if not isinstance(raw, dict):
        limitations.append("attack_surface.json: unexpected format")
        return [], limitations

    endpoints: list[str] = []
    endpoints_any = raw.get("endpoints") or raw.get("network_endpoints") or raw.get("services")
    if isinstance(endpoints_any, list):
        for ep in endpoints_any:
            if isinstance(ep, dict):
                name = ep.get("name") or ep.get("id") or ep.get("service")
                if name:
                    endpoints.append(str(name))
            elif isinstance(ep, str):
                endpoints.append(ep)

    return endpoints, limitations


# ---------------------------------------------------------------------------
# Group CVE matches by component
# ---------------------------------------------------------------------------


def _group_by_component(
    matches: list[dict[str, object]],
) -> list[tuple[str, str, list[str], str]]:
    """Return sorted list of (component, version, [cve_ids], binary_path).

    Groups multiple CVE IDs for the same component/version together and
    deduplicates.  Limited to _MAX_COMPONENTS entries.
    """
    # key: (component, version, binary_path)
    grouped: dict[tuple[str, str, str], list[str]] = {}

    for m in matches:
        comp = str(m.get("component", m.get("name", "unknown")))
        ver = str(m.get("version", ""))
        cve_id = str(m.get("cve_id", ""))
        # Try to get a binary path from evidence references or a direct field
        binary_path = str(
            m.get("binary_path", m.get("file_path", m.get("path", "")))
        )
        key = (comp, ver, binary_path)
        grouped.setdefault(key, [])
        if cve_id:
            grouped[key].append(cve_id)

    result = [
        (comp, ver, sorted(set(cve_ids)), bp)
        for (comp, ver, bp), cve_ids in sorted(grouped.items())
    ]
    return result[:_MAX_COMPONENTS]


# ---------------------------------------------------------------------------
# ReachabilityStage
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReachabilityStage:
    run_dir: Path
    case_id: str | None
    remaining_budget_s: Callable[[], float]
    no_llm: bool

    @property
    def name(self) -> str:
        return _STAGE_NAME

    def run(self, ctx: StageContext) -> StageOutcome:  # noqa: C901 (acceptable complexity)
        run_dir = ctx.run_dir
        time.monotonic()
        limitations: list[str] = []
        status = "ok"

        # ------------------------------------------------------------------ #
        # Setup output directory
        # ------------------------------------------------------------------ #
        stage_dir = run_dir / "stages" / _STAGE_NAME
        try:
            stage_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return StageOutcome(
                status="failed",
                details={"error": str(exc)},
                limitations=[f"Could not create stage directory: {exc}"],
            )

        # ------------------------------------------------------------------ #
        # Load inputs
        # ------------------------------------------------------------------ #

        # 1. CVE matches — mandatory; skip if absent
        matches_raw, cve_lims = _load_cve_matches(run_dir)
        limitations.extend(cve_lims)

        if not matches_raw:
            details: dict[str, JsonValue] = {
                "reason": "no_cve_matches",
                "components_analyzed": 0,
            }
            _write_stage_json(run_dir, stage_dir, "skipped", details, limitations)
            return StageOutcome(status="skipped", details=details, limitations=limitations)

        # 2. Communication graph — optional
        comm_graph, graph_lims = _load_comm_graph(run_dir)
        limitations.extend(graph_lims)

        # 3. Attack surface — optional (used to augment entry-node detection)
        as_endpoints, as_lims = _load_attack_surface(run_dir)
        limitations.extend(as_lims)

        # 4. Source-sink graph — optional enrichment only (recorded as evidence)
        ss_path = run_dir / "stages" / "surfaces" / "source_sink_graph.json"
        has_source_sink = ss_path.exists()

        # ------------------------------------------------------------------ #
        # Build graph structures
        # ------------------------------------------------------------------ #
        has_graph = comm_graph is not None

        if has_graph:
            adj, node_types = _build_adjacency(comm_graph)  # type: ignore[arg-type]

            # Derive entry nodes from graph node types
            entry_nodes = _entry_nodes(node_types)

            # Also treat attack_surface endpoint names as entry nodes if they
            # appear in the graph (by substring match)
            for ep_name in as_endpoints:
                ep_lower = ep_name.lower()
                for nid in adj:
                    if ep_lower in nid.lower() and nid not in entry_nodes:
                        entry_nodes.append(nid)
        else:
            adj = {}
            node_types = {}
            entry_nodes = []
            status = "partial"

        # ------------------------------------------------------------------ #
        # Group CVE matches by component
        # ------------------------------------------------------------------ #
        components = _group_by_component(matches_raw)

        cve_scan_ref = "stages/cve_scan/cve_matches.json"
        graph_ref = "stages/graph/communication_graph.json"

        # ------------------------------------------------------------------ #
        # Analyze each component
        # ------------------------------------------------------------------ #
        results: list[dict[str, object]] = []
        summary: dict[str, int] = {
            _DIRECTLY_REACHABLE: 0,
            _POTENTIALLY_REACHABLE: 0,
            _UNREACHABLE: 0,
            _NO_GRAPH_DATA: 0,
        }

        for comp, ver, cve_ids, binary_path in components:
            # Respect time budget
            if self.remaining_budget_s() < 5.0:
                limitations.append(
                    f"Time budget exhausted; {len(components) - len(results)} components not analyzed"
                )
                status = "partial"
                break

            ev_refs: list[str] = [cve_scan_ref]
            if has_graph:
                ev_refs.append(graph_ref)
            if has_source_sink:
                ev_refs.append("stages/surfaces/source_sink_graph.json")

            result = _analyze_component(
                component_name=comp,
                version=ver,
                cve_ids=cve_ids,
                binary_path=binary_path,
                entry_nodes=entry_nodes,
                adj=adj,
                node_types=node_types,
                evidence_refs=ev_refs,
            )
            results.append(result)

            r_class = str(result.get("reachability", _NO_GRAPH_DATA))
            if r_class in summary:
                summary[r_class] += 1
            else:
                summary[_NO_GRAPH_DATA] += 1

        # ------------------------------------------------------------------ #
        # Build output document
        # ------------------------------------------------------------------ #
        output: dict[str, object] = {
            "schema_version": "reachability-v1",
            "components_analyzed": len(results),
            "results": sorted(results, key=lambda r: str(r.get("component", ""))),
            "summary": dict(sorted(summary.items())),
            "limitations": limitations,
        }

        # ------------------------------------------------------------------ #
        # Write reachability.json
        # ------------------------------------------------------------------ #
        reach_path = stage_dir / "reachability.json"
        try:
            _write_json(run_dir, reach_path, output)
        except (OSError, AIEdgePolicyViolation) as exc:
            limitations.append(f"reachability.json write failed: {exc}")
            status = "partial"

        # ------------------------------------------------------------------ #
        # Compute artifact hash for stage.json
        # ------------------------------------------------------------------ #
        artifact_hash: str | None = None
        if reach_path.exists():
            try:
                artifact_hash = sha256_text(
                    reach_path.read_text(encoding="utf-8", errors="replace")
                )
            except OSError:
                pass

        # ------------------------------------------------------------------ #
        # Build details for stage.json / StageOutcome
        # ------------------------------------------------------------------ #
        details_out: dict[str, JsonValue] = {
            "components_analyzed": len(results),
            "directly_reachable": summary[_DIRECTLY_REACHABLE],
            "potentially_reachable": summary[_POTENTIALLY_REACHABLE],
            "unreachable": summary[_UNREACHABLE],
            "no_graph_data": summary[_NO_GRAPH_DATA],
            "has_graph": has_graph,
            "has_source_sink": has_source_sink,
            "reachability_path": rel_to_run_dir(run_dir, reach_path),
        }
        if artifact_hash is not None:
            details_out["reachability_sha256"] = artifact_hash

        # ------------------------------------------------------------------ #
        # Write stage.json
        # ------------------------------------------------------------------ #
        _write_stage_json(run_dir, stage_dir, status, details_out, limitations)

        return StageOutcome(
            status=cast("StageStatus", status),  # type: ignore[arg-type]  # noqa: F821
            details=details_out,
            limitations=limitations,
        )


# ---------------------------------------------------------------------------
# Internal helper — write stage.json
# ---------------------------------------------------------------------------


def _write_stage_json(
    run_dir: Path,
    stage_dir: Path,
    status: str,
    details: dict[str, JsonValue],
    limitations: list[str],
) -> None:
    stage_json: dict[str, JsonValue] = {
        "details": cast(JsonValue, details),
        "limitations": cast(JsonValue, limitations),
        "stage": _STAGE_NAME,
        "status": status,
    }
    stage_json_path = stage_dir / "stage.json"
    try:
        assert_under_dir(run_dir, stage_json_path)
        stage_json_path.write_text(
            json.dumps(stage_json, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    except (OSError, AIEdgePolicyViolation):
        pass  # non-fatal; caller already has outcome


# ---------------------------------------------------------------------------
# Factory (matches StageFactory signature in stage_registry.py)
# ---------------------------------------------------------------------------


def make_reachability_stage(
    info: object,
    case_id: str | None,
    remaining_budget_s: Callable[[], float],
    no_llm: bool,
) -> ReachabilityStage:
    """Factory function for registration in _STAGE_FACTORIES."""
    firmware_dest_any = getattr(info, "firmware_dest", None)
    run_dir = (
        firmware_dest_any.parent
        if isinstance(firmware_dest_any, Path)
        else Path(".")
    )
    return ReachabilityStage(
        run_dir=run_dir,
        case_id=case_id,
        remaining_budget_s=remaining_budget_s,
        no_llm=no_llm,
    )
