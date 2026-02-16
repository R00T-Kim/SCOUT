from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .confidence_caps import calibrated_confidence, evidence_level
from .policy import AIEdgePolicyViolation
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus


def _assert_under_dir(base_dir: Path, target: Path) -> None:
    base = base_dir.resolve()
    resolved = target.resolve()
    if not resolved.is_relative_to(base):
        raise AIEdgePolicyViolation(
            f"Refusing to write outside run dir: target={resolved} base={base}"
        )


def _rel_to_run_dir(run_dir: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(run_dir.resolve()))
    except Exception:
        return str(path)


def _clamp01(v: float) -> float:
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return float(v)


def _safe_ascii_label(text: str, *, max_len: int = 72) -> str:
    cleaned = " ".join(text.replace("\n", " ").replace("\r", " ").split())
    cleaned_ascii = cleaned.encode("ascii", errors="ignore").decode("ascii")
    if not cleaned_ascii:
        cleaned_ascii = "unknown"
    return cleaned_ascii[:max_len]


def _safe_node_value(value: str, *, max_len: int = 160) -> str:
    cleaned = " ".join(value.replace("\n", " ").replace("\r", " ").split())
    cleaned_ascii = cleaned.encode("ascii", errors="ignore").decode("ascii")
    if not cleaned_ascii:
        return "unknown"
    return cleaned_ascii[:max_len]


def _is_run_relative_path(path: object) -> bool:
    return isinstance(path, str) and bool(path) and not path.startswith("/")


def _load_json_object(path: Path) -> dict[str, object] | None:
    if not path.is_file():
        return None
    try:
        raw = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None
    return cast(dict[str, object], raw)


def _sorted_unique_refs(refs: list[str]) -> list[str]:
    return sorted({r.replace("\\", "/") for r in refs if _is_run_relative_path(r)})


@dataclass(frozen=True)
class _Node:
    node_id: str
    node_type: str
    label: str
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class _Edge:
    src: str
    dst: str
    edge_type: str
    confidence: float
    confidence_calibrated: float
    evidence_level: str
    evidence_refs: tuple[str, ...]


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


@dataclass(frozen=True)
class GraphStage:
    max_nodes: int = 1200
    max_edges: int = 4000

    @property
    def name(self) -> str:
        return "graph"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "graph"
        out_json = stage_dir / "comm_graph.json"
        out_dot = stage_dir / "comm_graph.dot"
        out_mmd = stage_dir / "comm_graph.mmd"
        out_ref_json = stage_dir / "reference_graph.json"
        out_comm_json = stage_dir / "communication_graph.json"

        _assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(stage_dir, out_json)
        _assert_under_dir(stage_dir, out_dot)
        _assert_under_dir(stage_dir, out_mmd)
        _assert_under_dir(stage_dir, out_ref_json)
        _assert_under_dir(stage_dir, out_comm_json)

        surfaces_path = run_dir / "stages" / "surfaces" / "surfaces.json"
        endpoints_path = run_dir / "stages" / "endpoints" / "endpoints.json"
        attribution_path = run_dir / "stages" / "attribution" / "attribution.json"
        inventory_path = run_dir / "stages" / "inventory" / "inventory.json"

        limitations: list[str] = []
        evidence_paths = [
            _rel_to_run_dir(run_dir, out_json),
            _rel_to_run_dir(run_dir, out_dot),
            _rel_to_run_dir(run_dir, out_mmd),
            _rel_to_run_dir(run_dir, out_ref_json),
            _rel_to_run_dir(run_dir, out_comm_json),
        ]

        for dep in (surfaces_path, endpoints_path, attribution_path, inventory_path):
            if dep.is_file():
                evidence_paths.append(_rel_to_run_dir(run_dir, dep))

        surfaces_obj = _load_json_object(surfaces_path)
        endpoints_obj = _load_json_object(endpoints_path)
        attribution_obj = _load_json_object(attribution_path)

        if surfaces_obj is None:
            limitations.append(
                "Surfaces output missing or invalid: stages/surfaces/surfaces.json"
            )
        if endpoints_obj is None:
            limitations.append(
                "Endpoints output missing or invalid: stages/endpoints/endpoints.json"
            )
        if attribution_obj is None:
            limitations.append(
                "Attribution output missing or invalid: stages/attribution/attribution.json"
            )

        nodes: dict[str, _Node] = {}
        edges: dict[tuple[str, str, str], _Edge] = {}
        component_refs: dict[str, set[str]] = {}
        component_nodes: set[str] = set()
        surface_nodes: set[str] = set()

        def upsert_node(
            *, node_type: str, value: str, label: str, refs: list[str]
        ) -> str:
            node_value = _safe_node_value(value)
            node_id = f"{node_type}:{node_value}"
            node_label = _safe_ascii_label(label)
            node_refs = tuple(_sorted_unique_refs(refs))
            existing = nodes.get(node_id)
            if existing is None:
                nodes[node_id] = _Node(
                    node_id=node_id,
                    node_type=node_type,
                    label=node_label,
                    evidence_refs=node_refs,
                )
                return node_id
            merged_refs = tuple(sorted(set(existing.evidence_refs) | set(node_refs)))
            merged_label = existing.label if existing.label != "unknown" else node_label
            nodes[node_id] = _Node(
                node_id=node_id,
                node_type=node_type,
                label=merged_label,
                evidence_refs=merged_refs,
            )
            return node_id

        def upsert_edge(
            *, src: str, dst: str, edge_type: str, confidence: float, refs: list[str]
        ) -> None:
            key = (src, dst, edge_type)
            edge_refs = tuple(_sorted_unique_refs(refs))
            observation = "static_reference"
            confidence_clamped = _clamp01(confidence)
            existing = edges.get(key)
            if existing is None:
                edges[key] = _Edge(
                    src=src,
                    dst=dst,
                    edge_type=edge_type,
                    confidence=confidence_clamped,
                    confidence_calibrated=calibrated_confidence(
                        confidence=confidence_clamped,
                        observation=observation,
                        evidence_refs=list(edge_refs),
                    ),
                    evidence_level=evidence_level(observation, list(edge_refs)),
                    evidence_refs=edge_refs,
                )
                return
            merged_refs = tuple(sorted(set(existing.evidence_refs) | set(edge_refs)))
            merged_confidence = max(existing.confidence, confidence_clamped)
            edges[key] = _Edge(
                src=src,
                dst=dst,
                edge_type=edge_type,
                confidence=merged_confidence,
                confidence_calibrated=calibrated_confidence(
                    confidence=merged_confidence,
                    observation=observation,
                    evidence_refs=list(merged_refs),
                ),
                evidence_level=evidence_level(observation, list(merged_refs)),
                evidence_refs=merged_refs,
            )

        surfaces_any = None if surfaces_obj is None else surfaces_obj.get("surfaces")
        if isinstance(surfaces_any, list):
            for surface_any in cast(list[object], surfaces_any):
                if not isinstance(surface_any, dict):
                    continue
                surface = cast(dict[str, object], surface_any)
                component_any = surface.get("component")
                surface_type_any = surface.get("surface_type")
                confidence_any = surface.get("confidence")
                refs_any = surface.get("evidence_refs")
                if not isinstance(component_any, str) or not component_any:
                    continue
                if not isinstance(surface_type_any, str) or not surface_type_any:
                    continue
                confidence = (
                    float(confidence_any)
                    if isinstance(confidence_any, (int, float))
                    else 0.5
                )
                surface_refs: list[str] = []
                if isinstance(refs_any, list):
                    surface_refs = [
                        cast(str, x)
                        for x in cast(list[object], refs_any)
                        if _is_run_relative_path(x)
                    ]

                component_id = upsert_node(
                    node_type="component",
                    value=component_any,
                    label=component_any,
                    refs=surface_refs,
                )
                component_nodes.add(component_id)
                component_refs.setdefault(component_id, set()).update(surface_refs)

                surface_label = f"{surface_type_any}:{component_any}"
                surface_id = upsert_node(
                    node_type="surface",
                    value=surface_label,
                    label=surface_label,
                    refs=surface_refs,
                )
                surface_nodes.add(surface_id)

                upsert_edge(
                    src=component_id,
                    dst=surface_id,
                    edge_type="exposes",
                    confidence=confidence,
                    refs=surface_refs,
                )
        elif surfaces_obj is not None:
            limitations.append("Surfaces output missing list field: surfaces")

        unknown_component_id: str | None = None
        endpoints_any = (
            None if endpoints_obj is None else endpoints_obj.get("endpoints")
        )
        if isinstance(endpoints_any, list):
            for endpoint_any in cast(list[object], endpoints_any):
                if not isinstance(endpoint_any, dict):
                    continue
                endpoint = cast(dict[str, object], endpoint_any)
                endpoint_type_any = endpoint.get("type")
                value_any = endpoint.get("value")
                confidence_any = endpoint.get("confidence")
                refs_any = endpoint.get("evidence_refs")
                if not isinstance(endpoint_type_any, str) or not endpoint_type_any:
                    continue
                if not isinstance(value_any, str) or not value_any:
                    continue

                endpoint_confidence = (
                    float(confidence_any)
                    if isinstance(confidence_any, (int, float))
                    else 0.5
                )
                endpoint_refs: list[str] = []
                if isinstance(refs_any, list):
                    endpoint_refs = [
                        cast(str, x)
                        for x in cast(list[object], refs_any)
                        if _is_run_relative_path(x)
                    ]

                endpoint_label = f"{endpoint_type_any}:{value_any}"
                endpoint_id = upsert_node(
                    node_type="endpoint",
                    value=endpoint_label,
                    label=endpoint_label,
                    refs=endpoint_refs,
                )

                candidate_components: list[str] = []
                ref_set = set(endpoint_refs)
                if ref_set:
                    for component_id in sorted(component_nodes):
                        comp_refs = component_refs.get(component_id, set())
                        if comp_refs and ref_set.intersection(comp_refs):
                            candidate_components.append(component_id)

                if candidate_components:
                    for component_id in candidate_components:
                        upsert_edge(
                            src=component_id,
                            dst=endpoint_id,
                            edge_type="references",
                            confidence=endpoint_confidence,
                            refs=endpoint_refs,
                        )
                    continue

                if surface_nodes:
                    surface_id = sorted(surface_nodes)[0]
                    upsert_edge(
                        src=surface_id,
                        dst=endpoint_id,
                        edge_type="references",
                        confidence=min(0.5, endpoint_confidence),
                        refs=endpoint_refs,
                    )
                    limitations.append(
                        "Some endpoints could not be mapped to a component; linked from first deterministic surface node"
                    )
                else:
                    if unknown_component_id is None:
                        unknown_component_id = upsert_node(
                            node_type="component",
                            value="unknown",
                            label="unknown",
                            refs=[],
                        )
                        component_nodes.add(unknown_component_id)
                    upsert_edge(
                        src=unknown_component_id,
                        dst=endpoint_id,
                        edge_type="references",
                        confidence=min(0.4, endpoint_confidence),
                        refs=endpoint_refs,
                    )
                    limitations.append(
                        "Some endpoints could not be mapped to a component or surface; linked from component:unknown"
                    )
        elif endpoints_obj is not None:
            limitations.append("Endpoints output missing list field: endpoints")

        claims_any = None if attribution_obj is None else attribution_obj.get("claims")
        vendor_nodes: list[str] = []
        if isinstance(claims_any, list):
            for claim_any in cast(list[object], claims_any):
                if not isinstance(claim_any, dict):
                    continue
                claim = cast(dict[str, object], claim_any)
                claim_type_any = claim.get("claim_type")
                value_any = claim.get("value")
                confidence_any = claim.get("confidence")
                refs_any = claim.get("evidence_refs")
                if claim_type_any not in {"vendor", "product", "version"}:
                    continue
                if not isinstance(value_any, str) or not value_any:
                    continue
                claim_refs: list[str] = []
                if isinstance(refs_any, list):
                    claim_refs = [
                        cast(str, x)
                        for x in cast(list[object], refs_any)
                        if _is_run_relative_path(x)
                    ]
                confidence = (
                    float(confidence_any)
                    if isinstance(confidence_any, (int, float))
                    else 0.3
                )
                vendor_label = f"{claim_type_any}:{value_any}"
                vendor_id = upsert_node(
                    node_type="vendor",
                    value=vendor_label,
                    label=vendor_label,
                    refs=claim_refs,
                )
                vendor_nodes.append(vendor_id)

                for component_id in sorted(component_nodes):
                    upsert_edge(
                        src=component_id,
                        dst=vendor_id,
                        edge_type="attributed_to",
                        confidence=min(0.45, confidence),
                        refs=claim_refs,
                    )
        elif attribution_obj is not None:
            limitations.append("Attribution output missing list field: claims")

        node_items = sorted(
            nodes.values(),
            key=lambda n: (n.node_type, n.node_id, n.label),
        )
        edge_items = sorted(
            edges.values(),
            key=lambda e: (e.edge_type, e.src, e.dst, -e.confidence, e.evidence_refs),
        )

        if len(node_items) > int(self.max_nodes):
            limitations.append(
                f"Graph node count reached max_nodes cap ({int(self.max_nodes)}); additional nodes were skipped"
            )
            kept_ids = {n.node_id for n in node_items[: int(self.max_nodes)]}
            node_items = node_items[: int(self.max_nodes)]
            edge_items = [
                e for e in edge_items if e.src in kept_ids and e.dst in kept_ids
            ]
        if len(edge_items) > int(self.max_edges):
            limitations.append(
                f"Graph edge count reached max_edges cap ({int(self.max_edges)}); additional edges were skipped"
            )
            edge_items = edge_items[: int(self.max_edges)]

        node_payload: list[dict[str, JsonValue]] = [
            {
                "id": node.node_id,
                "type": node.node_type,
                "label": node.label,
                "evidence_refs": cast(
                    list[JsonValue], cast(list[object], list(node.evidence_refs))
                ),
            }
            for node in node_items
        ]
        edge_payload: list[dict[str, JsonValue]] = [
            {
                "src": edge.src,
                "dst": edge.dst,
                "edge_type": edge.edge_type,
                "confidence": _clamp01(edge.confidence),
                "confidence_calibrated": edge.confidence_calibrated,
                "evidence_level": edge.evidence_level,
                "observation": "static_reference",
                "evidence_refs": cast(
                    list[JsonValue], cast(list[object], list(edge.evidence_refs))
                ),
            }
            for edge in edge_items
        ]

        summary: dict[str, JsonValue] = {
            "nodes": len(node_payload),
            "edges": len(edge_payload),
            "components": len([n for n in node_items if n.node_type == "component"]),
            "endpoints": len([n for n in node_items if n.node_type == "endpoint"]),
            "surfaces": len([n for n in node_items if n.node_type == "surface"]),
            "vendors": len([n for n in node_items if n.node_type == "vendor"]),
            "source_artifacts": cast(
                list[JsonValue],
                cast(list[object], sorted(set(evidence_paths[5:]))),
            ),
            "classification": "candidate",
            "observation": "static_reference",
        }

        status: StageStatus = "ok"
        if not node_payload or not edge_payload or surfaces_obj is None:
            status = "partial"

        graph_payload: dict[str, JsonValue] = {
            "status": status,
            "nodes": cast(list[JsonValue], cast(list[object], node_payload)),
            "edges": cast(list[JsonValue], cast(list[object], edge_payload)),
            "summary": summary,
            "limitations": cast(
                list[JsonValue],
                cast(list[object], sorted(set(limitations))),
            ),
            "note": "Static-first communication graph inferred from prior artifacts; edges indicate static references and inferred ownership only, not runtime communication.",
        }

        comm_summary: dict[str, JsonValue] = {
            "nodes": 0,
            "edges": 0,
            "components": 0,
            "endpoints": 0,
            "surfaces": 0,
            "vendors": 0,
            "source_artifacts": cast(list[JsonValue], cast(list[object], [])),
            "classification": "candidate",
            "observation": "runtime_communication",
        }
        communication_payload: dict[str, JsonValue] = {
            "status": "partial",
            "nodes": cast(list[JsonValue], cast(list[object], [])),
            "edges": cast(list[JsonValue], cast(list[object], [])),
            "summary": comm_summary,
            "limitations": cast(
                list[JsonValue],
                cast(
                    list[object],
                    [
                        "Runtime communication evidence not available; communication graph is currently empty and deterministic"
                    ],
                ),
            ),
            "note": "Observed communication graph is runtime-evidence driven and may remain empty until runtime signals are available.",
        }

        _ = out_json.write_text(
            json.dumps(graph_payload, indent=2, sort_keys=True, ensure_ascii=True)
            + "\n",
            encoding="utf-8",
        )
        _ = out_ref_json.write_text(
            json.dumps(graph_payload, indent=2, sort_keys=True, ensure_ascii=True)
            + "\n",
            encoding="utf-8",
        )
        _ = out_comm_json.write_text(
            json.dumps(
                communication_payload, indent=2, sort_keys=True, ensure_ascii=True
            )
            + "\n",
            encoding="utf-8",
        )

        dot_lines: list[str] = ["digraph comm_graph {"]
        for node in node_items:
            dot_lines.append(
                f'  "{_dot_escape(node.node_id)}" [label="{_dot_escape(node.label)}", shape="box"];'
            )
        for edge in edge_items:
            dot_lines.append(
                f'  "{_dot_escape(edge.src)}" -> "{_dot_escape(edge.dst)}" [label="{_dot_escape(edge.edge_type)}:{edge.confidence:.2f}"];'
            )
        dot_lines.append("}")
        _ = out_dot.write_text("\n".join(dot_lines) + "\n", encoding="utf-8")

        mermaid_lines: list[str] = ["flowchart TD"]
        mermaid_alias: dict[str, str] = {}
        for idx, node in enumerate(node_items, start=1):
            alias = f"n{idx:04d}"
            mermaid_alias[node.node_id] = alias
            mermaid_lines.append(
                f'  {alias}["{_safe_ascii_label(node.label, max_len=60)}"]'
            )
        for edge in edge_items:
            src_alias = mermaid_alias.get(edge.src)
            dst_alias = mermaid_alias.get(edge.dst)
            if not src_alias or not dst_alias:
                continue
            mermaid_lines.append(
                f"  {src_alias} -->|{edge.edge_type}:{edge.confidence:.2f}| {dst_alias}"
            )
        _ = out_mmd.write_text("\n".join(mermaid_lines) + "\n", encoding="utf-8")

        details: dict[str, JsonValue] = {
            "summary": summary,
            "nodes": cast(list[JsonValue], cast(list[object], node_payload)),
            "edges": cast(list[JsonValue], cast(list[object], edge_payload)),
            "graph_json": _rel_to_run_dir(run_dir, out_json),
            "graph_dot": _rel_to_run_dir(run_dir, out_dot),
            "graph_mermaid": _rel_to_run_dir(run_dir, out_mmd),
            "reference_graph_json": _rel_to_run_dir(run_dir, out_ref_json),
            "communication_graph_json": _rel_to_run_dir(run_dir, out_comm_json),
            "evidence": cast(
                list[JsonValue],
                cast(
                    list[object],
                    [{"path": p} for p in sorted(set(evidence_paths))],
                ),
            ),
            "classification": "candidate",
            "observation": "static_reference",
        }

        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
