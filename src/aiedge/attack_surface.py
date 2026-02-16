from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .confidence_caps import calibrated_confidence, evidence_level
from .policy import AIEdgePolicyViolation
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus


ATTACK_SURFACE_BENCHMARK_FIXTURE_RELATIVE_PATH = (
    "benchmarks/attack_surface_accuracy/benchmark_fixture.json"
)
ATTACK_SURFACE_METRICS_RELATIVE_PATH = (
    "stages/attack_surface/attack_surface_metrics.json"
)


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
    return sorted({x.replace("\\", "/") for x in refs if _is_run_relative_path(x)})


def _surface_label(surface_type: str, component: str) -> str:
    return f"{surface_type}:{component}"


def _parse_endpoint_label(label: str) -> tuple[str, str] | None:
    if ":" not in label:
        return None
    endpoint_type, endpoint_value = label.split(":", 1)
    endpoint_type = endpoint_type.strip()
    endpoint_value = endpoint_value.strip()
    if not endpoint_type or not endpoint_value:
        return None
    return endpoint_type, endpoint_value


def _as_claim_confidence(claim: dict[str, JsonValue]) -> float:
    confidence_any = claim.get("confidence")
    if isinstance(confidence_any, (int, float)):
        return float(confidence_any)
    return 0.0


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return _clamp01(float(numerator) / float(denominator))


def _extract_fixture_endpoint_tuples(items_any: object) -> list[tuple[str, str]]:
    if not isinstance(items_any, list):
        return []
    tuples: set[tuple[str, str]] = set()
    for item_any in cast(list[object], items_any):
        if not isinstance(item_any, dict):
            continue
        item = cast(dict[str, object], item_any)
        endpoint_type = item.get("type")
        endpoint_value = item.get("value")
        if not isinstance(endpoint_type, str) or not endpoint_type:
            continue
        if not isinstance(endpoint_value, str) or not endpoint_value:
            continue
        tuples.add((endpoint_type, endpoint_value))
    return sorted(tuples, key=lambda x: (x[0], x[1]))


def _extract_metric_endpoint_tuples(
    items: list[dict[str, JsonValue]],
) -> list[tuple[str, str]]:
    tuples: set[tuple[str, str]] = set()
    for item in items:
        endpoint_any = item.get("endpoint")
        if not isinstance(endpoint_any, dict):
            continue
        endpoint = cast(dict[str, object], endpoint_any)
        endpoint_type = endpoint.get("type")
        endpoint_value = endpoint.get("value")
        if not isinstance(endpoint_type, str) or not endpoint_type:
            continue
        if not isinstance(endpoint_value, str) or not endpoint_value:
            continue
        tuples.add((endpoint_type, endpoint_value))
    return sorted(tuples, key=lambda x: (x[0], x[1]))


def _build_attack_surface_metrics_payload(
    *,
    benchmark_fixture_rel: str,
    endpoint_records: list[_EndpointRecord],
    attack_surface: list[dict[str, JsonValue]],
    non_promoted: list[dict[str, JsonValue]],
    benchmark_fixture: dict[str, object],
    evidence_refs: list[str],
) -> dict[str, JsonValue] | None:
    labels_any = benchmark_fixture.get("labels")
    if not isinstance(labels_any, dict):
        return None
    labels = cast(dict[str, object], labels_any)
    positive_any = labels.get("positive")
    if not isinstance(positive_any, dict):
        return None
    positive = cast(dict[str, object], positive_any)

    endpoint_candidates = _extract_fixture_endpoint_tuples(
        positive.get("endpoint_candidates")
    )
    promotion_labels = _extract_fixture_endpoint_tuples(
        positive.get("promotion_labels")
    )

    if not endpoint_candidates:
        return None

    extracted_endpoint_list = sorted(
        [(e.endpoint_type, e.endpoint_value) for e in endpoint_records],
        key=lambda x: (x[0], x[1]),
    )
    extracted_endpoint_set = set(extracted_endpoint_list)
    endpoint_candidate_set = set(endpoint_candidates)
    promotion_label_set = set(promotion_labels)
    promoted_set = set(_extract_metric_endpoint_tuples(attack_surface))
    static_only_set = set(_extract_metric_endpoint_tuples(non_promoted))

    duplicate_ratio = _safe_ratio(
        len(extracted_endpoint_list) - len(extracted_endpoint_set),
        len(extracted_endpoint_list),
    )

    taxonomy_true_positive = sum(
        1 for endpoint in extracted_endpoint_set if endpoint in endpoint_candidate_set
    )
    promotion_true_positive = sum(
        1 for endpoint in promoted_set if endpoint in promotion_label_set
    )

    metrics: dict[str, JsonValue] = {
        "duplicate_ratio": duplicate_ratio,
        "promotion_precision": _safe_ratio(promotion_true_positive, len(promoted_set)),
        "promotion_recall": _safe_ratio(
            promotion_true_positive,
            len(promotion_label_set),
        ),
        "static_only_ratio": _safe_ratio(
            len(static_only_set), len(extracted_endpoint_set)
        ),
        "taxonomy_precision": _safe_ratio(
            taxonomy_true_positive,
            len(extracted_endpoint_set),
        ),
        "taxonomy_recall": _safe_ratio(
            taxonomy_true_positive,
            len(endpoint_candidate_set),
        ),
    }

    payload: dict[str, JsonValue] = {
        "schema_version": 1,
        "fixture": benchmark_fixture_rel,
        "metrics": cast(JsonValue, metrics),
        "calibration": {
            "mode": "rule_based",
            "dataset": "benchmark_fixture_labels",
            "supports_probability_calibration": False,
        },
        "evidence_refs": cast(
            list[JsonValue], cast(list[object], _sorted_unique_refs(evidence_refs))
        ),
    }
    return payload


def _write_attack_surface_metrics_artifact(
    *,
    run_dir: Path,
    stage_dir: Path,
    endpoint_records: list[_EndpointRecord],
    attack_surface: list[dict[str, JsonValue]],
    non_promoted: list[dict[str, JsonValue]],
    evidence_refs: list[str],
) -> str | None:
    benchmark_fixture_rel = ATTACK_SURFACE_BENCHMARK_FIXTURE_RELATIVE_PATH
    benchmark_fixture_path = run_dir / benchmark_fixture_rel
    benchmark_fixture = _load_json_object(benchmark_fixture_path)
    if benchmark_fixture is None:
        return None

    metrics_payload = _build_attack_surface_metrics_payload(
        benchmark_fixture_rel=benchmark_fixture_rel,
        endpoint_records=endpoint_records,
        attack_surface=attack_surface,
        non_promoted=non_promoted,
        benchmark_fixture=benchmark_fixture,
        evidence_refs=evidence_refs,
    )
    if metrics_payload is None:
        return None

    metrics_path = stage_dir / "attack_surface_metrics.json"
    _assert_under_dir(run_dir, metrics_path)
    _ = metrics_path.write_text(
        json.dumps(metrics_payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return ATTACK_SURFACE_METRICS_RELATIVE_PATH


def _attack_surface_item_sort_key(
    item: dict[str, JsonValue],
) -> tuple[str, str, str, str]:
    surface_any = item.get("surface")
    endpoint_any = item.get("endpoint")
    if not isinstance(surface_any, dict) or not isinstance(endpoint_any, dict):
        return ("", "", "", "")
    surface = cast(dict[str, object], surface_any)
    endpoint = cast(dict[str, object], endpoint_any)
    return (
        str(surface.get("surface_type", "")),
        str(surface.get("component", "")),
        str(endpoint.get("type", "")),
        str(endpoint.get("value", "")),
    )


def _unknown_item_sort_key(item: dict[str, JsonValue]) -> tuple[str, str]:
    endpoint_any = item.get("endpoint")
    if not isinstance(endpoint_any, dict):
        return ("", "")
    endpoint = cast(dict[str, object], endpoint_any)
    return (str(endpoint.get("type", "")), str(endpoint.get("value", "")))


@dataclass(frozen=True)
class _SurfaceRecord:
    surface_type: str
    component: str
    confidence: float
    refs: tuple[str, ...]


@dataclass(frozen=True)
class _EndpointRecord:
    endpoint_type: str
    endpoint_value: str
    confidence: float
    refs: tuple[str, ...]


@dataclass(frozen=True)
class _GraphNode:
    node_id: str
    node_type: str
    label: str
    refs: tuple[str, ...]


@dataclass(frozen=True)
class _GraphEdge:
    src: str
    dst: str
    edge_type: str
    refs: tuple[str, ...]


def _extract_graph_records(
    graph_obj: dict[str, object] | None,
    *,
    limitations: list[str],
    graph_name: str,
) -> tuple[dict[str, _GraphNode], list[_GraphEdge]]:
    graph_nodes: dict[str, _GraphNode] = {}
    graph_edges: list[_GraphEdge] = []
    if graph_obj is None:
        return graph_nodes, graph_edges

    nodes_any = graph_obj.get("nodes")
    if isinstance(nodes_any, list):
        for node_any in cast(list[object], nodes_any):
            if not isinstance(node_any, dict):
                continue
            node = cast(dict[str, object], node_any)
            node_id_any = node.get("id")
            node_type_any = node.get("type")
            label_any = node.get("label")
            refs_any = node.get("evidence_refs")
            if not isinstance(node_id_any, str) or not node_id_any:
                continue
            if not isinstance(node_type_any, str) or not node_type_any:
                continue
            if not isinstance(label_any, str) or not label_any:
                continue
            node_refs: list[str] = []
            if isinstance(refs_any, list):
                node_refs = [
                    cast(str, r)
                    for r in cast(list[object], refs_any)
                    if _is_run_relative_path(r)
                ]
            graph_nodes[node_id_any] = _GraphNode(
                node_id=node_id_any,
                node_type=node_type_any,
                label=label_any,
                refs=tuple(_sorted_unique_refs(node_refs)),
            )
    else:
        limitations.append(f"{graph_name} output missing list field: nodes")

    edges_any = graph_obj.get("edges")
    if isinstance(edges_any, list):
        for edge_any in cast(list[object], edges_any):
            if not isinstance(edge_any, dict):
                continue
            edge = cast(dict[str, object], edge_any)
            src_any = edge.get("src")
            dst_any = edge.get("dst")
            edge_type_any = edge.get("edge_type")
            refs_any = edge.get("evidence_refs")
            if not isinstance(src_any, str) or not src_any:
                continue
            if not isinstance(dst_any, str) or not dst_any:
                continue
            if not isinstance(edge_type_any, str) or not edge_type_any:
                continue
            edge_item_refs: list[str] = []
            if isinstance(refs_any, list):
                edge_item_refs = [
                    cast(str, r)
                    for r in cast(list[object], refs_any)
                    if _is_run_relative_path(r)
                ]
            graph_edges.append(
                _GraphEdge(
                    src=src_any,
                    dst=dst_any,
                    edge_type=edge_type_any,
                    refs=tuple(_sorted_unique_refs(edge_item_refs)),
                )
            )
    else:
        limitations.append(f"{graph_name} output missing list field: edges")

    return graph_nodes, graph_edges


def _derive_items_from_graph(
    *,
    surface_records: list[_SurfaceRecord],
    endpoint_by_key: dict[tuple[str, str], _EndpointRecord],
    attribution_payload: list[dict[str, JsonValue]],
    attribution_refs: list[str],
    graph_nodes: dict[str, _GraphNode],
    graph_edges: list[_GraphEdge],
    observation: str,
    edge_semantics: str,
    source_graph: str,
) -> tuple[list[dict[str, JsonValue]], set[tuple[str, str]]]:
    component_node_ids_by_label: dict[str, set[str]] = {}
    surface_node_ids_by_label: dict[str, set[str]] = {}
    endpoint_node_ids_by_key: dict[tuple[str, str], set[str]] = {}
    for node in sorted(
        graph_nodes.values(),
        key=lambda n: (n.node_type, n.label, n.node_id),
    ):
        if node.node_type == "component":
            component_node_ids_by_label.setdefault(node.label, set()).add(node.node_id)
            continue
        if node.node_type == "surface":
            surface_node_ids_by_label.setdefault(node.label, set()).add(node.node_id)
            continue
        if node.node_type == "endpoint":
            parsed = _parse_endpoint_label(node.label)
            if parsed is None:
                continue
            endpoint_node_ids_by_key.setdefault(parsed, set()).add(node.node_id)

    component_ids_by_surface_id: dict[str, set[str]] = {}
    endpoint_ids_by_component_id: dict[str, set[str]] = {}
    endpoint_ids_by_surface_id: dict[str, set[str]] = {}
    edge_refs_by_key: dict[tuple[str, str, str], tuple[str, ...]] = {}
    for edge in sorted(
        graph_edges,
        key=lambda e: (e.edge_type, e.src, e.dst, e.refs),
    ):
        edge_refs_by_key[(edge.src, edge.dst, edge.edge_type)] = edge.refs
        src_node = graph_nodes.get(edge.src)
        dst_node = graph_nodes.get(edge.dst)
        if src_node is None or dst_node is None:
            continue
        if edge.edge_type == "exposes":
            if src_node.node_type == "component" and dst_node.node_type == "surface":
                component_ids_by_surface_id.setdefault(dst_node.node_id, set()).add(
                    src_node.node_id
                )
            elif src_node.node_type == "surface" and dst_node.node_type == "component":
                component_ids_by_surface_id.setdefault(src_node.node_id, set()).add(
                    dst_node.node_id
                )
            continue
        if src_node.node_type == "component" and dst_node.node_type == "endpoint":
            endpoint_ids_by_component_id.setdefault(src_node.node_id, set()).add(
                dst_node.node_id
            )
            continue
        if src_node.node_type == "surface" and dst_node.node_type == "endpoint":
            endpoint_ids_by_surface_id.setdefault(src_node.node_id, set()).add(
                dst_node.node_id
            )

    attack_surface: list[dict[str, JsonValue]] = []
    item_keys_seen: set[tuple[str, str, str, str]] = set()
    linked_endpoint_keys: set[tuple[str, str]] = set()
    for surface in sorted(
        surface_records,
        key=lambda s: (s.surface_type, s.component, s.refs),
    ):
        surface_node_label = _surface_label(surface.surface_type, surface.component)
        surface_node_ids = sorted(
            surface_node_ids_by_label.get(surface_node_label, set())
        )
        component_node_ids = sorted(
            component_node_ids_by_label.get(surface.component, set())
        )
        for surface_node_id in surface_node_ids:
            component_node_ids.extend(
                sorted(component_ids_by_surface_id.get(surface_node_id, set()))
            )
        component_node_ids = sorted(set(component_node_ids))

        endpoint_node_ids: set[str] = set()
        for component_node_id in component_node_ids:
            endpoint_node_ids.update(
                endpoint_ids_by_component_id.get(component_node_id, set())
            )
        for surface_node_id in surface_node_ids:
            endpoint_node_ids.update(
                endpoint_ids_by_surface_id.get(surface_node_id, set())
            )

        for endpoint_node_id in sorted(endpoint_node_ids):
            endpoint_node = graph_nodes.get(endpoint_node_id)
            if endpoint_node is None or endpoint_node.node_type != "endpoint":
                continue
            parsed_endpoint = _parse_endpoint_label(endpoint_node.label)
            if parsed_endpoint is None:
                continue
            endpoint_type, endpoint_value = parsed_endpoint
            key = (
                surface.surface_type,
                surface.component,
                endpoint_type,
                endpoint_value,
            )
            if key in item_keys_seen:
                continue

            item_refs: list[str] = list(surface.refs)
            endpoint_record = endpoint_by_key.get((endpoint_type, endpoint_value))
            if endpoint_record is not None:
                item_refs.extend(endpoint_record.refs)
            item_refs.extend(endpoint_node.refs)

            for surface_node_id in surface_node_ids:
                surface_node = graph_nodes.get(surface_node_id)
                if surface_node is not None:
                    item_refs.extend(surface_node.refs)
            for component_node_id in component_node_ids:
                component_node = graph_nodes.get(component_node_id)
                if component_node is not None:
                    item_refs.extend(component_node.refs)
                for edge_type in sorted({e.edge_type for e in graph_edges}):
                    component_edge_refs = edge_refs_by_key.get(
                        (component_node_id, endpoint_node_id, edge_type)
                    )
                    if component_edge_refs is not None:
                        item_refs.extend(component_edge_refs)
            for surface_node_id in surface_node_ids:
                for edge_type in sorted({e.edge_type for e in graph_edges}):
                    surface_edge_refs = edge_refs_by_key.get(
                        (surface_node_id, endpoint_node_id, edge_type)
                    )
                    if surface_edge_refs is not None:
                        item_refs.extend(surface_edge_refs)
            for surface_node_id in surface_node_ids:
                for component_node_id in component_node_ids:
                    expose_edge_refs = edge_refs_by_key.get(
                        (component_node_id, surface_node_id, "exposes")
                    )
                    if expose_edge_refs is not None:
                        item_refs.extend(expose_edge_refs)
                    reverse_expose_edge_refs = edge_refs_by_key.get(
                        (surface_node_id, component_node_id, "exposes")
                    )
                    if reverse_expose_edge_refs is not None:
                        item_refs.extend(reverse_expose_edge_refs)

            item_refs.extend(attribution_refs)
            evidence_refs = _sorted_unique_refs(item_refs)
            if not evidence_refs:
                continue

            base_confidence = surface.confidence
            if endpoint_record is not None:
                base_confidence = max(base_confidence, endpoint_record.confidence)

            item_keys_seen.add(key)
            linked_endpoint_keys.add((endpoint_type, endpoint_value))
            item: dict[str, JsonValue] = {
                "surface": {
                    "surface_type": surface.surface_type,
                    "component": surface.component,
                },
                "endpoint": {
                    "type": endpoint_type,
                    "value": endpoint_value,
                },
                "edge_semantics": edge_semantics,
                "source_graph": source_graph,
                "confidence_calibrated": calibrated_confidence(
                    confidence=base_confidence,
                    observation=observation,
                    evidence_refs=evidence_refs,
                ),
                "evidence_level": evidence_level(observation, evidence_refs),
                "evidence_refs": cast(
                    list[JsonValue], cast(list[object], evidence_refs)
                ),
                "classification": "candidate",
                "observation": observation,
            }
            if attribution_payload:
                item["attribution_context"] = cast(
                    list[JsonValue], cast(list[object], attribution_payload)
                )
            attack_surface.append(item)

    return sorted(
        attack_surface, key=_attack_surface_item_sort_key
    ), linked_endpoint_keys


@dataclass(frozen=True)
class AttackSurfaceStage:
    max_items: int = 500
    max_unknowns: int = 200

    @property
    def name(self) -> str:
        return "attack_surface"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "attack_surface"
        out_json = stage_dir / "attack_surface.json"

        _assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(stage_dir, out_json)

        surfaces_path = run_dir / "stages" / "surfaces" / "surfaces.json"
        endpoints_path = run_dir / "stages" / "endpoints" / "endpoints.json"
        attribution_path = run_dir / "stages" / "attribution" / "attribution.json"
        communication_graph_path = (
            run_dir / "stages" / "graph" / "communication_graph.json"
        )
        reference_graph_path = run_dir / "stages" / "graph" / "reference_graph.json"
        legacy_graph_path = run_dir / "stages" / "graph" / "comm_graph.json"

        limitations: list[str] = []
        evidence: list[dict[str, JsonValue]] = []

        for dep in (
            surfaces_path,
            endpoints_path,
            attribution_path,
            communication_graph_path,
            reference_graph_path,
            legacy_graph_path,
        ):
            if dep.is_file():
                evidence.append({"path": _rel_to_run_dir(run_dir, dep)})

        surfaces_obj = _load_json_object(surfaces_path)
        endpoints_obj = _load_json_object(endpoints_path)
        attribution_obj = _load_json_object(attribution_path)
        communication_graph_obj = _load_json_object(communication_graph_path)
        reference_graph_obj = _load_json_object(reference_graph_path)
        reference_graph_source = reference_graph_path
        if reference_graph_obj is None:
            reference_graph_obj = _load_json_object(legacy_graph_path)
            reference_graph_source = legacy_graph_path

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
        if communication_graph_obj is None:
            limitations.append(
                "Communication graph output missing or invalid: stages/graph/communication_graph.json"
            )
        if reference_graph_obj is None:
            limitations.append(
                "Reference graph output missing or invalid: stages/graph/reference_graph.json or stages/graph/comm_graph.json"
            )

        surface_records: list[_SurfaceRecord] = []
        endpoint_records: list[_EndpointRecord] = []
        attribution_claims: list[dict[str, JsonValue]] = []
        communication_graph_nodes: dict[str, _GraphNode] = {}
        communication_graph_edges: list[_GraphEdge] = []
        reference_graph_nodes: dict[str, _GraphNode] = {}
        reference_graph_edges: list[_GraphEdge] = []

        surfaces_any = None if surfaces_obj is None else surfaces_obj.get("surfaces")
        if isinstance(surfaces_any, list):
            for surface_any in cast(list[object], surfaces_any):
                if not isinstance(surface_any, dict):
                    continue
                surface = cast(dict[str, object], surface_any)
                surface_type_any = surface.get("surface_type")
                component_any = surface.get("component")
                refs_any = surface.get("evidence_refs")
                confidence_any = surface.get("confidence")
                if not isinstance(surface_type_any, str) or not surface_type_any:
                    continue
                if not isinstance(component_any, str) or not component_any:
                    continue
                surface_confidence = (
                    float(confidence_any)
                    if isinstance(confidence_any, (int, float))
                    else 0.5
                )
                surface_refs: list[str] = []
                if isinstance(refs_any, list):
                    surface_refs = [
                        cast(str, r)
                        for r in cast(list[object], refs_any)
                        if _is_run_relative_path(r)
                    ]
                surface_records.append(
                    _SurfaceRecord(
                        surface_type=surface_type_any,
                        component=component_any,
                        confidence=max(0.0, min(1.0, surface_confidence)),
                        refs=tuple(_sorted_unique_refs(surface_refs)),
                    )
                )
        elif surfaces_obj is not None:
            limitations.append("Surfaces output missing list field: surfaces")

        endpoints_any = (
            None if endpoints_obj is None else endpoints_obj.get("endpoints")
        )
        if isinstance(endpoints_any, list):
            for endpoint_any in cast(list[object], endpoints_any):
                if not isinstance(endpoint_any, dict):
                    continue
                endpoint = cast(dict[str, object], endpoint_any)
                endpoint_type_any = endpoint.get("type")
                endpoint_value_any = endpoint.get("value")
                refs_any = endpoint.get("evidence_refs")
                confidence_any = endpoint.get("confidence")
                if not isinstance(endpoint_type_any, str) or not endpoint_type_any:
                    continue
                if not isinstance(endpoint_value_any, str) or not endpoint_value_any:
                    continue
                endpoint_confidence = (
                    float(confidence_any)
                    if isinstance(confidence_any, (int, float))
                    else 0.5
                )
                endpoint_refs: list[str] = []
                if isinstance(refs_any, list):
                    endpoint_refs = [
                        cast(str, r)
                        for r in cast(list[object], refs_any)
                        if _is_run_relative_path(r)
                    ]
                endpoint_records.append(
                    _EndpointRecord(
                        endpoint_type=endpoint_type_any,
                        endpoint_value=endpoint_value_any,
                        confidence=max(0.0, min(1.0, endpoint_confidence)),
                        refs=tuple(_sorted_unique_refs(endpoint_refs)),
                    )
                )
        elif endpoints_obj is not None:
            limitations.append("Endpoints output missing list field: endpoints")

        claims_any = None if attribution_obj is None else attribution_obj.get("claims")
        if isinstance(claims_any, list):
            for claim_any in cast(list[object], claims_any):
                if not isinstance(claim_any, dict):
                    continue
                claim = cast(dict[str, object], claim_any)
                claim_type_any = claim.get("claim_type")
                value_any = claim.get("value")
                confidence_any = claim.get("confidence")
                refs_any = claim.get("evidence_refs")
                if not isinstance(claim_type_any, str) or not claim_type_any:
                    continue
                if not isinstance(value_any, str) or not value_any:
                    continue
                confidence = (
                    float(confidence_any)
                    if isinstance(confidence_any, (int, float))
                    else 0.0
                )
                claim_refs: list[str] = []
                if isinstance(refs_any, list):
                    claim_refs = [
                        cast(str, r)
                        for r in cast(list[object], refs_any)
                        if _is_run_relative_path(r)
                    ]
                attribution_claims.append(
                    {
                        "claim_type": claim_type_any,
                        "value": value_any,
                        "confidence": max(0.0, min(1.0, confidence)),
                        "evidence_refs": cast(
                            list[JsonValue],
                            cast(list[object], _sorted_unique_refs(claim_refs)),
                        ),
                    }
                )
        elif attribution_obj is not None:
            limitations.append("Attribution output missing list field: claims")

        (
            communication_graph_nodes,
            communication_graph_edges,
        ) = _extract_graph_records(
            communication_graph_obj,
            limitations=limitations,
            graph_name="Communication graph",
        )
        (
            reference_graph_nodes,
            reference_graph_edges,
        ) = _extract_graph_records(
            reference_graph_obj,
            limitations=limitations,
            graph_name="Reference graph",
        )

        endpoint_by_key: dict[tuple[str, str], _EndpointRecord] = {}
        for endpoint in sorted(
            endpoint_records, key=lambda e: (e.endpoint_type, e.endpoint_value, e.refs)
        ):
            endpoint_by_key[(endpoint.endpoint_type, endpoint.endpoint_value)] = (
                endpoint
            )

        attribution_payload = sorted(
            attribution_claims,
            key=lambda c: (
                str(c.get("claim_type", "")),
                -_as_claim_confidence(c),
                str(c.get("value", "")),
            ),
        )
        attribution_refs: list[str] = []
        for claim in attribution_payload:
            refs_any = claim.get("evidence_refs")
            if isinstance(refs_any, list):
                attribution_refs.extend(
                    cast(str, r)
                    for r in cast(list[object], refs_any)
                    if _is_run_relative_path(r)
                )
        attribution_refs = _sorted_unique_refs(attribution_refs)

        attack_surface, linked_endpoint_keys = _derive_items_from_graph(
            surface_records=surface_records,
            endpoint_by_key=endpoint_by_key,
            attribution_payload=attribution_payload,
            attribution_refs=attribution_refs,
            graph_nodes=communication_graph_nodes,
            graph_edges=communication_graph_edges,
            observation="runtime_communication",
            edge_semantics="surface->component->endpoint via communication graph runtime semantics",
            source_graph="communication_graph",
        )

        reference_candidates, reference_linked_endpoint_keys = _derive_items_from_graph(
            surface_records=surface_records,
            endpoint_by_key=endpoint_by_key,
            attribution_payload=attribution_payload,
            attribution_refs=attribution_refs,
            graph_nodes=reference_graph_nodes,
            graph_edges=reference_graph_edges,
            observation="static_reference",
            edge_semantics="surface->component->endpoint via static graph references",
            source_graph=str(_rel_to_run_dir(run_dir, reference_graph_source)),
        )

        promoted_keys = {_attack_surface_item_sort_key(item) for item in attack_surface}
        non_promoted: list[dict[str, JsonValue]] = []
        for candidate in reference_candidates:
            if _attack_surface_item_sort_key(candidate) in promoted_keys:
                continue
            non_promoted_item = dict(candidate)
            non_promoted_item["reason"] = (
                "Reference-only linkage without runtime communication evidence"
            )
            non_promoted_item["promotion_status"] = "not_promoted"
            non_promoted.append(non_promoted_item)

        unknowns: list[dict[str, JsonValue]] = []
        all_endpoint_keys = sorted(
            {(e.endpoint_type, e.endpoint_value) for e in endpoint_records},
            key=lambda x: (x[0], x[1]),
        )
        for endpoint_type, endpoint_value in all_endpoint_keys:
            if (endpoint_type, endpoint_value) in linked_endpoint_keys:
                continue
            if (endpoint_type, endpoint_value) in reference_linked_endpoint_keys:
                continue
            unknown_refs: list[str] = []
            endpoint_record = endpoint_by_key.get((endpoint_type, endpoint_value))
            if endpoint_record is not None:
                unknown_refs.extend(endpoint_record.refs)
            for endpoint_node_id in sorted(
                set(communication_graph_nodes.keys()).intersection(
                    {
                        node_id
                        for node_id, node in communication_graph_nodes.items()
                        if node.node_type == "endpoint"
                        and _parse_endpoint_label(node.label)
                        == (endpoint_type, endpoint_value)
                    }
                )
            ):
                endpoint_node = communication_graph_nodes.get(endpoint_node_id)
                if endpoint_node is not None:
                    unknown_refs.extend(endpoint_node.refs)
            for endpoint_node_id in sorted(
                set(reference_graph_nodes.keys()).intersection(
                    {
                        node_id
                        for node_id, node in reference_graph_nodes.items()
                        if node.node_type == "endpoint"
                        and _parse_endpoint_label(node.label)
                        == (endpoint_type, endpoint_value)
                    }
                )
            ):
                endpoint_node = reference_graph_nodes.get(endpoint_node_id)
                if endpoint_node is not None:
                    unknown_refs.extend(endpoint_node.refs)
            endpoint_json_rel = _rel_to_run_dir(run_dir, endpoints_path)
            if _is_run_relative_path(endpoint_json_rel):
                unknown_refs.append(endpoint_json_rel)
            evidence_refs = _sorted_unique_refs(unknown_refs)
            if not evidence_refs:
                continue
            unknowns.append(
                {
                    "reason": "Endpoint exists but no communication-graph or reference-graph mapping path was found",
                    "endpoint": {"type": endpoint_type, "value": endpoint_value},
                    "evidence_refs": cast(
                        list[JsonValue], cast(list[object], evidence_refs)
                    ),
                    "classification": "candidate",
                    "observation": "static_reference",
                }
            )

        attack_surface = sorted(attack_surface, key=_attack_surface_item_sort_key)
        non_promoted = sorted(non_promoted, key=_attack_surface_item_sort_key)
        unknowns = sorted(unknowns, key=_unknown_item_sort_key)

        if len(attack_surface) > int(self.max_items):
            limitations.append(
                f"Attack-surface extraction reached max_items cap ({int(self.max_items)}); additional items were skipped"
            )
            attack_surface = attack_surface[: int(self.max_items)]

        if len(unknowns) > int(self.max_unknowns):
            limitations.append(
                f"Attack-surface extraction reached max_unknowns cap ({int(self.max_unknowns)}); additional unknown entries were skipped"
            )
            unknowns = unknowns[: int(self.max_unknowns)]

        if len(non_promoted) > int(self.max_items):
            limitations.append(
                f"Attack-surface extraction reached non_promoted cap ({int(self.max_items)}); additional items were skipped"
            )
            non_promoted = non_promoted[: int(self.max_items)]

        attack_surface_rel = _rel_to_run_dir(run_dir, out_json)
        metrics_rel = _write_attack_surface_metrics_artifact(
            run_dir=run_dir,
            stage_dir=stage_dir,
            endpoint_records=endpoint_records,
            attack_surface=attack_surface,
            non_promoted=non_promoted,
            evidence_refs=_sorted_unique_refs(
                [
                    _rel_to_run_dir(run_dir, surfaces_path),
                    _rel_to_run_dir(run_dir, endpoints_path),
                    _rel_to_run_dir(run_dir, attribution_path),
                    _rel_to_run_dir(run_dir, communication_graph_path),
                    _rel_to_run_dir(run_dir, reference_graph_source),
                    _rel_to_run_dir(
                        run_dir,
                        run_dir / ATTACK_SURFACE_BENCHMARK_FIXTURE_RELATIVE_PATH,
                    ),
                    attack_surface_rel,
                ]
            ),
        )

        summary: dict[str, JsonValue] = {
            "surfaces": len(surface_records),
            "endpoints": len(endpoint_records),
            "communication_graph_nodes": len(communication_graph_nodes),
            "communication_graph_edges": len(communication_graph_edges),
            "reference_graph_nodes": len(reference_graph_nodes),
            "reference_graph_edges": len(reference_graph_edges),
            "attack_surface_items": len(attack_surface),
            "non_promoted": len(non_promoted),
            "unknowns": len(unknowns),
            "classification": "candidate",
            "observation": "runtime_communication",
        }

        status: StageStatus = "ok"
        if not attack_surface:
            status = "partial"
        if (
            surfaces_obj is None
            or endpoints_obj is None
            or communication_graph_obj is None
            or reference_graph_obj is None
        ):
            status = "partial"

        payload: dict[str, JsonValue] = {
            "status": status,
            "summary": summary,
            "attack_surface": cast(list[JsonValue], cast(list[object], attack_surface)),
            "non_promoted": cast(list[JsonValue], cast(list[object], non_promoted)),
            "unknowns": cast(list[JsonValue], cast(list[object], unknowns)),
            "limitations": cast(
                list[JsonValue], cast(list[object], sorted(set(limitations)))
            ),
            "note": "Primary attack_surface is communication-first (runtime semantics). Static reference-only candidates are preserved in non_promoted for deterministic review.",
        }
        _ = out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        evidence.append({"path": attack_surface_rel})
        if metrics_rel is not None:
            evidence.append({"path": metrics_rel})
        details: dict[str, JsonValue] = {
            "summary": summary,
            "attack_surface": cast(list[JsonValue], cast(list[object], attack_surface)),
            "non_promoted": cast(list[JsonValue], cast(list[object], non_promoted)),
            "unknowns": cast(list[JsonValue], cast(list[object], unknowns)),
            "attack_surface_json": attack_surface_rel,
            "evidence": cast(
                list[JsonValue],
                cast(
                    list[object],
                    sorted(
                        {
                            cast(str, ev.get("path", ""))
                            for ev in evidence
                            if ev.get("path")
                        },
                    ),
                ),
            ),
            "classification": "candidate",
            "observation": "runtime_communication",
        }
        if metrics_rel is not None:
            details["attack_surface_metrics_json"] = metrics_rel
        details["evidence"] = cast(
            list[JsonValue],
            cast(
                list[object],
                [{"path": p} for p in cast(list[str], details["evidence"])],
            ),
        )

        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
