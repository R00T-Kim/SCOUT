from __future__ import annotations

import json
import importlib.util
from pathlib import Path
from typing import Protocol, cast

from aiedge.confidence_caps import EVIDENCE_LEVELS, STATIC_ONLY_CAP
from aiedge.attack_surface import (
    ATTACK_SURFACE_BENCHMARK_FIXTURE_RELATIVE_PATH,
    ATTACK_SURFACE_METRICS_RELATIVE_PATH,
    AttackSurfaceStage,
)
from aiedge.run import create_run, run_subset
from aiedge.stage import StageContext


class _BenchmarkModule(Protocol):
    def load_attack_surface_benchmark_fixture(self) -> dict[str, object]: ...

    def load_attack_surface_metrics_baseline(self) -> dict[str, object]: ...


def _load_benchmark_module() -> _BenchmarkModule:
    module_path = Path(__file__).resolve().parent / "attack_surface_benchmark.py"
    spec = importlib.util.spec_from_file_location(
        "attack_surface_benchmark", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load attack_surface_benchmark helper module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return cast(_BenchmarkModule, cast(object, module))


def test_benchmark_fixture_contract() -> None:
    benchmark = _load_benchmark_module()
    fixture = benchmark.load_attack_surface_benchmark_fixture()

    assert fixture["schema_version"] == 1
    assert fixture["source"] == "ref.md"

    categories = cast(list[object], fixture["categories"])
    assert categories

    label_obj = cast(dict[str, object], fixture["labels"])
    positive_obj = cast(dict[str, object], label_obj["positive"])
    negative_obj = cast(dict[str, object], label_obj["negative"])

    endpoint_candidates = cast(list[object], positive_obj["endpoint_candidates"])
    assert endpoint_candidates
    endpoint_tuples: list[tuple[str, str]] = []
    for item_any in endpoint_candidates:
        item = cast(dict[str, object], item_any)
        endpoint_type = cast(str, item["type"])
        endpoint_value = cast(str, item["value"])
        assert endpoint_type
        assert endpoint_value
        endpoint_tuples.append((endpoint_type, endpoint_value))
    assert endpoint_tuples == sorted(endpoint_tuples, key=lambda x: (x[0], x[1]))

    promotion_labels = cast(list[object], positive_obj["promotion_labels"])
    promotion_tuples: list[tuple[str, str]] = []
    for item_any in promotion_labels:
        item = cast(dict[str, object], item_any)
        promotion_tuples.append((cast(str, item["type"]), cast(str, item["value"])))
    assert promotion_tuples == sorted(promotion_tuples, key=lambda x: (x[0], x[1]))

    noise_labels = cast(list[object], negative_obj["noise_tokens"])
    assert noise_labels == ["*.ko", "accountmsg.*", "authority.*", "config*.*"]


def test_benchmark_metrics_baseline_contract() -> None:
    benchmark = _load_benchmark_module()
    baseline = benchmark.load_attack_surface_metrics_baseline()

    assert baseline["schema_version"] == 1
    assert (
        baseline["fixture"]
        == "tests/fixtures/attack_surface_accuracy/benchmark_fixture.json"
    )

    metrics = cast(dict[str, object], baseline["metrics"])
    expected_metric_keys = [
        "duplicate_ratio",
        "promotion_precision",
        "promotion_recall",
        "static_only_ratio",
        "taxonomy_precision",
        "taxonomy_recall",
    ]
    assert sorted(metrics.keys()) == expected_metric_keys

    for key in expected_metric_keys:
        value = metrics[key]
        assert isinstance(value, (int, float))
        assert 0.0 <= float(value) <= 1.0

    calibration = cast(dict[str, object], baseline["calibration"])
    assert calibration["mode"] == "rule_based"
    assert calibration["dataset"] == "benchmark_fixture_labels"
    assert calibration["supports_probability_calibration"] is False


def _ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    input_dir = run_dir / "input"
    logs_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    input_dir.mkdir(parents=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


def _read_json_obj(path: Path) -> dict[str, object]:
    raw = cast(object, json.loads(path.read_text(encoding="utf-8")))
    assert isinstance(raw, dict)
    return cast(dict[str, object], raw)


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _fixture_endpoint_tuples(entries: list[object]) -> list[tuple[str, str]]:
    tuples: list[tuple[str, str]] = []
    for entry_any in entries:
        entry = cast(dict[str, object], entry_any)
        endpoint_type = cast(str, entry["type"])
        endpoint_value = cast(str, entry["value"])
        tuples.append((endpoint_type, endpoint_value))
    return tuples


def _metric_float(metrics: dict[str, object], key: str) -> float:
    value = metrics[key]
    assert isinstance(value, (int, float))
    return float(value)


def _seed_attack_surface_inputs(run_dir: Path) -> None:
    _write_json(
        run_dir / "stages" / "surfaces" / "surfaces.json",
        {
            "status": "ok",
            "surfaces": [
                {
                    "surface_type": "web",
                    "component": "httpd",
                    "confidence": 0.8,
                    "classification": "candidate",
                    "observation": "static_reference",
                    "evidence_refs": ["stages/inventory/svc/httpd.conf"],
                }
            ],
        },
    )
    _write_json(
        run_dir / "stages" / "endpoints" / "endpoints.json",
        {
            "status": "ok",
            "endpoints": [
                {
                    "type": "url",
                    "value": "https://api.example.test/v1",
                    "confidence": 0.8,
                    "classification": "candidate",
                    "observation": "static_reference",
                    "evidence_refs": ["stages/inventory/svc/httpd.conf"],
                },
                {
                    "type": "domain",
                    "value": "orphan.example.test",
                    "confidence": 0.7,
                    "classification": "candidate",
                    "observation": "static_reference",
                    "evidence_refs": ["stages/inventory/svc/orphan.conf"],
                },
            ],
        },
    )
    _write_json(
        run_dir / "stages" / "attribution" / "attribution.json",
        {
            "status": "ok",
            "claims": [
                {
                    "claim_type": "vendor",
                    "value": "acme",
                    "confidence": 0.9,
                    "evidence_refs": ["stages/attribution/claims.txt"],
                }
            ],
        },
    )
    reference_graph_payload: dict[str, object] = {
        "status": "ok",
        "nodes": [
            {
                "id": "component:httpd",
                "type": "component",
                "label": "httpd",
                "evidence_refs": ["stages/inventory/svc/httpd.conf"],
            },
            {
                "id": "surface:web:httpd",
                "type": "surface",
                "label": "web:httpd",
                "evidence_refs": ["stages/inventory/svc/httpd.conf"],
            },
            {
                "id": "endpoint:url:https://api.example.test/v1",
                "type": "endpoint",
                "label": "url:https://api.example.test/v1",
                "evidence_refs": ["stages/inventory/svc/httpd.conf"],
            },
            {
                "id": "endpoint:domain:orphan.example.test",
                "type": "endpoint",
                "label": "domain:orphan.example.test",
                "evidence_refs": ["stages/inventory/svc/orphan.conf"],
            },
        ],
        "edges": [
            {
                "src": "component:httpd",
                "dst": "surface:web:httpd",
                "edge_type": "exposes",
                "confidence": 0.8,
                "evidence_refs": ["stages/inventory/svc/httpd.conf"],
            },
            {
                "src": "component:httpd",
                "dst": "endpoint:url:https://api.example.test/v1",
                "edge_type": "references",
                "confidence": 0.8,
                "evidence_refs": ["stages/inventory/svc/httpd.conf"],
            },
            {
                "src": "surface:web:httpd",
                "dst": "endpoint:domain:orphan.example.test",
                "edge_type": "references",
                "confidence": 0.7,
                "evidence_refs": ["stages/inventory/svc/orphan.conf"],
            },
        ],
    }
    _write_json(
        run_dir / "stages" / "graph" / "reference_graph.json",
        reference_graph_payload,
    )
    _write_json(
        run_dir / "stages" / "graph" / "comm_graph.json",
        reference_graph_payload,
    )
    _write_json(
        run_dir / "stages" / "graph" / "communication_graph.json",
        {
            "status": "ok",
            "nodes": [
                {
                    "id": "component:httpd",
                    "type": "component",
                    "label": "httpd",
                    "evidence_refs": ["stages/inventory/svc/httpd.conf"],
                },
                {
                    "id": "surface:web:httpd",
                    "type": "surface",
                    "label": "web:httpd",
                    "evidence_refs": ["stages/inventory/svc/httpd.conf"],
                },
                {
                    "id": "endpoint:url:https://api.example.test/v1",
                    "type": "endpoint",
                    "label": "url:https://api.example.test/v1",
                    "evidence_refs": ["stages/inventory/svc/httpd.conf"],
                },
            ],
            "edges": [
                {
                    "src": "component:httpd",
                    "dst": "surface:web:httpd",
                    "edge_type": "exposes",
                    "confidence": 0.8,
                    "evidence_refs": ["stages/inventory/svc/httpd.conf"],
                },
                {
                    "src": "component:httpd",
                    "dst": "endpoint:url:https://api.example.test/v1",
                    "edge_type": "runtime_flow",
                    "confidence": 0.8,
                    "evidence_refs": ["stages/inventory/svc/httpd.conf"],
                },
            ],
        },
    )


def test_attack_surface_stage_deterministic_with_unknowns(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    _seed_attack_surface_inputs(ctx.run_dir)

    stage = AttackSurfaceStage()
    out1 = stage.run(ctx)
    assert out1.status == "ok"
    out_path = ctx.run_dir / "stages" / "attack_surface" / "attack_surface.json"
    text1 = out_path.read_text(encoding="utf-8")

    out2 = stage.run(ctx)
    assert out2.status == "ok"
    text2 = out_path.read_text(encoding="utf-8")
    assert text1 == text2

    payload = _read_json_obj(out_path)
    items_any = payload.get("attack_surface")
    assert isinstance(items_any, list)
    items = cast(list[object], items_any)
    assert items

    promoted_endpoints: list[tuple[str, str]] = []

    for item_any in items:
        assert isinstance(item_any, dict)
        item = cast(dict[str, object], item_any)
        source_graph = item.get("source_graph")
        assert source_graph == "communication_graph"
        confidence_calibrated = item.get("confidence_calibrated")
        evidence_level_value = item.get("evidence_level")
        observation = item.get("observation")
        assert isinstance(confidence_calibrated, (int, float))
        assert 0.0 <= float(confidence_calibrated) <= 1.0
        assert isinstance(evidence_level_value, str)
        assert evidence_level_value in EVIDENCE_LEVELS
        if observation == "static_reference":
            assert float(confidence_calibrated) <= STATIC_ONLY_CAP
        refs_any = item.get("evidence_refs")
        assert isinstance(refs_any, list) and refs_any
        for ref in cast(list[object], refs_any):
            assert isinstance(ref, str)
            assert not ref.startswith("/")
        endpoint_any = item.get("endpoint")
        assert isinstance(endpoint_any, dict)
        endpoint = cast(dict[str, object], endpoint_any)
        endpoint_type = endpoint.get("type")
        endpoint_value = endpoint.get("value")
        assert isinstance(endpoint_type, str)
        assert isinstance(endpoint_value, str)
        promoted_endpoints.append((endpoint_type, endpoint_value))

    assert ("domain", "orphan.example.test") not in promoted_endpoints

    non_promoted_any = payload.get("non_promoted")
    assert isinstance(non_promoted_any, list)
    non_promoted = cast(list[object], non_promoted_any)
    assert non_promoted

    first_non_promoted = cast(dict[str, object], non_promoted[0])
    np_reason = first_non_promoted.get("reason")
    assert isinstance(np_reason, str) and "Reference-only linkage" in np_reason
    np_endpoint_any = first_non_promoted.get("endpoint")
    assert isinstance(np_endpoint_any, dict)
    np_endpoint = cast(dict[str, object], np_endpoint_any)
    assert np_endpoint.get("type") == "domain"
    assert np_endpoint.get("value") == "orphan.example.test"
    np_refs_any = first_non_promoted.get("evidence_refs")
    assert isinstance(np_refs_any, list) and np_refs_any
    for ref in cast(list[object], np_refs_any):
        assert isinstance(ref, str)
        assert not ref.startswith("/")

    unknowns_any = payload.get("unknowns")
    assert isinstance(unknowns_any, list)
    unknowns = cast(list[object], unknowns_any)
    assert not unknowns


def test_run_subset_with_attack_surface_populates_report(tmp_path: Path) -> None:
    firmware = tmp_path / "firmware.bin"
    _ = firmware.write_bytes(b"attack-surface-subset")
    info = create_run(
        str(firmware),
        case_id="case-attack-surface-subset",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _seed_attack_surface_inputs(info.run_dir)

    rep = run_subset(info, ["attack_surface"], time_budget_s=10, no_llm=True)
    assert [r.stage for r in rep.stage_results] == ["attack_surface"]

    report = _read_json_obj(info.report_json_path)
    attack_surface_obj = report.get("attack_surface")
    assert isinstance(attack_surface_obj, dict)
    section = cast(dict[str, object], attack_surface_obj)
    assert section.get("status") == "ok"
    items_any = section.get("attack_surface")
    assert isinstance(items_any, list)
    assert items_any


def test_attack_surface_metrics_non_regression_gate(tmp_path: Path) -> None:
    benchmark = _load_benchmark_module()
    fixture = benchmark.load_attack_surface_benchmark_fixture()
    baseline = benchmark.load_attack_surface_metrics_baseline()

    ctx = _ctx(tmp_path)
    _write_json(
        ctx.run_dir / ATTACK_SURFACE_BENCHMARK_FIXTURE_RELATIVE_PATH,
        fixture,
    )

    labels = cast(dict[str, object], fixture["labels"])
    positive = cast(dict[str, object], labels["positive"])
    endpoint_candidates = _fixture_endpoint_tuples(
        cast(list[object], positive["endpoint_candidates"])
    )
    promotion_labels = _fixture_endpoint_tuples(
        cast(list[object], positive["promotion_labels"])
    )
    promotion_set = set(promotion_labels)
    non_promoted_candidates = [
        ep for ep in endpoint_candidates if ep not in promotion_set
    ]
    assert len(non_promoted_candidates) == 2
    non_promoted_endpoint = non_promoted_candidates[0]

    endpoint_records: list[dict[str, object]] = []
    for endpoint_type, endpoint_value in endpoint_candidates:
        endpoint_records.append(
            {
                "type": endpoint_type,
                "value": endpoint_value,
                "confidence": 0.8,
                "classification": "candidate",
                "observation": "static_reference",
                "evidence_refs": [
                    f"stages/inventory/endpoints/{endpoint_type}_{endpoint_value.replace(':', '_').replace('/', '_')}.txt"
                ],
            }
        )

    _write_json(
        ctx.run_dir / "stages" / "surfaces" / "surfaces.json",
        {
            "status": "ok",
            "surfaces": [
                {
                    "surface_type": "web",
                    "component": "httpd",
                    "confidence": 0.9,
                    "classification": "candidate",
                    "observation": "static_reference",
                    "evidence_refs": ["stages/inventory/svc/httpd.conf"],
                }
            ],
        },
    )
    _write_json(
        ctx.run_dir / "stages" / "endpoints" / "endpoints.json",
        {
            "status": "ok",
            "endpoints": endpoint_records,
        },
    )
    _write_json(
        ctx.run_dir / "stages" / "attribution" / "attribution.json",
        {
            "status": "ok",
            "claims": [
                {
                    "claim_type": "vendor",
                    "value": "acme",
                    "confidence": 0.9,
                    "evidence_refs": ["stages/attribution/claims.txt"],
                }
            ],
        },
    )

    comm_nodes: list[dict[str, object]] = [
        {
            "id": "component:httpd",
            "type": "component",
            "label": "httpd",
            "evidence_refs": ["stages/inventory/svc/httpd.conf"],
        },
        {
            "id": "surface:web:httpd",
            "type": "surface",
            "label": "web:httpd",
            "evidence_refs": ["stages/inventory/svc/httpd.conf"],
        },
    ]
    comm_edges: list[dict[str, object]] = [
        {
            "src": "component:httpd",
            "dst": "surface:web:httpd",
            "edge_type": "exposes",
            "confidence": 0.9,
            "evidence_refs": ["stages/inventory/svc/httpd.conf"],
        }
    ]
    for endpoint_type, endpoint_value in promotion_labels:
        endpoint_node_id = f"endpoint:{endpoint_type}:{endpoint_value}"
        endpoint_label = f"{endpoint_type}:{endpoint_value}"
        comm_nodes.append(
            {
                "id": endpoint_node_id,
                "type": "endpoint",
                "label": endpoint_label,
                "evidence_refs": ["stages/runtime/flow.log"],
            }
        )
        comm_edges.append(
            {
                "src": "component:httpd",
                "dst": endpoint_node_id,
                "edge_type": "runtime_flow",
                "confidence": 0.9,
                "evidence_refs": ["stages/runtime/flow.log"],
            }
        )

    ref_nodes = list(comm_nodes)
    ref_edges = list(comm_edges)
    non_promoted_type, non_promoted_value = non_promoted_endpoint
    non_promoted_node_id = f"endpoint:{non_promoted_type}:{non_promoted_value}"
    ref_nodes.append(
        {
            "id": non_promoted_node_id,
            "type": "endpoint",
            "label": f"{non_promoted_type}:{non_promoted_value}",
            "evidence_refs": ["stages/inventory/svc/httpd.conf"],
        }
    )
    ref_edges.append(
        {
            "src": "surface:web:httpd",
            "dst": non_promoted_node_id,
            "edge_type": "references",
            "confidence": 0.8,
            "evidence_refs": ["stages/inventory/svc/httpd.conf"],
        }
    )

    _write_json(
        ctx.run_dir / "stages" / "graph" / "communication_graph.json",
        {"status": "ok", "nodes": comm_nodes, "edges": comm_edges},
    )
    _write_json(
        ctx.run_dir / "stages" / "graph" / "reference_graph.json",
        {"status": "ok", "nodes": ref_nodes, "edges": ref_edges},
    )
    _write_json(
        ctx.run_dir / "stages" / "graph" / "comm_graph.json",
        {"status": "ok", "nodes": ref_nodes, "edges": ref_edges},
    )

    outcome = AttackSurfaceStage().run(ctx)
    assert outcome.status == "ok"

    metrics_payload = _read_json_obj(ctx.run_dir / ATTACK_SURFACE_METRICS_RELATIVE_PATH)
    assert metrics_payload["schema_version"] == 1
    assert metrics_payload["fixture"] == ATTACK_SURFACE_BENCHMARK_FIXTURE_RELATIVE_PATH

    metrics = cast(dict[str, object], metrics_payload["metrics"])
    baseline_metrics = cast(dict[str, object], baseline["metrics"])

    assert _metric_float(metrics, "taxonomy_precision") >= _metric_float(
        baseline_metrics, "taxonomy_precision"
    )
    assert _metric_float(metrics, "taxonomy_recall") >= _metric_float(
        baseline_metrics, "taxonomy_recall"
    )
    assert _metric_float(metrics, "promotion_precision") >= _metric_float(
        baseline_metrics, "promotion_precision"
    )
    assert _metric_float(metrics, "promotion_recall") >= _metric_float(
        baseline_metrics, "promotion_recall"
    )
    assert _metric_float(metrics, "static_only_ratio") <= _metric_float(
        baseline_metrics, "static_only_ratio"
    )
    assert _metric_float(metrics, "duplicate_ratio") <= _metric_float(
        baseline_metrics, "duplicate_ratio"
    )
