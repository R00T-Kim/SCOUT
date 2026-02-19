from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from aiedge.confidence_caps import EVIDENCE_LEVELS, STATIC_ONLY_CAP
from aiedge.graph import GraphStage
from aiedge.run import create_run, run_subset
from aiedge.stage import StageContext


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


def test_graph_stage_emits_deterministic_json_dot_and_mermaid(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    _write_json(
        ctx.run_dir / "stages" / "surfaces" / "surfaces.json",
        {
            "status": "ok",
            "surfaces": [
                {
                    "surface_type": "web",
                    "component": "httpd",
                    "confidence": 0.8,
                    "evidence_refs": ["stages/inventory/svc/httpd.conf"],
                    "classification": "candidate",
                    "observation": "static_reference",
                }
            ],
        },
    )
    _write_json(
        ctx.run_dir / "stages" / "endpoints" / "endpoints.json",
        {
            "status": "ok",
            "endpoints": [
                {
                    "type": "url",
                    "value": "https://api.example.test/v1",
                    "confidence": 0.82,
                    "classification": "candidate",
                    "observation": "static_reference",
                    "evidence_refs": ["stages/inventory/svc/httpd.conf"],
                }
            ],
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
                    "confidence": 0.88,
                    "evidence_refs": ["stages/attribution/claims.txt"],
                },
                {
                    "claim_type": "version",
                    "value": "1.2.3",
                    "confidence": 0.6,
                    "evidence_refs": ["stages/attribution/claims.txt"],
                },
            ],
        },
    )

    stage = GraphStage()
    out1 = stage.run(ctx)
    assert out1.status == "ok"

    graph_dir = ctx.run_dir / "stages" / "graph"
    graph_json = graph_dir / "comm_graph.json"
    graph_dot = graph_dir / "comm_graph.dot"
    graph_mmd = graph_dir / "comm_graph.mmd"
    reference_graph_json = graph_dir / "reference_graph.json"
    communication_graph_json = graph_dir / "communication_graph.json"
    communication_nodes_csv = graph_dir / "communication_graph.nodes.csv"
    communication_edges_csv = graph_dir / "communication_graph.edges.csv"
    communication_cypher = graph_dir / "communication_graph.cypher"
    communication_schema_cypher = graph_dir / "communication_graph.schema.cypher"
    communication_queries_cypher = graph_dir / "communication_graph.queries.cypher"
    communication_matrix_json = graph_dir / "communication_matrix.json"
    communication_matrix_csv = graph_dir / "communication_matrix.csv"
    assert graph_json.is_file()
    assert graph_dot.is_file()
    assert graph_mmd.is_file()
    assert reference_graph_json.is_file()
    assert communication_graph_json.is_file()
    assert communication_nodes_csv.is_file()
    assert communication_edges_csv.is_file()
    assert communication_cypher.is_file()
    assert communication_schema_cypher.is_file()
    assert communication_queries_cypher.is_file()
    assert communication_matrix_json.is_file()
    assert communication_matrix_csv.is_file()

    text_json_1 = graph_json.read_text(encoding="utf-8")
    text_dot_1 = graph_dot.read_text(encoding="utf-8")
    text_mmd_1 = graph_mmd.read_text(encoding="utf-8")
    text_ref_json_1 = reference_graph_json.read_text(encoding="utf-8")
    text_comm_json_1 = communication_graph_json.read_text(encoding="utf-8")
    nodes_csv_text_1 = communication_nodes_csv.read_text(encoding="utf-8")
    edges_csv_text_1 = communication_edges_csv.read_text(encoding="utf-8")
    cypher_text_1 = communication_cypher.read_text(encoding="utf-8")
    schema_cypher_text_1 = communication_schema_cypher.read_text(encoding="utf-8")
    queries_cypher_text_1 = communication_queries_cypher.read_text(encoding="utf-8")
    matrix_json_text_1 = communication_matrix_json.read_text(encoding="utf-8")
    matrix_csv_text_1 = communication_matrix_csv.read_text(encoding="utf-8")

    out2 = stage.run(ctx)
    assert out2.status == "ok"
    assert text_json_1 == graph_json.read_text(encoding="utf-8")
    assert text_dot_1 == graph_dot.read_text(encoding="utf-8")
    assert text_mmd_1 == graph_mmd.read_text(encoding="utf-8")
    assert text_ref_json_1 == reference_graph_json.read_text(encoding="utf-8")
    assert text_comm_json_1 == communication_graph_json.read_text(encoding="utf-8")
    assert nodes_csv_text_1 == communication_nodes_csv.read_text(encoding="utf-8")
    assert edges_csv_text_1 == communication_edges_csv.read_text(encoding="utf-8")
    assert cypher_text_1 == communication_cypher.read_text(encoding="utf-8")
    assert schema_cypher_text_1 == communication_schema_cypher.read_text(encoding="utf-8")
    assert queries_cypher_text_1 == communication_queries_cypher.read_text(encoding="utf-8")
    assert matrix_json_text_1 == communication_matrix_json.read_text(encoding="utf-8")
    assert matrix_csv_text_1 == communication_matrix_csv.read_text(encoding="utf-8")

    payload = _read_json_obj(graph_json)
    reference_payload = _read_json_obj(reference_graph_json)
    communication_payload = _read_json_obj(communication_graph_json)
    communication_matrix_payload = _read_json_obj(communication_matrix_json)
    assert payload.get("status") == "ok"
    assert payload == reference_payload
    nodes_any = payload.get("nodes")
    edges_any = payload.get("edges")
    assert isinstance(nodes_any, list)
    assert isinstance(edges_any, list)
    nodes = cast(list[object], nodes_any)
    edges = cast(list[object], edges_any)
    assert nodes
    assert edges

    node_ids: list[str] = []
    for node_any in nodes:
        assert isinstance(node_any, dict)
        node = cast(dict[str, object], node_any)
        node_id = node.get("id")
        node_type = node.get("type")
        refs_any = node.get("evidence_refs")
        assert isinstance(node_id, str) and ":" in node_id
        assert isinstance(node_type, str)
        assert node_type in {"component", "endpoint", "surface", "vendor"}
        assert isinstance(refs_any, list)
        for ref in cast(list[object], refs_any):
            assert isinstance(ref, str) and not ref.startswith("/")
        node_ids.append(node_id)
    assert node_ids == sorted(node_ids)

    edge_tuples: list[tuple[str, str, str]] = []
    edge_types: set[str] = set()
    for edge_any in edges:
        assert isinstance(edge_any, dict)
        edge = cast(dict[str, object], edge_any)
        src = edge.get("src")
        dst = edge.get("dst")
        edge_type = edge.get("edge_type")
        conf = edge.get("confidence")
        conf_calibrated = edge.get("confidence_calibrated")
        evidence_level_value = edge.get("evidence_level")
        observation = edge.get("observation")
        refs_any = edge.get("evidence_refs")
        assert isinstance(src, str) and src
        assert isinstance(dst, str) and dst
        assert isinstance(edge_type, str)
        assert edge_type in {"references", "exposes", "attributed_to"}
        assert isinstance(conf, (int, float))
        assert 0.0 <= float(conf) <= 1.0
        assert isinstance(conf_calibrated, (int, float))
        assert 0.0 <= float(conf_calibrated) <= 1.0
        assert isinstance(evidence_level_value, str)
        assert evidence_level_value in EVIDENCE_LEVELS
        assert observation == "static_reference"
        assert float(conf_calibrated) <= STATIC_ONLY_CAP
        assert isinstance(refs_any, list)
        edge_tuples.append((src, dst, edge_type))
        edge_types.add(edge_type)
    assert edge_tuples == sorted(edge_tuples, key=lambda x: (x[2], x[0], x[1]))
    assert edge_types == {"references", "exposes", "attributed_to"}

    assert communication_payload.get("status") == "partial"
    comm_nodes_any = communication_payload.get("nodes")
    comm_edges_any = communication_payload.get("edges")
    comm_summary_any = communication_payload.get("summary")
    assert isinstance(comm_nodes_any, list)
    assert isinstance(comm_edges_any, list)
    assert comm_nodes_any == []
    assert comm_edges_any == []
    assert isinstance(comm_summary_any, dict)
    comm_summary = cast(dict[str, object], comm_summary_any)
    assert comm_summary.get("observation") == "runtime_communication"
    assert comm_summary.get("nodes") == 0
    assert comm_summary.get("edges") == 0
    assert comm_summary.get("neo4j_schema_version") == "neo4j-comm-v2"
    assert isinstance(communication_matrix_payload.get("status"), str)
    assert isinstance(communication_matrix_payload.get("rows"), list)
    matrix_summary_any = communication_matrix_payload.get("summary")
    assert isinstance(matrix_summary_any, dict)
    matrix_summary = cast(dict[str, object], matrix_summary_any)
    assert matrix_summary.get("classification") == "candidate"
    assert matrix_summary.get("rows_dynamic") == 0
    assert matrix_summary.get("rows_exploit") == 0
    assert matrix_summary.get("rows_dynamic_exploit") == 0
    comm_matrix_summary_any = comm_summary.get("matrix")
    assert isinstance(comm_matrix_summary_any, dict)
    comm_matrix_summary = cast(dict[str, object], comm_matrix_summary_any)
    assert comm_matrix_summary.get("path_json") == "stages/graph/communication_matrix.json"
    assert comm_matrix_summary.get("path_csv") == "stages/graph/communication_matrix.csv"
    assert nodes_csv_text_1.startswith("id,type,label,evidence_refs\n")
    assert edges_csv_text_1.startswith(
        "src,dst,edge_type,confidence,confidence_calibrated,evidence_level,observation,evidence_badge,evidence_signals,dynamic_evidence_count,exploit_evidence_count,verified_chain_evidence_count,static_evidence_count,dynamic_exploit_chain,evidence_refs\n"
    )
    assert matrix_csv_text_1.startswith(
        "component_id,component_label,host,service_host,service_port,protocol,confidence,evidence_level,observation,evidence_badge,evidence_signals,dynamic_evidence_count,exploit_evidence_count,verified_chain_evidence_count,static_evidence_count,dynamic_exploit_chain,evidence_refs\n"
    )
    assert "communication" in cypher_text_1.lower()
    assert "neo4j-comm-v2" in schema_cypher_text_1
    assert "Query 0: one-click priority view" in queries_cypher_text_1
    assert "Query 1: dynamic+exploit evidence backed service paths" in queries_cypher_text_1

    assert text_dot_1.startswith("digraph comm_graph {")
    assert text_mmd_1.startswith("flowchart TD\n")


def test_run_subset_with_graph_populates_report(tmp_path: Path) -> None:
    firmware = tmp_path / "firmware.bin"
    _ = firmware.write_bytes(b"graph-subset")
    info = create_run(
        str(firmware),
        case_id="case-graph-subset",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    _write_json(
        info.run_dir / "stages" / "surfaces" / "surfaces.json",
        {
            "status": "ok",
            "surfaces": [
                {
                    "surface_type": "ssh",
                    "component": "dropbear",
                    "confidence": 0.7,
                    "evidence_refs": ["stages/inventory/svc/dropbear.conf"],
                    "classification": "candidate",
                    "observation": "static_reference",
                }
            ],
        },
    )
    _write_json(
        info.run_dir / "stages" / "endpoints" / "endpoints.json",
        {
            "status": "ok",
            "endpoints": [
                {
                    "type": "domain",
                    "value": "updates.example.test",
                    "confidence": 0.7,
                    "classification": "candidate",
                    "observation": "static_reference",
                    "evidence_refs": ["stages/inventory/svc/dropbear.conf"],
                }
            ],
        },
    )
    _write_json(
        info.run_dir / "stages" / "attribution" / "attribution.json",
        {
            "status": "ok",
            "claims": [
                {
                    "claim_type": "vendor",
                    "value": "acme",
                    "confidence": 0.8,
                    "evidence_refs": ["stages/attribution/claims.txt"],
                }
            ],
        },
    )

    rep = run_subset(info, ["graph"], time_budget_s=10, no_llm=True)
    assert [r.stage for r in rep.stage_results] == ["graph"]

    report = _read_json_obj(info.report_json_path)
    graph_obj = report.get("graph")
    assert isinstance(graph_obj, dict)
    graph_section = cast(dict[str, object], graph_obj)
    assert graph_section.get("status") == "ok"
    nodes_any = graph_section.get("nodes")
    edges_any = graph_section.get("edges")
    assert isinstance(nodes_any, list) and nodes_any
    assert isinstance(edges_any, list) and edges_any
