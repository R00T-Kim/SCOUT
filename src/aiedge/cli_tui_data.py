"""TUI data collection: snapshot building and candidate grouping."""

from __future__ import annotations

import re
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

from .cli_common import (
    _TUI_DYNAMIC_VALIDATION_REQUIRED_REFS,
    _TUI_VERIFIED_CHAIN_REF,
    _as_float,
    _as_int,
    _normalize_ref,
    _path_tail,
    _safe_ascii_label_for_comm,
    _safe_load_json_object,
    _safe_node_value,
    _short_text,
    _sorted_count_pairs,
)

# Re-export helpers used by cli_tui_render
__all__ = [
    "_collect_tui_chain_bundle_index",
    "_collect_tui_verifier_artifacts",
    "_candidate_evidence_refs",
    "_candidate_verification_signals",
    "_candidate_signal_badge",
    "_candidate_group_payload",
    "_collect_tui_candidate_groups",
    "_extract_service_node_value",
    "_service_endpoint",
    "_collect_runtime_communication_summary",
    "_count_bar",
    "_sorted_count_pairs",
    "_collect_tui_asset_inventory",
    "_collect_tui_threat_model",
    "_collect_tui_runtime_health",
    "_build_tui_snapshot",
    "_candidate_family_text",
    "_candidate_next_step_text",
]


def _collect_tui_chain_bundle_index(*, run_dir: Path) -> dict[str, str]:
    index: dict[str, str] = {}
    exploits_dir = run_dir / "exploits"
    if not exploits_dir.is_dir():
        return index

    for chain_dir in sorted(
        [
            path
            for path in exploits_dir.iterdir()
            if path.is_dir() and path.name.startswith("chain_")
        ],
        key=lambda path: path.name,
    ):
        bundle_path = chain_dir / "evidence_bundle.json"
        if not bundle_path.is_file():
            continue
        rel = bundle_path.resolve().relative_to(run_dir.resolve()).as_posix()
        chain_name = chain_dir.name
        chain_id = chain_name.removeprefix("chain_")
        if chain_id:
            index[chain_id] = rel
        index[chain_name] = rel

    return index


def _collect_tui_verifier_artifacts(*, run_dir: Path) -> dict[str, object]:
    dynamic_present: list[str] = []
    dynamic_missing: list[str] = []
    for ref in _TUI_DYNAMIC_VALIDATION_REQUIRED_REFS:
        if (run_dir / ref).is_file():
            dynamic_present.append(ref)
        else:
            dynamic_missing.append(ref)

    exploit_bundle_refs: list[str] = []
    exploits_dir = run_dir / "exploits"
    if exploits_dir.is_dir():
        for chain_dir in sorted(
            [
                path
                for path in exploits_dir.iterdir()
                if path.is_dir() and path.name.startswith("chain_")
            ],
            key=lambda path: path.name,
        ):
            bundle_path = chain_dir / "evidence_bundle.json"
            if bundle_path.is_file():
                exploit_bundle_refs.append(
                    bundle_path.resolve().relative_to(run_dir.resolve()).as_posix()
                )

    verified_chain_present = (run_dir / _TUI_VERIFIED_CHAIN_REF).is_file()
    refs: list[str] = []
    if verified_chain_present:
        refs.append(_TUI_VERIFIED_CHAIN_REF)
    refs.extend(dynamic_present)
    refs.extend(exploit_bundle_refs)

    return {
        "dynamic_required_refs": list(_TUI_DYNAMIC_VALIDATION_REQUIRED_REFS),
        "dynamic_present_refs": sorted(dynamic_present),
        "dynamic_missing_refs": sorted(dynamic_missing),
        "verified_chain_present": bool(verified_chain_present),
        "exploit_bundle_refs": sorted(exploit_bundle_refs),
        "all_refs": sorted(set(refs)),
    }


def _candidate_evidence_refs(
    item: dict[str, object],
    *,
    chain_bundle_index: dict[str, str],
    include_chain_bundles: bool = True,
) -> list[str]:
    refs_any = item.get("evidence_refs")
    refs = (
        {
            ref
            for ref in [_normalize_ref(ref) for ref in cast(list[object], refs_any)]
            if ref
        }
        if isinstance(refs_any, list)
        else set()
    )

    if include_chain_bundles:
        chain_id = _short_text(item.get("chain_id"))
        if chain_id and chain_id in chain_bundle_index:
            refs.add(chain_bundle_index[chain_id])

    return sorted(refs)


def _candidate_verification_signals(
    item: dict[str, object],
    *,
    chain_bundle_index: dict[str, str],
    verified_chain_present: bool,
) -> list[str]:
    refs = _candidate_evidence_refs(
        item,
        chain_bundle_index=chain_bundle_index,
    )
    signals: list[str] = []
    if any(ref.startswith("stages/dynamic_validation/") for ref in refs):
        signals.append("dynamic_validation")
    if any(
        ref.startswith("exploits/") and ref.endswith("/evidence_bundle.json")
        for ref in refs
    ):
        signals.append("exploit_bundle")
    if any(ref.startswith("verified_chain/") for ref in refs):
        signals.append("verified_chain")
    chain_id = _short_text(item.get("chain_id"))
    if chain_id:
        signals.append("chain_linked")
        if verified_chain_present:
            if "verified_chain" not in signals:
                signals.append("verified_chain")
    return signals


def _candidate_signal_badge(signals: list[str]) -> str:
    sig = set(signals)
    has_d = "dynamic_validation" in sig
    has_e = "exploit_bundle" in sig
    has_v = "verified_chain" in sig
    if has_d and has_e and has_v:
        return "D+E+V"
    if has_d and has_e:
        return "D+E"
    if has_v:
        return "V"
    if has_e:
        return "E"
    if has_d:
        return "D"
    if "chain_linked" in sig:
        return "C"
    return "S"


def _candidate_family_text(item: dict[str, object]) -> str:
    families_any = item.get("families")
    if isinstance(families_any, list):
        families = [x for x in cast(list[object], families_any) if isinstance(x, str)]
    else:
        families = []
    return ",".join(families[:3]) if families else "unknown"


def _candidate_next_step_text(item: dict[str, object]) -> str:
    plan_any = item.get("validation_plan")
    plans = (
        [x for x in cast(list[object], plan_any) if isinstance(x, str)]
        if isinstance(plan_any, list)
        else []
    )
    if not plans:
        fallback_any = item.get("analyst_next_steps")
        plans = (
            [x for x in cast(list[object], fallback_any) if isinstance(x, str)]
            if isinstance(fallback_any, list)
            else []
        )
    return _short_text(plans[0], max_len=220) if plans else ""


def _candidate_group_payload(item: dict[str, object]) -> dict[str, object]:
    family_text = _candidate_family_text(item)
    families_any = item.get("families")
    families = (
        [x for x in cast(list[object], families_any) if isinstance(x, str)]
        if isinstance(families_any, list)
        else []
    )
    if families:
        family_text = ",".join(families[:3])
    impacts_any = item.get("expected_impact")
    impacts = (
        [x for x in cast(list[object], impacts_any) if isinstance(x, str)]
        if isinstance(impacts_any, list)
        else []
    )
    plans = _candidate_next_step_text(item)

    attack = _short_text(item.get("attack_hypothesis"), max_len=240)
    impact = _short_text(impacts[0], max_len=240) if impacts else "unknown"
    next_step = _short_text(plans, max_len=240) if plans else ""

    score = _as_float(item.get("score"))
    priority = _short_text(item.get("priority"), max_len=16) or "unknown"
    source = _short_text(item.get("source"), max_len=16) or "unknown"
    path = item.get("path")
    path_signature = _path_tail(path, max_segments=2, max_len=60)
    sample_path = _path_tail(path, max_segments=5, max_len=84)
    candidate_id = item.get("candidate_id")
    return {
        "family": family_text,
        "source": source,
        "path": path,
        "path_signature": path_signature,
        "score": score,
        "priority": priority,
        "hypothesis": attack,
        "impact": impact,
        "next_step": next_step,
        "path_count": 1,
        "candidate_ids": (
            [cast(str, candidate_id)]
            if isinstance(item.get("candidate_id"), str)
            else []
        ),
        "max_score": score,
        "sample_paths": [sample_path] if sample_path else [],
        "representative_id": (
            cast(str, candidate_id) if isinstance(candidate_id, str) else ""
        ),
    }


def _collect_tui_candidate_groups(
    candidates: list[dict[str, object]],
) -> list[dict[str, object]]:
    groups: dict[tuple[str, str, str, str, str], dict[str, object]] = {}
    for item in candidates:
        payload = _candidate_group_payload(item)
        group_key = (
            cast(str, payload["priority"]),
            cast(str, payload["family"]),
            cast(str, payload["hypothesis"]),
            cast(str, payload["impact"]),
            cast(str, payload["source"]),
        )
        group = groups.get(group_key)
        if group is None:
            groups[group_key] = payload
            continue
        group["path_count"] = _as_int(group.get("path_count")) + 1
        group_sample_paths = cast(list[str], group.get("sample_paths", []))
        item_path = _path_tail(item.get("path"), max_segments=5, max_len=84)
        if item_path and item_path not in group_sample_paths:
            group_sample_paths.append(item_path)
            group["sample_paths"] = group_sample_paths[:3]
        current_max_score = _as_float(group.get("max_score"))
        candidate_score = _as_float(item.get("score"))
        if candidate_score > current_max_score:
            group["max_score"] = candidate_score
            group["hypothesis"] = _short_text(
                item.get("attack_hypothesis"), max_len=240
            )
            impacts_any = item.get("expected_impact")
            impacts = (
                [x for x in cast(list[object], impacts_any) if isinstance(x, str)]
                if isinstance(impacts_any, list)
                else []
            )
            group["impact"] = (
                _short_text(impacts[0], max_len=240)
                if impacts
                else _short_text(group.get("impact"), max_len=240)
            )
            next = _candidate_next_step_text(item)
            if next:
                group["next_step"] = next
        group_ids = cast(list[str], group.get("candidate_ids", []))
        candidate_id = item.get("candidate_id")
        if isinstance(candidate_id, str) and candidate_id not in group_ids:
            group_ids.append(candidate_id)
            group["candidate_ids"] = group_ids

    ordered = sorted(
        groups.values(),
        key=lambda g: (
            -_as_int(g.get("path_count")),
            -_as_float(g.get("max_score")),
            _short_text(g.get("priority"), max_len=16) or "unknown",
            _short_text(g.get("family"), max_len=24) or "",
            _short_text(g.get("hypothesis"), max_len=240) or "",
            _short_text(g.get("path_signature"), max_len=80) or "",
        ),
    )
    return ordered


def _extract_service_node_value(value: str) -> tuple[str, int, str]:
    value_text = value.strip()
    if value_text.startswith("service:"):
        value_text = value_text[len("service:") :]
    if "/" in value_text:
        service_part, protocol = value_text.rsplit("/", 1)
        proto = protocol.lower().strip() or "tcp"
    else:
        service_part = value_text
        proto = "tcp"
    if "]:" in service_part and service_part.startswith("["):
        host, rest = service_part.rsplit("]:", 1)
        host = host.strip("[]")
        if rest and rest.isdigit():
            port = int(rest)
        else:
            port = 0
        return host, port, proto
    if ":" in service_part:
        host, port_text = service_part.rsplit(":", 1)
        if port_text.isdigit():
            return host, int(port_text), proto
    return service_part, 0, proto


def _service_endpoint(host: object, port: object, protocol: object) -> str:
    service_host = _short_text(host, max_len=220)
    service_port = _as_int(port)
    service_protocol = _short_text(protocol, max_len=12).upper() or "TCP"
    if service_host and service_port > 0:
        return f"{service_host}:{service_port}/{service_protocol}"
    if service_host:
        return f"{service_host}/{service_protocol}"
    return service_protocol


def _count_bar(label: str, *, count: int, max_count: int, width: int = 24) -> str:
    if width <= 0:
        width = 24
    denom = max(1, max_count)
    filled = int(round((max(0, count) / float(denom)) * float(width)))
    filled = max(0, min(width, filled))
    bar = ("#" * filled) + ("-" * (width - filled))
    return f"{label:<6} |{bar}| {count}"


def _collect_runtime_communication_summary(*, run_dir: Path) -> dict[str, object]:
    matrix_path = run_dir / "stages" / "graph" / "communication_matrix.json"
    if matrix_path.is_file():
        matrix_payload = _safe_load_json_object(matrix_path)
        if matrix_payload:
            matrix_rows_any = matrix_payload.get("rows")
            summary_any = matrix_payload.get("summary")
            if isinstance(matrix_rows_any, list):
                matrix_rows: list[dict[str, object]] = []
                for row_any in matrix_rows_any:
                    if not isinstance(row_any, dict):
                        continue
                    row = cast(dict[str, object], row_any)
                    host = _safe_node_value(_short_text(row.get("host"), max_len=220))
                    service_host = _safe_node_value(
                        _short_text(row.get("service_host"), max_len=220)
                    )
                    if not service_host:
                        service_host = host
                    component_label = _short_text(
                        row.get("component_label"), max_len=80
                    ) or _short_text(row.get("component_id"), max_len=80)
                    service_port = _as_int(row.get("service_port"))
                    protocol = _short_text(row.get("protocol"), max_len=12) or "tcp"
                    if not host or not service_host:
                        continue
                    if not component_label:
                        component_label = "unmapped"
                    evidence_badge = (
                        _short_text(row.get("evidence_badge"), max_len=20) or "S"
                    )
                    evidence_signals_any = row.get("evidence_signals")
                    evidence_signals = (
                        [
                            _short_text(x, max_len=32)
                            for x in cast(list[object], evidence_signals_any)
                            if isinstance(x, str) and _short_text(x, max_len=32)
                        ]
                        if isinstance(evidence_signals_any, list)
                        else []
                    )
                    dynamic_exploit_chain = bool(
                        row.get("dynamic_exploit_chain", False)
                    )
                    matrix_rows.append(
                        {
                            "host": host,
                            "service_host": service_host,
                            "port": service_port,
                            "protocol": protocol,
                            "components": [component_label],
                            "component": component_label,
                            "confidence": row.get("confidence"),
                            "observation": row.get(
                                "observation", "runtime_communication"
                            ),
                            "evidence_badge": evidence_badge,
                            "evidence_signals": evidence_signals,
                            "dynamic_evidence_count": _as_int(
                                row.get("dynamic_evidence_count"), default=0
                            ),
                            "exploit_evidence_count": _as_int(
                                row.get("exploit_evidence_count"), default=0
                            ),
                            "verified_chain_evidence_count": _as_int(
                                row.get("verified_chain_evidence_count"), default=0
                            ),
                            "dynamic_exploit_chain": dynamic_exploit_chain,
                        }
                    )

                if matrix_rows:
                    host_components_map: dict[str, set[str]] = {}
                    host_service_map: dict[str, set[str]] = {}
                    protocol_counts: dict[str, int] = {}
                    for row_any in matrix_rows:
                        row = cast(dict[str, object], row_any)
                        row_host = _short_text(row.get("host"), max_len=220)
                        row_component = _short_text(row.get("component"), max_len=120)
                        row_service_host = _short_text(
                            row.get("service_host"), max_len=220
                        )
                        row_port = _as_int(row.get("port"))
                        row_protocol = (
                            _short_text(row.get("protocol"), max_len=12) or "tcp"
                        )
                        endpoint = _service_endpoint(
                            row_service_host, row_port, row_protocol
                        )
                        if row_host:
                            if row_component:
                                host_components_map.setdefault(row_host, set()).add(
                                    row_component
                                )
                            if endpoint:
                                host_service_map.setdefault(row_host, set()).add(
                                    endpoint
                                )
                            protocol_counts[row_protocol] = (
                                protocol_counts.get(row_protocol, 0) + 1
                            )
                    runtime_system_map: list[dict[str, object]] = []
                    host_component_counts: dict[str, int] = {}
                    host_service_counts: dict[str, int] = {}
                    for map_host in sorted(host_components_map):
                        components = sorted(host_components_map.get(map_host, set()))
                        services = sorted(host_service_map.get(map_host, set()))
                        host_component_counts[map_host] = len(components)
                        host_service_counts[map_host] = len(services)
                        runtime_system_map.append(
                            {
                                "host": map_host,
                                "components": components,
                                "services": services,
                                "component_count": len(components),
                                "service_count": len(services),
                            }
                        )
                    summary = {
                        "hosts": 0,
                        "services": 0,
                        "components": 0,
                        "artifacts": [
                            _path_tail(str(matrix_path), max_segments=4, max_len=90),
                        ],
                    }
                    if isinstance(summary_any, dict):
                        summary.update(
                            {
                                "hosts": _as_int(summary_any.get("hosts"), default=0),
                                "services": _as_int(
                                    summary_any.get("services"), default=0
                                ),
                                "components": _as_int(
                                    summary_any.get("components"), default=0
                                ),
                                "rows_dynamic": _as_int(
                                    summary_any.get("rows_dynamic"), default=0
                                ),
                                "rows_exploit": _as_int(
                                    summary_any.get("rows_exploit"), default=0
                                ),
                                "rows_verified_chain": _as_int(
                                    summary_any.get("rows_verified_chain"), default=0
                                ),
                                "rows_dynamic_exploit": _as_int(
                                    summary_any.get("rows_dynamic_exploit"), default=0
                                ),
                                "service_count_by_protocol": protocol_counts,
                                "host_service_counts": host_service_counts,
                                "host_component_counts": host_component_counts,
                                "runtime_system_map": cast(
                                    list[object], runtime_system_map
                                ),
                            }
                        )
                    return {
                        "available": True,
                        "status": _short_text(matrix_payload.get("status"), max_len=16)
                        or "partial",
                        "rows": cast(list[object], matrix_rows),
                        "summary": summary,
                    }

            return {
                "available": True,
                "status": _short_text(matrix_payload.get("status"), max_len=16)
                or "partial",
                "reason": "communication matrix empty",
                "rows": cast(list[object], []),
                "summary": {
                    "hosts": 0,
                    "services": 0,
                    "components": 0,
                    "rows_dynamic": 0,
                    "rows_exploit": 0,
                    "rows_verified_chain": 0,
                    "rows_dynamic_exploit": 0,
                    "service_count_by_protocol": {},
                    "host_service_counts": {},
                    "host_component_counts": {},
                    "runtime_system_map": [],
                    "artifacts": [
                        _path_tail(str(matrix_path), max_segments=4, max_len=90)
                    ],
                },
            }

    comm_path = run_dir / "stages" / "graph" / "communication_graph.json"
    if not comm_path.is_file():
        return {"available": False, "reason": "missing communication graph"}

    payload_any = _safe_load_json_object(comm_path)
    if not payload_any:
        return {"available": False, "reason": "communication graph invalid"}

    nodes_any = payload_any.get("nodes")
    edges_any = payload_any.get("edges")
    if not isinstance(nodes_any, list) or not isinstance(edges_any, list):
        return {"available": False, "reason": "communication graph incomplete"}

    nodes: dict[str, dict[str, object]] = {}
    for node_any in nodes_any:
        if not isinstance(node_any, dict):
            continue
        node = cast(dict[str, object], node_any)
        node_id = node.get("id")
        if not isinstance(node_id, str):
            continue
        nodes[node_id] = node

    host_services: dict[str, list[tuple[str, int, str]]] = {}
    component_hosts: dict[str, set[str]] = {}
    host_components: dict[str, set[str]] = {}
    protocol_counts: dict[str, int] = {}
    host_service_counts: dict[str, int] = {}
    runtime_system_map: list[dict[str, object]] = []
    for edge_any in edges_any:
        if not isinstance(edge_any, dict):
            continue
        edge = cast(dict[str, object], edge_any)
        edge_type = edge.get("edge_type")
        src = cast(
            str | None, edge.get("src") if isinstance(edge.get("src"), str) else None
        )
        dst = cast(
            str | None, edge.get("dst") if isinstance(edge.get("dst"), str) else None
        )
        if not src or not dst:
            continue
        if edge_type == "runtime_host_flow":
            src_node = nodes.get(src)
            dst_node = nodes.get(dst)
            if (
                src_node is not None
                and dst_node is not None
                and src_node.get("type") == "component"
                and dst_node.get("type") == "host"
            ):
                # Prior code referenced an undefined ``_safe_ascii_label``
                # (silenced with noqa: F821) -- route through the shared
                # ``_safe_ascii_label_for_comm`` helper which performs the
                # same ASCII label sanitization.
                comp = _safe_node_value(_safe_ascii_label_for_comm(src))
                host = _safe_node_value(_safe_ascii_label_for_comm(cast(str, dst)))
                component_hosts.setdefault(comp, set()).add(host)
                host_components.setdefault(host, set()).add(comp)
            continue
        if edge_type != "runtime_service_binding":
            continue
        src_node = nodes.get(src)
        dst_node = nodes.get(dst)
        if src_node is None or dst_node is None:
            continue
        if src_node.get("type") != "host" or dst_node.get("type") != "service":
            continue
        host_label = _safe_node_value(_short_text(src_node.get("label"), max_len=220))
        service_label = _short_text(dst_node.get("label"), max_len=220)
        host = (
            host_label.removeprefix("host:")
            if host_label.startswith("host:")
            else host_label
        )
        service_host, service_port, service_proto = _extract_service_node_value(
            str(service_label)
        )
        if not service_host and host:
            service_host = host
        service_proto = (service_proto or "tcp").lower()
        service_key = (service_host, service_port, service_proto)
        host_services.setdefault(host, []).append(service_key)
        protocol_counts[service_proto] = protocol_counts.get(service_proto, 0) + 1

    service_rows: list[dict[str, object]] = []
    for host, services in sorted(
        host_services.items(), key=lambda item: item[0].lower()
    ):
        unique_services = sorted(
            set(services), key=lambda item: (item[0], item[1], item[2])
        )
        host_service_counts[host] = len(unique_services)
        comp_names = sorted(host_components.get(host, set())) or ["unmapped"]
        seen: set[tuple[str, int, str]] = set()
        for service_host, service_port, service_proto in unique_services:
            if (service_host, service_port, service_proto) in seen:
                continue
            seen.add((service_host, service_port, service_proto))
            if not service_host:
                service_host = host
            service_rows.append(
                {
                    "host": host,
                    "service_host": service_host,
                    "port": service_port,
                    "protocol": service_proto,
                    "components": comp_names,
                }
            )
        if unique_services:
            runtime_system_map.append(
                {
                    "host": host,
                    "components": comp_names,
                    "services": sorted(
                        {
                            _service_endpoint(svc_host, svc_port, svc_proto)
                            for svc_host, svc_port, svc_proto in unique_services
                        }
                    ),
                    "component_count": len(comp_names),
                    "service_count": len(unique_services),
                }
            )

    return {
        "available": True,
        "status": _short_text(payload_any.get("status"), max_len=16) or "partial",
        "rows": cast(list[object], service_rows),
        "summary": {
            "hosts": len(host_services),
            "services": len(service_rows),
            "components": len(component_hosts),
            "rows_dynamic": 0,
            "rows_exploit": 0,
            "rows_verified_chain": 0,
            "rows_dynamic_exploit": 0,
            "service_count_by_protocol": protocol_counts,
            "host_service_counts": host_service_counts,
            "host_component_counts": {
                host: len(components) for host, components in host_components.items()
            },
            "runtime_system_map": cast(list[object], runtime_system_map),
            "artifacts": [
                _path_tail(str(comm_path), max_segments=4, max_len=90),
            ],
        },
    }


def _collect_tui_asset_inventory(
    *,
    run_dir: Path,
    candidates: list[dict[str, object]],
) -> dict[str, object]:
    inv_obj = _safe_load_json_object(
        run_dir / "stages" / "inventory" / "inventory.json"
    )
    endpoints_obj = _safe_load_json_object(
        run_dir / "stages" / "endpoints" / "endpoints.json"
    )
    ports_obj = _safe_load_json_object(
        run_dir / "stages" / "dynamic_validation" / "network" / "ports.json"
    )
    ifaces_obj = _safe_load_json_object(
        run_dir / "stages" / "dynamic_validation" / "network" / "interfaces.json"
    )

    inv_summary_any = inv_obj.get("summary")
    inv_summary = (
        cast(dict[str, object], inv_summary_any)
        if isinstance(inv_summary_any, dict)
        else {}
    )
    files = _as_int(inv_summary.get("files"))
    binaries = _as_int(inv_summary.get("binaries"))
    configs = _as_int(inv_summary.get("configs"))
    roots_scanned = _as_int(inv_summary.get("roots_scanned"))
    string_hits = _as_int(inv_summary.get("string_hits"))

    service_candidates_any = inv_obj.get("service_candidates")
    service_candidates = (
        cast(list[dict[str, object]], service_candidates_any)
        if isinstance(service_candidates_any, list)
        else []
    )
    service_kind_counts: dict[str, int] = {}
    daemon_rank: dict[str, tuple[float, str]] = {}
    daemon_paths: list[str] = []
    for candidate_any in service_candidates:
        if not isinstance(candidate_any, dict):
            continue
        candidate = cast(dict[str, object], candidate_any)
        kind = _short_text(candidate.get("kind"), max_len=24) or "unknown"
        name = _short_text(candidate.get("name"), max_len=40) or "unknown"
        confidence = _as_float(candidate.get("confidence"), default=0.0)
        service_kind_counts[kind] = service_kind_counts.get(kind, 0) + 1
        normalized_name = name.lower()
        include_in_daemon_rank = not (
            normalized_name.startswith(".")
            or normalized_name.startswith("readme")
            or normalized_name.startswith("depend")
        )
        existing = daemon_rank.get(name) if include_in_daemon_rank else None
        rel_path = ""
        evidence_any = candidate.get("evidence")
        if isinstance(evidence_any, list) and evidence_any:
            ev0 = evidence_any[0]
            if isinstance(ev0, dict):
                rel_path = _path_tail(ev0.get("path"), max_segments=6, max_len=96)
        if include_in_daemon_rank:
            if existing is None or confidence > existing[0]:
                daemon_rank[name] = (confidence, kind)
        if include_in_daemon_rank and rel_path and rel_path not in daemon_paths:
            daemon_paths.append(rel_path)

    top_daemons = [
        name
        for name, _ in sorted(
            daemon_rank.items(),
            key=lambda kv: (-float(kv[1][0]), kv[0]),
        )[:8]
    ]

    endpoints_any = endpoints_obj.get("endpoints")
    endpoints = (
        cast(list[dict[str, object]], endpoints_any)
        if isinstance(endpoints_any, list)
        else []
    )
    endpoint_type_counts: dict[str, int] = {}
    endpoint_protocol_counts: dict[str, int] = {}
    endpoint_port_counts: dict[str, int] = {}
    for endpoint_any in endpoints:
        if not isinstance(endpoint_any, dict):
            continue
        endpoint = cast(dict[str, object], endpoint_any)
        endpoint_type = _short_text(endpoint.get("type"), max_len=20) or "unknown"
        endpoint_type_counts[endpoint_type] = (
            endpoint_type_counts.get(endpoint_type, 0) + 1
        )
        value = _short_text(endpoint.get("value"), max_len=260)
        if not value:
            continue
        parsed = urlparse(value)
        if parsed.scheme:
            scheme = parsed.scheme.lower().strip()
            if scheme:
                endpoint_protocol_counts[scheme] = (
                    endpoint_protocol_counts.get(scheme, 0) + 1
                )
            try:
                parsed_port = parsed.port
            except ValueError:
                parsed_port = None
            if parsed_port is not None and 0 <= int(parsed_port) <= 65535:
                port_key = str(int(parsed_port))
                endpoint_port_counts[port_key] = (
                    endpoint_port_counts.get(port_key, 0) + 1
                )
            continue
        host_port = re.match(r"^[a-zA-Z0-9_.:-]+:(\d{1,5})$", value)
        if host_port:
            port_num = int(host_port.group(1))
            if 0 <= port_num <= 65535:
                port_key = str(port_num)
                endpoint_port_counts[port_key] = (
                    endpoint_port_counts.get(port_key, 0) + 1
                )

    ports_any = ports_obj.get("ports")
    ports = (
        cast(list[dict[str, object]], ports_any) if isinstance(ports_any, list) else []
    )
    ports_summary_any = ports_obj.get("summary")
    ports_summary = (
        cast(dict[str, object], ports_summary_any)
        if isinstance(ports_summary_any, dict)
        else {}
    )
    scan_strategy = _short_text(ports_obj.get("scan_strategy"), max_len=40)
    scanned_total = _as_int(ports_summary.get("scanned"))
    range_total = _as_int(ports_summary.get("range_total"))
    coverage_pct = _as_float(ports_summary.get("coverage_pct"))
    budget_hit = bool(ports_summary.get("budget_hit", False))
    dynamic_proto_counts: dict[str, int] = {}
    dynamic_state_counts: dict[str, int] = {}
    port_samples: list[str] = []
    open_ports_from_rows: list[str] = []
    for row_any in ports:
        if not isinstance(row_any, dict):
            continue
        row = cast(dict[str, object], row_any)
        port = _as_int(row.get("port"), default=-1)
        if port < 0:
            continue
        proto = _short_text(row.get("proto"), max_len=12).lower() or "tcp"
        state = _short_text(row.get("state"), max_len=20).lower() or "unknown"
        dynamic_proto_counts[proto] = dynamic_proto_counts.get(proto, 0) + 1
        dynamic_state_counts[state] = dynamic_state_counts.get(state, 0) + 1
        sample = f"{proto}/{port}({state})"
        if sample not in port_samples:
            port_samples.append(sample)
        if state == "open" and sample not in open_ports_from_rows:
            open_ports_from_rows.append(sample)

    if ports_summary:
        for key in ("open", "closed", "filtered", "error"):
            count = _as_int(ports_summary.get(key))
            if count > 0:
                dynamic_state_counts[key] = count
        if scanned_total > 0 and not dynamic_proto_counts:
            dynamic_proto_counts["tcp"] = scanned_total

    open_ports_any = ports_obj.get("open_ports")
    open_ports_numeric = (
        [int(x) for x in cast(list[object], open_ports_any) if isinstance(x, int)]
        if isinstance(open_ports_any, list)
        else []
    )
    open_ports = [f"tcp/{p}" for p in sorted(set(open_ports_numeric))]
    if not open_ports:
        open_ports = open_ports_from_rows

    interfaces_any = ifaces_obj.get("interfaces")
    interfaces = (
        cast(list[dict[str, object]], interfaces_any)
        if isinstance(interfaces_any, list)
        else []
    )
    interface_labels: list[str] = []
    for iface_any in interfaces:
        if not isinstance(iface_any, dict):
            continue
        iface = cast(dict[str, object], iface_any)
        ifname = _short_text(iface.get("ifname"), max_len=20) or "if"
        ipv4_any = iface.get("ipv4")
        ipv4s = (
            [
                _short_text(x, max_len=32)
                for x in cast(list[object], ipv4_any)
                if isinstance(x, str)
            ]
            if isinstance(ipv4_any, list)
            else []
        )
        if ipv4s:
            label = f"{ifname}:{','.join(ipv4s[:2])}"
        else:
            label = ifname
        if label not in interface_labels:
            interface_labels.append(label)

    candidate_paths: list[str] = []
    for item_any in candidates:
        if not isinstance(item_any, dict):
            continue
        item = cast(dict[str, object], item_any)
        candidate_path = _path_tail(item.get("path"), max_segments=6, max_len=104)
        if candidate_path and candidate_path not in candidate_paths:
            candidate_paths.append(candidate_path)

    return {
        "available": bool(inv_obj or endpoints_obj or ports_obj or ifaces_obj),
        "inventory_status": _short_text(inv_obj.get("status"), max_len=16) or "unknown",
        "files": files,
        "binaries": binaries,
        "configs": configs,
        "roots_scanned": roots_scanned,
        "string_hits": string_hits,
        "service_candidates": len(service_candidates),
        "service_kind_counts": service_kind_counts,
        "top_daemons": top_daemons,
        "service_paths": daemon_paths[:5],
        "endpoint_total": len(endpoints),
        "endpoint_type_counts": endpoint_type_counts,
        "endpoint_protocol_counts": endpoint_protocol_counts,
        "endpoint_port_counts": endpoint_port_counts,
        "target_ip": _short_text(ports_obj.get("target_ip"), max_len=32),
        "probed_ports": scanned_total if scanned_total > 0 else len(ports),
        "scan_range_total": range_total,
        "scan_coverage_pct": coverage_pct if coverage_pct > 0 else 0.0,
        "scan_budget_hit": budget_hit,
        "scan_strategy": scan_strategy,
        "open_ports": open_ports,
        "port_samples": port_samples[:8],
        "dynamic_protocol_counts": dynamic_proto_counts,
        "dynamic_state_counts": dynamic_state_counts,
        "interfaces": interface_labels[:5],
        "candidate_paths": candidate_paths[:5],
    }


def _collect_tui_threat_model(*, run_dir: Path) -> dict[str, object]:
    threat_obj = _safe_load_json_object(
        run_dir / "stages" / "threat_model" / "threat_model.json"
    )
    if not threat_obj:
        return {
            "available": False,
            "status": "unavailable",
            "threat_count": 0,
            "unknown_count": 0,
            "mitigation_count": 0,
            "assumption_count": 0,
            "attack_surface_items": 0,
            "category_counts": {},
            "top_threats": [],
            "limitations": [],
        }

    summary_any = threat_obj.get("summary")
    summary = (
        cast(dict[str, object], summary_any) if isinstance(summary_any, dict) else {}
    )
    threats_any = threat_obj.get("threats")
    threats = (
        cast(list[dict[str, object]], threats_any)
        if isinstance(threats_any, list)
        else []
    )
    unknowns_any = threat_obj.get("unknowns")
    unknowns = (
        cast(list[dict[str, object]], unknowns_any)
        if isinstance(unknowns_any, list)
        else []
    )
    mitigations_any = threat_obj.get("mitigations")
    mitigations = (
        cast(list[dict[str, object]], mitigations_any)
        if isinstance(mitigations_any, list)
        else []
    )
    assumptions_any = threat_obj.get("assumptions")
    assumptions = (
        cast(list[dict[str, object]], assumptions_any)
        if isinstance(assumptions_any, list)
        else []
    )
    limitations_any = threat_obj.get("limitations")
    limitations = (
        [x for x in cast(list[object], limitations_any) if isinstance(x, str)]
        if isinstance(limitations_any, list)
        else []
    )

    category_counts: dict[str, int] = {}
    top_threats: list[str] = []
    for threat_any in threats:
        if not isinstance(threat_any, dict):
            continue
        threat = cast(dict[str, object], threat_any)
        category = _short_text(threat.get("category"), max_len=48) or "unknown"
        category_counts[category] = category_counts.get(category, 0) + 1

        if len(top_threats) >= 3:
            continue
        title = _short_text(threat.get("title"), max_len=84)
        endpoint_any = threat.get("endpoint")
        endpoint_value = ""
        if isinstance(endpoint_any, dict):
            endpoint = cast(dict[str, object], endpoint_any)
            endpoint_value = _short_text(endpoint.get("value"), max_len=72)
        sample = (
            f"{category}: {title} -> {endpoint_value}"
            if title and endpoint_value
            else f"{category}: {title}" if title else category
        )
        if sample not in top_threats:
            top_threats.append(sample)

    threat_count = _as_int(summary.get("threats"))
    unknown_count = _as_int(summary.get("unknowns"))
    mitigation_count = _as_int(summary.get("mitigations"))
    assumption_count = _as_int(summary.get("assumptions"))
    if threat_count <= 0:
        threat_count = len(threats)
    if unknown_count <= 0:
        unknown_count = len(unknowns)
    if mitigation_count <= 0:
        mitigation_count = len(mitigations)
    if assumption_count <= 0:
        assumption_count = len(assumptions)

    return {
        "available": True,
        "status": _short_text(threat_obj.get("status"), max_len=16) or "unknown",
        "classification": _short_text(summary.get("classification"), max_len=20),
        "observation": _short_text(summary.get("observation"), max_len=40),
        "attack_surface_items": _as_int(summary.get("attack_surface_items")),
        "threat_count": threat_count,
        "unknown_count": unknown_count,
        "mitigation_count": mitigation_count,
        "assumption_count": assumption_count,
        "category_counts": category_counts,
        "top_threats": top_threats,
        "limitations": limitations[:4],
    }


def _collect_tui_runtime_health(*, run_dir: Path) -> dict[str, object]:
    dynamic_obj = _safe_load_json_object(
        run_dir / "stages" / "dynamic_validation" / "dynamic_validation.json"
    )
    dynamic_stage = _safe_load_json_object(
        run_dir / "stages" / "dynamic_validation" / "stage.json"
    )
    emu_stage = _safe_load_json_object(run_dir / "stages" / "emulation" / "stage.json")

    dynamic_status = _short_text(dynamic_obj.get("status"), max_len=24) or (
        _short_text(dynamic_stage.get("status"), max_len=24) or "unknown"
    )
    dynamic_scope = (
        _short_text(dynamic_obj.get("dynamic_scope"), max_len=40) or "unknown"
    )

    target_any = dynamic_obj.get("target")
    target = cast(dict[str, object], target_any) if isinstance(target_any, dict) else {}
    target_ip = _short_text(target.get("ip"), max_len=48)
    target_iid = _short_text(target.get("iid"), max_len=24)

    boot_any = dynamic_obj.get("boot")
    boot = cast(dict[str, object], boot_any) if isinstance(boot_any, dict) else {}
    boot_success = bool(boot.get("success", False))
    attempts_any = boot.get("attempts")
    attempts = (
        cast(list[dict[str, object]], attempts_any)
        if isinstance(attempts_any, list)
        else []
    )
    boot_attempts = len(attempts)
    last_error = ""
    last_returncode = 0
    if attempts:
        last_attempt = attempts[-1]
        if isinstance(last_attempt, dict):
            last_error = _short_text(last_attempt.get("error"), max_len=240)
            last_returncode = _as_int(last_attempt.get("returncode"))

    privileged_any = dynamic_obj.get("privileged_executor")
    privileged = (
        cast(dict[str, object], privileged_any)
        if isinstance(privileged_any, dict)
        else {}
    )
    priv_mode = _short_text(privileged.get("mode"), max_len=24) or "-"
    priv_source = _short_text(privileged.get("source"), max_len=48) or "-"

    dynamic_limitations_any = dynamic_obj.get("limitations")
    dynamic_limitations = (
        [x for x in cast(list[object], dynamic_limitations_any) if isinstance(x, str)]
        if isinstance(dynamic_limitations_any, list)
        else []
    )
    stage_limitations_any = dynamic_stage.get("limitations")
    stage_limitations = (
        [x for x in cast(list[object], stage_limitations_any) if isinstance(x, str)]
        if isinstance(stage_limitations_any, list)
        else []
    )
    emu_limitations_any = emu_stage.get("limitations")
    emu_limitations = (
        [x for x in cast(list[object], emu_limitations_any) if isinstance(x, str)]
        if isinstance(emu_limitations_any, list)
        else []
    )
    limitation_list = [
        x
        for x in dict.fromkeys(
            dynamic_limitations + stage_limitations + emu_limitations
        )
        if x
    ]

    isolation_any = dynamic_obj.get("isolation")
    isolation = (
        cast(dict[str, object], isolation_any)
        if isinstance(isolation_any, dict)
        else {}
    )
    fw_cmds_any = isolation.get("firewall_commands")
    fw_cmds = (
        cast(list[dict[str, object]], fw_cmds_any)
        if isinstance(fw_cmds_any, list)
        else []
    )
    no_new_priv = False
    netlink_denied = False
    for cmd_any in fw_cmds:
        if not isinstance(cmd_any, dict):
            continue
        cmd = cast(dict[str, object], cmd_any)
        stderr = _short_text(cmd.get("stderr"), max_len=800).lower()
        if "no new privileges" in stderr:
            no_new_priv = True
        if "operation not permitted" in stderr:
            netlink_denied = True

    emu_status = _short_text(emu_stage.get("status"), max_len=24) or "unknown"
    docker_permission_denied = any(
        "docker is installed but not usable" in x.lower()
        or "permission denied" in x.lower()
        for x in emu_limitations
    )

    blockers: list[str] = []
    if no_new_priv:
        blockers.append("no_new_privileges")
    if "sudo_execution_blocked" in limitation_list:
        blockers.append("sudo_execution_blocked")
    if "privileged_runner_failed" in limitation_list:
        blockers.append("privileged_runner_failed")
    if docker_permission_denied:
        blockers.append("docker_permission_denied")
    if "boot_timeout" in limitation_list:
        blockers.append("boot_timeout")
    if "boot_flaky" in limitation_list:
        blockers.append("boot_flaky")
    if netlink_denied:
        blockers.append("netlink_permission_denied")

    run_ref: str
    try:
        run_ref = run_dir.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except Exception:
        run_ref = str(run_dir)

    remediation: list[str] = []
    if ("sudo_execution_blocked" in blockers) or ("no_new_privileges" in blockers):
        remediation.append(
            "priv-run 설정: export AIEDGE_PRIV_RUNNER=./scripts/priv-run"
        )
        remediation.append("sudo 검증: sudo -n true (필요 시 SUDO_PASSWORD 설정)")
    if "privileged_runner_failed" in blockers:
        remediation.append("priv-run 경로/권한 확인: ls -l ./scripts/priv-run")
    if ("boot_timeout" in blockers) or ("boot_flaky" in blockers):
        remediation.append("부팅 로그 확인: stages/dynamic_validation/firmae/boot.log")
    if docker_permission_denied:
        remediation.append("docker 권한 확인: docker ps (daemon/group 권한 점검)")
    if blockers:
        remediation.append(
            f"재시도: ./scout stages {run_ref} --stages dynamic_validation,graph,exploit_autopoc"
        )

    health_state = "healthy"
    if dynamic_status not in {"ok"}:
        health_state = "degraded"
    if blockers and health_state == "healthy":
        health_state = "degraded"

    return {
        "available": bool(dynamic_obj or dynamic_stage),
        "state": health_state,
        "dynamic_status": dynamic_status,
        "dynamic_scope": dynamic_scope,
        "target_ip": target_ip,
        "target_iid": target_iid,
        "boot_success": bool(boot_success),
        "boot_attempts": boot_attempts,
        "last_error": last_error,
        "last_returncode": last_returncode,
        "privileged_mode": priv_mode,
        "privileged_source": priv_source,
        "emulation_status": emu_status,
        "limitations": limitation_list[:8],
        "blockers": blockers,
        "remediation": remediation[:5],
    }


def _collect_tui_findings_with_trails(
    *, run_dir: Path, max_findings: int = 10
) -> list[dict[str, object]]:
    """Return findings that carry a non-empty ``reasoning_trail``.

    PR #13 -- TUI surface for the LLM debate steps captured by PR #11.
    Loads ``stages/findings/findings.json`` (fail-open: empty list on any
    error) and returns the first ``max_findings`` entries that have a
    non-empty trail. Each returned dict is shallow-copied with only the
    fields the TUI cares about so the snapshot stays small.
    """
    findings_payload = _safe_load_json_object(
        run_dir / "stages" / "findings" / "findings.json"
    )
    findings_any = findings_payload.get("findings")
    if not isinstance(findings_any, list):
        return []
    out: list[dict[str, object]] = []
    for finding_any in cast(list[object], findings_any):
        if not isinstance(finding_any, dict):
            continue
        finding = cast(dict[str, object], finding_any)
        trail_any = finding.get("reasoning_trail")
        if not isinstance(trail_any, list) or not trail_any:
            continue
        clean_trail: list[dict[str, object]] = []
        for entry_any in cast(list[object], trail_any):
            if isinstance(entry_any, dict):
                clean_trail.append(dict(cast(dict[str, object], entry_any)))
        if not clean_trail:
            continue
        slim: dict[str, object] = {
            "id": finding.get("id"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "category": finding.get("category"),
            "reasoning_trail": clean_trail,
        }
        out.append(slim)
        if len(out) >= max_findings:
            break
    return out


def _build_tui_snapshot(*, run_dir: Path) -> dict[str, object]:
    manifest = _safe_load_json_object(run_dir / "manifest.json")
    report = _safe_load_json_object(run_dir / "report" / "report.json")
    digest = _safe_load_json_object(run_dir / "report" / "analyst_digest.json")
    candidates_payload = _safe_load_json_object(
        run_dir / "stages" / "findings" / "exploit_candidates.json"
    )

    profile_any = manifest.get("profile")
    profile = profile_any if isinstance(profile_any, str) and profile_any else "unknown"

    report_completeness_any = report.get("report_completeness")
    report_completeness = (
        cast(dict[str, object], report_completeness_any)
        if isinstance(report_completeness_any, dict)
        else {}
    )
    report_status = _short_text(report_completeness.get("status")) or "unknown"
    gate_passed = report_completeness.get("gate_passed")
    gate_passed_text = (
        "true"
        if gate_passed is True
        else "false" if gate_passed is False else "unknown"
    )

    llm_any = report.get("llm")
    llm = cast(dict[str, object], llm_any) if isinstance(llm_any, dict) else {}
    llm_status = _short_text(llm.get("status")) or "unknown"

    verdict_any = digest.get("exploitability_verdict")
    verdict = (
        cast(dict[str, object], verdict_any) if isinstance(verdict_any, dict) else {}
    )
    verdict_state = _short_text(verdict.get("state")) or "unknown"
    reason_codes_any = verdict.get("reason_codes")
    reason_codes = (
        [x for x in cast(list[object], reason_codes_any) if isinstance(x, str)]
        if isinstance(reason_codes_any, list)
        else []
    )

    summary_any = candidates_payload.get("summary")
    summary = (
        cast(dict[str, object], summary_any) if isinstance(summary_any, dict) else {}
    )
    high = _as_int(summary.get("high"))
    medium = _as_int(summary.get("medium"))
    low = _as_int(summary.get("low"))
    chain_backed = _as_int(summary.get("chain_backed"))
    candidate_count = _as_int(summary.get("candidate_count"))
    max_bucket = max(high, medium, low, 1)

    candidates_any = candidates_payload.get("candidates")
    candidates = (
        cast(list[dict[str, object]], candidates_any)
        if isinstance(candidates_any, list)
        else []
    )
    candidate_groups = _collect_tui_candidate_groups(candidates)
    verifier_artifacts = _collect_tui_verifier_artifacts(run_dir=run_dir)
    chain_bundle_index = _collect_tui_chain_bundle_index(run_dir=run_dir)
    runtime_model = _collect_runtime_communication_summary(run_dir=run_dir)
    asset_inventory = _collect_tui_asset_inventory(
        run_dir=run_dir,
        candidates=candidates,
    )
    threat_model = _collect_tui_threat_model(run_dir=run_dir)
    runtime_health = _collect_tui_runtime_health(run_dir=run_dir)
    findings_with_trails = _collect_tui_findings_with_trails(run_dir=run_dir)

    return {
        "profile": profile,
        "report_status": report_status,
        "gate_passed_text": gate_passed_text,
        "llm_status": llm_status,
        "verdict_state": verdict_state,
        "reason_codes": reason_codes,
        "schema_version": _short_text(candidates_payload.get("schema_version"))
        or "unknown",
        "high": high,
        "medium": medium,
        "low": low,
        "chain_backed": chain_backed,
        "candidate_count": candidate_count,
        "max_bucket": max_bucket,
        "candidates": candidates,
        "candidate_groups": candidate_groups,
        "verifier_artifacts": cast(dict[str, object], verifier_artifacts),
        "chain_bundle_index": chain_bundle_index,
        "runtime_model": runtime_model,
        "asset_inventory": asset_inventory,
        "threat_model": threat_model,
        "runtime_health": runtime_health,
        "findings_with_trails": cast(list[object], findings_with_trails),
    }
