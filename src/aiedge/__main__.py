"""Module entrypoint.

Allows: python -m aiedge
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import importlib
import json
import os
import re
import sys
import textwrap
import time
from collections.abc import Sequence
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from types import ModuleType
from typing import Callable, Protocol, cast
from urllib.parse import urlparse

from . import __version__
from .corpus import (
    CorpusValidationError,
    corpus_summary,
    format_summary,
    load_corpus_manifest,
)
from .codex_probe import resolve_llm_gate_input
from .quality_metrics import (
    QualityMetricsError,
    build_quality_delta_report,
    evaluate_quality_metrics_harness,
    format_quality_metrics,
    write_quality_metrics,
)
from .quality_policy import (
    QUALITY_GATE_INVALID_METRICS,
    QUALITY_GATE_INVALID_REPORT,
    QUALITY_GATE_LLM_REQUIRED,
    QualityGateError,
    evaluate_quality_gate,
    format_quality_gate,
    load_json_object,
    write_quality_gate,
)
from .schema import JsonValue


class _RunInfo(Protocol):
    run_dir: Path


class _RunReport(Protocol):
    status: str


_CANONICAL_8MB_SHA256 = (
    "387d97fd925125471691d5c565fcc0ff009e111bdbdfd2ddb057f9212a939c8a"
)
_CANONICAL_8MB_SIZE_BYTES = 8_388_608
_TUI_VERIFIED_CHAIN_REF = "verified_chain/verified_chain.json"
_TUI_DYNAMIC_VALIDATION_REQUIRED_REFS = (
    "stages/dynamic_validation/dynamic_validation.json",
    "stages/dynamic_validation/isolation/firewall_snapshot.txt",
    "stages/dynamic_validation/pcap/dynamic_validation.pcap",
)
_TUI_RUNTIME_COMMUNICATION_NODE_TYPE_ORDER = {
    "service": 0,
    "host": 1,
    "endpoint": 2,
    "component": 3,
    "surface": 4,
    "vendor": 5,
    "unknown": 6,
}

_ANSI_RESET = "\x1b[0m"
_ANSI_BOLD = "\x1b[1m"
_ANSI_DIM = "\x1b[2m"
_ANSI_CYAN = "\x1b[36m"
_ANSI_GREEN = "\x1b[32m"
_ANSI_YELLOW = "\x1b[33m"
_ANSI_RED = "\x1b[31m"
_ANSI_MAGENTA = "\x1b[35m"
_ANSI_BLUE = "\x1b[34m"


def _tui_ansi_supported() -> bool:
    no_color = os.environ.get("NO_COLOR")
    if no_color:
        return False
    force_color = os.environ.get("FORCE_COLOR") or os.environ.get("CLICOLOR_FORCE")
    if force_color and force_color != "0":
        return True
    if os.environ.get("TERM", "dumb").lower() == "dumb":
        return False
    if os.environ.get("CLICOLOR") == "0":
        return False
    return bool(sys.stdout.isatty())


def _tui_unicode_supported() -> bool:
    if os.environ.get("AIEDGE_TUI_ASCII") == "1":
        return False
    encoding = (sys.stdout.encoding or "").lower()
    if not encoding:
        return False
    return "utf" in encoding


def _ansi(text: str, *codes: str, enabled: bool) -> str:
    if not enabled or not codes:
        return text
    return "".join(codes) + text + _ANSI_RESET


def _serve_report_directory(
    *,
    run_dir_path: str,
    host: str,
    port: int,
    once: bool,
    duration_s: float | None,
) -> int:
    run_dir = Path(run_dir_path).expanduser().resolve()
    report_dir = run_dir / "report"
    viewer_path = report_dir / "viewer.html"

    if not run_dir.is_dir():
        print(f"Run directory not found: {run_dir}", file=sys.stderr)
        return 20
    if not report_dir.is_dir():
        print(f"Report directory not found: {report_dir}", file=sys.stderr)
        return 20
    if not viewer_path.is_file():
        print(
            f"Viewer file not found: {viewer_path} (run analyze first)",
            file=sys.stderr,
        )
        return 20

    if port < 0 or port > 65535:
        print("Invalid --port value: must be in range 0..65535", file=sys.stderr)
        return 20

    if duration_s is not None and duration_s <= 0:
        print("Invalid --duration-s value: must be > 0", file=sys.stderr)
        return 20

    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(report_dir))
    try:
        httpd = HTTPServer((host, int(port)), handler)
    except OSError as e:
        print(f"Failed to start report server: {e}", file=sys.stderr)
        return 20

    with httpd:
        bound_host = cast(str, httpd.server_address[0])
        bound_port = int(httpd.server_address[1])
        print(
            f"http://{bound_host}:{bound_port}/viewer.html",
            flush=True,
        )
        try:
            if once:
                httpd.handle_request()
                return 0
            if duration_s is not None:
                deadline = time.monotonic() + float(duration_s)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0.0:
                        break
                    httpd.timeout = min(1.0, max(0.05, remaining))
                    httpd.handle_request()
                return 0
            httpd.serve_forever()
        except KeyboardInterrupt:
            return 0

    return 0


def _safe_load_json_object(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        obj_any = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return {}
    if not isinstance(obj_any, dict):
        return {}
    return cast(dict[str, object], obj_any)


def _as_int(value: object, *, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return int(value)
    return default


def _as_float(value: object, *, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    return default


def _short_text(value: object, *, max_len: int = 96) -> str:
    if not isinstance(value, str):
        return ""
    text = " ".join(value.split())
    if len(text) <= max_len:
        return text
    if max_len <= 3:
        return text[:max_len]
    return text[: max_len - 3] + "..."


def _short_path(value: object, *, max_len: int = 120) -> str:
    if not isinstance(value, str):
        return ""
    text = " ".join(value.split())
    if len(text) <= max_len:
        return text
    if max_len <= 7:
        return text[:max_len]
    keep = max_len - 3
    head = int(keep * 0.55)
    tail = keep - head
    return text[:head] + "..." + text[-tail:]


def _path_tail(value: object, *, max_segments: int = 4, max_len: int = 84) -> str:
    if not isinstance(value, str):
        return ""
    text = " ".join(value.split())
    if not text:
        return ""
    parts = [p for p in text.split("/") if p]
    if not parts:
        return _short_path(text, max_len=max_len)
    tail = "/".join(parts[-max_segments:])
    if len(parts) > max_segments:
        tail = ".../" + tail
    return _short_path(tail, max_len=max_len)


def _safe_node_text(value: object, *, fallback: str = "unknown", max_len: int = 160) -> str:
    if not isinstance(value, str):
        return fallback
    text = " ".join(value.replace("\n", " ").replace("\r", " ").split())
    text = text.encode("ascii", errors="ignore").decode("ascii")
    if not text:
        return fallback
    return text[:max_len]


def _safe_ascii_label_for_comm(value: object, *, max_len: int = 72) -> str:
    return _safe_node_text(value, max_len=max_len)


def _safe_node_value(value: str) -> str:
    return _safe_node_text(value, max_len=220)


def _as_path(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.replace("\\", "/").strip()


def _normalize_ref(value: object) -> str | None:
    text = _as_path(value)
    if not text:
        return None
    if text.startswith("/"):
        return text.lstrip("/")
    return text


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
        "candidate_ids": [cast(str, candidate_id)]
        if isinstance(item.get("candidate_id"), str)
        else [],
        "max_score": score,
        "sample_paths": [sample_path] if sample_path else [],
        "representative_id": cast(str, candidate_id) if isinstance(candidate_id, str) else "",
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
            group["hypothesis"] = _short_text(item.get("attack_hypothesis"), max_len=240)
            impacts_any = item.get("expected_impact")
            impacts = (
                [x for x in cast(list[object], impacts_any) if isinstance(x, str)]
                if isinstance(impacts_any, list)
                else []
            )
            group["impact"] = (
                _short_text(impacts[0], max_len=240) if impacts else _short_text(group.get("impact"), max_len=240)
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


def _collect_runtime_communication_summary(
    *, run_dir: Path
) -> dict[str, object]:
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
                    host = _safe_node_value(
                        _short_text(row.get("host"), max_len=220)
                    )
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
                    evidence_badge = _short_text(row.get("evidence_badge"), max_len=20) or "S"
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
                    dynamic_exploit_chain = bool(row.get("dynamic_exploit_chain", False))
                    matrix_rows.append(
                        {
                            "host": host,
                            "service_host": service_host,
                            "port": service_port,
                            "protocol": protocol,
                            "components": [component_label],
                            "component": component_label,
                            "confidence": row.get("confidence"),
                            "observation": row.get("observation", "runtime_communication"),
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
                        row_service_host = _short_text(row.get("service_host"), max_len=220)
                        row_port = _as_int(row.get("port"))
                        row_protocol = (
                            _short_text(row.get("protocol"), max_len=12) or "tcp"
                        )
                        endpoint = _service_endpoint(row_service_host, row_port, row_protocol)
                        if row_host:
                            if row_component:
                                host_components_map.setdefault(row_host, set()).add(
                                    row_component
                                )
                            if endpoint:
                                host_service_map.setdefault(row_host, set()).add(endpoint)
                            protocol_counts[row_protocol] = protocol_counts.get(
                                row_protocol, 0
                            ) + 1
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
                                "services": _as_int(summary_any.get("services"), default=0),
                                "components": _as_int(summary_any.get("components"), default=0),
                                "rows_dynamic": _as_int(summary_any.get("rows_dynamic"), default=0),
                                "rows_exploit": _as_int(summary_any.get("rows_exploit"), default=0),
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
                        "status": _short_text(
                            matrix_payload.get("status"), max_len=16
                        ) or "partial",
                        "rows": cast(list[object], matrix_rows),
                        "summary": summary,
                    }

            return {
                "available": True,
                "status": _short_text(matrix_payload.get("status"), max_len=16) or "partial",
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
                    "artifacts": [_path_tail(str(matrix_path), max_segments=4, max_len=90)],
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
        src = cast(str | None, edge.get("src") if isinstance(edge.get("src"), str) else None)
        dst = cast(str | None, edge.get("dst") if isinstance(edge.get("dst"), str) else None)
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
                comp = _safe_node_value(_safe_ascii_label(src))
                host = _safe_node_value(_safe_ascii_label(cast(str, dst)))
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
        host = host_label.removeprefix("host:") if host_label.startswith("host:") else host_label
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
        unique_services = sorted(set(services), key=lambda item: (item[0], item[1], item[2]))
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


def _count_bar(label: str, *, count: int, max_count: int, width: int = 24) -> str:
    if width <= 0:
        width = 24
    denom = max(1, max_count)
    filled = int(round((max(0, count) / float(denom)) * float(width)))
    filled = max(0, min(width, filled))
    bar = ("#" * filled) + ("-" * (width - filled))
    return f"{label:<6} |{bar}| {count}"


def _sorted_count_pairs(
    counts: dict[str, int],
    *,
    limit: int = 6,
) -> list[tuple[str, int]]:
    ordered = sorted(
        ((k, v) for k, v in counts.items() if k and v > 0),
        key=lambda kv: (-int(kv[1]), kv[0]),
    )
    return ordered[: max(0, limit)]


def _collect_tui_asset_inventory(
    *,
    run_dir: Path,
    candidates: list[dict[str, object]],
) -> dict[str, object]:
    inv_obj = _safe_load_json_object(run_dir / "stages" / "inventory" / "inventory.json")
    endpoints_obj = _safe_load_json_object(run_dir / "stages" / "endpoints" / "endpoints.json")
    ports_obj = _safe_load_json_object(
        run_dir / "stages" / "dynamic_validation" / "network" / "ports.json"
    )
    ifaces_obj = _safe_load_json_object(
        run_dir / "stages" / "dynamic_validation" / "network" / "interfaces.json"
    )

    inv_summary_any = inv_obj.get("summary")
    inv_summary = cast(dict[str, object], inv_summary_any) if isinstance(inv_summary_any, dict) else {}
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
        endpoint_type_counts[endpoint_type] = endpoint_type_counts.get(endpoint_type, 0) + 1
        value = _short_text(endpoint.get("value"), max_len=260)
        if not value:
            continue
        parsed = urlparse(value)
        if parsed.scheme:
            scheme = parsed.scheme.lower().strip()
            if scheme:
                endpoint_protocol_counts[scheme] = endpoint_protocol_counts.get(scheme, 0) + 1
            if parsed.port is not None and 0 <= int(parsed.port) <= 65535:
                port_key = str(int(parsed.port))
                endpoint_port_counts[port_key] = endpoint_port_counts.get(port_key, 0) + 1
            continue
        host_port = re.match(r"^[a-zA-Z0-9_.:-]+:(\d{1,5})$", value)
        if host_port:
            port_num = int(host_port.group(1))
            if 0 <= port_num <= 65535:
                port_key = str(port_num)
                endpoint_port_counts[port_key] = endpoint_port_counts.get(port_key, 0) + 1

    ports_any = ports_obj.get("ports")
    ports = cast(list[dict[str, object]], ports_any) if isinstance(ports_any, list) else []
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
            [_short_text(x, max_len=32) for x in cast(list[object], ipv4_any) if isinstance(x, str)]
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
        cast(dict[str, object], summary_any)
        if isinstance(summary_any, dict)
        else {}
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
            else f"{category}: {title}"
            if title
            else category
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
    dynamic_scope = _short_text(dynamic_obj.get("dynamic_scope"), max_len=40) or "unknown"

    target_any = dynamic_obj.get("target")
    target = cast(dict[str, object], target_any) if isinstance(target_any, dict) else {}
    target_ip = _short_text(target.get("ip"), max_len=48)
    target_iid = _short_text(target.get("iid"), max_len=24)

    boot_any = dynamic_obj.get("boot")
    boot = cast(dict[str, object], boot_any) if isinstance(boot_any, dict) else {}
    boot_success = bool(boot.get("success", False))
    attempts_any = boot.get("attempts")
    attempts = cast(list[dict[str, object]], attempts_any) if isinstance(attempts_any, list) else []
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
        for x in dict.fromkeys(dynamic_limitations + stage_limitations + emu_limitations)
        if x
    ]

    isolation_any = dynamic_obj.get("isolation")
    isolation = cast(dict[str, object], isolation_any) if isinstance(isolation_any, dict) else {}
    fw_cmds_any = isolation.get("firewall_commands")
    fw_cmds = cast(list[dict[str, object]], fw_cmds_any) if isinstance(fw_cmds_any, list) else []
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
        remediation.append(
            "sudo 검증: sudo -n true (필요 시 SUDO_PASSWORD 설정)"
        )
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
        "true" if gate_passed is True else "false" if gate_passed is False else "unknown"
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
    summary = cast(dict[str, object], summary_any) if isinstance(summary_any, dict) else {}
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

    return {
        "profile": profile,
        "report_status": report_status,
        "gate_passed_text": gate_passed_text,
        "llm_status": llm_status,
        "verdict_state": verdict_state,
        "reason_codes": reason_codes,
        "schema_version": _short_text(candidates_payload.get("schema_version")) or "unknown",
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
    }


def _build_tui_snapshot_lines(
    *,
    run_dir: Path,
    limit: int,
    use_ansi: bool | None = None,
    use_unicode: bool | None = None,
) -> list[str]:
    if use_ansi is None:
        use_ansi = _tui_ansi_supported()
    if use_unicode is None:
        use_unicode = _tui_unicode_supported()

    snapshot = _build_tui_snapshot(run_dir=run_dir)
    profile = _short_text(snapshot.get("profile"), max_len=40) or "unknown"
    report_status = _short_text(snapshot.get("report_status"), max_len=40) or "unknown"
    gate_passed_text = (
        _short_text(snapshot.get("gate_passed_text"), max_len=16) or "unknown"
    )
    llm_status = _short_text(snapshot.get("llm_status"), max_len=40) or "unknown"
    verdict_state = _short_text(snapshot.get("verdict_state"), max_len=48) or "unknown"
    reason_codes = cast(list[str], snapshot.get("reason_codes", []))
    candidate_count = _as_int(snapshot.get("candidate_count"))
    chain_backed = _as_int(snapshot.get("chain_backed"))
    high = _as_int(snapshot.get("high"))
    medium = _as_int(snapshot.get("medium"))
    low = _as_int(snapshot.get("low"))
    max_bucket = _as_int(snapshot.get("max_bucket"), default=1)
    schema_version = _short_text(snapshot.get("schema_version"), max_len=48) or "unknown"
    verifier_artifacts = cast(
        dict[str, object], snapshot.get("verifier_artifacts", {})
    )
    chain_bundle_index = cast(
        dict[str, str], snapshot.get("chain_bundle_index", {})
    )
    dynamic_present = _as_int(
        len(cast(list[str], verifier_artifacts.get("dynamic_present_refs", [])))
    )
    dynamic_missing_refs = cast(list[str], verifier_artifacts.get("dynamic_missing_refs", []))
    dynamic_total = dynamic_present + _as_int(len(dynamic_missing_refs))
    exploit_bundle_refs = cast(list[str], verifier_artifacts.get("exploit_bundle_refs", []))
    verified_chain_present = bool(verifier_artifacts.get("verified_chain_present", False))

    horizontal = "─" if use_unicode else "-"
    section_rule = horizontal * 96

    lines: list[str] = []
    lines.append(_ansi(f"AIEdge TUI :: {run_dir}", _ANSI_BOLD, _ANSI_CYAN, enabled=use_ansi))
    lines.append(_ansi(section_rule, _ANSI_DIM, enabled=use_ansi))
    lines.append(
        _ansi("Status", _ANSI_BOLD, _ANSI_MAGENTA, enabled=use_ansi)
        + f"  profile={profile} | report_completeness={report_status} (gate_passed={gate_passed_text}) | llm={llm_status}"
    )
    verdict_style = (_ANSI_BOLD, _ANSI_RED)
    verdict_upper = verdict_state.upper()
    if "VERIFIED" in verdict_upper:
        verdict_style = (_ANSI_BOLD, _ANSI_GREEN)
    elif "NOT_ATTEMPTED" in verdict_upper:
        verdict_style = (_ANSI_BOLD, _ANSI_YELLOW)
    lines.append("verdict=" + _ansi(verdict_state, *verdict_style, enabled=use_ansi))
    if reason_codes:
        lines.append("reason_codes=" + ", ".join(reason_codes[:5]))
    lines.append("")
    lines.append(_ansi("Exploit Candidate Map", _ANSI_BOLD, _ANSI_MAGENTA, enabled=use_ansi))
    lines.append(_ansi(section_rule, _ANSI_DIM, enabled=use_ansi))
    lines.append(
        f"candidate_count={candidate_count} | chain_backed={chain_backed} | schema={schema_version}"
    )
    if dynamic_total == 0 and not exploit_bundle_refs and not verified_chain_present:
        lines.append(
            "Verifier artifacts: not_started (dynamic_validation=0/0) | verified_chain=no | exploit_bundles=0"
        )
    else:
        dynamic_status = (
            "present"
            if dynamic_missing_refs == []
            and dynamic_total > 0
            else "partial"
            if dynamic_missing_refs
            else "not_started"
        )
        lines.append(
            "Verifier artifacts: "
            f"dynamic_validation={dynamic_status} ({dynamic_present}/{dynamic_total}) | "
            f"verified_chain={'yes' if verified_chain_present else 'no'} | "
            f"exploit_bundles={len(exploit_bundle_refs)}"
        )
    if dynamic_missing_refs:
        lines.append(
            "  missing_dynamic="
            + ", ".join(dynamic_missing_refs[:3])
            + (" ..." if len(dynamic_missing_refs) > 3 else "")
        )
    if exploit_bundle_refs:
        lines.append(
            "  exploit_bundles="
            + ", ".join(
                _path_tail(x, max_segments=3, max_len=96) for x in exploit_bundle_refs[:2]
            )
            + (" ..." if len(exploit_bundle_refs) > 2 else "")
        )
    runtime_model = cast(dict[str, object], snapshot.get("runtime_model", {}))
    runtime_available = bool(runtime_model.get("available", False))
    if runtime_available:
        runtime_summary = cast(
            dict[str, object], runtime_model.get("summary", {})
        )
        rows = cast(list[object], runtime_model.get("rows", []))
        runtime_system_map_any = runtime_summary.get("runtime_system_map", [])
        runtime_system_map = (
            [cast(dict[str, object], x) for x in cast(list[object], runtime_system_map_any)]
            if isinstance(runtime_system_map_any, list)
            else []
        )
        runtime_protocol_counts_any = runtime_summary.get("service_count_by_protocol", {})
        runtime_protocol_counts = (
            cast(dict[str, int], runtime_protocol_counts_any)
            if isinstance(runtime_protocol_counts_any, dict)
            else {}
        )
        runtime_host_service_counts_any = runtime_summary.get("host_service_counts", {})
        runtime_host_service_counts = (
            cast(dict[str, int], runtime_host_service_counts_any)
            if isinstance(runtime_host_service_counts_any, dict)
            else {}
        )
        lines.append(
            f"runtime: hosts={_as_int(runtime_summary.get('hosts'))} | "
            f"services={_as_int(runtime_summary.get('services'))} | "
            f"components={_as_int(runtime_summary.get('components'))} | "
            f"D={_as_int(runtime_summary.get('rows_dynamic'))} "
            f"E={_as_int(runtime_summary.get('rows_exploit'))} "
            f"V={_as_int(runtime_summary.get('rows_verified_chain'))} "
            f"D+E={_as_int(runtime_summary.get('rows_dynamic_exploit'))} | "
            f"status={_short_text(runtime_model.get('status'), max_len=16) or 'partial'}"
        )
        if runtime_protocol_counts:
            protocol_text = ", ".join(
                f"{k}:{v}" for k, v in _sorted_count_pairs(runtime_protocol_counts, limit=4)
            )
            if protocol_text:
                lines.append(f"runtime_protocols: {protocol_text}")
        if runtime_host_service_counts:
            host_text = ", ".join(
                f"{k}->{v}"
                for k, v in _sorted_count_pairs(runtime_host_service_counts, limit=4)
            )
            if host_text:
                lines.append(f"runtime_system_map: {host_text}")
        lines.append(
            _ansi("Runtime Exposure Model", _ANSI_BOLD, _ANSI_MAGENTA, enabled=use_ansi)
        )
        lines.append(_ansi(section_rule, _ANSI_DIM, enabled=use_ansi))
        if rows:
            lines.append("service_protocol_component map:")
            for row_any in rows[: min(limit, len(rows))]:
                row = cast(dict[str, object], row_any)
                row_host = _short_text(row.get("host"), max_len=24)
                row_service_host = _short_text(row.get("service_host"), max_len=24)
                row_port = _as_int(row.get("port"))
                row_protocol = (
                    _short_text(row.get("protocol"), max_len=10) or "tcp"
                ).upper()
                row_components = row.get("components", [])
                if not isinstance(row_components, list):
                    row_components = []
                components = ", ".join(
                    _short_text(v, max_len=24) for v in cast(list[str], row_components[:2])
                )
                evidence_badge = (
                    _short_text(row.get("evidence_badge"), max_len=16) or "S"
                )
                evidence_counts = (
                    f"D{_as_int(row.get('dynamic_evidence_count'))}"
                    f"/E{_as_int(row.get('exploit_evidence_count'))}"
                    f"/V{_as_int(row.get('verified_chain_evidence_count'))}"
                )
                dynamic_exploit = bool(row.get("dynamic_exploit_chain", False))
                badge_style = (_ANSI_BOLD, _ANSI_RED) if dynamic_exploit else (_ANSI_BOLD, _ANSI_YELLOW)
                rendered_badge = _ansi(
                    evidence_badge,
                    *badge_style,
                    enabled=use_ansi,
                )
                evidence_signals = row.get("evidence_signals")
                if not isinstance(evidence_signals, list):
                    evidence_signals = []
                evidence_text = ",".join(
                    sorted(
                        str(x)
                        for x in cast(list[object], evidence_signals)
                        if isinstance(x, str)
                    )
                )
                if not evidence_text:
                    evidence_text = evidence_badge
                service_endpoint = f"{row_service_host}:{row_port}/{row_protocol}"
                lines.append(
                    f"  {row_host: <24} | {service_endpoint: <18} | "
                    f"{(components if components else 'unmapped'): <24} "
                    f"[{rendered_badge}] {evidence_counts} ({evidence_text})"
                )
            lines.append(
                "  legend: D=dynamic, E=exploit, V=verified_chain, S=static, D+E=D+E"
            )
        else:
            lines.append("service_protocol_component map: (no mapped host->service rows)")
    else:
        lines.append("Runtime Exposure Model: unavailable")

    threat_model = cast(dict[str, object], snapshot.get("threat_model", {}))
    if threat_model:
        lines.append("")
        lines.append(_ansi("Threat Modeling Overview", _ANSI_BOLD, _ANSI_MAGENTA, enabled=use_ansi))
        lines.append(_ansi(section_rule, _ANSI_DIM, enabled=use_ansi))
        if bool(threat_model.get("available")):
            tm_status = _short_text(threat_model.get("status"), max_len=20) or "unknown"
            tm_threats = _as_int(threat_model.get("threat_count"))
            tm_unknowns = _as_int(threat_model.get("unknown_count"))
            tm_mitigations = _as_int(threat_model.get("mitigation_count"))
            tm_assumptions = _as_int(threat_model.get("assumption_count"))
            tm_surface_items = _as_int(threat_model.get("attack_surface_items"))
            tm_class = _short_text(threat_model.get("classification"), max_len=20) or "-"
            tm_obs = _short_text(threat_model.get("observation"), max_len=28) or "-"
            lines.append(
                f"threat_model: status={tm_status} | threats={tm_threats} | unknowns={tm_unknowns} | "
                f"mitigations={tm_mitigations} | assumptions={tm_assumptions} | "
                f"attack_surface_items={tm_surface_items}"
            )
            lines.append(f"classification={tm_class} | observation={tm_obs}")
            category_counts_any = threat_model.get("category_counts")
            category_counts = (
                cast(dict[str, int], category_counts_any)
                if isinstance(category_counts_any, dict)
                else {}
            )
            category_text = ", ".join(
                f"{k}={v}" for k, v in _sorted_count_pairs(category_counts, limit=4)
            ) or "-"
            lines.append(f"categories: {category_text}")
            top_threats_any = threat_model.get("top_threats")
            top_threats = (
                [x for x in cast(list[object], top_threats_any) if isinstance(x, str)]
                if isinstance(top_threats_any, list)
                else []
            )
            if top_threats:
                lines.append("top_threats:")
                for sample in top_threats[:3]:
                    lines.append("  - " + sample)
            limitations_any = threat_model.get("limitations")
            limitations = (
                [x for x in cast(list[object], limitations_any) if isinstance(x, str)]
                if isinstance(limitations_any, list)
                else []
            )
            if limitations:
                lines.append("limitations: " + ", ".join(limitations[:3]))
        else:
            lines.append("threat_model: unavailable (run stage: threat_model)")

    runtime_health = cast(dict[str, object], snapshot.get("runtime_health", {}))
    if runtime_health:
        blockers_any = runtime_health.get("blockers")
        blockers = (
            [x for x in cast(list[object], blockers_any) if isinstance(x, str)]
            if isinstance(blockers_any, list)
            else []
        )
        limitations_any = runtime_health.get("limitations")
        limitations = (
            [x for x in cast(list[object], limitations_any) if isinstance(x, str)]
            if isinstance(limitations_any, list)
            else []
        )
        remediation_any = runtime_health.get("remediation")
        remediation = (
            [x for x in cast(list[object], remediation_any) if isinstance(x, str)]
            if isinstance(remediation_any, list)
            else []
        )

        state = _short_text(runtime_health.get("state"), max_len=20) or "unknown"
        dyn_status = _short_text(runtime_health.get("dynamic_status"), max_len=20) or "unknown"
        dyn_scope = _short_text(runtime_health.get("dynamic_scope"), max_len=28) or "unknown"
        target_ip = _short_text(runtime_health.get("target_ip"), max_len=40) or "-"
        boot_success = bool(runtime_health.get("boot_success"))
        boot_attempts = _as_int(runtime_health.get("boot_attempts"))
        emu_status = _short_text(runtime_health.get("emulation_status"), max_len=20) or "unknown"
        priv_mode = _short_text(runtime_health.get("privileged_mode"), max_len=20) or "-"
        status_color = (_ANSI_BOLD, _ANSI_GREEN) if state == "healthy" else (_ANSI_BOLD, _ANSI_YELLOW)

        lines.append("")
        lines.append(_ansi("Runtime Reliability", _ANSI_BOLD, _ANSI_MAGENTA, enabled=use_ansi))
        lines.append(_ansi(section_rule, _ANSI_DIM, enabled=use_ansi))
        lines.append(
            "state="
            + _ansi(state, *status_color, enabled=use_ansi)
            + f" | dynamic={dyn_status}({dyn_scope}) | emulation={emu_status} | target={target_ip}"
        )
        lines.append(
            f"boot: success={'yes' if boot_success else 'no'} attempts={boot_attempts} | privileged={priv_mode}"
        )
        if limitations:
            lines.append("limitations: " + ", ".join(limitations[:3]))
        if blockers:
            lines.append(
                _ansi(
                    "blockers: " + ", ".join(blockers[:4]),
                    _ANSI_YELLOW,
                    enabled=use_ansi,
                )
            )
        last_error = _short_text(runtime_health.get("last_error"), max_len=180)
        if last_error:
            lines.append("last_error: " + last_error)
        if remediation:
            lines.append("quick_fix:")
            for hint in remediation[:4]:
                lines.append("  - " + hint)

    asset_inventory = cast(dict[str, object], snapshot.get("asset_inventory", {}))
    if asset_inventory:
        service_kinds_any = asset_inventory.get("service_kind_counts")
        service_kinds = (
            cast(dict[str, int], service_kinds_any)
            if isinstance(service_kinds_any, dict)
            else {}
        )
        endpoint_types_any = asset_inventory.get("endpoint_type_counts")
        endpoint_types = (
            cast(dict[str, int], endpoint_types_any)
            if isinstance(endpoint_types_any, dict)
            else {}
        )
        endpoint_protocols_any = asset_inventory.get("endpoint_protocol_counts")
        endpoint_protocols = (
            cast(dict[str, int], endpoint_protocols_any)
            if isinstance(endpoint_protocols_any, dict)
            else {}
        )
        dynamic_protocols_any = asset_inventory.get("dynamic_protocol_counts")
        dynamic_protocols = (
            cast(dict[str, int], dynamic_protocols_any)
            if isinstance(dynamic_protocols_any, dict)
            else {}
        )
        dynamic_states_any = asset_inventory.get("dynamic_state_counts")
        dynamic_states = (
            cast(dict[str, int], dynamic_states_any)
            if isinstance(dynamic_states_any, dict)
            else {}
        )
        top_daemons_any = asset_inventory.get("top_daemons")
        top_daemons = (
            [x for x in cast(list[object], top_daemons_any) if isinstance(x, str)]
            if isinstance(top_daemons_any, list)
            else []
        )
        service_paths_any = asset_inventory.get("service_paths")
        service_paths = (
            [x for x in cast(list[object], service_paths_any) if isinstance(x, str)]
            if isinstance(service_paths_any, list)
            else []
        )
        open_ports_any = asset_inventory.get("open_ports")
        open_ports = (
            [x for x in cast(list[object], open_ports_any) if isinstance(x, str)]
            if isinstance(open_ports_any, list)
            else []
        )
        port_samples_any = asset_inventory.get("port_samples")
        port_samples = (
            [x for x in cast(list[object], port_samples_any) if isinstance(x, str)]
            if isinstance(port_samples_any, list)
            else []
        )
        interfaces_any = asset_inventory.get("interfaces")
        interfaces = (
            [x for x in cast(list[object], interfaces_any) if isinstance(x, str)]
            if isinstance(interfaces_any, list)
            else []
        )
        candidate_paths_any = asset_inventory.get("candidate_paths")
        candidate_paths = (
            [x for x in cast(list[object], candidate_paths_any) if isinstance(x, str)]
            if isinstance(candidate_paths_any, list)
            else []
        )

        kind_text = ", ".join(
            f"{k}={v}" for k, v in _sorted_count_pairs(service_kinds, limit=4)
        ) or "-"
        endpoint_type_text = ", ".join(
            f"{k}={v}" for k, v in _sorted_count_pairs(endpoint_types, limit=4)
        ) or "-"
        endpoint_protocol_text = ", ".join(
            f"{k}={v}" for k, v in _sorted_count_pairs(endpoint_protocols, limit=4)
        ) or "-"
        dynamic_protocol_text = ", ".join(
            f"{k}={v}" for k, v in _sorted_count_pairs(dynamic_protocols, limit=3)
        ) or "-"
        dynamic_state_text = ", ".join(
            f"{k}={v}" for k, v in _sorted_count_pairs(dynamic_states, limit=4)
        ) or "-"
        scan_strategy = _short_text(asset_inventory.get("scan_strategy"), max_len=32) or "default"
        scan_coverage = _as_float(asset_inventory.get("scan_coverage_pct"), default=0.0)
        scan_range_total = _as_int(asset_inventory.get("scan_range_total"))
        scan_budget_hit = bool(asset_inventory.get("scan_budget_hit", False))
        target_ip = _short_text(asset_inventory.get("target_ip"), max_len=40) or "-"

        lines.append("")
        lines.append(
            _ansi("Firmware Service & Protocol Inventory", _ANSI_BOLD, _ANSI_MAGENTA, enabled=use_ansi)
        )
        lines.append(_ansi(section_rule, _ANSI_DIM, enabled=use_ansi))
        lines.append(
            "inventory: "
            f"files={_as_int(asset_inventory.get('files'))} "
            f"binaries={_as_int(asset_inventory.get('binaries'))} "
            f"configs={_as_int(asset_inventory.get('configs'))} "
            f"service_candidates={_as_int(asset_inventory.get('service_candidates'))}"
        )
        lines.append(f"service_kinds: {kind_text}")
        if top_daemons:
            lines.append("daemon_candidates: " + ", ".join(top_daemons[:8]))
        if service_paths:
            lines.append(
                "daemon_evidence: "
                + ", ".join(_path_tail(x, max_segments=6, max_len=96) for x in service_paths[:3])
            )
        lines.append(
            f"endpoints: total={_as_int(asset_inventory.get('endpoint_total'))} | types={endpoint_type_text}"
        )
        lines.append(
            f"protocols: static_url={endpoint_protocol_text} | dynamic_probe={dynamic_protocol_text}"
        )
        port_line = (
            f"ports: target={target_ip} | probed={_as_int(asset_inventory.get('probed_ports'))} "
            f"| open={len(open_ports)} | states={dynamic_state_text}"
        )
        if scan_range_total > 0:
            port_line += f" | coverage={scan_coverage:.1f}%/{scan_range_total}"
        if scan_strategy and scan_strategy != "default":
            port_line += f" | scan={scan_strategy}"
        lines.append(port_line)
        if scan_budget_hit:
            lines.append("  scan_note=budget_hit (increase AIEDGE_PORTSCAN_BUDGET_S if needed)")
        if open_ports:
            lines.append("  open_ports=" + ", ".join(open_ports[:6]))
        elif port_samples:
            lines.append("  probed_sample=" + ", ".join(port_samples[:6]))
        if interfaces:
            lines.append("interfaces: " + ", ".join(interfaces[:4]))
        if candidate_paths:
            lines.append("candidate_paths(top): " + ", ".join(candidate_paths[:4]))

    lines.append(
        _ansi(_count_bar("HIGH", count=high, max_count=max_bucket), _ANSI_RED, enabled=use_ansi)
    )
    lines.append(
        _ansi(
            _count_bar("MEDIUM", count=medium, max_count=max_bucket),
            _ANSI_YELLOW,
            enabled=use_ansi,
        )
    )
    lines.append(
        _ansi(_count_bar("LOW", count=low, max_count=max_bucket), _ANSI_GREEN, enabled=use_ansi)
    )

    candidates = cast(list[dict[str, object]], snapshot.get("candidates", []))
    if not candidates:
        lines.append("")
        lines.append("(no candidates)")
        return lines

    lines.append("")
    candidate_groups = cast(
        list[dict[str, object]], snapshot.get("candidate_groups", [])
    )
    if not candidate_groups:
        candidate_groups = _collect_tui_candidate_groups(candidates)

    lines.append(
        f"Top {min(limit, len(candidate_groups))} grouped candidate(s) [compact]"
    )
    lines.append(_ansi(section_rule, _ANSI_DIM, enabled=use_ansi))
    lines.append(f"Candidate groups: {len(candidate_groups)} unique")
    lines.append(_ansi("ID  P   Score   Hits  Evidence  Family", _ANSI_BOLD, _ANSI_BLUE, enabled=use_ansi))
    lines.append(_ansi(section_rule, _ANSI_DIM, enabled=use_ansi))
    previous_triplet: tuple[str, str, str] | None = None
    for idx, group in enumerate(candidate_groups[: min(limit, len(candidate_groups))], start=1):
        priority = _short_text(group.get("priority"), max_len=12) or "unknown"
        priority_tag = priority[:1].upper() if priority else "?"
        family = _short_text(group.get("family"), max_len=42) or "unknown"
        count = _as_int(group.get("path_count"))
        max_score = _as_float(group.get("max_score"))
        source = _short_text(group.get("source", ""), max_len=16) or "unknown"
        representative_id = _short_text(group.get("representative_id"), max_len=120)
        representative: dict[str, object] | None = None
        if representative_id:
            for candidate in candidates:
                if (
                    _short_text(candidate.get("candidate_id"), max_len=120)
                    == representative_id
                ):
                    representative = candidate
                    break
        signal_items = ["static"]
        if representative is not None:
            signal_text = ",".join(
                _candidate_verification_signals(
                    representative,
                    chain_bundle_index=chain_bundle_index,
                    verified_chain_present=verified_chain_present,
                )
            )
            if signal_text:
                signal_items = signal_text.split(",")
        signal_badge = _candidate_signal_badge(signal_items)
        header_line = (
            f"G{idx:02d} [{priority_tag}] family={family} source={source} "
            f"count={count} max_score={max_score:.3f} evidence={signal_badge}"
        )
        priority_style: tuple[str, ...] = (_ANSI_DIM,)
        if priority_tag == "H":
            priority_style = (_ANSI_BOLD, _ANSI_RED)
        elif priority_tag == "M":
            priority_style = (_ANSI_BOLD, _ANSI_YELLOW)
        elif priority_tag == "L":
            priority_style = (_ANSI_BOLD, _ANSI_GREEN)
        lines.append(_ansi(header_line, *priority_style, enabled=use_ansi))

        path_signature = _short_text(group.get("path_signature"), max_len=72) or "(unspecified)"
        lines.append(f"    path: {path_signature}")
        hypothesis = _short_text(group.get("hypothesis"), max_len=140)
        impact = _short_text(group.get("impact"), max_len=140)
        next_step = _short_text(group.get("next_step"), max_len=140)
        current_triplet = (hypothesis, impact, next_step)
        if previous_triplet is not None and current_triplet == previous_triplet:
            lines.append("    note: same attack/impact/next as previous candidate group")
        else:
            if hypothesis:
                lines.append(f"    attack: {hypothesis}")
            if impact:
                lines.append(f"    impact: {impact}")
            if next_step:
                lines.append(f"    next: {next_step}")
        previous_triplet = current_triplet

        lines.append(f"    source={source} | evidence={','.join(signal_items)}")
        sample_paths_all = cast(list[str], group.get("sample_paths"))
        sample_paths = [x for x in sample_paths_all if isinstance(x, str) and x]
        if sample_paths:
            lines.append("    sample_paths:")
            for sample in sample_paths[:3]:
                lines.append(f"      - {_path_tail(sample, max_segments=6, max_len=96)}")

    return lines


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


def _safe_curses_addstr(
    window: object,
    *,
    y: int,
    x: int,
    text: str,
    attr: int = 0,
) -> None:
    win = cast("curses._CursesWindow", window)
    max_y, max_x = win.getmaxyx()
    if y < 0 or y >= max_y or x >= max_x:
        return
    allowed = max(0, max_x - x - 1)
    if allowed <= 0:
        return
    snippet = text[:allowed]
    try:
        if attr:
            win.addstr(y, x, snippet, attr)
        else:
            win.addstr(y, x, snippet)
    except Exception:
        return


def _build_tui_color_theme(*, curses_mod: object) -> dict[str, int]:
    curses = cast(object, curses_mod)
    theme: dict[str, int] = {}
    try:
        has_colors = bool(getattr(curses, "has_colors")())
    except Exception:
        has_colors = False
    if not has_colors:
        return theme

    try:
        _ = getattr(curses, "start_color")()
    except Exception:
        return theme

    try:
        use_default = getattr(curses, "use_default_colors", None)
        if callable(use_default):
            use_default()
    except Exception:
        pass

    # pair id -> foreground / background(default)
    pair_defs: list[tuple[int, int]] = [
        (1, getattr(curses, "COLOR_CYAN")),  # header
        (2, getattr(curses, "COLOR_GREEN")),  # success
        (3, getattr(curses, "COLOR_YELLOW")),  # warning
        (4, getattr(curses, "COLOR_RED")),  # error/high
        (5, getattr(curses, "COLOR_MAGENTA")),  # accent
        (6, getattr(curses, "COLOR_BLUE")),  # divider/meta
    ]

    for pair_id, fg in pair_defs:
        try:
            getattr(curses, "init_pair")(pair_id, int(fg), -1)
        except Exception:
            continue

    try:
        theme["header"] = int(getattr(curses, "color_pair")(1)) | int(
            getattr(curses, "A_BOLD")
        )
        theme["success"] = int(getattr(curses, "color_pair")(2))
        theme["warning"] = int(getattr(curses, "color_pair")(3))
        theme["error"] = int(getattr(curses, "color_pair")(4))
        theme["accent"] = int(getattr(curses, "color_pair")(5))
        theme["meta"] = int(getattr(curses, "color_pair")(6))
    except Exception:
        return {}
    return theme


def _draw_interactive_tui_frame(
    *,
    stdscr: object,
    run_dir: Path,
    snapshot: dict[str, object],
    candidates: list[dict[str, object]],
    candidate_groups: list[dict[str, object]],
    selected_index: int,
    list_limit: int,
    detail_mode: str = "candidate",
    theme: dict[str, int] | None = None,
) -> None:
    import curses

    win = cast("curses._CursesWindow", stdscr)
    win.erase()
    max_y, max_x = win.getmaxyx()
    if max_y < 14 or max_x < 72:
        _safe_curses_addstr(
            win,
            y=0,
            x=0,
            text="Terminal too small (need >=72x14). Resize and retry.",
        )
        win.refresh()
        return

    theme = theme or {}

    def _attr(name: str, *, bold: bool = False) -> int:
        base = int(theme.get(name, 0))
        if bold:
            base |= curses.A_BOLD
        return base

    if not candidate_groups:
        candidate_groups = _collect_tui_candidate_groups(candidates)

    profile = _short_text(snapshot.get("profile"), max_len=24) or "unknown"
    report_status = _short_text(snapshot.get("report_status"), max_len=20) or "unknown"
    gate_passed_text = (
        _short_text(snapshot.get("gate_passed_text"), max_len=16) or "unknown"
    )
    llm_status = _short_text(snapshot.get("llm_status"), max_len=20) or "unknown"
    verdict_state = _short_text(snapshot.get("verdict_state"), max_len=40) or "unknown"
    reason_codes = cast(list[str], snapshot.get("reason_codes", []))
    high = _as_int(snapshot.get("high"))
    medium = _as_int(snapshot.get("medium"))
    low = _as_int(snapshot.get("low"))
    chain_backed = _as_int(snapshot.get("chain_backed"))
    candidate_count = _as_int(snapshot.get("candidate_count"))
    verifier_artifacts = cast(
        dict[str, object], snapshot.get("verifier_artifacts", {})
    )
    chain_bundle_index = cast(
        dict[str, str], snapshot.get("chain_bundle_index", {})
    )
    dynamic_missing = cast(list[str], verifier_artifacts.get("dynamic_missing_refs", []))
    dynamic_total = len(cast(list[str], verifier_artifacts.get("dynamic_required_refs", [])))
    dynamic_present = max(0, dynamic_total - len(dynamic_missing))
    exploit_bundle_refs = cast(list[str], verifier_artifacts.get("exploit_bundle_refs", []))
    verified_chain_present = bool(verifier_artifacts.get("verified_chain_present", False))
    runtime_model = cast(dict[str, object], snapshot.get("runtime_model", {}))
    runtime_summary = cast(dict[str, object], runtime_model.get("summary", {}))
    runtime_available = bool(runtime_model.get("available"))
    asset_inventory = cast(dict[str, object], snapshot.get("asset_inventory", {}))
    threat_model = cast(dict[str, object], snapshot.get("threat_model", {}))
    runtime_health = cast(dict[str, object], snapshot.get("runtime_health", {}))
    runtime_protocol_counts_any = runtime_summary.get("service_count_by_protocol", {})
    runtime_protocol_counts = (
        cast(dict[str, int], runtime_protocol_counts_any)
        if isinstance(runtime_protocol_counts_any, dict)
        else {}
    )
    runtime_system_map_any = runtime_summary.get("runtime_system_map", [])
    runtime_system_map = (
        [cast(dict[str, object], x) for x in cast(list[object], runtime_system_map_any)]
        if isinstance(runtime_system_map_any, list)
        else []
    )
    runtime_host_services_any = runtime_summary.get("host_service_counts", {})
    runtime_host_services = (
        cast(dict[str, int], runtime_host_services_any)
        if isinstance(runtime_host_services_any, dict)
        else {}
    )

    _safe_curses_addstr(
        win,
        y=0,
        x=0,
        text=f"AIEdge Interactive TUI :: {run_dir.name}",
        attr=_attr("header"),
    )
    _safe_curses_addstr(
        win,
        y=1,
        x=0,
        text=(
            f"status  profile:{profile}  report:{report_status}(gate={gate_passed_text})  "
            f"llm:{llm_status}"
        ),
        attr=_attr("accent"),
    )
    verdict_upper = verdict_state.upper()
    verdict_attr = _attr("warning")
    if "VERIFIED" in verdict_upper:
        verdict_attr = _attr("success", bold=True)
    elif "FAILED" in verdict_upper:
        verdict_attr = _attr("error", bold=True)
    _safe_curses_addstr(
        win,
        y=2,
        x=0,
        text=(
            f"verdict {verdict_state}"
            + (
                f"  |  reason: {', '.join(reason_codes[:2])}"
                + (f" (+{len(reason_codes) - 2})" if len(reason_codes) > 2 else "")
                if reason_codes
                else "  |  reason: -"
            )
        ),
        attr=verdict_attr,
    )
    _safe_curses_addstr(
        win,
        y=3,
        x=0,
        text=(
            f"scope   candidates:{candidate_count}  high:{high}  medium:{medium}  low:{low}  "
            f"chain_backed:{chain_backed}"
        ),
        attr=_attr("accent"),
    )
    proof_attr = (
        _attr("success")
        if dynamic_total > 0 and dynamic_present == dynamic_total
        else _attr("warning")
    )
    _safe_curses_addstr(
        win,
        y=4,
        x=0,
        text=(
            f"proof   dynamic:{dynamic_present}/{dynamic_total}  "
            f"verified_chain:{'on' if verified_chain_present else 'off'}  "
            f"bundles:{len(exploit_bundle_refs)}"
        ),
        attr=proof_attr,
    )
    _safe_curses_addstr(
        win,
        y=5,
        x=0,
        text=(
            f"runtime {'on' if runtime_available else 'off'}  "
            f"hosts:{_as_int(runtime_summary.get('hosts'))}  "
            f"services:{_as_int(runtime_summary.get('services'))}  "
            f"components:{_as_int(runtime_summary.get('components'))}  "
            f"D+E:{_as_int(runtime_summary.get('rows_dynamic_exploit'))}  "
            f"D:{_as_int(runtime_summary.get('rows_dynamic'))} "
            f"E:{_as_int(runtime_summary.get('rows_exploit'))} "
            f"V:{_as_int(runtime_summary.get('rows_verified_chain'))}"
        ),
        attr=_attr("meta"),
    )
    proto_text_runtime = ", ".join(
        f"{k}:{v}" for k, v in _sorted_count_pairs(runtime_protocol_counts, limit=4)
    ) or "-"
    map_text = ", ".join(
        f"{k}->{v}" for k, v in _sorted_count_pairs(runtime_host_services, limit=4)
    ) or "-"
    if proto_text_runtime:
        _safe_curses_addstr(
            win,
            y=6,
            x=0,
            text=f"runtime_proto:{proto_text_runtime}",
            attr=_attr("meta"),
        )
    if map_text:
        _safe_curses_addstr(
            win,
            y=7,
            x=0,
            text=f"runtime_map:{map_text}",
            attr=_attr("meta"),
        )
    asset_protocol_counts_any = asset_inventory.get("endpoint_protocol_counts")
    asset_protocol_counts = (
        cast(dict[str, int], asset_protocol_counts_any)
        if isinstance(asset_protocol_counts_any, dict)
        else {}
    )
    asset_open_ports_any = asset_inventory.get("open_ports")
    asset_open_ports = (
        [x for x in cast(list[object], asset_open_ports_any) if isinstance(x, str)]
        if isinstance(asset_open_ports_any, list)
        else []
    )
    proto_text = ",".join(
        f"{k}:{v}" for k, v in _sorted_count_pairs(asset_protocol_counts, limit=2)
    ) or "-"
    asset_scan_cov = _as_float(asset_inventory.get("scan_coverage_pct"), default=0.0)
    blockers_any = runtime_health.get("blockers")
    blockers_count = (
        len([x for x in cast(list[object], blockers_any) if isinstance(x, str)])
        if isinstance(blockers_any, list)
        else 0
    )
    health_line = 8
    _safe_curses_addstr(
        win,
        y=health_line,
        x=0,
        text=(
            f"health  state:{_short_text(runtime_health.get('state'), max_len=12) or '-'}  "
            f"dyn:{_short_text(runtime_health.get('dynamic_status'), max_len=12) or '-'}  "
            f"emu:{_short_text(runtime_health.get('emulation_status'), max_len=12) or '-'}  "
            f"boot:{'ok' if bool(runtime_health.get('boot_success')) else 'no'}  "
            f"blockers:{blockers_count}"
        ),
        attr=_attr("warning"),
    )
    _safe_curses_addstr(
        win,
        y=health_line + 1,
        x=0,
        text=(
            f"assets  files:{_as_int(asset_inventory.get('files'))}  "
            f"bins:{_as_int(asset_inventory.get('binaries'))}  "
            f"svcs:{_as_int(asset_inventory.get('service_candidates'))}  "
            f"proto:{proto_text}  "
            f"ports_open:{len(asset_open_ports)}/{_as_int(asset_inventory.get('probed_ports'))}  "
            f"scan_cov:{asset_scan_cov:.0f}%"
        ),
        attr=_attr("meta"),
    )
    threat_row_line = 9
    tm_available = bool(threat_model.get("available"))
    tm_status = _short_text(threat_model.get("status"), max_len=12) or "-"
    tm_threats = _as_int(threat_model.get("threat_count"))
    tm_unknowns = _as_int(threat_model.get("unknown_count"))
    tm_mitigations = _as_int(threat_model.get("mitigation_count"))
    tm_categories_any = threat_model.get("category_counts")
    tm_categories = (
        cast(dict[str, int], tm_categories_any)
        if isinstance(tm_categories_any, dict)
        else {}
    )
    tm_category_text = ",".join(
        f"{k}:{v}" for k, v in _sorted_count_pairs(tm_categories, limit=2)
    ) or "-"
    tm_attr = _attr("success") if tm_available and tm_threats > 0 else _attr("warning")
    _safe_curses_addstr(
        win,
        y=threat_row_line,
        x=0,
        text=(
            f"threat  {'on' if tm_available else 'off'}  status:{tm_status}  "
            f"threats:{tm_threats}  unknowns:{tm_unknowns}  mitigations:{tm_mitigations}  "
            f"top:{tm_category_text}"
        ),
        attr=tm_attr,
    )
    status_row = max_y - 1
    if runtime_system_map:
        map_line = threat_row_line + 1
        for map_entry in runtime_system_map[: max(1, max_y - map_line - 1)]:
            host_label = _short_text(map_entry.get("host"), max_len=24) or "unknown"
            service_count = _as_int(map_entry.get("service_count"))
            component_count = _as_int(map_entry.get("component_count"))
            services_any = map_entry.get("services")
            service_values = (
                [x for x in cast(list[object], services_any) if isinstance(x, str)]
                if isinstance(services_any, list)
                else []
            )
            service_sample = ", ".join(service_values[:2]) or "-"
            _safe_curses_addstr(
                win,
                y=map_line,
                x=0,
                text=(
                    f"runtime_map {host_label:<24} svcs={service_count:<3} "
                    f"daemons={component_count:<3} {service_sample}"
                ),
                attr=_attr("meta"),
            )
            map_line += 1
        divider_y = max(map_line, threat_row_line + 1)
    else:
        divider_y = threat_row_line

    divider_y = min(divider_y, status_row - 1)

    _safe_curses_addstr(
        win,
        y=divider_y,
        x=0,
        text="-" * (max_x - 1),
        attr=_attr("meta"),
    )

    list_top = divider_y + 1
    list_height = max(3, status_row - list_top)
    list_body_height = max(1, list_height - 1)
    left_width = max(42, int(max_x * 0.52))
    left_width = min(left_width, max_x - 24)
    right_x = left_width + 2

    _safe_curses_addstr(
        win,
        y=list_top - 1,
        x=0,
        text=(
            "[Candidate Groups] "
            f"showing {min(list_limit, len(candidate_groups))}/{len(candidate_groups)}"
        ),
        attr=_attr("header"),
    )
    detail_title = {
        "threat": "Threat Model",
        "runtime": "Runtime Model",
        "asset": "Asset & Protocol Inventory",
    }.get(detail_mode, "Details")
    _safe_curses_addstr(
        win,
        y=list_top - 1,
        x=right_x,
        text=f"[{detail_title}]",
        attr=_attr("header"),
    )
    _safe_curses_addstr(
        win,
        y=list_top,
        x=0,
        text="#  P  Score  Hits  Family                      Sig",
        attr=_attr("accent", bold=True),
    )
    _safe_curses_addstr(
        win,
        y=list_top,
        x=right_x,
        text="Sig: S=static C=chain D=dynamic E=bundle V=verified",
        attr=_attr("meta"),
    )
    for y in range(list_top - 1, status_row):
        _safe_curses_addstr(win, y=y, x=left_width + 1, text="|", attr=_attr("meta"))

    shown_groups = candidate_groups[:list_limit]
    if not shown_groups:
        _safe_curses_addstr(win, y=list_top + 1, x=0, text="(no candidate groups)")
    else:
        selected_index = max(0, min(selected_index, len(shown_groups) - 1))
        if selected_index < list_body_height // 2:
            start = 0
        else:
            start = selected_index - (list_body_height // 2)
        max_start = max(0, len(shown_groups) - list_body_height)
        start = min(start, max_start)
        stop = min(len(shown_groups), start + list_body_height)

        for row, idx in enumerate(range(start, stop), start=1):
            group = shown_groups[idx]
            pr = _short_text(group.get("priority"), max_len=12) or "unknown"
            pr_tag = pr[:1].upper() if pr else "?"
            score = _as_float(group.get("max_score"))
            family = _short_text(group.get("family"), max_len=24) or "unknown"
            path_count = _as_int(group.get("path_count"))
            representative_id = _short_text(group.get("representative_id"), max_len=120)
            representative: dict[str, object] | None = None
            if representative_id:
                for item in candidates:
                    if (
                        _short_text(item.get("candidate_id"), max_len=120)
                        == representative_id
                    ):
                        representative = item
                        break
            signal_items = ["static"]
            if representative is not None:
                signal_text = ",".join(
                    _candidate_verification_signals(
                        representative,
                        chain_bundle_index=chain_bundle_index,
                        verified_chain_present=verified_chain_present,
                    )
                )
                if signal_text:
                    signal_items = signal_text.split(",")
            signal_badge = _candidate_signal_badge(signal_items)
            family_cell = _short_text(family, max_len=26)
            line = (
                f"{idx + 1:02d} {pr_tag:>2} {score:>6.3f}  x{path_count:<2}  "
                f"{family_cell:<26}  [{signal_badge}]"
            )
            max_line_width = max(18, left_width - 3)
            if len(line) > max_line_width:
                line = line[:max_line_width]
            row_attr = 0
            if pr_tag == "H":
                row_attr = _attr("error")
            elif pr_tag == "M":
                row_attr = _attr("warning")
            elif pr_tag == "L":
                row_attr = _attr("success")
            else:
                row_attr = _attr("meta")
            attr = (row_attr | curses.A_REVERSE | curses.A_BOLD) if idx == selected_index else row_attr
            _safe_curses_addstr(win, y=list_top + row, x=0, text=line, attr=attr)

    details: list[str] = []
    right_width = max(24, max_x - right_x - 3)

    def _wrap_detail(text: str, *, prefix: str = "") -> list[str]:
        wrapped = textwrap.wrap(
            text,
            width=max(12, right_width - len(prefix)),
            break_long_words=False,
            break_on_hyphens=False,
        )
        if not wrapped:
            return [prefix]
        return [prefix + part for part in wrapped]

    dynamic_protocols_any = asset_inventory.get("dynamic_protocol_counts")
    dynamic_protocols = (
        cast(dict[str, int], dynamic_protocols_any)
        if isinstance(dynamic_protocols_any, dict)
        else {}
    )
    dynamic_states_any = asset_inventory.get("dynamic_state_counts")
    dynamic_states = (
        cast(dict[str, int], dynamic_states_any)
        if isinstance(dynamic_states_any, dict)
        else {}
    )
    endpoint_types_any = asset_inventory.get("endpoint_type_counts")
    endpoint_types = (
        cast(dict[str, int], endpoint_types_any)
        if isinstance(endpoint_types_any, dict)
        else {}
    )
    interfaces_any = asset_inventory.get("interfaces")
    interfaces = (
        [x for x in cast(list[object], interfaces_any) if isinstance(x, str)]
        if isinstance(interfaces_any, list)
        else []
    )
    service_paths_any = asset_inventory.get("service_paths")
    service_paths = (
        [x for x in cast(list[object], service_paths_any) if isinstance(x, str)]
        if isinstance(service_paths_any, list)
        else []
    )
    top_daemons_any = asset_inventory.get("top_daemons")
    top_daemons = (
        [x for x in cast(list[object], top_daemons_any) if isinstance(x, str)]
        if isinstance(top_daemons_any, list)
        else []
    )

    if detail_mode == "threat":
        details.append("view: threat model (c: candidates)")
        details.append("")
        tm = cast(dict[str, object], snapshot.get("threat_model", {}))
        if not bool(tm.get("available")):
            details.append("threat_model: unavailable")
            details.append("hint: run stage threat_model")
        else:
            details.append(
                f"status={_short_text(tm.get('status'), max_len=12) or '-'}  "
                f"threats={_as_int(tm.get('threat_count'))}  "
                f"unknowns={_as_int(tm.get('unknown_count'))}"
            )
            details.append(
                f"mitigations={_as_int(tm.get('mitigation_count'))}  "
                f"assumptions={_as_int(tm.get('assumption_count'))}"
            )
            details.append(
                f"attack_surface_items={_as_int(tm.get('attack_surface_items'))}"
            )
            tm_cat_any = tm.get("category_counts")
            tm_cat = cast(dict[str, int], tm_cat_any) if isinstance(tm_cat_any, dict) else {}
            cat_text = ", ".join(
                f"{k}:{v}" for k, v in _sorted_count_pairs(tm_cat, limit=4)
            ) or "-"
            details.extend(_wrap_detail("categories: " + cat_text))
            details.append("")
            tm_top_any = tm.get("top_threats")
            tm_top = (
                [x for x in cast(list[object], tm_top_any) if isinstance(x, str)]
                if isinstance(tm_top_any, list)
                else []
            )
            details.append("top_threats:")
            if tm_top:
                for sample in tm_top[:3]:
                    details.extend(_wrap_detail(sample, prefix="  - "))
            else:
                details.append("  - (none)")

            tm_lim_any = tm.get("limitations")
            tm_lim = (
                [x for x in cast(list[object], tm_lim_any) if isinstance(x, str)]
                if isinstance(tm_lim_any, list)
                else []
            )
            if tm_lim:
                details.append("")
                details.append("limitations:")
                for item in tm_lim[:3]:
                    details.extend(_wrap_detail(item, prefix="  - "))

        details.append("")
        details.append("system context:")
        details.append(
            f"runtime hosts={_as_int(runtime_summary.get('hosts'))} "
            f"services={_as_int(runtime_summary.get('services'))} "
            f"components={_as_int(runtime_summary.get('components'))}"
        )
        details.append(
            f"assets endpoints={_as_int(asset_inventory.get('endpoint_total'))} "
            f"daemons={_as_int(asset_inventory.get('service_candidates'))} "
            f"open_ports={len(asset_open_ports)}"
        )
    elif detail_mode == "runtime":
        details.append("view: runtime model (c: candidates)")
        details.append("")
        runtime_rows = cast(list[object], runtime_model.get("rows", []))
        runtime_system_map_local = runtime_summary.get("runtime_system_map", [])
        runtime_system_map_local_rows = (
            [cast(dict[str, object], x) for x in cast(list[object], runtime_system_map_local)]
            if isinstance(runtime_system_map_local, list)
            else []
        )
        details.append(
            f"status={_short_text(runtime_model.get('status'), max_len=12) or '-'}  "
            f"hosts={_as_int(runtime_summary.get('hosts'))}  "
            f"services={_as_int(runtime_summary.get('services'))}  "
            f"components={_as_int(runtime_summary.get('components'))}  "
            f"rows={len(runtime_rows)}"
        )
        details.append(
            f"evidence: "
            f"D={_as_int(runtime_summary.get('rows_dynamic'))}, "
            f"E={_as_int(runtime_summary.get('rows_exploit'))}, "
            f"V={_as_int(runtime_summary.get('rows_verified_chain'))}, "
            f"D+E={_as_int(runtime_summary.get('rows_dynamic_exploit'))}"
        )
        runtime_protocol_counts_any = runtime_summary.get("service_count_by_protocol", {})
        runtime_protocol_counts = (
            cast(dict[str, int], runtime_protocol_counts_any)
            if isinstance(runtime_protocol_counts_any, dict)
            else {}
        )
        if runtime_protocol_counts:
            details.append(
                "protocols: "
                + ", ".join(
                    f"{k}:{v}" for k, v in _sorted_count_pairs(runtime_protocol_counts, limit=6)
                )
            )
        if runtime_system_map_local_rows:
            details.append("")
            details.append("system map:")
            for row in runtime_system_map_local_rows[: max(3, min(6, right_width // 16))]:
                host = _short_text(row.get("host"), max_len=24)
                service_count = _as_int(row.get("service_count"))
                component_count = _as_int(row.get("component_count"))
                services_any = row.get("services")
                service_values = (
                    [x for x in cast(list[object], services_any) if isinstance(x, str)]
                    if isinstance(services_any, list)
                    else []
                )
                details.append(
                    f" - {host:<18} svcs:{service_count:>2} daemons:{component_count:>2} "
                    f"{', '.join(service_values[:3])}"
                )
        if runtime_rows:
            details.append("")
            details.append("top_communications:")
            for row_any in runtime_rows[: max(6, min(10, right_width // 12))]:
                row = cast(dict[str, object], row_any)
                row_host = _short_text(row.get("host"), max_len=16)
                row_service_host = _short_text(row.get("service_host"), max_len=16)
                row_port = _as_int(row.get("port"))
                row_protocol = (_short_text(row.get("protocol"), max_len=8) or "tcp").upper()
                row_badge = _short_text(row.get("evidence_badge"), max_len=8) or "S"
                row_components = row.get("components")
                if not isinstance(row_components, list):
                    row_components = []
                component_text = ", ".join(_short_text(v, max_len=20) for v in row_components[:2])
                if not component_text:
                    component_text = "unmapped"
                evidence_signals = row.get("evidence_signals")
                if not isinstance(evidence_signals, list):
                    evidence_signals = []
                evidence_text = ",".join(
                    sorted(
                        str(x)
                        for x in cast(list[object], evidence_signals)
                        if isinstance(x, str)
                    )
                )
                if not evidence_text:
                    evidence_text = row_badge
                evidence_counts = (
                    f"D{_as_int(row.get('dynamic_evidence_count'))}"
                    f"/E{_as_int(row.get('exploit_evidence_count'))}"
                    f"/V{_as_int(row.get('verified_chain_evidence_count'))}"
                )
                svc = f"{row_service_host}:{row_port}/{row_protocol}"
                details.extend(
                    _wrap_detail(
                        f" - {row_host: <15} => {svc: <16} [{row_badge}] "
                        f"{evidence_counts} {component_text} ({evidence_text})"
                    )
                )
        else:
            details.append("")
            details.append("communication matrix: unavailable or empty")
    elif detail_mode == "asset":
        details.append("view: asset inventory (c: candidates)")
        details.append("")
        details.append(
            f"files={_as_int(asset_inventory.get('files'))}  "
            f"binaries={_as_int(asset_inventory.get('binaries'))}  "
            f"configs={_as_int(asset_inventory.get('configs'))}  "
            f"service_candidates={_as_int(asset_inventory.get('service_candidates'))}"
        )
        kind_pairs = cast(
            dict[str, int],
            asset_inventory.get("service_kind_counts", {})
            if isinstance(asset_inventory.get("service_kind_counts"), dict)
            else {},
        )
        if kind_pairs:
            kind_text = ", ".join(
                f"{k}:{v}" for k, v in _sorted_count_pairs(kind_pairs, limit=6)
            )
            details.append(f"service_kinds={kind_text}")
        if endpoint_types:
            endpoint_text = ", ".join(
                f"{k}:{v}" for k, v in _sorted_count_pairs(endpoint_types, limit=5)
            )
            details.append(f"endpoint_types={endpoint_text}")
        details.append(
            f"open_ports={len(asset_open_ports)}  "
            f"probed={_as_int(asset_inventory.get('probed_ports'))}  "
            f"scan_strategy={_short_text(asset_inventory.get('scan_strategy'), max_len=16)}"
        )
        if asset_open_ports:
            details.append("open_ports=" + ", ".join(asset_open_ports[:6]))
        proto_pairs = _sorted_count_pairs(
            cast(
                dict[str, int],
                dynamic_protocols if isinstance(dynamic_protocols, dict) else {},
            ),
            limit=4,
        )
        if proto_pairs:
            details.append(
                "dynamic_proto="
                + ", ".join(f"{k}:{v}" for k, v in proto_pairs)
            )
        state_pairs = _sorted_count_pairs(
            cast(
                dict[str, int],
                dynamic_states if isinstance(dynamic_states, dict) else {},
            ),
            limit=4,
        )
        if state_pairs:
            details.append(
                "dynamic_state="
                + ", ".join(f"{k}:{v}" for k, v in state_pairs)
            )
        if interfaces:
            details.append("interfaces=" + ", ".join(interfaces[:5]))
        daemon_paths = [
            x for x in cast(list[object], service_paths) if isinstance(x, str)
        ]
        if daemon_paths:
            details.append(
                "daemon_evidence="
                + ", ".join(_path_tail(x, max_segments=5, max_len=96) for x in daemon_paths[:4])
            )
        if top_daemons:
            details.append("top_daemons=" + ", ".join(top_daemons[:6]))
    elif shown_groups:
        selected = cast(dict[str, object], shown_groups[selected_index])
        representative_id = _short_text(selected.get("representative_id"), max_len=120)
        representative = None
        if representative_id:
            for item in candidates:
                if _short_text(item.get("candidate_id"), max_len=120) == representative_id:
                    representative = item
                    break
        path_signature = _short_text(selected.get("path_signature"), max_len=72)

        details.append(
            f"group G{selected_index + 1:02d}  "
            f"priority={_short_text(selected.get('priority'), max_len=10)}  "
            f"family={_short_text(selected.get('family'), max_len=28)}"
        )
        details.append(
            f"score={_as_float(selected.get('max_score')):.3f}  hits={_as_int(selected.get('path_count'))}"
        )
        if path_signature:
            details.extend(_wrap_detail(f"path: {path_signature}"))
        details.append("")

        if representative is not None:
            details.extend(
                _wrap_detail(
                    "candidate_id: "
                    + (
                        _short_text(
                            representative.get("candidate_id"),
                            max_len=max(20, right_width - 2),
                        )
                        or "(none)"
                    )
                )
            )
            rep_chain_id = _short_text(representative.get("chain_id"), max_len=48)
            if rep_chain_id:
                details.append(f"chain_id: {rep_chain_id}")
            details.append(
                "source: "
                + (
                    f"{_short_text(representative.get('source'), max_len=16) or 'unknown'}"
                )
            )

            selected_signals = _candidate_verification_signals(
                representative,
                chain_bundle_index=chain_bundle_index,
                verified_chain_present=verified_chain_present,
            )
            details.append(
                "signals: "
                + (
                    ",".join(selected_signals)
                    if selected_signals
                    else "static"
                )
                + f" [{_candidate_signal_badge(selected_signals)}]"
            )
            details.append("")

            representative_path = (
                _path_tail(
                    representative.get("path"),
                    max_segments=6,
                    max_len=max(24, right_width - 2),
                )
                or "(none)"
            )
            details.extend(_wrap_detail("path: " + representative_path))

            attack_text = _short_text(
                representative.get("attack_hypothesis"),
                max_len=max(24, right_width * 3),
            ) or "(none)"
            details.append("attack:")
            details.extend(_wrap_detail(attack_text, prefix="  "))

            impacts_any = representative.get("expected_impact")
            if isinstance(impacts_any, list):
                impacts = [x for x in cast(list[object], impacts_any) if isinstance(x, str)]
            else:
                impacts = []
            impact_text = _short_text(
                impacts[0] if impacts else "(none)",
                max_len=max(24, right_width * 2),
            )
            details.append("impact:")
            details.extend(_wrap_detail(impact_text, prefix="  "))

            next_text = _candidate_next_step_text(representative) or "(none)"
            details.append("next:")
            details.extend(_wrap_detail(next_text, prefix="  "))

            refs = _candidate_evidence_refs(
                representative,
                chain_bundle_index=chain_bundle_index,
                include_chain_bundles=True,
            )
            details.append("evidence_refs:")
            if refs:
                for ref in refs[:3]:
                    details.extend(
                        _wrap_detail(
                            _short_text(ref, max_len=max(20, right_width * 2)),
                            prefix="  - ",
                        )
                    )
            else:
                details.append("  - (none)")
        else:
            details.append("No representative candidate available.")
    else:
        details.append("No candidate groups available.")

    truncated_detail_lines = max(0, len(details) - list_height)
    visible_detail_rows = list_height if truncated_detail_lines == 0 else max(1, list_height - 1)
    for i, line in enumerate(details[:visible_detail_rows]):
        detail_attr = 0
        if line.startswith("attack:") or line.startswith("impact:"):
            detail_attr = _attr("warning", bold=True)
        elif line.startswith("next:"):
            detail_attr = _attr("accent", bold=True)
        elif line.startswith("evidence_refs:"):
            detail_attr = _attr("meta", bold=True)
        elif line.startswith("  - "):
            detail_attr = _attr("meta")
        elif (
            line.startswith("candidate_id:")
            or line.startswith("group G")
            or line.startswith("view:")
            or line.startswith("status=")
            or line.startswith("threat_model:")
        ):
            detail_attr = _attr("header")
        _safe_curses_addstr(
            win,
            y=list_top + i,
            x=right_x,
            text=line,
            attr=detail_attr,
        )
    if truncated_detail_lines > 0:
        _safe_curses_addstr(
            win,
            y=list_top + visible_detail_rows,
            x=right_x,
            text=f"... (+{truncated_detail_lines} more lines)",
            attr=_attr("meta"),
        )

    _safe_curses_addstr(
        win,
        y=status_row,
        x=0,
        text="j/k or ↑/↓ move | g/G top/bottom | c candidate | t threat | m runtime | a assets | r refresh | q quit",
        attr=_attr("meta"),
    )
    win.refresh()


def _run_tui_interactive(*, run_dir: Path, limit: int, interval_s: float) -> int:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("Interactive mode requires a TTY (stdin/stdout).", file=sys.stderr)
        return 20

    try:
        import curses
    except Exception as e:
        print(f"Interactive mode unavailable: {e}", file=sys.stderr)
        return 20

    refresh_interval = max(0.3, float(interval_s))

    def _curses_main(stdscr: object) -> int:
        win = cast("curses._CursesWindow", stdscr)
        win.nodelay(True)
        win.keypad(True)
        try:
            curses.curs_set(0)
        except Exception:
            pass
        theme = _build_tui_color_theme(curses_mod=curses)

        selected_index = 0
        detail_mode = "candidate"
        snapshot = _build_tui_snapshot(run_dir=run_dir)
        last_refresh = time.monotonic()
        force_refresh = False

        while True:
            now = time.monotonic()
            if force_refresh or (now - last_refresh) >= refresh_interval:
                snapshot = _build_tui_snapshot(run_dir=run_dir)
                candidate_groups_now = cast(
                    list[dict[str, object]], snapshot.get("candidate_groups", [])
                )
                if candidate_groups_now:
                    selected_index = min(
                        selected_index, min(limit, len(candidate_groups_now)) - 1
                    )
                else:
                    selected_index = 0
                last_refresh = now
                force_refresh = False

            candidates = cast(list[dict[str, object]], snapshot.get("candidates", []))
            candidate_groups = cast(
                list[dict[str, object]], snapshot.get("candidate_groups", [])
            )
            _draw_interactive_tui_frame(
                stdscr=win,
                run_dir=run_dir,
                snapshot=snapshot,
                candidates=candidates,
                candidate_groups=candidate_groups,
                selected_index=selected_index,
                list_limit=limit,
                detail_mode=detail_mode,
                theme=theme,
            )

            key = win.getch()
            if key == -1:
                time.sleep(0.05)
                continue
            if key in (ord("q"), ord("Q")):
                return 0
            selectable_count = min(limit, len(candidate_groups))
            if key in (ord("j"), curses.KEY_DOWN):
                if candidate_groups and selectable_count > 0:
                    selected_index = min(selected_index + 1, selectable_count - 1)
                continue
            if key in (ord("k"), curses.KEY_UP):
                if candidate_groups:
                    selected_index = max(0, selected_index - 1)
                continue
            if key in (ord("g"),):
                selected_index = 0
                continue
            if key in (ord("G"),):
                if candidate_groups:
                    selected_index = selectable_count - 1
                continue
            if key in (ord("r"), ord("R")):
                force_refresh = True
                continue
            if key in (ord("t"), ord("T")):
                detail_mode = "threat"
                continue
            if key in (ord("m"), ord("M")):
                detail_mode = "runtime"
                continue
            if key in (ord("a"), ord("A")):
                detail_mode = "asset"
                continue
            if key in (ord("c"), ord("C")):
                detail_mode = "candidate"
                continue

    try:
        return int(curses.wrapper(_curses_main))
    except KeyboardInterrupt:
        print("")
        return 0


def _run_tui(
    *,
    run_dir_path: str,
    limit: int,
    mode: str,
    interval_s: float,
    # kept for compatibility with old CLI usage; mode is authoritative.
    watch: bool,
    interactive: bool,
) -> int:
    run_dir = Path(run_dir_path).expanduser().resolve()
    if not run_dir.is_dir():
        print(f"Run directory not found: {run_dir}", file=sys.stderr)
        return 20
    if limit <= 0:
        print("Invalid --limit value: must be > 0", file=sys.stderr)
        return 20
    if interval_s <= 0:
        print("Invalid --interval-s value: must be > 0", file=sys.stderr)
        return 20
    effective_mode = mode
    if interactive and watch:
        print("Invalid flags: --interactive and --watch cannot be combined", file=sys.stderr)
        return 20
    if interactive:
        effective_mode = "interactive"
    elif watch:
        effective_mode = "watch"
    elif mode not in ("auto", "once", "watch", "interactive"):
        print("Invalid --mode value", file=sys.stderr)
        return 20

    if effective_mode == "auto":
        effective_mode = (
            "interactive"
            if sys.stdin.isatty() and sys.stdout.isatty()
            else "once"
        )

    if effective_mode == "interactive":
        return _run_tui_interactive(run_dir=run_dir, limit=limit, interval_s=interval_s)

    supports_ansi = _tui_ansi_supported()

    def render_once() -> int:
        lines = _build_tui_snapshot_lines(run_dir=run_dir, limit=limit)
        print("\n".join(lines))
        return 0

    if effective_mode != "watch":
        return render_once()

    watch_clear = bool(
        supports_ansi
        and sys.stdout.isatty()
        and os.environ.get("TERM", "dumb").lower() != "dumb"
    )
    last_snapshot: str | None = None

    try:
        while True:
            lines = _build_tui_snapshot_lines(run_dir=run_dir, limit=limit)
            snapshot = "\n".join(lines)
            if snapshot != last_snapshot:
                if watch_clear:
                    # ANSI clear+home for lightweight terminal dashboard refresh.
                    print("\x1b[2J\x1b[H" + snapshot, end="", flush=True)
                else:
                    if last_snapshot is not None:
                        print("\n" + ("-" * 88))
                    print(snapshot, flush=True)
                last_snapshot = snapshot
            time.sleep(float(interval_s))
    except KeyboardInterrupt:
        print("")
        return 0


def _looks_like_run_dir(path: Path) -> bool:
    if not path.is_dir():
        return False
    manifest_ok = (path / "manifest.json").is_file()
    report_ok = (path / "report" / "report.json").is_file() or (path / "report" / "viewer.html").is_file()
    return bool(manifest_ok and report_ok)


def _run_dir_mtime(path: Path) -> float:
    candidates = [
        path / "report" / "report.json",
        path / "report" / "analyst_digest.json",
        path / "manifest.json",
        path,
    ]
    for candidate in candidates:
        try:
            if candidate.exists():
                return float(candidate.stat().st_mtime)
        except OSError:
            continue
    return 0.0


def _discover_latest_run_dir(*, cwd: Path) -> Path | None:
    env_roots_raw = os.environ.get("AIEDGE_RUNS_DIRS", "").strip()
    env_roots = [x for x in env_roots_raw.split(os.pathsep) if x] if env_roots_raw else []
    roots: list[Path] = [Path(x).expanduser() for x in env_roots]
    roots.extend(
        [
            cwd / "aiedge-runs",
            cwd / "aiedge-8mb-runs",
            cwd,
        ]
    )

    seen_roots: set[str] = set()
    discovered: list[Path] = []
    for root in roots:
        try:
            root_resolved = root.resolve()
        except Exception:
            root_resolved = root
        root_key = str(root_resolved)
        if root_key in seen_roots:
            continue
        seen_roots.add(root_key)

        if not root_resolved.is_dir():
            continue

        if _looks_like_run_dir(root_resolved):
            discovered.append(root_resolved)

        try:
            children = list(root_resolved.iterdir())
        except OSError:
            continue

        for child in children:
            if not child.is_dir():
                continue
            if _looks_like_run_dir(child):
                discovered.append(child)

    if not discovered:
        return None

    discovered.sort(
        key=lambda p: (_run_dir_mtime(p), str(p)),
        reverse=True,
    )
    return discovered[0]


def _resolve_tui_run_dir(raw: str | None) -> Path | None:
    token = (raw or "").strip()
    if token == ".":
        cwd = Path.cwd().resolve()
        if _looks_like_run_dir(cwd):
            return cwd
    latest_tokens = {"", "latest", "@latest"}
    if token not in latest_tokens:
        return Path(token).expanduser().resolve()
    return _discover_latest_run_dir(cwd=Path.cwd())


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_manifest_track_marker(manifest_path: Path) -> None:
    obj_any = cast(object, json.loads(manifest_path.read_text(encoding="utf-8")))
    if not isinstance(obj_any, dict):
        raise ValueError("manifest.json is not an object")
    obj = cast(dict[str, object], obj_any)
    obj["track"] = {
        "track_id": "8mb",
        "canonical_sha256_prefix": _CANONICAL_8MB_SHA256[:12],
        "canonical_size_bytes": _CANONICAL_8MB_SIZE_BYTES,
    }
    _ = manifest_path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _write_manifest_profile_marker(
    manifest_path: Path,
    *,
    profile: str,
    exploit_gate: dict[str, str] | None,
) -> None:
    obj_any = cast(object, json.loads(manifest_path.read_text(encoding="utf-8")))
    if not isinstance(obj_any, dict):
        raise ValueError("manifest.json is not an object")
    obj = cast(dict[str, object], obj_any)
    obj["profile"] = profile
    if exploit_gate is not None:
        obj["exploit_gate"] = dict(exploit_gate)
    _ = manifest_path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _build_parser() -> argparse.ArgumentParser:
    epilog = textwrap.dedent(
        """\
        Exit codes:
          0   Success
          10  Partial success
          20  Fatal error
          30  Policy violation
        """
    )

    parser = argparse.ArgumentParser(
        prog="aiedge",
        description="Internal aiedge v1 scaffold",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = parser.add_argument(
        "--version",
        action="version",
        version=f"aiedge {__version__}",
        help="Print version and exit.",
    )
    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser(
        "analyze",
        help="Create a run directory for a firmware analysis (best-effort extraction).",
    )
    _ = analyze.add_argument(
        "input_firmware",
        help="Path to firmware binary to analyze.",
    )
    _ = analyze.add_argument(
        "--case-id",
        required=True,
        help="Case identifier recorded into the run manifest.",
    )
    _ = analyze.add_argument(
        "--ack-authorization",
        action="store_true",
        help="Acknowledge you are authorized to analyze this firmware.",
    )
    _ = analyze.add_argument(
        "--time-budget-s",
        type=int,
        default=3600,
        help="Overall pipeline time budget in seconds (default: 3600).",
    )
    _ = analyze.add_argument(
        "--open-egress",
        action="store_true",
        help="Record an override allowing full internet egress for this run.",
    )
    _ = analyze.add_argument(
        "--egress-allow",
        action="append",
        default=[],
        metavar="HOST",
        help="Add an allowed internet egress host; may be repeated.",
    )
    _ = analyze.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM probing and record deterministic skipped LLM report fields.",
    )
    _ = analyze.add_argument(
        "--profile",
        choices=["analysis", "exploit"],
        default="analysis",
        help="Execution profile (default: analysis).",
    )
    _ = analyze.add_argument(
        "--exploit-flag",
        default="",
        help="Exploit profile gate flag (required for --profile exploit).",
    )
    _ = analyze.add_argument(
        "--exploit-attestation",
        default="",
        help="Exploit profile attestation (required for --profile exploit).",
    )
    _ = analyze.add_argument(
        "--exploit-scope",
        default="",
        help="Exploit profile explicit scope string (required for --profile exploit).",
    )
    _ = analyze.add_argument(
        "--stages",
        default=None,
        help=("Comma-separated subset of stages to run (example: tooling,structure)."),
    )
    _ = analyze.add_argument(
        "--ref-md",
        default=None,
        metavar="PATH",
        help="Path to governed reference markdown context file.",
    )
    _ = analyze.add_argument(
        "--require-ref-md",
        action="store_true",
        help="Fail closed if --ref-md is missing or unreadable.",
    )
    _ = analyze.add_argument(
        "--force-retriage",
        action="store_true",
        help=(
            "Operator override: reopen duplicate-suppressed findings for retriage "
            "and emit deterministic duplicate-gate audit events."
        ),
    )

    analyze_8mb = sub.add_parser(
        "analyze-8mb",
        help=(
            "Analyze only the canonical 8MB firmware snapshot (sha256-locked); writes runs under aiedge-8mb-runs/."
        ),
    )
    _ = analyze_8mb.add_argument(
        "input_firmware",
        help=(
            "Path to firmware binary to analyze (must match canonical 8MB snapshot by sha256/size)."
        ),
    )
    _ = analyze_8mb.add_argument(
        "--case-id",
        required=True,
        help="Case identifier recorded into the run manifest.",
    )
    _ = analyze_8mb.add_argument(
        "--ack-authorization",
        action="store_true",
        help="Acknowledge you are authorized to analyze this firmware.",
    )
    _ = analyze_8mb.add_argument(
        "--time-budget-s",
        type=int,
        default=3600,
        help="Overall pipeline time budget in seconds (default: 3600).",
    )
    _ = analyze_8mb.add_argument(
        "--open-egress",
        action="store_true",
        help="Record an override allowing full internet egress for this run.",
    )
    _ = analyze_8mb.add_argument(
        "--egress-allow",
        action="append",
        default=[],
        metavar="HOST",
        help="Add an allowed internet egress host; may be repeated.",
    )
    _ = analyze_8mb.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM probing and record deterministic skipped LLM report fields.",
    )
    _ = analyze_8mb.add_argument(
        "--profile",
        choices=["analysis", "exploit"],
        default="analysis",
        help="Execution profile (default: analysis).",
    )
    _ = analyze_8mb.add_argument(
        "--exploit-flag",
        default="",
        help="Exploit profile gate flag (required for --profile exploit).",
    )
    _ = analyze_8mb.add_argument(
        "--exploit-attestation",
        default="",
        help="Exploit profile attestation (required for --profile exploit).",
    )
    _ = analyze_8mb.add_argument(
        "--exploit-scope",
        default="",
        help="Exploit profile explicit scope string (required for --profile exploit).",
    )
    _ = analyze_8mb.add_argument(
        "--stages",
        default=None,
        help=("Comma-separated subset of stages to run (example: tooling,structure)."),
    )
    _ = analyze_8mb.add_argument(
        "--ref-md",
        default=None,
        metavar="PATH",
        help="Path to governed reference markdown context file.",
    )
    _ = analyze_8mb.add_argument(
        "--require-ref-md",
        action="store_true",
        help="Fail closed if --ref-md is missing or unreadable.",
    )
    _ = analyze_8mb.add_argument(
        "--force-retriage",
        action="store_true",
        help=(
            "Operator override: reopen duplicate-suppressed findings for retriage "
            "and emit deterministic duplicate-gate audit events."
        ),
    )

    stages = sub.add_parser(
        "stages",
        help="Run a stage subset against an existing run directory.",
    )
    _ = stages.add_argument(
        "run_dir",
        help="Path to an existing run directory.",
    )
    _ = stages.add_argument(
        "--stages",
        required=True,
        help=("Comma-separated subset of stages to run (example: tooling,structure)."),
    )
    _ = stages.add_argument(
        "--time-budget-s",
        type=int,
        default=3600,
        help="Overall pipeline time budget in seconds (default: 3600).",
    )
    _ = stages.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM probing and record deterministic skipped LLM report fields.",
    )

    corpus_validate = sub.add_parser(
        "corpus-validate",
        help="Validate corpus manifest and print deterministic split summary.",
    )
    _ = corpus_validate.add_argument(
        "--manifest",
        default="benchmarks/corpus/manifest.json",
        metavar="PATH",
        help="Path to corpus manifest JSON (default: benchmarks/corpus/manifest.json).",
    )

    quality_metrics = sub.add_parser(
        "quality-metrics",
        help=(
            "Evaluate corpus labels with deterministic quality metrics and optional baseline delta output."
        ),
    )
    _ = quality_metrics.add_argument(
        "--manifest",
        default="benchmarks/corpus/manifest.json",
        metavar="PATH",
        help="Path to corpus manifest JSON (default: benchmarks/corpus/manifest.json).",
    )
    _ = quality_metrics.add_argument(
        "--baseline",
        default=None,
        metavar="PATH",
        help="Optional baseline metrics JSON for deterministic delta comparison.",
    )
    _ = quality_metrics.add_argument(
        "--out",
        default="metrics.json",
        metavar="PATH",
        help="Path for metrics report JSON output (default: metrics.json).",
    )
    _ = quality_metrics.add_argument(
        "--delta-out",
        default="metrics.delta.json",
        metavar="PATH",
        help="Path for baseline delta JSON output when --baseline is set (default: metrics.delta.json).",
    )
    _ = quality_metrics.add_argument(
        "--max-regression",
        type=float,
        default=0.01,
        metavar="FLOAT",
        help=(
            "Maximum allowed metric regression before flagging (default: 0.01). "
            "Regression is baseline-current for precision/recall/f1, and current-baseline for fpr/fnr."
        ),
    )

    quality_gate = sub.add_parser(
        "quality-gate",
        help=(
            "Enforce release-quality thresholds against metrics.json and emit a deterministic verdict artifact."
        ),
    )
    _ = quality_gate.add_argument(
        "--metrics",
        default="metrics.json",
        metavar="PATH",
        help="Path to quality metrics JSON (default: metrics.json).",
    )
    _ = quality_gate.add_argument(
        "--report",
        default=None,
        metavar="PATH",
        help="Optional report JSON for additive release-mode confirmed high/critical constraint.",
    )
    _ = quality_gate.add_argument(
        "--release-mode",
        action="store_true",
        help="Enable additive release constraint checks that consider report findings.",
    )
    _ = quality_gate.add_argument(
        "--llm-primary",
        action="store_true",
        help="Enable LLM-primary gating policy checks.",
    )
    _ = quality_gate.add_argument(
        "--llm-fixture",
        default=None,
        metavar="PATH",
        help=(
            "Optional LLM gate fixture JSON path; when omitted in llm-primary mode, "
            "a verdict is derived from report.llm.status."
        ),
    )
    _ = quality_gate.add_argument(
        "--out",
        default="quality_gate.json",
        metavar="PATH",
        help="Path for gate verdict JSON output artifact (default: quality_gate.json).",
    )

    release_quality_gate = sub.add_parser(
        "release-quality-gate",
        help=(
            "Alias for quality-gate with release-mode enabled by default for release CI policy checks."
        ),
    )
    _ = release_quality_gate.add_argument(
        "--metrics",
        default="metrics.json",
        metavar="PATH",
        help="Path to quality metrics JSON (default: metrics.json).",
    )
    _ = release_quality_gate.add_argument(
        "--report",
        default=None,
        metavar="PATH",
        help="Optional report JSON for additive release-mode confirmed high/critical constraint.",
    )
    _ = release_quality_gate.add_argument(
        "--llm-primary",
        action="store_true",
        help="Enable LLM-primary gating policy checks (release-quality-gate enables this by default).",
    )
    _ = release_quality_gate.add_argument(
        "--llm-fixture",
        default=None,
        metavar="PATH",
        help=(
            "Optional LLM gate fixture JSON path; when omitted in llm-primary mode, "
            "a verdict is derived from report.llm.status."
        ),
    )
    _ = release_quality_gate.add_argument(
        "--out",
        default="quality_gate.json",
        metavar="PATH",
        help="Path for gate verdict JSON output artifact (default: quality_gate.json).",
    )

    serve = sub.add_parser(
        "serve",
        help=(
            "Serve an existing run report directory over local HTTP and print the viewer URL."
        ),
    )
    _ = serve.add_argument(
        "run_dir",
        help="Path to an existing run directory (must contain report/viewer.html).",
    )
    _ = serve.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host interface to bind (default: 127.0.0.1).",
    )
    _ = serve.add_argument(
        "--port",
        type=int,
        default=8000,
        help="TCP port to bind (default: 8000, use 0 for auto-assign).",
    )
    _ = serve.add_argument(
        "--once",
        action="store_true",
        help="Serve a single request and exit (useful for automation/tests).",
    )
    _ = serve.add_argument(
        "--duration-s",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Optional max runtime in seconds before auto-stop.",
    )

    tui = sub.add_parser(
        "tui",
        help="Render an analyst-focused terminal dashboard for an existing run directory.",
    )
    _ = tui.add_argument(
        "run_dir",
        nargs="?",
        default="latest",
        help=(
            "Path to an existing run directory. Omit (or use 'latest') to auto-pick "
            "the most recent run from aiedge-runs/ or aiedge-8mb-runs/."
        ),
    )
    _ = tui.add_argument(
        "-m",
        "--mode",
        choices=("once", "watch", "interactive", "auto"),
        default="auto",
        help=(
            "Dashboard mode (default: auto). auto selects interactive on TTY, "
            "otherwise renders once."
        ),
    )
    _ = tui.add_argument(
        "-n",
        "--limit",
        type=int,
        default=12,
        help="Maximum number of exploit candidates to print (default: 12).",
    )
    _ = tui.add_argument(
        "-w",
        "--watch",
        action="store_true",
        help="Alias for --mode watch. Refresh dashboard continuously until Ctrl+C.",
    )
    _ = tui.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Alias for --mode interactive. Launch interactive terminal UI (keyboard navigation).",
    )
    _ = tui.add_argument(
        "-t",
        "--interval-s",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="Refresh interval for --watch mode (default: 2.0).",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = _build_parser()
    try:
        args = parser.parse_args(list(argv))
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 20

    command = cast(str | None, getattr(args, "command", None))
    if command is None:
        parser.print_help()
        return 0

    def parse_stage_names(stages_raw: str | None) -> list[str] | None:
        if stages_raw is None:
            return None
        stage_names_local = [
            part.strip() for part in stages_raw.split(",") if part.strip()
        ]
        if not stage_names_local:
            print(
                "Invalid --stages value: provide at least one non-empty stage name.",
                file=sys.stderr,
            )
            return []
        return stage_names_local

    if command in ("analyze", "analyze-8mb"):
        input_firmware = cast(str, getattr(args, "input_firmware"))
        case_id = cast(str, getattr(args, "case_id"))
        ack_authorization = bool(getattr(args, "ack_authorization", False))
        time_budget_s = cast(int, getattr(args, "time_budget_s"))
        open_egress = bool(getattr(args, "open_egress", False))
        egress_allow = cast(list[str], getattr(args, "egress_allow", []))
        no_llm = bool(getattr(args, "no_llm", False))
        stages_raw = cast(str | None, getattr(args, "stages", None))
        ref_md = cast(str | None, getattr(args, "ref_md", None))
        require_ref_md = bool(getattr(args, "require_ref_md", False))
        force_retriage = bool(getattr(args, "force_retriage", False))
        profile = cast(str, getattr(args, "profile", "analysis"))
        exploit_flag = cast(str, getattr(args, "exploit_flag", ""))
        exploit_att = cast(str, getattr(args, "exploit_attestation", ""))
        exploit_scope = cast(str, getattr(args, "exploit_scope", ""))

        enforce_canonical_8mb = command == "analyze-8mb"
        if enforce_canonical_8mb:
            src = Path(input_firmware)
            if not src.is_file():
                print(f"Input firmware not found: {input_firmware}", file=sys.stderr)
                return 20
            if src.stat().st_size != _CANONICAL_8MB_SIZE_BYTES:
                print(
                    "8MB track requires the canonical snapshot (size mismatch)",
                    file=sys.stderr,
                )
                return 30
            if _sha256_file(src) != _CANONICAL_8MB_SHA256:
                print(
                    "8MB track requires the canonical snapshot (sha256 mismatch)",
                    file=sys.stderr,
                )
                return 30

        if not ack_authorization:
            print(
                "Missing required acknowledgement: --ack-authorization",
                file=sys.stderr,
            )
            return 30

        exploit_gate: dict[str, str] | None = None
        if profile == "exploit":
            if not (exploit_flag and exploit_att and exploit_scope):
                print(
                    "Exploit profile requires --exploit-flag, --exploit-attestation, and --exploit-scope",
                    file=sys.stderr,
                )
                return 30
            exploit_gate = {
                "flag": exploit_flag,
                "attestation": exploit_att,
                "scope": exploit_scope,
            }

        run_mod: ModuleType = importlib.import_module("aiedge.run")
        create_run = cast(Callable[..., object], getattr(run_mod, "create_run"))
        analyze_run = cast(
            Callable[..., object] | None, getattr(run_mod, "analyze_run", None)
        )
        run_subset = cast(
            Callable[..., object] | None, getattr(run_mod, "run_subset", None)
        )
        policy_exc = cast(
            type[BaseException],
            getattr(run_mod, "AIEdgePolicyViolation", RuntimeError),
        )

        stage_names = parse_stage_names(stages_raw)
        if stage_names == []:
            return 20

        try:
            info = create_run(
                input_firmware,
                case_id=case_id,
                ack_authorization=ack_authorization,
                open_egress=open_egress,
                egress_allowlist=egress_allow,
                ref_md_path=ref_md,
                require_ref_md=require_ref_md,
                runs_root=(Path.cwd() / "aiedge-8mb-runs")
                if enforce_canonical_8mb
                else None,
            )

            if enforce_canonical_8mb:
                info_obj = info
                manifest_path_any = getattr(info_obj, "manifest_path", None)
                if not isinstance(manifest_path_any, Path):
                    raise RuntimeError("create_run did not return a manifest_path")
                _write_manifest_profile_marker(
                    manifest_path_any,
                    profile=profile,
                    exploit_gate=exploit_gate,
                )
                _write_manifest_track_marker(manifest_path_any)
            else:
                info_obj = info
                manifest_path_any = getattr(info_obj, "manifest_path", None)
                if isinstance(manifest_path_any, Path):
                    _write_manifest_profile_marker(
                        manifest_path_any,
                        profile=profile,
                        exploit_gate=exploit_gate,
                    )

            stage_status: str | None = None
            if stage_names is not None:
                if not callable(run_subset):
                    raise RuntimeError("run_subset is unavailable in aiedge.run")
                rep = cast(
                    _RunReport,
                    run_subset(
                        info,
                        stage_names,
                        time_budget_s=time_budget_s,
                        no_llm=no_llm,
                    ),
                )
                stage_status = rep.status
            elif callable(analyze_run):
                stage_status = cast(
                    str,
                    analyze_run(
                        info,
                        time_budget_s=time_budget_s,
                        no_llm=no_llm,
                        force_retriage=force_retriage,
                    ),
                )
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 20
        except policy_exc as e:
            print(str(e), file=sys.stderr)
            return 30
        except FileNotFoundError:
            print(f"Input firmware not found: {input_firmware}", file=sys.stderr)
            return 20
        except Exception as e:
            print(f"Fatal error: {e}", file=sys.stderr)
            return 20

        info_typed = cast(_RunInfo, info)
        print(str(info_typed.run_dir))
        if stage_status in ("partial", "failed"):
            return 10
        return 0

    if command == "stages":
        run_dir = cast(str, getattr(args, "run_dir"))
        time_budget_s = cast(int, getattr(args, "time_budget_s"))
        no_llm = bool(getattr(args, "no_llm", False))
        stages_raw = cast(str, getattr(args, "stages"))

        stage_names = parse_stage_names(stages_raw)
        if stage_names in (None, []):
            return 20

        run_mod_existing: ModuleType = importlib.import_module("aiedge.run")
        load_existing_run = cast(
            Callable[..., object] | None,
            getattr(run_mod_existing, "load_existing_run", None),
        )
        run_subset = cast(
            Callable[..., object] | None,
            getattr(run_mod_existing, "run_subset", None),
        )
        policy_exc = cast(
            type[BaseException],
            getattr(run_mod_existing, "AIEdgePolicyViolation", RuntimeError),
        )

        try:
            if not callable(load_existing_run):
                raise RuntimeError("load_existing_run is unavailable in aiedge.run")
            if not callable(run_subset):
                raise RuntimeError("run_subset is unavailable in aiedge.run")

            info = load_existing_run(run_dir)
            rep = cast(
                _RunReport,
                run_subset(
                    info,
                    stage_names,
                    time_budget_s=time_budget_s,
                    no_llm=no_llm,
                ),
            )
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 20
        except policy_exc as e:
            print(str(e), file=sys.stderr)
            return 30
        except Exception as e:
            print(f"Fatal error: {e}", file=sys.stderr)
            return 20

        info_typed = cast(_RunInfo, info)
        print(str(info_typed.run_dir))
        if rep.status in ("partial", "failed"):
            return 10
        return 0

    if command == "serve":
        run_dir = cast(str, getattr(args, "run_dir"))
        host = cast(str, getattr(args, "host"))
        port = cast(int, getattr(args, "port"))
        once = bool(getattr(args, "once", False))
        duration_s = cast(float | None, getattr(args, "duration_s", None))

        try:
            return _serve_report_directory(
                run_dir_path=run_dir,
                host=host,
                port=port,
                once=once,
                duration_s=duration_s,
            )
        except Exception as e:
            print(f"Fatal error: {e}", file=sys.stderr)
            return 20

    if command == "tui":
        run_dir_raw = cast(str | None, getattr(args, "run_dir", None))
        run_dir_path = _resolve_tui_run_dir(run_dir_raw)
        if run_dir_path is None:
            print(
                (
                    "Run directory not found: provide <run_dir> or create at least one run under "
                    "./aiedge-runs (or set AIEDGE_RUNS_DIRS)."
                ),
                file=sys.stderr,
            )
            return 20
        limit = cast(int, getattr(args, "limit"))
        mode = cast(str, getattr(args, "mode", "auto"))
        watch = bool(getattr(args, "watch", False))
        interactive = bool(getattr(args, "interactive", False))
        interval_s = cast(float, getattr(args, "interval_s"))

        try:
            return _run_tui(
                run_dir_path=str(run_dir_path),
                limit=limit,
                mode=mode,
                watch=watch,
                interval_s=interval_s,
                interactive=interactive,
            )
        except Exception as e:
            print(f"Fatal error: {e}", file=sys.stderr)
            return 20

    if command == "corpus-validate":
        manifest_raw = cast(str, getattr(args, "manifest"))
        manifest_path = Path(manifest_raw)

        try:
            payload = load_corpus_manifest(manifest_path)
            summary = corpus_summary(payload)
        except FileNotFoundError:
            err = {
                "error_token": "CORPUS_INVALID_SAMPLE",
                "message": f"manifest file not found: {manifest_raw}",
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20
        except json.JSONDecodeError as e:
            err = {
                "error_token": "CORPUS_INVALID_SAMPLE",
                "message": f"manifest is not valid JSON: {e.msg}",
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20
        except CorpusValidationError as e:
            err = {
                "error_token": e.token,
                "message": str(e),
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20

        print(format_summary(summary), end="")
        return 0

    if command == "quality-metrics":
        manifest_raw = cast(str, getattr(args, "manifest"))
        baseline_raw = cast(str | None, getattr(args, "baseline", None))
        out_raw = cast(str, getattr(args, "out"))
        delta_out_raw = cast(str, getattr(args, "delta_out"))
        max_regression = cast(float, getattr(args, "max_regression"))
        manifest_path = Path(manifest_raw)
        baseline_path = Path(baseline_raw) if baseline_raw is not None else None
        out_path = Path(out_raw)
        delta_out_path = Path(delta_out_raw)

        try:
            if max_regression < 0.0:
                raise QualityMetricsError(
                    "QUALITY_METRICS_INVALID_THRESHOLD",
                    "max regression threshold must be >= 0.0",
                )

            payload, baseline_payload = evaluate_quality_metrics_harness(
                manifest_path=manifest_path,
                baseline_path=baseline_path,
            )
            write_quality_metrics(out_path, payload)

            if baseline_path is not None:
                if baseline_payload is None:
                    raise QualityMetricsError(
                        "QUALITY_METRICS_INVALID_BASELINE",
                        "baseline payload is required",
                    )
                delta_payload = build_quality_delta_report(
                    current_metrics=payload,
                    baseline_metrics=baseline_payload,
                    manifest_path=str(manifest_path),
                    baseline_path=str(baseline_path),
                    max_regression=max_regression,
                )
                write_quality_metrics(delta_out_path, delta_payload)
        except FileNotFoundError as e:
            missing_any = cast(object, getattr(e, "filename", None))
            missing = str(missing_any) if isinstance(missing_any, str) else manifest_raw
            err = {
                "error_token": "QUALITY_METRICS_INPUT_NOT_FOUND",
                "message": f"required input file not found: {missing}",
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20
        except json.JSONDecodeError as e:
            err = {
                "error_token": "QUALITY_METRICS_INVALID_BASELINE",
                "message": f"input JSON is invalid: {e.msg}",
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20
        except CorpusValidationError as e:
            err = {
                "error_token": e.token,
                "message": str(e),
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20
        except QualityMetricsError as e:
            err = {
                "error_token": e.token,
                "message": str(e),
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20

        print(format_quality_metrics(payload), end="")
        return 0

    if command in ("quality-gate", "release-quality-gate"):
        metrics_raw = cast(str, getattr(args, "metrics"))
        report_raw = cast(str | None, getattr(args, "report", None))
        llm_fixture_raw = cast(str | None, getattr(args, "llm_fixture", None))
        out_raw = cast(str, getattr(args, "out"))
        release_mode = command == "release-quality-gate" or bool(
            getattr(args, "release_mode", False)
        )
        llm_primary = command == "release-quality-gate" or bool(
            getattr(args, "llm_primary", False)
        )

        metrics_path = Path(metrics_raw)
        out_path = Path(out_raw)
        report_path = Path(report_raw) if report_raw is not None else None
        llm_fixture_path = (
            Path(llm_fixture_raw) if llm_fixture_raw is not None else None
        )

        verdict: dict[str, object]
        exit_code = 0
        try:
            metrics_payload = load_json_object(
                metrics_path,
                error_token=QUALITY_GATE_INVALID_METRICS,
                object_name="metrics",
            )
            report_payload: dict[str, object] | None = None
            if report_path is not None:
                report_payload = load_json_object(
                    report_path,
                    error_token=QUALITY_GATE_INVALID_REPORT,
                    object_name="report",
                )

            llm_gate_payload: dict[str, object] | None = None
            llm_gate_path: str | None = None
            if llm_primary:
                if report_payload is None:
                    raise QualityGateError(
                        QUALITY_GATE_LLM_REQUIRED,
                        "llm-primary policy requires --report",
                    )
                if llm_fixture_path is not None:
                    llm_gate_payload, llm_gate_path = resolve_llm_gate_input(
                        fixture_path=llm_fixture_path,
                        run_dir=Path.cwd(),
                        report=cast(dict[str, JsonValue], report_payload),
                    )
                else:
                    llm_status: str | None = None
                    llm_any = report_payload.get("llm")
                    if isinstance(llm_any, dict):
                        llm_status_any = cast(dict[str, object], llm_any).get("status")
                        if isinstance(llm_status_any, str):
                            llm_status = llm_status_any
                    llm_gate_payload = {
                        "verdict": "pass" if llm_status == "ok" else "fail"
                    }
                    llm_gate_path = "report.llm"

            verdict = evaluate_quality_gate(
                metrics_payload=metrics_payload,
                metrics_path=str(metrics_path),
                report_payload=report_payload,
                report_path=str(report_path) if report_path is not None else None,
                release_mode=release_mode,
                llm_primary=llm_primary,
                llm_gate_payload=llm_gate_payload,
                llm_gate_path=llm_gate_path,
            )
            if not bool(verdict.get("passed", False)):
                exit_code = 30
        except FileNotFoundError as e:
            missing_any = cast(object, getattr(e, "filename", None))
            missing = str(missing_any) if isinstance(missing_any, str) else metrics_raw
            err = {
                "error_token": "QUALITY_GATE_INPUT_NOT_FOUND",
                "message": f"required input file not found: {missing}",
            }
            verdict = {
                "schema_version": 1,
                "verdict": "fail",
                "passed": False,
                "metrics_path": str(metrics_path),
                "report_path": str(report_path) if report_path is not None else None,
                "errors": [err],
            }
            exit_code = 20
        except QualityGateError as e:
            err = {
                "error_token": e.token,
                "message": str(e),
            }
            verdict = {
                "schema_version": 1,
                "verdict": "fail",
                "passed": False,
                "metrics_path": str(metrics_path),
                "report_path": str(report_path) if report_path is not None else None,
                "errors": [err],
            }
            exit_code = 20

        write_quality_gate(out_path, verdict)
        if not bool(verdict.get("passed", False)):
            errors_any = verdict.get("errors")
            if isinstance(errors_any, list):
                for err_any in cast(list[object], errors_any):
                    if isinstance(err_any, dict):
                        print(
                            json.dumps(err_any, sort_keys=True, ensure_ascii=True),
                            file=sys.stderr,
                        )
        print(format_quality_gate(verdict), end="")
        return exit_code

    print(f"Unknown command: {command}", file=sys.stderr)
    return 20


if __name__ == "__main__":
    raise SystemExit(main())
