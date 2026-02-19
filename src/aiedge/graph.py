from __future__ import annotations

import csv
import json
import ipaddress
import os
import re
import stat
from dataclasses import dataclass
from urllib.parse import urlsplit
from pathlib import Path
from typing import cast

from .confidence_caps import calibrated_confidence, evidence_level
from .policy import AIEdgePolicyViolation
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus


def _assert_under_dir(base_dir: Path, target: Path) -> None:
    base = _safe_resolve(base_dir) or base_dir.absolute()
    resolved = _safe_resolve(target) or target.absolute()
    if not resolved.is_relative_to(base):
        raise AIEdgePolicyViolation(
            f"Refusing to write outside run dir: target={resolved} base={base}"
        )


def _safe_resolve(path: Path) -> Path | None:
    try:
        return path.resolve()
    except OSError:
        return None


def _read_nested_str(
    obj: object | None, *, path: list[str], fallback: str | None = None
) -> str | None:
    if not isinstance(obj, dict):
        return fallback
    cursor: object | None = obj
    for key in path:
        if not isinstance(cursor, dict):
            return fallback
        cursor = cast(dict[str, object], cursor).get(key)
    if not isinstance(cursor, str) or not cursor.strip():
        return fallback
    return cursor


def _safe_non_absolute_rel(value: str, *, fallback: str = "unresolved_path") -> str:
    norm = value.replace("\\", "/").strip()
    if not norm:
        return fallback
    if norm.startswith("/"):
        norm = norm.lstrip("/")
    if not norm or norm.startswith("../") or "/home/" in norm:
        return fallback
    return norm


def _rel_to_run_dir(run_dir: Path, path: Path) -> str:
    run_resolved = _safe_resolve(run_dir) or run_dir.absolute()
    path_resolved = _safe_resolve(path)
    if isinstance(path_resolved, Path):
        try:
            return _safe_non_absolute_rel(str(path_resolved.relative_to(run_resolved)))
        except Exception:
            pass
    try:
        return _safe_non_absolute_rel(str(path.relative_to(run_resolved)))
    except Exception:
        try:
            return _safe_non_absolute_rel(
                os.path.relpath(str(path), start=str(run_resolved))
            )
        except Exception:
            return _safe_non_absolute_rel(path.name)


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


_BINARY_EXTS = {".bin", ".elf", ".so", ".out", ".exe", ".a", ".o"}
_KNOWN_BINARY_NAMES = {
    "busybox",
    "sh",
    "bash",
    "dropbear",
    "sshd",
    "httpd",
    "lighttpd",
    "nginx",
    "ubusd",
    "ubnt",
    "dnsmasq",
    "iptables",
    "udhcpd",
}
_KNOWN_SERVICE_PORT_PROTOCOLS = {
    20: "ftp",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    443: "https",
    1883: "mqtt",
    8883: "mqtt",
    554: "rtsp",
    8080: "http",
    8443: "https",
}
_SERVICE_DEFAULT_PORTS = {"http": 80, "https": 443}
_KNOWN_SERVICE_PORT_HINTS = {
    "ssh": {22},
    "sshd": {22},
    "dropbear": {22},
    "http": {80, 443},
    "https": {443},
    "lighttpd": {80, 443},
    "nginx": {80, 443},
    "httpd": {80, 443},
    "dns": {53},
    "dnsmasq": {53},
    "mqtt": {1883, 8883},
    "postgres": {5432},
    "redis": {6379},
    "ipsec": {500, 4500},
    "ntp": {123},
    "smtp": {25},
}
_DYNAMIC_VALIDATION_INTERFACES_PATHS = {
    "summary_field": "network/interfaces",
    "default_rel_path": "stages/dynamic_validation/network/interfaces.json",
}
_DYNAMIC_VALIDATION_PORTS_PATHS = {
    "summary_field": "network/ports",
    "default_rel_path": "stages/dynamic_validation/network/ports.json",
}
_DYNAMIC_VALIDATION_SUMMARY_PATH = (
    "stages/dynamic_validation/dynamic_validation.json"
)
_DYNAMIC_SUMMARY_IPS_KEY = "target_ip"
_DYNAMIC_SUMMARY_PORTS_KEY = "target_port"
_DYNAMIC_SUMMARY_TARGET_KEY = "target"
_DYNAMIC_SUMMARY_TARGET_IP_KEY = "ip"
_DYNAMIC_SUMMARY_TARGET_IID_KEY = "iid"
_HOST_PORT_RE = re.compile(r"^(?:https?://)?(?P<host>[^:/\s]+)(?::(?P<port>\d+))?")
_HOST_PORT_ANY_RE = re.compile(
    r"(?:https?://)?(?P<host>(?:\[[^\]]+\]|[A-Za-z0-9._:-]+))(?:\:(?P<port>\d{1,5}))?"
)


def _safe_candidate_refs(value: object) -> list[str]:
    if not isinstance(value, list):
        return []

    refs: list[str] = []
    for item in cast(list[object], value):
        if isinstance(item, str):
            refs.append(item)
            continue
        if not isinstance(item, dict):
            continue
        path_any = cast(dict[str, object], item).get("path")
        if isinstance(path_any, str):
            refs.append(path_any)

    return refs


def _normalize_run_relative_list(paths: list[str], *, run_dir: Path) -> list[str]:
    normalized: list[str] = []
    for item in paths:
        if not isinstance(item, str):
            continue
        normalized.append(_safe_non_absolute_rel(item))
    _ = run_dir
    return normalized


def _rel_if_available(run_dir: Path, value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None

    if value.startswith(".") or value.startswith(".."):  # pragma: no branch
        candidate = run_dir / value
    elif value.startswith("/"):
        candidate = Path(value)
    else:
        candidate = run_dir / value

    resolved = _safe_resolve(candidate)
    if resolved is None:
        return None
    run_resolved = _safe_resolve(run_dir)
    if isinstance(run_resolved, Path) and not resolved.is_relative_to(run_resolved):
        return None
    return _safe_non_absolute_rel(str(resolved.relative_to(run_resolved or run_dir)))


def _read_json_payload_as_list(path: Path) -> list[dict[str, object]]:
    obj = _load_json_object(path)
    if not isinstance(obj, dict):
        return []
    items_any = obj.get("items")
    if isinstance(items_any, list):
        return [cast(dict[str, object], x) for x in items_any if isinstance(x, dict)]

    return []


def _as_int(value: object) -> int | None:
    if not isinstance(value, int):
        return None
    if 0 < int(value) <= 65535:
        return int(value)
    return None


def _as_str(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _normalize_protocol(value: object) -> str:
    text = _as_str(value)
    if text is None:
        return "tcp"
    value_norm = text.lower().strip()
    if value_norm in {"", "unknown"}:
        return "tcp"
    if value_norm in {"udp", "tcp", "icmp", "ip", "sctp", "esp", "udplite"}:
        return value_norm
    if value_norm.startswith("tcp/"):
        return "tcp"
    if value_norm.startswith("udp/"):
        return "udp"
    return value_norm


def _parse_ip_port_hint(value: str) -> tuple[str | None, int | None]:
    m = _HOST_PORT_RE.match(value.strip())
    if not m:
        return None, None
    host = (m.group("host") or "").strip()
    port_raw = m.group("port")
    port = int(port_raw) if port_raw and port_raw.isdigit() else None
    if not host:
        return None, port
    if port and 0 < port <= 65535:
        return host, port
    return host, None


def _to_ip_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except Exception:
        return None


def _normalize_host_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text:
        return None
    return text


@dataclass(frozen=True)
class _RuntimeEdge:
    src: str
    dst: str
    edge_type: str
    confidence: float
    confidence_calibrated: float
    evidence_level: str
    observation: str
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class _EndpointRecord:
    node_id: str
    raw_type: str
    raw_value: str
    host: str
    ports: tuple[int, ...]
    protocol: str
    confidence: float
    refs: tuple[str, ...]
    source_component_ids: set[str]


def _safe_join_for_csv(values: list[str]) -> str:
    if not values:
        return ""
    return ";".join(sorted(set(values)))


def _export_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        _ = writer.writerow(headers)
        for row in rows:
            _ = writer.writerow(row)


def _extract_service_candidates_from_inventory(
    run_dir: Path,
) -> list[dict[str, object]]:
    inv_path = run_dir / "stages" / "inventory" / "inventory.json"
    inv_obj = _load_json_object(inv_path)
    if inv_obj is None:
        return []

    candidates = inv_obj.get("service_candidates")
    if not isinstance(candidates, list):
        return []

    normalized: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for item_any in cast(list[object], candidates):
        if not isinstance(item_any, dict):
            continue
        item = cast(dict[str, object], item_any)
        name_any = item.get("name")
        kind_any = item.get("kind")
        conf_any = item.get("confidence")
        evidence_any = item.get("evidence")

        if not isinstance(name_any, str) or not name_any.strip():
            continue
        if not isinstance(kind_any, str) or not kind_any:
            continue

        name = name_any.strip()
        kind = kind_any.strip().lower()
        confidence = float(conf_any) if isinstance(conf_any, (int, float)) else 0.5
        refs = _safe_candidate_refs(evidence_any)
        normalized_refs = sorted({_safe_non_absolute_rel(x) for x in refs if x})
        key = (name.lower(), kind, "|".join(normalized_refs))
        if key in seen:
            continue
        seen.add(key)
        normalized.append(
            {
                "name": name,
                "kind": kind,
                "confidence": confidence,
                "evidence_refs": normalized_refs,
                "raw": item,
            }
        )

    return normalized


def _as_int_port(value: object) -> int | None:
    if not isinstance(value, int):
        return None
    if 0 < int(value) <= 65535:
        return int(value)
    return None


def _pick_endpoint_protocol_and_ports(
    endpoint_type: str,
    endpoint_value: str,
) -> tuple[str, list[int], str]:
    et = endpoint_type.lower()
    value = endpoint_value.strip()

    if et == "url":
        try:
            parsed = urlsplit(value)
        except Exception:
            parsed = None

        if parsed is not None:
            proto = (parsed.scheme or "").lower()
            if parsed.port is not None and 0 < parsed.port <= 65535:
                return (proto or "unknown", [int(parsed.port)], value)
            if proto in _SERVICE_DEFAULT_PORTS:
                return (proto, [_SERVICE_DEFAULT_PORTS[proto]], value)

        if value.startswith("http://") or value.startswith("https://"):
            return (
                "http",
                [_SERVICE_DEFAULT_PORTS["https" if value.startswith("https://") else "http"]],
                value,
            )

    m = _HOST_PORT_RE.match(value)
    if et in {"domain", "hostname", "host", "ip", "ipv4", "ipv6"} and m is not None:
        host = (m.group("host") or "").strip()
        port_any = m.group("port")
        ports: list[int] = []
        if port_any and port_any.isdigit():
            p = int(port_any)
            if 0 < p <= 65535:
                ports.append(p)
        return ("unknown", ports, host)

    if et == "port":
        p = _as_int_port(value)
        if p is not None:
            return ("tcp", [p], value)

    return ("unknown", [], value)


def _node_key(node_type: str, value: str) -> str:
    return f"{node_type}:{value}"


def _looks_like_binary(path: Path, *, stat_result: os.stat_result | None = None) -> bool:
    try:
        st = path.stat() if stat_result is None else stat_result
    except OSError:
        return False

    if stat.S_ISREG(st.st_mode):
        if st.st_mode & 0o111:
            return True
    suffix = path.suffix.lower()
    if suffix in _BINARY_EXTS:
        return True
    if path.name in _KNOWN_BINARY_NAMES:
        return True
    if suffix in {".sh", ".cgi", ".py"}:
        return False
    return False


def _binary_confidence(path: Path, *, stat_result: os.stat_result | None = None) -> float:
    try:
        if stat_result is None:
            stat_result = path.stat()
    except OSError:
        return 0.35

    if stat.S_ISREG(stat_result.st_mode) and (stat_result.st_mode & 0o111):
        return 0.72
    if path.name in _KNOWN_BINARY_NAMES:
        return 0.7
    suffix = path.suffix.lower()
    if suffix in _BINARY_EXTS:
        return 0.64
    return 0.42


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
    observation: str
    evidence_refs: tuple[str, ...]


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _pick_dynamic_artifact_path(
    run_dir: Path,
    summary_obj: dict[str, object] | None,
    *,
    summary_field: list[str],
    default_rel_path: str,
) -> Path:

    configured = _read_nested_str(summary_obj, path=summary_field)
    if configured:
        configured_norm = _safe_non_absolute_rel(configured)
        if configured_norm not in {"", "unresolved_path"}:
            configured_candidate = run_dir / configured_norm
            if configured_candidate.is_file():
                return configured_candidate

    return run_dir / default_rel_path


def _normalize_dynamic_host(host: object) -> str | None:
    host_value = _as_str(host)
    if host_value is None:
        return None
    host_value = host_value.strip().lower()
    if host_value in {"0.0.0.0", "::", "*", "any", "any4", "any6"}:
        return None
    ip_v = _to_ip_string(host_value)
    if ip_v is not None:
        return ip_v
    return host_value


def _pick_port_list(value: object) -> list[int]:
    if not isinstance(value, list):
        return []

    found: list[int] = []
    for item in cast(list[object], value):
        parsed = _as_int(item)
        if parsed is None:
            continue
        found.append(parsed)
    return sorted(set(found))


def _extract_open_ports_from_object(port_obj: dict[str, object] | None) -> list[int]:
    if port_obj is None:
        return []

    open_ports = _pick_port_list(port_obj.get("open_ports"))
    if open_ports:
        return open_ports

    port_entries = port_obj.get("ports")
    if not isinstance(port_entries, list):
        return []

    found: list[int] = []
    for item_any in cast(list[object], port_entries):
        if not isinstance(item_any, dict):
            continue
        item = cast(dict[str, object], item_any)
        state_any = item.get("state")
        if not isinstance(state_any, str) or state_any.lower() != "open":
            continue
        found.append(_as_int(item.get("port")) or 0)
    return sorted({p for p in found if p > 0})


def _safe_csv_field(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ";".join(_safe_csv_field(v) for v in value)
    text = str(value)
    if "\n" in text:
        text = text.replace("\n", "\\n")
    return text


def _escape_cypher_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _normalize_host_candidates(host: object) -> list[str]:
    host_value = _to_ip_string(host)
    if host_value is not None:
        return [host_value]
    host_text = _as_str(host)
    if host_text is None:
        return []
    host_text = host_text.strip().lower()
    if not host_text or host_text in {"any", "any4", "any6", "*", "0.0.0.0", "::"}:
        return []
    if _to_ip_string(host_text) is not None:
        return [_to_ip_string(host_text)]
    return [host_text]


def _is_loopback_host(host: str) -> bool:
    return host.startswith("127.") or host == "::1" or host.lower() == "localhost"


def _parse_service_label(raw_value: str) -> tuple[str, int, str]:
    value = raw_value.strip()
    if not value:
        return ("unknown", 0, "tcp")

    # accept both explicit service:* and plain host:port/proto styles
    candidate = value
    if candidate.startswith("service:"):
        candidate = candidate[len("service:") :]

    if "/" in candidate:
        candidate, proto = candidate.rsplit("/", 1)
        protocol = proto.lower().strip() or "tcp"
    else:
        protocol = "tcp"

    if "]:" in candidate and candidate.startswith("["):
        # IPv6-like endpoint with explicit brackets
        host, rest = candidate.rsplit("]:", 1)
        host = host.strip("[]")
        if rest:
            port_str = rest.split("/", 1)[0]
            return host, int(port_str) if port_str.isdigit() else 0, protocol
        return host, 0, protocol

    if ":" not in candidate:
        return candidate, 0, protocol

    host, port_str = candidate.rsplit(":", 1)
    return host, int(port_str) if port_str.isdigit() else 0, protocol


def _collect_dynamic_interface_hosts(
    interfaces_obj: dict[str, object] | None,
) -> list[str]:
    interfaces = interfaces_obj.get("interfaces") if interfaces_obj else None
    if not isinstance(interfaces, list):
        return []
    host_values: set[str] = set()
    for item in cast(list[object], interfaces):
        if not isinstance(item, dict):
            continue
        data = cast(dict[str, object], item)
        for key in ("ipv4", "ipv6"):
            values = data.get(key)
            if not isinstance(values, list):
                continue
            for value in cast(list[object], values):
                if not isinstance(value, str):
                    continue
                normalized = _normalize_host_candidates(value)
                for host in normalized:
                    if host and not _is_loopback_host(host):
                        host_values.add(host)
    return sorted(host_values)


def _collect_dynamic_open_ports(ports_obj: dict[str, object] | None) -> list[tuple[int, str]]:
    if not isinstance(ports_obj, dict):
        return []
    ports_items: list[tuple[int, str]] = []
    if not isinstance(ports_obj.get("ports"), list):
        return []
    ports_any = cast(list[object], ports_obj.get("ports"))
    for entry_any in ports_any:
        if not isinstance(entry_any, dict):
            continue
        state_any = entry_any.get("state")
        if not isinstance(state_any, str) or state_any.lower() != "open":
            continue
        port = _as_int(entry_any.get("port"))
        if port is None:
            continue
        proto_any = _normalize_protocol(entry_any.get("proto"))
        if not proto_any:
            continue
        ports_items.append((port, proto_any))
    if not ports_items:
        return []
    return sorted(set(ports_items))


def _collect_dynamic_runtime_targets(
    summary_obj: dict[str, object] | None,
    interfaces_obj: dict[str, object] | None,
    ports_obj: dict[str, object] | None,
) -> tuple[list[str], list[tuple[int, str]], list[str], dict[str, list[str]]]:
    if summary_obj is None:
        return [], [], [], {}

    target_ip = _read_nested_str(summary_obj, path=[_DYNAMIC_SUMMARY_IPS_KEY])
    if target_ip is None:
        target_ips_any = summary_obj.get("target")
        if isinstance(target_ips_any, dict):
            target_ip = _read_nested_str(cast(dict[str, object], target_ips_any), path=["ip"])

    host_candidates: list[str] = []
    if target_ip:
        host_candidates.extend(_normalize_host_candidates(target_ip))
    if not host_candidates and interfaces_obj is not None:
        host_candidates.extend(_collect_dynamic_interface_hosts(interfaces_obj))

    host_candidates = _sorted_unique_refs(host_candidates)

    open_ports = _extract_open_ports_from_object(ports_obj) if isinstance(ports_obj, dict) else []
    probe_ports = _collect_dynamic_open_ports(ports_obj)
    evidence_refs: list[str] = []
    evidence_by_source: dict[str, list[str]] = {}
    network = summary_obj.get("network")
    if isinstance(network, dict):
        network_obj = cast(dict[str, object], network)
        iface_ref = _read_nested_str(
            network_obj, path=[_DYNAMIC_VALIDATION_INTERFACES_PATHS["summary_field"]]
        )
        if iface_ref:
            normalized_iface_ref = _safe_non_absolute_rel(iface_ref, fallback="")
            if normalized_iface_ref:
                evidence_refs.append(normalized_iface_ref)
            evidence_by_source.setdefault("interfaces", []).append(normalized_iface_ref)
        ports_ref = _read_nested_str(
            network_obj, path=[_DYNAMIC_VALIDATION_PORTS_PATHS["summary_field"]]
        )
        if ports_ref:
            normalized_ports_ref = _safe_non_absolute_rel(ports_ref, fallback="")
            if normalized_ports_ref:
                evidence_refs.append(normalized_ports_ref)
            evidence_by_source.setdefault("ports", []).append(normalized_ports_ref)

    if not open_ports and not probe_ports:
        summary_ports = _as_int(summary_obj.get("target_port"))
        if summary_ports is not None:
            open_ports = [summary_ports]

    service_points: list[tuple[int, str]] = []
    if probe_ports:
        service_points.extend(probe_ports)
    for port in open_ports:
        if port <= 0:
            continue
        if any(existing_port == port for existing_port, _ in service_points):
            continue
        service_points.append((port, "tcp"))

    service_points = sorted(set(service_points))
    return host_candidates, service_points, sorted(_sorted_unique_refs(evidence_refs)), evidence_by_source


def _collect_exploit_chain_records(
    run_dir: Path,
) -> list[tuple[str, dict[str, object], list[str], list[str]]]:
    exploits_dir = run_dir / "exploits"
    if not exploits_dir.is_dir():
        return []
    records: list[tuple[str, dict[str, object], list[str], list[str]]] = []
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
        bundle_obj = _load_json_object(bundle_path)
        if bundle_obj is None:
            continue
        chain_id = _as_str(bundle_obj.get("chain_id")) or chain_dir.name
        runtime_refs: list[str] = []
        runtime_refs.extend(_collect_attempt_proof_refs(bundle_obj))
        rel_bundle_path = _safe_non_absolute_rel(
            _rel_to_run_dir(run_dir, bundle_path), fallback="unresolved_path"
        )
        if rel_bundle_path != "unresolved_path":
            runtime_refs.append(rel_bundle_path)
        records.append(
            (
                chain_id,
                cast(dict[str, object], bundle_obj),
                runtime_refs,
                cast(list[str], _sorted_unique_refs(runtime_refs)),
            )
        )
    return records


def _extract_runtime_targets_from_exploit_record(
    chain_id: str,
    runtime: dict[str, object],
) -> list[tuple[str, tuple[int | None, str | None], str, list[str]]]:
    result: list[tuple[str, tuple[int | None, str | None], str, list[str]]] = []
    host = _as_str(runtime.get("target_ip"))
    if host is None:
        return result
    host_normalized = _normalize_host_name(host)
    if host_normalized is None:
        return result

    port_value = runtime.get("target_port")
    port = _as_int(port_value)

    attempt_count = runtime.get("attempts")
    passed_count = runtime.get("passed_attempts")
    attempts_str = ""
    if attempt_count is not None and passed_count is not None:
        attempts_str = f"target={host_normalized}:{port_value if port_value is not None else ''};{chain_id};pass_rate={passed_count}/{attempt_count}"
        proto_hint = "tcp" if port is not None else "unknown"
    elif port is not None:
        proto_hint = "tcp"
        attempts_str = f"target={host_normalized}:{port}"
    else:
        proto_hint = None
        attempts_str = f"target={host_normalized}"

    result.append((chain_id, (port, proto_hint), attempts_str, []))
    return result


def _parse_targets_from_proof_text(proof: str) -> list[tuple[str, int | None, str | None]]:
    found: list[tuple[str, int | None, str | None]] = []
    if not proof:
        return found

    for raw in re.split(r"[\s,;]+", proof):
        if not raw:
            continue
        token = raw.strip().strip("'\"[]()")
        if token.startswith("target="):
            token = token.split("=", 1)[1]
        host, port = _parse_ip_port_hint(token)
        if host is None and token.startswith("http"):
            host, port = _parse_ip_port_hint(token)
        if host is None:
            for m in _HOST_PORT_ANY_RE.finditer(token):
                host = _normalize_host_name(m.group("host"))
                if host is None:
                    continue
                port_text = m.group("port")
                parsed_port = int(port_text) if port_text and port_text.isdigit() else None
                found.append((host, parsed_port, None))
            continue

        protocol = "tcp"
        parsed_port = port
        if parsed_port is None and "://" in token and token.endswith("https"):
            protocol = "https"
        found.append((host, parsed_port, protocol))
    return found


def _normalized_host_from_node_label(label: str) -> str:
    text = label.strip()
    if text.startswith("host:"):
        text = text[len("host:") :].strip()
    if not text:
        return "unresolved_host"
    return text


def _evidence_signal_profile(
    refs: tuple[str, ...] | list[str],
) -> tuple[list[str], str, dict[str, int], bool]:
    normalized_refs = [
        x
        for x in _sorted_unique_refs([str(v) for v in refs if isinstance(v, str)])
        if x
    ]
    dynamic_count = sum(
        1 for ref in normalized_refs if ref.startswith("stages/dynamic_validation/")
    )
    exploit_count = sum(1 for ref in normalized_refs if ref.startswith("exploits/"))
    verified_count = sum(
        1 for ref in normalized_refs if ref.startswith("verified_chain/")
    )
    static_count = max(
        0, len(normalized_refs) - dynamic_count - exploit_count - verified_count
    )

    signals: list[str] = []
    if dynamic_count > 0:
        signals.append("dynamic_validation")
    if exploit_count > 0:
        signals.append("exploit")
    if verified_count > 0:
        signals.append("verified_chain")
    if static_count > 0:
        signals.append("static")

    if dynamic_count > 0 and exploit_count > 0 and verified_count > 0:
        badge = "D+E+V"
    elif dynamic_count > 0 and exploit_count > 0:
        badge = "D+E"
    elif dynamic_count > 0 and verified_count > 0:
        badge = "D+V"
    elif exploit_count > 0 and verified_count > 0:
        badge = "E+V"
    elif dynamic_count > 0:
        badge = "D"
    elif exploit_count > 0:
        badge = "E"
    elif verified_count > 0:
        badge = "V"
    else:
        badge = "S"

    return (
        signals,
        badge,
        {
            "dynamic": dynamic_count,
            "exploit": exploit_count,
            "verified_chain": verified_count,
            "static": static_count,
        },
        dynamic_count > 0 and exploit_count > 0,
    )


def _communication_matrix_payload(
    comm_nodes: dict[str, _Node],
    comm_edges: list[_RuntimeEdge],
) -> dict[str, JsonValue]:
    host_to_components: dict[str, set[str]] = {}
    host_to_service_edges: dict[str, list[_RuntimeEdge]] = {}

    for edge in comm_edges:
        src_node = comm_nodes.get(edge.src)
        dst_node = comm_nodes.get(edge.dst)
        if src_node is None or dst_node is None:
            continue
        if edge.edge_type == "runtime_host_flow" and src_node.node_type == "component" and dst_node.node_type == "host":
            host_to_components.setdefault(dst_node.node_id, set()).add(src_node.node_id)
        if edge.edge_type == "runtime_service_binding" and src_node.node_type == "host" and dst_node.node_type == "service":
            host_to_service_edges.setdefault(src_node.node_id, []).append(edge)

    matrix_rows: list[dict[str, JsonValue]] = []
    seen_rows: set[tuple[str, str, str, int, str]] = set()
    for host_node_id, service_edges in sorted(host_to_service_edges.items()):
        host_node = comm_nodes.get(host_node_id)
        if host_node is None:
            continue
        host_value = _normalized_host_from_node_label(host_node.label)
        components_for_host = sorted(
            host_to_components.get(host_node_id, set()) or {"component:unknown"}
        )
        for service_edge in sorted(
            service_edges,
            key=lambda item: item.dst,
        ):
            service_node = comm_nodes.get(service_edge.dst)
            if service_node is None:
                continue
            service_host, service_port, protocol = _parse_service_label(
                service_node.label
            )
            service_host = service_host or host_value
            service_port = int(service_port)
            protocol = _normalize_protocol(protocol) or "tcp"
            for component_id in components_for_host:
                row_key = (
                    component_id,
                    host_value,
                    service_host,
                    service_port,
                    protocol,
                )
                if row_key in seen_rows:
                    continue
                seen_rows.add(row_key)
                component_node = comm_nodes.get(component_id)
                component_label = (
                    component_node.label if component_node else _safe_ascii_label(component_id)
                )
                evidence_signals, evidence_badge, evidence_counts, dynamic_exploit_chain = (
                    _evidence_signal_profile(service_edge.evidence_refs)
                )
                matrix_rows.append(
                    {
                        "component_id": component_id,
                        "component_label": component_label,
                        "host": host_value,
                        "service_host": service_host,
                        "service_port": service_port,
                        "protocol": protocol,
                        "confidence": service_edge.confidence,
                        "evidence_level": service_edge.evidence_level,
                        "observation": service_edge.observation,
                        "evidence_signals": cast(
                            list[JsonValue], cast(list[object], list(evidence_signals))
                        ),
                        "evidence_badge": evidence_badge,
                        "dynamic_evidence_count": int(evidence_counts["dynamic"]),
                        "exploit_evidence_count": int(evidence_counts["exploit"]),
                        "verified_chain_evidence_count": int(
                            evidence_counts["verified_chain"]
                        ),
                        "static_evidence_count": int(evidence_counts["static"]),
                        "dynamic_exploit_chain": bool(dynamic_exploit_chain),
                        "evidence_refs": cast(
                            list[JsonValue],
                            cast(list[object], list(service_edge.evidence_refs)),
                        ),
                    }
                )

    matrix_rows = sorted(
        matrix_rows,
        key=lambda row: (
            str(row.get("component_id", "")),
            str(row.get("host", "")),
            int(row.get("service_port", 0)),
            str(row.get("protocol", "")),
        ),
    )
    matrix_payload: dict[str, JsonValue] = {
        "status": "ok" if matrix_rows else "partial",
        "rows": cast(list[JsonValue], cast(list[object], matrix_rows)),
        "summary": {
            "components": len({row.get("component_id") for row in matrix_rows}),
            "hosts": len({row.get("host") for row in matrix_rows}),
            "services": len(
                {
                    (row.get("service_host"), row.get("service_port"), row.get("protocol"))
                    for row in matrix_rows
                }
            ),
            "observations": sorted(
                {row.get("observation", "") for row in matrix_rows}
            ),
            "rows_dynamic": sum(
                1
                for row in matrix_rows
                if _as_int(row.get("dynamic_evidence_count")) is not None
                and int(cast(int, row.get("dynamic_evidence_count"))) > 0
            ),
            "rows_exploit": sum(
                1
                for row in matrix_rows
                if _as_int(row.get("exploit_evidence_count")) is not None
                and int(cast(int, row.get("exploit_evidence_count"))) > 0
            ),
            "rows_verified_chain": sum(
                1
                for row in matrix_rows
                if _as_int(row.get("verified_chain_evidence_count")) is not None
                and int(cast(int, row.get("verified_chain_evidence_count"))) > 0
            ),
            "rows_dynamic_exploit": sum(
                1 for row in matrix_rows if bool(row.get("dynamic_exploit_chain"))
            ),
            "evidence_badges": sorted(
                {str(row.get("evidence_badge", "S")) for row in matrix_rows}
            ),
            "classification": "candidate",
        },
    }
    return matrix_payload


def _as_jsonable_exploit_runtime(bundle_obj: dict[str, object]) -> dict[str, object]:
    attempts_any = bundle_obj.get("attempts")
    runtime_obj = bundle_obj.get("runtime")
    record: dict[str, object] = {}
    if isinstance(runtime_obj, dict):
        for field in ("target_ip", "target_port"):
            runtime_val = cast(dict[str, object], runtime_obj).get(field)
            if runtime_val is not None:
                record[field] = runtime_val
    if isinstance(attempts_any, list):
        pass_count = 0
        for attempt in cast(list[object], attempts_any):
            if isinstance(attempt, dict) and attempt.get("status") == "pass":
                pass_count += 1
        record["attempts"] = len(attempts_any)
        record["passed_attempts"] = pass_count
    return record


def _collect_attempt_proof_refs(bundle_obj: dict[str, object]) -> list[str]:
    proof_refs: list[str] = []
    attempts_any = bundle_obj.get("attempts")
    if isinstance(attempts_any, list):
        for attempt_any in cast(list[object], attempts_any):
            if not isinstance(attempt_any, dict):
                continue
            proof = _as_str(cast(dict[str, object], attempt_any).get("proof_evidence"))
            if proof:
                proof_refs.append(_safe_non_absolute_rel(proof, fallback=""))
    artifacts_any = bundle_obj.get("artifacts")
    if isinstance(artifacts_any, dict):
        for item in cast(dict[str, object], artifacts_any).values():
            if isinstance(item, str):
                proof_refs.append(_safe_non_absolute_rel(item, fallback=""))
            elif isinstance(item, list):
                for nested in cast(list[object], item):
                    if isinstance(nested, str):
                        proof_refs.append(_safe_non_absolute_rel(nested, fallback=""))
    return [x for x in _sorted_unique_refs(proof_refs)]


def _derive_endpoint_record(
    endpoint_type: str, endpoint_value: str
) -> tuple[str, list[int], str]:
    normalized_type = endpoint_type.strip().lower()
    value = endpoint_value.strip()
    host_candidates: set[str] = set()
    ports: list[int] = []
    protocol = "unknown"

    if normalized_type == "url":
        try:
            parsed = urlsplit(value)
            host = parsed.hostname
            if host:
                host_candidates.add(host.lower())
            if parsed.scheme:
                protocol = parsed.scheme.lower()
            if parsed.port is not None:
                parsed_port = _as_int(parsed.port)
                if parsed_port is not None:
                    ports.append(parsed_port)
            elif protocol in _SERVICE_DEFAULT_PORTS:
                ports.append(_SERVICE_DEFAULT_PORTS[protocol])
        except Exception:
            pass

    elif normalized_type in {"domain", "hostname", "ip", "ipv4", "ipv6"}:
        host_any, port_any = _parse_ip_port_hint(value)
        if host_any:
            host_candidates.add(host_any)
        protocol = "unknown"
        if port_any is not None:
            ports.append(port_any)

    elif normalized_type == "port":
        port = _as_int(value)
        if port is not None:
            ports.append(port)
        protocol = "tcp"

    else:
        parsed_host, parsed_port = _parse_ip_port_hint(value)
        if parsed_host:
            host_candidates.add(parsed_host)
        if parsed_port is not None:
            ports.append(parsed_port)
        protocol = _normalize_protocol(
            normalized_type if normalized_type in {"tcp", "udp", "icmp"} else "unknown"
        )

    raw = _as_str(value) or ""
    if not host_candidates:
        for m in _HOST_PORT_ANY_RE.finditer(raw):
            host_any = _normalize_host_name(m.group("host"))
            if host_any:
                host_candidates.add(host_any)
            m_port = m.group("port")
            if m_port and m_port.isdigit():
                parsed = _as_int(m_port)
                if parsed is not None:
                    ports.append(parsed)

    host = _safe_node_value(",".join(sorted(host_candidates)), max_len=220)
    return host, _sorted_unique_refs(ports), _normalize_protocol(protocol)


def _is_host_covered(
    host: str, dynamic_hosts: list[str], summary_host_fallback: str | None = None
) -> bool:
    if host:
        if host in dynamic_hosts:
            return True
        if _is_loopback_host(host):
            return False
    if summary_host_fallback:
        if summary_host_fallback == host:
            return True
    return False


def _service_matches_observation(
    endpoint_ports: list[int],
    endpoint_protocol: str,
    observed_ports: list[tuple[int, str]],
) -> bool:
    if not endpoint_ports:
        return True if observed_ports else False
    service_protocols = {p: True for p, _ in observed_ports}
    if not observed_ports:
        return False
    for port in endpoint_ports:
        for observed_port, observed_proto in observed_ports:
            if observed_port != port:
                continue
            if endpoint_protocol in {"unknown", "tcp"} and observed_proto in {"tcp", "unknown"}:
                return True
            if endpoint_protocol == observed_proto:
                return True
    return False


def _best_attempt_signature(attempts: list[tuple[str, list[int], str]]) -> str:
    if not attempts:
        return "attempt=none"
    attempt = attempts[0]
    if len(attempts) == 1:
        return attempt[2]
    # keep first as stable representative
    return attempt[2]


def _extract_endpoint_hosts(value: str) -> list[str]:
    if not value:
        return []
    hosts: set[str] = set()
    for candidate in [part.strip() for part in value.split(",") if part.strip()]:
        host = _normalize_host_name(candidate)
        if host is not None:
            hosts.add(host)
    return sorted(hosts)


def _format_cypher_string_list(values: tuple[str, ...] | list[str]) -> str:
    return "[" + ", ".join([f"'{_escape_cypher_string(v)}'" for v in values]) + "]"


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
        out_comm_nodes_csv = stage_dir / "communication_graph.nodes.csv"
        out_comm_edges_csv = stage_dir / "communication_graph.edges.csv"
        out_comm_cypher = stage_dir / "communication_graph.cypher"
        out_comm_schema_cypher = stage_dir / "communication_graph.schema.cypher"
        out_comm_queries_cypher = stage_dir / "communication_graph.queries.cypher"
        out_matrix_json = stage_dir / "communication_matrix.json"
        out_matrix_csv = stage_dir / "communication_matrix.csv"

        _assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(stage_dir, out_json)
        _assert_under_dir(stage_dir, out_dot)
        _assert_under_dir(stage_dir, out_mmd)
        _assert_under_dir(stage_dir, out_ref_json)
        _assert_under_dir(stage_dir, out_comm_json)
        _assert_under_dir(stage_dir, out_comm_nodes_csv)
        _assert_under_dir(stage_dir, out_comm_edges_csv)
        _assert_under_dir(stage_dir, out_comm_cypher)
        _assert_under_dir(stage_dir, out_comm_schema_cypher)
        _assert_under_dir(stage_dir, out_comm_queries_cypher)
        _assert_under_dir(stage_dir, out_matrix_json)
        _assert_under_dir(stage_dir, out_matrix_csv)

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
            _rel_to_run_dir(run_dir, out_comm_nodes_csv),
            _rel_to_run_dir(run_dir, out_comm_edges_csv),
            _rel_to_run_dir(run_dir, out_comm_cypher),
            _rel_to_run_dir(run_dir, out_comm_schema_cypher),
            _rel_to_run_dir(run_dir, out_comm_queries_cypher),
            _rel_to_run_dir(run_dir, out_matrix_json),
            _rel_to_run_dir(run_dir, out_matrix_csv),
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
        surface_component_map: dict[str, set[str]] = {}
        endpoint_records: list[_EndpointRecord] = []
        endpoint_record_by_id: dict[str, _EndpointRecord] = {}

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
                *,
                src: str,
                dst: str,
                edge_type: str,
                confidence: float,
                refs: list[str],
                observation: str | None = "static_reference",
            ) -> None:
            key = (src, dst, edge_type)
            edge_refs = tuple(_sorted_unique_refs(refs))
            if observation is None:
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
                    observation=observation,
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
                    observation=observation,
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
                surface_component_map.setdefault(surface_id, set()).add(component_id)

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
                associated_surfaces: set[str] = set()
                ref_set = set(endpoint_refs)
                if ref_set:
                    for component_id in sorted(component_nodes):
                        comp_refs = component_refs.get(component_id, set())
                        if comp_refs and ref_set.intersection(comp_refs):
                            candidate_components.append(component_id)
                            for surface_id, owners in sorted(
                                surface_component_map.items()
                            ):
                                if component_id in owners:
                                    associated_surfaces.add(surface_id)

                fallback_surface_id: str | None = None
                source_component_ids: set[str] = set()
                if candidate_components:
                    source_component_ids.update(candidate_components)
                    for component_id in candidate_components:
                        upsert_edge(
                            src=component_id,
                            dst=endpoint_id,
                            edge_type="references",
                            confidence=endpoint_confidence,
                            refs=endpoint_refs,
                        )
                elif surface_nodes:
                    fallback_surface_id = sorted(surface_nodes)[0]
                    upsert_edge(
                        src=fallback_surface_id,
                        dst=endpoint_id,
                        edge_type="references",
                        confidence=min(0.5, endpoint_confidence),
                        refs=endpoint_refs,
                    )
                    associated_surfaces.add(fallback_surface_id)
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
                    source_component_ids.add(unknown_component_id)
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

                # retain endpoint metadata for runtime communication linkage
                host, endpoint_ports, endpoint_protocol = _derive_endpoint_record(
                    endpoint_type_any,
                    value_any,
                )
                endpoint_records.append(
                    _EndpointRecord(
                        node_id=endpoint_id,
                        raw_type=endpoint_type_any,
                        raw_value=value_any,
                        host=host,
                        ports=tuple(endpoint_ports),
                        protocol=endpoint_protocol,
                        confidence=endpoint_confidence,
                        refs=tuple(_sorted_unique_refs(endpoint_refs)),
                        source_component_ids=source_component_ids,
                    )
                )
                endpoint_record_by_id[endpoint_id] = endpoint_records[-1]

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
                "observation": edge.observation,
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
            "services": 0,
            "hosts": 0,
            "source_artifacts": cast(list[JsonValue], cast(list[object], [])),
            "classification": "candidate",
            "observation": "runtime_communication",
        }
        communication_summary_limitations: list[str] = []

        def _add_run_artifact_if_exists(path: Path, *, target: list[str]) -> None:
            if not path.is_file():
                return
            rel = _rel_to_run_dir(run_dir, path)
            if rel and rel != "unresolved_path":
                target.append(rel)

        dynamic_summary_obj = _load_json_object(run_dir / _DYNAMIC_VALIDATION_SUMMARY_PATH)
        dynamic_interfaces_path = _pick_dynamic_artifact_path(
            run_dir,
            dynamic_summary_obj,
            summary_field=_DYNAMIC_VALIDATION_INTERFACES_PATHS["summary_field"],
            default_rel_path=_DYNAMIC_VALIDATION_INTERFACES_PATHS["default_rel_path"],
        )
        dynamic_ports_path = _pick_dynamic_artifact_path(
            run_dir,
            dynamic_summary_obj,
            summary_field=_DYNAMIC_VALIDATION_PORTS_PATHS["summary_field"],
            default_rel_path=_DYNAMIC_VALIDATION_PORTS_PATHS["default_rel_path"],
        )

        dynamic_interfaces_obj = _load_json_object(dynamic_interfaces_path)
        dynamic_ports_obj = _load_json_object(dynamic_ports_path)
        (
            dynamic_host_candidates,
            dynamic_service_points,
            dynamic_evidence_refs,
            dynamic_refs_by_source,
        ) = _collect_dynamic_runtime_targets(
            dynamic_summary_obj, dynamic_interfaces_obj, dynamic_ports_obj
        )

        communication_source_artifacts: list[str] = []
        _add_run_artifact_if_exists(run_dir / _DYNAMIC_VALIDATION_SUMMARY_PATH, target=communication_source_artifacts)
        _add_run_artifact_if_exists(dynamic_interfaces_path, target=communication_source_artifacts)
        _add_run_artifact_if_exists(dynamic_ports_path, target=communication_source_artifacts)
        communication_source_artifacts.extend(_sorted_unique_refs(dynamic_evidence_refs))

        flow_observations: list[dict[str, object]] = []
        flow_source = "dynamic_validation"

        for host in dynamic_host_candidates:
            host_norm = _normalize_host_name(host)
            if host_norm is None:
                continue
            flow_observations.append(
                {
                    "source": flow_source,
                    "host": host_norm,
                    "port": None,
                    "protocol": None,
                    "refs": tuple(dynamic_evidence_refs),
                    "matched": False,
                }
            )

        for chain_id, bundle_obj, runtime_refs, _ in _collect_exploit_chain_records(run_dir):
            for runtime_host, runtime_port_proto, _, _ in _extract_runtime_targets_from_exploit_record(
                chain_id, cast(dict[str, object], bundle_obj.get("runtime", {}))
            ):
                runtime_port, runtime_protocol = runtime_port_proto
                runtime_host_norm = _normalize_host_name(runtime_host)
                if runtime_host_norm is None:
                    continue
                flow_observations.append(
                    {
                        "source": f"exploit:{chain_id}",
                        "host": runtime_host_norm,
                        "port": runtime_port,
                        "protocol": runtime_protocol,
                        "refs": tuple(sorted(set(runtime_refs))),
                        "matched": False,
                    }
                )

            attempts_any = bundle_obj.get("attempts")
            if isinstance(attempts_any, list):
                for attempt_any in cast(list[object], attempts_any):
                    if not isinstance(attempt_any, dict):
                        continue
                    attempt_obj = cast(dict[str, object], attempt_any)
                    proof = _as_str(attempt_obj.get("proof_evidence"))
                    if not proof:
                        continue
                    proof_refs: list[str] = []
                    proof_ref = _as_str(attempt_obj.get("proof_evidence"))
                    if proof_ref is not None:
                        proof_ref_norm = _safe_non_absolute_rel(proof_ref, fallback="")
                        if proof_ref_norm:
                            proof_refs.append(proof_ref_norm)
                    if not proof_refs:
                        proof_refs.extend(dynamic_evidence_refs)
                    for host, port, protocol in _parse_targets_from_proof_text(proof):
                        host_norm = _normalize_host_name(host)
                        if host_norm is None:
                            continue
                        flow_observations.append(
                            {
                                "source": f"exploit:{chain_id}:proof",
                                "host": host_norm,
                                "port": port,
                                "protocol": protocol,
                                "refs": tuple(sorted(set(runtime_refs + proof_refs))),
                                "matched": False,
                            }
                        )

        communication_source_artifacts.extend(_sorted_unique_refs(dynamic_evidence_refs))
        for record in _collect_exploit_chain_records(run_dir):
            communication_source_artifacts.extend(record[2])
        communication_source_artifacts = _sorted_unique_refs(communication_source_artifacts)

        communication_nodes: dict[str, _Node] = {}
        communication_edges: dict[tuple[str, str, str], _RuntimeEdge] = {}

        def _upsert_communication_node(
            *,
            node_type: str,
            value: str,
            label: str,
            refs: list[str],
        ) -> str:
            node_value = _safe_node_value(value)
            node_id = _safe_node_value(f"{node_type}:{node_value}")
            existing = communication_nodes.get(node_id)
            node_refs = tuple(_sorted_unique_refs(refs))
            if existing is None:
                communication_nodes[node_id] = _Node(
                    node_id=node_id,
                    node_type=node_type,
                    label=_safe_ascii_label(label),
                    evidence_refs=node_refs,
                )
                return node_id
            merged_refs = tuple(sorted(set(existing.evidence_refs) | set(node_refs)))
            merged_label = existing.label if existing.label != "unknown" else _safe_ascii_label(label)
            communication_nodes[node_id] = _Node(
                node_id=node_id,
                node_type=node_type,
                label=merged_label,
                evidence_refs=merged_refs,
            )
            return node_id

        def _copy_static_node(node_id: str) -> str | None:
            static_node = nodes.get(node_id)
            if static_node is None:
                return None
            existing = communication_nodes.get(node_id)
            if existing is None:
                communication_nodes[node_id] = static_node
                return node_id
            merged_refs = tuple(
                sorted(set(existing.evidence_refs) | set(static_node.evidence_refs))
            )
            merged_label = existing.label if existing.label != "unknown" else static_node.label
            communication_nodes[node_id] = _Node(
                node_id=node_id,
                node_type=existing.node_type,
                label=merged_label,
                evidence_refs=merged_refs,
            )
            return node_id

        def _upsert_communication_edge(
            *,
            src: str,
            dst: str,
            edge_type: str,
            confidence: float,
            refs: list[str],
            observation: str | None = "runtime_communication",
        ) -> None:
            key = (src, dst, edge_type)
            edge_refs = tuple(_sorted_unique_refs(refs))
            confidence_clamped = _clamp01(confidence)
            if observation is None:
                observation = "runtime_communication"
            existing = communication_edges.get(key)
            if existing is None:
                communication_edges[key] = _RuntimeEdge(
                    src=src,
                    dst=dst,
                    edge_type=edge_type,
                    confidence=confidence_clamped,
                    confidence_calibrated=calibrated_confidence(
                        confidence=confidence_clamped,
                        observation=observation,
                        evidence_refs=edge_refs,
                    ),
                    evidence_level=evidence_level(observation, edge_refs),
                    observation=observation,
                    evidence_refs=edge_refs,
                )
                return
            merged_refs = tuple(sorted(set(existing.evidence_refs) | set(edge_refs)))
            merged_confidence = max(existing.confidence, confidence_clamped)
            communication_edges[key] = _RuntimeEdge(
                src=src,
                dst=dst,
                edge_type=edge_type,
                confidence=merged_confidence,
                confidence_calibrated=calibrated_confidence(
                    confidence=merged_confidence,
                    observation=observation,
                    evidence_refs=merged_refs,
                ),
                evidence_level=evidence_level(observation, merged_refs),
                observation=observation,
                evidence_refs=merged_refs,
            )

        def _resolve_or_create_component_for_runtime() -> str:
            nonlocal unknown_component_id
            if sorted(component_nodes):
                return sorted(component_nodes)[0]
            if unknown_component_id is None:
                unknown_component_id = _upsert_communication_node(
                    node_type="component",
                    value="unknown",
                    label="unknown",
                    refs=[],
                )
            return unknown_component_id

        def _add_service_node(
            host: str,
            port: int,
            protocol: str | None,
            refs: list[str],
        ) -> str:
            proto = _normalize_protocol(protocol)
            service_value = f"{host}:{port}/{proto}"
            service_label = f"service:{service_value}"
            return _upsert_communication_node(
                node_type="service",
                value=service_value,
                label=service_label,
                refs=refs,
            )

        for observation in sorted(
            [
                x
                for x in flow_observations
                if isinstance(x.get("host"), str) and _normalize_host_name(x.get("host"))
            ],
            key=lambda item: (
                str(item.get("host") or ""),
                int(item.get("port") or 0),
                str(item.get("protocol") or ""),
            ),
        ):
            host = cast(str, observation.get("host"))
            host = _normalize_host_name(host) or ""
            if not host:
                continue
            port = observation.get("port")
            protocol = _normalize_protocol(observation.get("protocol"))
            port_candidates: list[tuple[int, str]] = []
            if port is not None:
                try:
                    p_norm = int(port)
                except Exception:
                    p_norm = None
                if isinstance(p_norm, int) and 0 < p_norm <= 65535:
                    port_candidates.append((p_norm, protocol))
            if not port_candidates:
                port_candidates.extend(dynamic_service_points)
            refs = _sorted_unique_refs(list(cast(tuple[str, ...], observation.get("refs", ()))))
            source_tag = cast(str, observation.get("source"))

            matching_endpoints: list[_EndpointRecord] = []
            for endpoint in sorted(
                endpoint_records, key=lambda record: (record.node_id, record.host, record.ports)
            ):
                endpoint_hosts = _extract_endpoint_hosts(endpoint.host)
                if not endpoint_hosts:
                    continue
                host_match = (
                    host in endpoint_hosts
                    or any(_is_host_covered(host, [candidate]) for candidate in endpoint_hosts)
                    or any(
                        _is_host_covered(candidate, [host])
                        for candidate in endpoint_hosts
                    )
                )
                if not host_match:
                    continue

                if _service_matches_observation(list(endpoint.ports), endpoint.protocol, port_candidates):
                    matching_endpoints.append(endpoint)
                    obs_mark = cast(dict[str, object], observation)
                    obs_mark["matched"] = True
                    source_components = sorted(endpoint.source_component_ids)
                    if not source_components:
                        source_components = [_resolve_or_create_component_for_runtime()]

                    service_label_type = source_tag.startswith("exploit")
                    host_node_id = _upsert_communication_node(
                        node_type="host",
                        value=host,
                        label=f"host:{host}",
                        refs=refs,
                    )
                    host_refs = refs
                    if host_node_id not in communication_nodes:
                        host_refs = refs

                    for source_component in sorted(source_components):
                        _copy_static_node(source_component)
                        host_observation = (
                            "exploit_chain" if source_tag.startswith("exploit") else "dynamic_validation"
                        )
                        confidence = endpoint.confidence
                        if host_observation == "exploit_chain":
                            confidence = min(1.0, max(0.85, _clamp01(confidence + 0.20)))
                        else:
                            confidence = min(1.0, max(0.70, _clamp01(confidence + 0.10)))
                        _upsert_communication_edge(
                            src=source_component,
                            dst=endpoint.node_id,
                            edge_type="runtime_flow",
                            confidence=confidence,
                            refs=refs + list(endpoint.refs),
                            observation="runtime_communication",
                        )
                        _upsert_communication_edge(
                            src=source_component,
                            dst=host_node_id,
                            edge_type="runtime_host_flow",
                            confidence=min(0.80, max(0.4, confidence - 0.15)),
                            refs=refs + list(endpoint.refs),
                            observation="runtime_communication",
                        )

                        if port_candidates:
                            for service_port, service_protocol in port_candidates:
                                service_node_id = _add_service_node(
                                    host=host,
                                    port=service_port,
                                    protocol=service_protocol,
                                    refs=refs + list(endpoint.refs),
                                )
                                _upsert_communication_edge(
                                    src=host_node_id,
                                    dst=service_node_id,
                                    edge_type="runtime_service_binding",
                                    confidence=min(0.75, max(0.45, confidence - 0.30)),
                                    refs=refs + list(endpoint.refs),
                                    observation="runtime_communication",
                                )
                                if service_label_type:
                                    break
                            break

            if not matching_endpoints and not port_candidates:
                # host was observed at runtime without endpoint match; track it as an
                # unresolved runtime communication point.
                target_component = _resolve_or_create_component_for_runtime()
                host_node_id = _upsert_communication_node(
                    node_type="host",
                    value=host,
                    label=f"host:{host}",
                    refs=refs,
                )
                _upsert_communication_node(
                    node_type="host",
                    value=host,
                    label=f"host:{host}",
                    refs=refs,
                )
                _upsert_communication_edge(
                    src=target_component,
                    dst=host_node_id,
                    edge_type="runtime_discovery",
                    confidence=0.50,
                    refs=refs,
                    observation="runtime_communication",
                )
                for service_port, service_protocol in dynamic_service_points:
                    service_node_id = _add_service_node(
                        host=host,
                        port=service_port,
                        protocol=service_protocol,
                        refs=refs,
                    )
                    _upsert_communication_edge(
                        src=host_node_id,
                        dst=service_node_id,
                        edge_type="runtime_service_binding",
                        confidence=0.45,
                        refs=refs,
                        observation="runtime_communication",
                    )
                observation["matched"] = False
                communication_summary_limitations.append(
                    f"Runtime observation for host {host} could not be mapped to endpoint record; retained as host/service evidence."
                )

        # Merge any unresolved exploitation-only evidence as host/service context without a direct endpoint mapping.
        if communication_edges and all(not item.get("matched") for item in flow_observations):
            fallback_comp = _resolve_or_create_component_for_runtime()
            for host in sorted(set(
                cast(str, item.get("host"))
                for item in flow_observations
                if isinstance(item.get("host"), str)
            )):
                if not host:
                    continue
                host_refs = _sorted_unique_refs(
                    cast(list[str], [*dynamic_evidence_refs])
                )
                host_node_id = _upsert_communication_node(
                    node_type="host",
                    value=host,
                    label=f"host:{host}",
                    refs=host_refs,
                )
                _upsert_communication_edge(
                    src=fallback_comp,
                    dst=host_node_id,
                    edge_type="runtime_discovery",
                    confidence=0.50,
                    refs=host_refs,
                    observation="runtime_communication",
                )

        # Add fallback static nodes that are referenced by copied runtime edges.
        for edge in list(communication_edges):
            src_node = nodes.get(edge[0])
            dst_node = nodes.get(edge[1])
            if src_node is not None:
                _copy_static_node(src_node.node_id)
            if dst_node is not None:
                if (
                    dst_node.node_type == "endpoint"
                    or dst_node.node_type == "component"
                    or dst_node.node_type == "surface"
                ):
                    _copy_static_node(dst_node.node_id)

        comm_node_items = sorted(
            communication_nodes.values(),
            key=lambda n: (n.node_type, n.node_id, n.label),
        )
        comm_edge_items = sorted(
            communication_edges.values(),
            key=lambda e: (e.edge_type, e.src, e.dst, -e.confidence, e.evidence_refs),
        )

        if len(comm_node_items) > int(self.max_nodes):
            communication_summary_limitations.append(
                f"Runtime communication node count reached max_nodes cap ({int(self.max_nodes)}); additional nodes were skipped"
            )
            kept_ids = {n.node_id for n in comm_node_items[: int(self.max_nodes)]}
            comm_node_items = comm_node_items[: int(self.max_nodes)]
            comm_edge_items = [
                e for e in comm_edge_items if e.src in kept_ids and e.dst in kept_ids
            ]
        if len(comm_edge_items) > int(self.max_edges):
            communication_summary_limitations.append(
                f"Runtime communication edge count reached max_edges cap ({int(self.max_edges)}); additional edges were skipped"
            )
            comm_edge_items = comm_edge_items[: int(self.max_edges)]

        communication_node_payload: list[dict[str, JsonValue]] = [
            {
                "id": node.node_id,
                "type": node.node_type,
                "label": node.label,
                "evidence_refs": cast(
                    list[JsonValue], cast(list[object], list(node.evidence_refs))
                ),
            }
            for node in comm_node_items
        ]
        communication_edge_payload: list[dict[str, JsonValue]] = []
        for edge in comm_edge_items:
            edge_signals, edge_badge, edge_counts, dynamic_exploit_chain = (
                _evidence_signal_profile(edge.evidence_refs)
            )
            communication_edge_payload.append(
                {
                    "src": edge.src,
                    "dst": edge.dst,
                    "edge_type": edge.edge_type,
                    "confidence": _clamp01(edge.confidence),
                    "confidence_calibrated": edge.confidence_calibrated,
                    "evidence_level": edge.evidence_level,
                    "observation": edge.observation,
                    "evidence_badge": edge_badge,
                    "evidence_signals": cast(
                        list[JsonValue], cast(list[object], list(edge_signals))
                    ),
                    "dynamic_evidence_count": int(edge_counts["dynamic"]),
                    "exploit_evidence_count": int(edge_counts["exploit"]),
                    "verified_chain_evidence_count": int(
                        edge_counts["verified_chain"]
                    ),
                    "static_evidence_count": int(edge_counts["static"]),
                    "dynamic_exploit_chain": bool(dynamic_exploit_chain),
                    "evidence_refs": cast(
                        list[JsonValue], cast(list[object], list(edge.evidence_refs))
                    ),
                }
            )

        communication_matrix_payload = _communication_matrix_payload(
            {n.node_id: n for n in comm_node_items},
            comm_edge_items,
        )
        communication_matrix_rows = cast(
            list[dict[str, JsonValue]],
            cast(list[object], communication_matrix_payload.get("rows", [])),
        )
        matrix_headers = [
            "component_id",
            "component_label",
            "host",
            "service_host",
            "service_port",
            "protocol",
            "confidence",
            "evidence_level",
            "observation",
            "evidence_badge",
            "evidence_signals",
            "dynamic_evidence_count",
            "exploit_evidence_count",
            "verified_chain_evidence_count",
            "static_evidence_count",
            "dynamic_exploit_chain",
            "evidence_refs",
        ]
        matrix_csv_rows: list[list[str]] = []
        for matrix_row_any in communication_matrix_rows:
            matrix_row = cast(dict[str, object], matrix_row_any)
            matrix_csv_rows.append(
                [
                    _safe_csv_field(matrix_row.get("component_id")),
                    _safe_csv_field(matrix_row.get("component_label")),
                    _safe_csv_field(matrix_row.get("host")),
                    _safe_csv_field(matrix_row.get("service_host")),
                    _safe_csv_field(matrix_row.get("service_port")),
                    _safe_csv_field(matrix_row.get("protocol")),
                    _safe_csv_field(matrix_row.get("confidence")),
                    _safe_csv_field(matrix_row.get("evidence_level")),
                    _safe_csv_field(matrix_row.get("observation")),
                    _safe_csv_field(matrix_row.get("evidence_badge")),
                    _safe_csv_field(matrix_row.get("evidence_signals")),
                    _safe_csv_field(matrix_row.get("dynamic_evidence_count")),
                    _safe_csv_field(matrix_row.get("exploit_evidence_count")),
                    _safe_csv_field(matrix_row.get("verified_chain_evidence_count")),
                    _safe_csv_field(matrix_row.get("static_evidence_count")),
                    _safe_csv_field(matrix_row.get("dynamic_exploit_chain")),
                    _safe_csv_field(matrix_row.get("evidence_refs")),
                ]
            )

        comm_summary = {
            "nodes": len(communication_node_payload),
            "edges": len(communication_edge_payload),
            "components": len([n for n in comm_node_items if n.node_type == "component"]),
            "endpoints": len([n for n in comm_node_items if n.node_type == "endpoint"]),
            "surfaces": len([n for n in comm_node_items if n.node_type == "surface"]),
            "vendors": len([n for n in comm_node_items if n.node_type == "vendor"]),
            "services": len([n for n in comm_node_items if n.node_type == "service"]),
            "hosts": len([n for n in comm_node_items if n.node_type == "host"]),
            "source_artifacts": cast(
                list[JsonValue],
                cast(list[object], sorted(set(communication_source_artifacts))),
            ),
            "matrix": {
                "path_json": _rel_to_run_dir(run_dir, out_matrix_json),
                "path_csv": _rel_to_run_dir(run_dir, out_matrix_csv),
                "rows": cast(
                    list[JsonValue],
                    cast(list[object], communication_matrix_rows),
                ),
                "summary": cast(
                    dict[str, JsonValue],
                    cast(dict[str, object], communication_matrix_payload.get("summary", {})),
                ),
            },
            "neo4j_schema_version": "neo4j-comm-v2",
            "classification": "candidate",
            "observation": "runtime_communication",
        }

        if not communication_node_payload and not communication_edge_payload:
            communication_summary_limitations.append(
                "Runtime communication evidence not available or could not be mapped to endpoint/component artifacts."
            )

        communication_status: StageStatus = "ok" if communication_edge_payload else "partial"
        communication_payload: dict[str, JsonValue] = {
            "status": communication_status,
            "nodes": cast(list[JsonValue], cast(list[object], communication_node_payload)),
            "edges": cast(list[JsonValue], cast(list[object], communication_edge_payload)),
            "summary": comm_summary,
            "limitations": cast(
                list[JsonValue],
                cast(
                    list[object],
                    sorted(set(limitations + communication_summary_limitations)),
                ),
            ),
            "note": "Observed communication graph built from dynamic validation + exploit evidence and mapped to endpoint/component artifacts when possible.",
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
        _ = out_matrix_json.write_text(
            json.dumps(communication_matrix_payload, indent=2, sort_keys=True, ensure_ascii=True)
            + "\n",
            encoding="utf-8",
        )
        _export_csv(
            out_matrix_csv,
            matrix_headers,
            matrix_csv_rows,
        )
        _export_csv(
            out_comm_nodes_csv,
            ["id", "type", "label", "evidence_refs"],
            [
                [
                    row.get("id", ""),
                    row.get("type", ""),
                    row.get("label", ""),
                    _safe_csv_field(
                        row.get("evidence_refs", "")
                    ),
                ]
                for row in communication_node_payload
            ],
        )
        _export_csv(
            out_comm_edges_csv,
            [
                "src",
                "dst",
                "edge_type",
                "confidence",
                "confidence_calibrated",
                "evidence_level",
                "observation",
                "evidence_badge",
                "evidence_signals",
                "dynamic_evidence_count",
                "exploit_evidence_count",
                "verified_chain_evidence_count",
                "static_evidence_count",
                "dynamic_exploit_chain",
                "evidence_refs",
            ],
            [
                [
                    row.get("src", ""),
                    row.get("dst", ""),
                    row.get("edge_type", ""),
                    _safe_csv_field(row.get("confidence")),
                    _safe_csv_field(row.get("confidence_calibrated")),
                    row.get("evidence_level", ""),
                    row.get("observation", ""),
                    _safe_csv_field(row.get("evidence_badge")),
                    _safe_csv_field(row.get("evidence_signals")),
                    _safe_csv_field(row.get("dynamic_evidence_count")),
                    _safe_csv_field(row.get("exploit_evidence_count")),
                    _safe_csv_field(row.get("verified_chain_evidence_count")),
                    _safe_csv_field(row.get("static_evidence_count")),
                    _safe_csv_field(row.get("dynamic_exploit_chain")),
                    _safe_csv_field(row.get("evidence_refs", "")),
                ]
                for row in communication_edge_payload
            ],
        )

        neo4j_schema_version = "neo4j-comm-v2"
        comm_schema_lines: list[str] = [
            f"// {neo4j_schema_version}",
            "// Neo4j schema for communication graph import",
            "CREATE CONSTRAINT comm_node_id_v2 IF NOT EXISTS FOR (n:CommNode) REQUIRE n.id IS UNIQUE;",
            "CREATE INDEX comm_node_type_v2 IF NOT EXISTS FOR (n:CommNode) ON (n.type);",
            "CREATE INDEX comm_node_label_v2 IF NOT EXISTS FOR (n:CommNode) ON (n.label);",
            "CREATE INDEX comm_node_schema_version_v2 IF NOT EXISTS FOR (n:CommNode) ON (n.schema_version);",
            "CREATE INDEX comm_flow_edge_type_v2 IF NOT EXISTS FOR ()-[r:COMM_FLOW]-() ON (r.edge_type);",
            "CREATE INDEX comm_flow_observation_v2 IF NOT EXISTS FOR ()-[r:COMM_FLOW]-() ON (r.observation);",
            "CREATE INDEX comm_flow_evidence_level_v2 IF NOT EXISTS FOR ()-[r:COMM_FLOW]-() ON (r.evidence_level);",
            "CREATE INDEX comm_flow_evidence_badge_v2 IF NOT EXISTS FOR ()-[r:COMM_FLOW]-() ON (r.evidence_badge);",
            "CREATE INDEX comm_flow_dynexp_v2 IF NOT EXISTS FOR ()-[r:COMM_FLOW]-() ON (r.dynamic_exploit_chain);",
        ]
        _ = out_comm_schema_cypher.write_text(
            "\n".join(comm_schema_lines) + "\n", encoding="utf-8"
        )

        comm_queries_lines: list[str] = [
            f"// {neo4j_schema_version}",
            "// Query 0: one-click priority view (Top D+E+V / D+E chains)",
            "MATCH (comp:CommComponent)-[:COMM_FLOW {edge_type:'runtime_host_flow'}]->(host:CommHost)-[s:COMM_FLOW {edge_type:'runtime_service_binding'}]->(svc:CommService)",
            "WITH comp, host, svc, s,",
            "CASE s.evidence_badge",
            "  WHEN 'D+E+V' THEN 3",
            "  WHEN 'D+E' THEN 2",
            "  WHEN 'E+V' THEN 1",
            "  WHEN 'D+V' THEN 1",
            "  ELSE 0",
            "END AS badge_priority",
            "WHERE badge_priority > 0",
            "RETURN badge_priority, s.evidence_badge AS evidence_badge, comp.id AS component_id, comp.label AS component, host.label AS host, svc.label AS service, s.confidence_calibrated AS confidence, s.dynamic_evidence_count AS dyn_refs, s.exploit_evidence_count AS exp_refs, s.verified_chain_evidence_count AS v_refs",
            "ORDER BY badge_priority DESC, confidence DESC, component_id ASC",
            "LIMIT 50;",
            "",
            "// Query 1: dynamic+exploit evidence backed service paths (high-value triage)",
            "MATCH (comp:CommComponent)-[h:COMM_FLOW {edge_type:'runtime_host_flow'}]->(host:CommHost)-[s:COMM_FLOW {edge_type:'runtime_service_binding'}]->(svc:CommService)",
            "WHERE s.dynamic_exploit_chain = true",
            "RETURN comp.id AS component_id, comp.label AS component, host.label AS host, svc.label AS service, s.evidence_badge AS evidence_badge, s.confidence_calibrated AS confidence",
            "ORDER BY s.confidence_calibrated DESC, comp.id ASC;",
            "",
            "// Query 2: evidence badge distribution",
            "MATCH ()-[r:COMM_FLOW]->()",
            "RETURN r.evidence_badge AS evidence_badge, count(*) AS edge_count, avg(r.confidence_calibrated) AS avg_confidence",
            "ORDER BY edge_count DESC, evidence_badge ASC;",
            "",
            "// Query 3: components with unresolved runtime discovery (no endpoint mapping)",
            "MATCH (comp:CommComponent)-[r:COMM_FLOW {edge_type:'runtime_discovery'}]->(host:CommHost)",
            "RETURN comp.id AS component_id, comp.label AS component, host.label AS host, r.confidence_calibrated AS confidence, r.evidence_refs AS evidence_refs",
            "ORDER BY r.confidence_calibrated DESC, component_id ASC;",
            "",
            "// Query 4: host->service inventory for operational threat modeling",
            "MATCH (host:CommHost)-[r:COMM_FLOW {edge_type:'runtime_service_binding'}]->(svc:CommService)",
            "RETURN host.label AS host, svc.label AS service, r.evidence_badge AS evidence_badge, r.dynamic_evidence_count AS dynamic_refs, r.exploit_evidence_count AS exploit_refs, r.verified_chain_evidence_count AS verified_refs",
            "ORDER BY host ASC, service ASC;",
        ]
        _ = out_comm_queries_cypher.write_text(
            "\n".join(comm_queries_lines) + "\n", encoding="utf-8"
        )

        comm_cypher_lines: list[str] = [
            "// Communication graph export (runtime + evidence-backed flows)",
            f"// schema_version={neo4j_schema_version}",
            "CREATE CONSTRAINT comm_node_id IF NOT EXISTS FOR (n:CommNode) REQUIRE n.id IS UNIQUE;",
            "UNWIND [",
        ]
        node_payload_lines: list[str] = []
        for node in comm_node_items:
            node_id = _safe_node_value(cast(str, node.node_id))
            node_refs = cast(tuple[str, ...], node.evidence_refs)
            if node.node_type == "component":
                neo4j_label = "CommComponent"
            elif node.node_type == "host":
                neo4j_label = "CommHost"
            elif node.node_type == "service":
                neo4j_label = "CommService"
            elif node.node_type == "endpoint":
                neo4j_label = "CommEndpoint"
            elif node.node_type == "surface":
                neo4j_label = "CommSurface"
            elif node.node_type == "vendor":
                neo4j_label = "CommVendor"
            else:
                neo4j_label = "CommUnknown"
            node_payload_lines.append(
                "  {id:'"
                + _escape_cypher_string(node_id)
                + "', type:'"
                + _escape_cypher_string(_safe_node_value(node.node_type))
                + "', label:'"
                + _escape_cypher_string(_safe_node_value(node.label))
                + "', evidence_refs:"
                + _format_cypher_string_list(node_refs)
                + ", neo4j_label:'"
                + _escape_cypher_string(neo4j_label)
                + "'"
                + "}"
            )
        comm_cypher_lines.append(",\n".join(node_payload_lines))
        comm_cypher_lines.extend(
            [
                "] AS row",
                "MERGE (n:CommNode {id: row.id})",
                "SET n.type = row.type, n.label = row.label, n.evidence_refs = row.evidence_refs, n.schema_version = '" + neo4j_schema_version + "'",
                "FOREACH (_ IN CASE WHEN row.neo4j_label = 'CommComponent' THEN [1] ELSE [] END | SET n:CommComponent)",
                "FOREACH (_ IN CASE WHEN row.neo4j_label = 'CommHost' THEN [1] ELSE [] END | SET n:CommHost)",
                "FOREACH (_ IN CASE WHEN row.neo4j_label = 'CommService' THEN [1] ELSE [] END | SET n:CommService)",
                "FOREACH (_ IN CASE WHEN row.neo4j_label = 'CommEndpoint' THEN [1] ELSE [] END | SET n:CommEndpoint)",
                "FOREACH (_ IN CASE WHEN row.neo4j_label = 'CommSurface' THEN [1] ELSE [] END | SET n:CommSurface)",
                "FOREACH (_ IN CASE WHEN row.neo4j_label = 'CommVendor' THEN [1] ELSE [] END | SET n:CommVendor)",
                "",
                "UNWIND [",
            ]
        )

        edge_payload_lines: list[str] = []
        for edge in comm_edge_items:
            edge_refs = cast(tuple[str, ...], edge.evidence_refs)
            edge_signals, edge_badge, edge_counts, dynamic_exploit_chain = (
                _evidence_signal_profile(edge_refs)
            )
            edge_payload_lines.append(
                "{src:'"
                + _escape_cypher_string(_safe_node_value(edge.src))
                + "', dst:'"
                + _escape_cypher_string(_safe_node_value(edge.dst))
                + "', edge_type:'"
                + _escape_cypher_string(_safe_node_value(edge.edge_type))
                + "', confidence:"
                + f"{edge.confidence:.16f}"
                + ", confidence_calibrated:"
                + f"{edge.confidence_calibrated:.16f}"
                + ", evidence_level:'"
                + _escape_cypher_string(_safe_node_value(edge.evidence_level))
                + "', observation:'"
                + _escape_cypher_string(_safe_node_value(edge.observation))
                + "', evidence_badge:'"
                + _escape_cypher_string(edge_badge)
                + "', evidence_signals:"
                + _format_cypher_string_list(tuple(edge_signals))
                + ", dynamic_evidence_count:"
                + str(int(edge_counts["dynamic"]))
                + ", exploit_evidence_count:"
                + str(int(edge_counts["exploit"]))
                + ", verified_chain_evidence_count:"
                + str(int(edge_counts["verified_chain"]))
                + ", static_evidence_count:"
                + str(int(edge_counts["static"]))
                + ", dynamic_exploit_chain:"
                + ("true" if dynamic_exploit_chain else "false")
                + ", evidence_refs:"
                + _format_cypher_string_list(edge_refs)
                + "}"
            )

        comm_cypher_lines.append(",\n".join(edge_payload_lines))
        comm_cypher_lines.extend(
            [
                "] AS row",
                "MATCH (src:CommNode {id: row.src}), (dst:CommNode {id: row.dst})",
                "MERGE (src)-[r:COMM_FLOW {edge_type: row.edge_type, src: row.src, dst: row.dst}]->(dst)",
                "SET r.confidence = row.confidence, r.confidence_calibrated = row.confidence_calibrated, r.evidence_level = row.evidence_level, r.observation = row.observation, r.evidence_refs = row.evidence_refs, r.evidence_badge = row.evidence_badge, r.evidence_signals = row.evidence_signals, r.dynamic_evidence_count = row.dynamic_evidence_count, r.exploit_evidence_count = row.exploit_evidence_count, r.verified_chain_evidence_count = row.verified_chain_evidence_count, r.static_evidence_count = row.static_evidence_count, r.dynamic_exploit_chain = row.dynamic_exploit_chain, r.schema_version = '" + neo4j_schema_version + "'",
            ]
        )
        if not comm_cypher_lines:
            comm_cypher_lines = ["// Communication graph is empty", "RETURN 0;"]
        _ = out_comm_cypher.write_text(
            "\n".join(comm_cypher_lines) + "\n", encoding="utf-8"
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
            "communication_graph_nodes_csv": _rel_to_run_dir(run_dir, out_comm_nodes_csv),
            "communication_graph_edges_csv": _rel_to_run_dir(run_dir, out_comm_edges_csv),
            "communication_graph_cypher": _rel_to_run_dir(run_dir, out_comm_cypher),
            "communication_graph_schema_cypher": _rel_to_run_dir(
                run_dir, out_comm_schema_cypher
            ),
            "communication_graph_queries_cypher": _rel_to_run_dir(
                run_dir, out_comm_queries_cypher
            ),
            "communication_matrix_json": _rel_to_run_dir(run_dir, out_matrix_json),
            "communication_matrix_csv": _rel_to_run_dir(run_dir, out_matrix_csv),
            "neo4j_schema_version": neo4j_schema_version,
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
