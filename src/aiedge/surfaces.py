from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .confidence_caps import calibrated_confidence, evidence_level
from .path_safety import assert_under_dir
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus


def _safe_resolve(path: Path) -> Path | None:
    try:
        return path.resolve()
    except OSError:
        return None


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


def _is_run_relative_path(path: object) -> bool:
    if not isinstance(path, str) or not path:
        return False
    return not path.startswith("/")


def _surface_type_from_name(name: str) -> str:
    lowered = name.lower()
    web_tokens = (
        "httpd",
        "nginx",
        "lighttpd",
        "uhttpd",
        "synowebapi",
        "webapi",
        "webman",
    )
    if any(token in lowered for token in web_tokens):
        return "web"
    if any(
        marker in lowered
        for marker in (
            ".cgi",
            "_cgi",
            "-cgi",
            "cgi-bin",
        )
    ):
        return "web"
    if any(x in lowered for x in ("dropbear", "sshd")):
        return "ssh"
    if any(x in lowered for x in ("telnetd", "in.telnetd")):
        return "telnet"
    if any(x in lowered for x in ("dnsmasq", "udhcpd", "dhcpd")):
        return "dns_dhcp"
    if any(x in lowered for x in ("dbus", "ubus", "rpcd", "netifd", "unix_socket", "ipc")):
        return "ipc"
    return "service"


def _surface_confidence(base: float, surface_type: str) -> float:
    offsets: dict[str, float] = {
        "web": 0.1,
        "ssh": 0.08,
        "telnet": 0.04,
        "dns_dhcp": 0.06,
        "ipc": 0.05,
        "service": 0.0,
    }
    return _clamp01(base + offsets.get(surface_type, 0.0))


def _load_json_object(path: Path) -> dict[str, object] | None:
    try:
        raw = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None
    return cast(dict[str, object], raw)


_EXEC_SINK_SYMBOLS = frozenset(
    {
        "system",
        "popen",
        "execve",
        "execvp",
        "execvpe",
        "execl",
        "execlp",
        "execle",
        "execv",
        "posix_spawn",
        "backtick",
        "eval",
        "shell_exec",
        "passthru",
    }
)

_SOURCE_ENDPOINT_TYPES = frozenset({"url", "http_path", "ipv4", "http_endpoint", "cgi_path"})


def _build_source_sink_graph(
    *,
    run_dir: Path,
    endpoints_obj: dict[str, object] | None,
    inventory_obj: dict[str, object] | None,
    surfaces_list: list[dict[str, JsonValue]],
    max_paths: int = 200,
) -> tuple[list[dict[str, JsonValue]], list[str]]:
    """Build source→component→sink paths from endpoints + binary analysis data."""
    limitations: list[str] = []
    paths: list[dict[str, JsonValue]] = []

    # --- Load binary_analysis.json ---
    binary_analysis_path = run_dir / "stages" / "inventory" / "binary_analysis.json"
    binary_analysis_obj = _load_json_object(binary_analysis_path)

    # --- Collect sink binaries (binaries with exec-related risky symbols) ---
    # Each sink: {"binary": name, "symbols": [...], "evidence_path": rel_path}
    sink_binaries: list[dict[str, object]] = []
    if binary_analysis_obj is not None:
        binaries_any = binary_analysis_obj.get("hits")
        if isinstance(binaries_any, list):
            for bin_any in cast(list[object], binaries_any):
                if not isinstance(bin_any, dict):
                    continue
                bin_obj = cast(dict[str, object], bin_any)
                # Gather risky symbols for this binary
                risky_syms_any = bin_obj.get("matched_symbols") or bin_obj.get("risky_symbols")
                risky_count_any = bin_obj.get("risky_symbol_count")
                found_syms: list[str] = []
                if isinstance(risky_syms_any, list):
                    for sym_any in cast(list[object], risky_syms_any):
                        if isinstance(sym_any, str) and sym_any.lower() in _EXEC_SINK_SYMBOLS:
                            found_syms.append(sym_any)
                elif isinstance(risky_count_any, (int, float)) and int(risky_count_any) > 0:
                    # Count > 0 but no symbol list — treat as unknown exec sink
                    found_syms = ["(exec_sink_detected)"]
                if not found_syms:
                    continue
                bin_name_any = bin_obj.get("name") or bin_obj.get("path") or bin_obj.get("binary")
                if not isinstance(bin_name_any, str) or not bin_name_any:
                    continue
                bin_path_any = bin_obj.get("path") or bin_obj.get("name")
                evidence_path = (
                    _safe_non_absolute_rel(cast(str, bin_path_any))
                    if isinstance(bin_path_any, str)
                    else "unresolved_path"
                )
                sink_binaries.append(
                    {
                        "binary": bin_name_any,
                        "symbols": found_syms,
                        "evidence_path": evidence_path,
                    }
                )
    else:
        limitations.append(
            "binary_analysis.json missing or unreadable; sink detection limited"
        )

    if not sink_binaries:
        # No sinks — nothing to trace
        return [], limitations

    # --- Collect source endpoints ---
    sources: list[dict[str, object]] = []
    if endpoints_obj is not None:
        endpoints_any = endpoints_obj.get("endpoints")
        if isinstance(endpoints_any, list):
            for ep_any in cast(list[object], endpoints_any):
                if not isinstance(ep_any, dict):
                    continue
                ep = cast(dict[str, object], ep_any)
                ep_type_any = ep.get("type") or ep.get("endpoint_type")
                ep_value_any = ep.get("value") or ep.get("endpoint") or ep.get("url")
                ep_conf_any = ep.get("confidence")
                if not isinstance(ep_type_any, str):
                    ep_type_any = "http_path"
                if not isinstance(ep_value_any, str) or not ep_value_any:
                    continue
                if ep_type_any.lower() not in _SOURCE_ENDPOINT_TYPES:
                    continue
                conf = float(ep_conf_any) if isinstance(ep_conf_any, (int, float)) else 0.5
                sources.append(
                    {
                        "type": ep_type_any,
                        "value": ep_value_any,
                        "confidence": _clamp01(conf),
                    }
                )

    # --- Augment sources from Ghidra string_refs: CGI handler functions ---
    ghidra_dir = run_dir / "stages" / "ghidra_analysis"
    for sr_file in ghidra_dir.rglob("string_refs.json"):
        try:
            sr_data = json.loads(sr_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(sr_data, dict):
            continue
        strings_any = sr_data.get("strings")
        if not isinstance(strings_any, list):
            continue
        for s_any in cast(list[object], strings_any):
            if not isinstance(s_any, dict):
                continue
            s = cast(dict[str, object], s_any)
            val = str(s.get("value", ""))
            # Detect CGI path patterns (e.g., "/cgi-bin/xxx", "apply.cgi", "appGet.cgi")
            if ".cgi" in val.lower() and "/" in val:
                sources.append({
                    "type": "cgi_path",
                    "value": val,
                    "confidence": 0.65,
                })
            # Detect embedded CGI handler function names (do_*_cgi, apply_cgi)
            refs_any = s.get("xrefs") or s.get("referencing_functions")
            if isinstance(refs_any, list):
                for ref in cast(list[object], refs_any):
                    ref_name = str(ref) if isinstance(ref, str) else str(ref)
                    if ref_name.startswith("do_") and "cgi" in ref_name.lower():
                        sources.append({
                            "type": "cgi_path",
                            "value": f"/{ref_name}",
                            "confidence": 0.60,
                        })

    if not sources:
        limitations.append(
            "No network-facing source endpoints found; source→sink tracing skipped"
        )
        return [], limitations

    # --- Build component map from surfaces for endpoint→component resolution ---
    # component_name → set of evidence_refs
    component_evidence: dict[str, set[str]] = {}
    for surf in surfaces_list:
        comp_any = surf.get("component")
        refs_any = surf.get("evidence_refs")
        if not isinstance(comp_any, str):
            continue
        if isinstance(refs_any, list):
            for ref_any in cast(list[object], refs_any):
                if isinstance(ref_any, str):
                    component_evidence.setdefault(comp_any, set()).add(ref_any)

    # Also pull service_candidates from inventory for component resolution
    # Map: component name → list of evidence file paths
    service_comp_map: dict[str, list[str]] = {}
    if inventory_obj is not None:
        cands_any = inventory_obj.get("service_candidates")
        if isinstance(cands_any, list):
            for cand_any in cast(list[object], cands_any):
                if not isinstance(cand_any, dict):
                    continue
                cand = cast(dict[str, object], cand_any)
                cname_any = cand.get("name")
                evid_any = cand.get("evidence")
                if not isinstance(cname_any, str) or not cname_any:
                    continue
                refs: list[str] = []
                if isinstance(evid_any, list):
                    for item_any in cast(list[object], evid_any):
                        if not isinstance(item_any, dict):
                            continue
                        p_any = cast(dict[str, object], item_any).get("path")
                        if isinstance(p_any, str) and p_any:
                            refs.append(p_any)
                service_comp_map[cname_any] = refs

    # Pick a default component if any exist
    default_component: str | None = None
    if service_comp_map:
        default_component = next(iter(service_comp_map))
    elif surfaces_list:
        comp_any2 = surfaces_list[0].get("component")
        if isinstance(comp_any2, str):
            default_component = comp_any2

    # --- Build paths ---
    endpoints_ref = "stages/endpoints/endpoints.json"
    binary_ref = "stages/inventory/binary_analysis.json"

    for source in sources:
        if len(paths) >= max_paths:
            limitations.append(
                f"source_sink_graph reached max_paths cap ({max_paths}); additional paths skipped"
            )
            break

        src_type = cast(str, source["type"])
        src_value = cast(str, source["value"])
        src_conf = cast(float, source["confidence"])

        # Find matching component — prefer one whose evidence path contains the endpoint value
        matched_component: str | None = None
        comp_evidence_path: str = ""
        for comp_name, refs in service_comp_map.items():
            for ref in refs:
                if src_value.lower() in ref.lower() or comp_name.lower() in src_value.lower():
                    matched_component = comp_name
                    comp_evidence_path = ref
                    break
            if matched_component:
                break

        if matched_component is None:
            matched_component = default_component or "unknown_component"
            comp_evidence_path = (
                service_comp_map.get(matched_component, [""])[0]
                if service_comp_map.get(matched_component)
                else ""
            )

        for sink in sink_binaries:
            if len(paths) >= max_paths:
                break

            sink_binary = cast(str, sink["binary"])
            sink_symbols = cast(list[str], sink["symbols"])
            sink_evidence = cast(str, sink["evidence_path"])

            # Compute sink_proximity: does sink live near the component's rootfs?
            sink_proximity = 0.2
            if comp_evidence_path and sink_evidence and sink_evidence != "unresolved_path":
                # Same directory → 1.0; same rootfs prefix → 0.5
                comp_dir = "/".join(comp_evidence_path.replace("\\", "/").split("/")[:-1])
                sink_dir = "/".join(sink_evidence.replace("\\", "/").split("/")[:-1])
                if comp_dir and sink_dir and comp_dir == sink_dir:
                    sink_proximity = 1.0
                elif comp_dir and sink_dir and (
                    comp_dir.startswith(sink_dir) or sink_dir.startswith(comp_dir)
                ):
                    sink_proximity = 0.5

            # component_match: 1.0 if we matched by value/name, 0.5 if default
            component_match = 1.0 if matched_component != default_component else 0.5

            combined_conf = _clamp01(
                src_conf * 0.5 + sink_proximity * 0.3 + component_match * 0.2
            )

            through_evidence = comp_evidence_path if comp_evidence_path else endpoints_ref
            path_entry: dict[str, JsonValue] = {
                "source": {
                    "type": src_type,
                    "value": src_value,
                    "confidence": src_conf,
                },
                "through": cast(
                    list[JsonValue],
                    cast(
                        list[object],
                        [
                            {
                                "type": "component",
                                "name": matched_component,
                                "evidence": through_evidence,
                            }
                        ],
                    ),
                ),
                "sink": {
                    "type": "exec_sink",
                    "binary": sink_binary,
                    "symbols": cast(list[JsonValue], cast(list[object], sink_symbols)),
                },
                "confidence": combined_conf,
                "evidence_refs": cast(
                    list[JsonValue],
                    cast(list[object], [endpoints_ref, binary_ref]),
                ),
            }
            paths.append(path_entry)

    return paths, limitations


@dataclass(frozen=True)
class SurfacesStage:
    max_surfaces: int = 200
    max_unknowns: int = 200

    @property
    def name(self) -> str:
        return "surfaces"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "surfaces"
        out_json = stage_dir / "surfaces.json"

        assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        assert_under_dir(stage_dir, out_json)

        inventory_path = run_dir / "stages" / "inventory" / "inventory.json"
        endpoints_path = run_dir / "stages" / "endpoints" / "endpoints.json"

        limitations: list[str] = []
        unknowns: list[dict[str, JsonValue]] = []
        evidence: list[dict[str, JsonValue]] = []

        inventory_obj = _load_json_object(inventory_path)
        inventory_present = inventory_path.is_file()
        if inventory_present:
            evidence.append({"path": _rel_to_run_dir(run_dir, inventory_path)})
        else:
            limitations.append(
                "Inventory output missing: stages/inventory/inventory.json"
            )

        candidates_any: object = None
        if inventory_obj is None:
            if inventory_present:
                limitations.append(
                    "Inventory output unreadable or invalid; expected JSON object"
                )
        else:
            candidates_any = inventory_obj.get("service_candidates")

        candidates_raw: list[object] = []
        if isinstance(candidates_any, list):
            candidates_raw = cast(list[object], candidates_any)
        elif inventory_obj is not None:
            limitations.append("Inventory service_candidates missing or invalid")

        name_kind_counts: dict[str, set[str]] = {}
        parsed_candidates: list[dict[str, object]] = []
        for candidate_any in candidates_raw:
            if not isinstance(candidate_any, dict):
                continue
            candidate = cast(dict[str, object], candidate_any)
            name_any = candidate.get("name")
            kind_any = candidate.get("kind")
            conf_any = candidate.get("confidence")
            evidence_any = candidate.get("evidence")
            if not isinstance(name_any, str) or not name_any:
                continue
            if not isinstance(kind_any, str) or not kind_any:
                continue
            if not isinstance(conf_any, (int, float)):
                continue
            refs: set[str] = set()
            if isinstance(evidence_any, list):
                for item_any in cast(list[object], evidence_any):
                    if not isinstance(item_any, dict):
                        continue
                    path_any = cast(dict[str, object], item_any).get("path")
                    if _is_run_relative_path(path_any):
                        refs.add(cast(str, path_any).replace("\\", "/"))
            if not refs:
                continue
            parsed_candidates.append(
                {
                    "name": name_any,
                    "kind": kind_any,
                    "confidence": _clamp01(float(conf_any)),
                    "evidence_refs": sorted(refs),
                }
            )
            name_kind_counts.setdefault(name_any.lower(), set()).add(kind_any.lower())

        merged: dict[tuple[str, str], dict[str, object]] = {}
        for candidate in parsed_candidates:
            name = cast(str, candidate["name"])
            kind = cast(str, candidate["kind"])
            base_conf = cast(float, candidate["confidence"])
            evidence_refs = cast(list[str], candidate["evidence_refs"])
            collision = len(name_kind_counts.get(name.lower(), set())) > 1
            component = f"{kind}:{name}" if collision else name
            surface_type = _surface_type_from_name(name)
            confidence = _surface_confidence(base_conf, surface_type)
            key = (surface_type, component)

            existing = merged.get(key)
            if existing is None:
                merged[key] = {
                    "surface_type": surface_type,
                    "component": component,
                    "confidence": confidence,
                    "evidence_refs": set(evidence_refs),
                }
                continue

            existing["confidence"] = max(
                cast(float, existing["confidence"]),
                confidence,
            )
            cast(set[str], existing["evidence_refs"]).update(evidence_refs)

        surfaces: list[dict[str, JsonValue]] = []
        for key in sorted(merged.keys(), key=lambda item: (item[0], item[1])):
            item = merged[key]
            item_refs = sorted(cast(set[str], item["evidence_refs"]))
            if not item_refs:
                continue
            confidence = _clamp01(cast(float, item["confidence"]))
            observation = "static_reference"
            surfaces.append(
                {
                    "surface_type": cast(str, item["surface_type"]),
                    "component": cast(str, item["component"]),
                    "confidence": confidence,
                    "confidence_calibrated": calibrated_confidence(
                        confidence=confidence,
                        observation=observation,
                        evidence_refs=item_refs,
                    ),
                    "evidence_refs": cast(
                        list[JsonValue], cast(list[object], item_refs)
                    ),
                    "classification": "candidate",
                    "observation": observation,
                    "evidence_level": evidence_level(observation, item_refs),
                }
            )

        if len(surfaces) > int(self.max_surfaces):
            limitations.append(
                f"Surface extraction reached max_surfaces cap ({int(self.max_surfaces)}); additional items were skipped"
            )
            surfaces = surfaces[: int(self.max_surfaces)]

        endpoints_obj = _load_json_object(endpoints_path)
        endpoints_count = 0
        if endpoints_obj is not None:
            evidence.append({"path": _rel_to_run_dir(run_dir, endpoints_path)})
            endpoints_any = endpoints_obj.get("endpoints")
            if isinstance(endpoints_any, list):
                endpoints_count = len(cast(list[object], endpoints_any))

        if endpoints_count > 0 and not surfaces:
            unknowns.append(
                {
                    "reason": "Endpoints were identified but no owning service candidates were inferred",
                    "evidence_refs": cast(
                        list[JsonValue],
                        cast(list[object], [_rel_to_run_dir(run_dir, endpoints_path)]),
                    ),
                }
            )

        if not parsed_candidates:
            limitations.append(
                "No service candidates available to infer input surfaces"
            )

        if len(unknowns) > int(self.max_unknowns):
            limitations.append(
                f"Surface extraction reached max_unknowns cap ({int(self.max_unknowns)}); additional unknown notes were skipped"
            )
            unknowns = unknowns[: int(self.max_unknowns)]

        summary: dict[str, JsonValue] = {
            "service_candidates_seen": len(parsed_candidates),
            "surfaces": len(surfaces),
            "unknowns": len(unknowns),
            "classification": "candidate",
            "observation": "static_reference",
        }

        status: StageStatus = "ok"
        if not inventory_present or not parsed_candidates:
            status = "partial"

        payload: dict[str, JsonValue] = {
            "status": status,
            "summary": summary,
            "surfaces": cast(list[JsonValue], cast(list[object], surfaces)),
            "unknowns": cast(list[JsonValue], cast(list[object], unknowns)),
            "limitations": cast(
                list[JsonValue],
                cast(list[object], sorted(set(limitations))),
            ),
            "note": "Static candidate input surfaces inferred from inventory service candidates; no runtime interaction evidence.",
        }
        _ = out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        # --- Source→Sink path tracing ---
        source_sink_json = stage_dir / "source_sink_graph.json"
        assert_under_dir(run_dir, source_sink_json)
        ss_paths, ss_limitations = _build_source_sink_graph(
            run_dir=run_dir,
            endpoints_obj=endpoints_obj,
            inventory_obj=inventory_obj,
            surfaces_list=surfaces,
            max_paths=200,
        )
        if ss_limitations:
            limitations.extend(ss_limitations)
        source_count = len(
            {p["source"]["value"] for p in ss_paths if isinstance(p.get("source"), dict)}  # type: ignore[index]
        )
        sink_count = len(
            {
                p["sink"]["binary"]  # type: ignore[index]
                for p in ss_paths
                if isinstance(p.get("sink"), dict)
            }
        )
        ss_payload: dict[str, JsonValue] = {
            "schema_version": "source-sink-v1",
            "paths": cast(list[JsonValue], cast(list[object], ss_paths)),
            "summary": {
                "total_paths": len(ss_paths),
                "high_confidence": len(
                    [p for p in ss_paths if cast(float, p.get("confidence", 0.0)) >= 0.7]
                ),
                "sources": source_count,
                "sinks": sink_count,
            },
        }
        _ = source_sink_json.write_text(
            json.dumps(ss_payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        evidence.append({"path": _rel_to_run_dir(run_dir, out_json)})
        evidence.append({"path": _rel_to_run_dir(run_dir, source_sink_json)})
        details: dict[str, JsonValue] = {
            "summary": summary,
            "surfaces": cast(list[JsonValue], cast(list[object], surfaces)),
            "unknowns": cast(list[JsonValue], cast(list[object], unknowns)),
            "evidence": cast(list[JsonValue], cast(list[object], evidence)),
            "surfaces_json": _rel_to_run_dir(run_dir, out_json),
            "source_sink_graph_json": _rel_to_run_dir(run_dir, source_sink_json),
            "classification": "candidate",
            "observation": "static_reference",
        }

        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
