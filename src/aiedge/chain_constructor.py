from __future__ import annotations

"""Exploit chain construction stage.

Builds multi-step exploit chains from individual findings by analyzing
same-binary source-to-sink paths and cross-binary IPC edges from the
communication graph.  Uses LLM (opus tier) for chain reasoning when
available; falls back to static-only chain assembly under ``--no-llm``.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .llm_driver import resolve_driver
from .path_safety import assert_under_dir
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus

_SCHEMA_VERSION = "chain-construction-v1"
_LLM_TIMEOUT_S = 180.0
_LLM_MAX_ATTEMPTS = 3
_RETRYABLE_TOKENS: tuple[str, ...] = (
    "stream disconnected",
    "error sending request",
    "connection reset",
    "connection refused",
    "timed out",
    "timeout",
    "temporary failure",
    "503",
    "502",
    "429",
)

_IPC_EDGE_TYPES: frozenset[str] = frozenset(
    {
        "ipc_unix_socket",
        "ipc_dbus",
        "ipc_shm",
        "ipc_pipe",
        "ipc_exec_chain",
    }
)

_MAX_CHAINS = 50


def _load_json_file(path: Path) -> object | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _clamp01(v: float) -> float:
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return float(v)


def _build_chain_prompt(
    findings_json: str,
    ipc_edges_json: str,
    shared_strings_json: str,
) -> str:
    return (
        "You are an expert firmware exploit chain analyst.\n"
        "Given individual findings, IPC communication edges, and shared\n"
        "string constants, construct multi-step exploit chains from\n"
        "external input to code execution.\n\n"
        "## Individual Findings\n"
        f"{findings_json}\n\n"
        "## IPC Communication Edges\n"
        f"{ipc_edges_json}\n\n"
        "## Shared String Constants Between Binaries\n"
        f"{shared_strings_json}\n\n"
        "## Rules\n"
        "- Each chain must start from an external input (network, web, etc.)\n"
        "- Chain steps should be connected via IPC or shared memory\n"
        "- End goal: code execution, privilege escalation, or data exfiltration\n"
        "- Identify missing evidence for each chain\n"
        "- Rate confidence based on evidence strength\n\n"
        "## Output Format\n"
        "Return ONLY a JSON object (no markdown fences):\n"
        "{\n"
        '  "chains": [\n'
        "    {\n"
        '      "id": "<chain_id>",\n'
        '      "description": "<chain description>",\n'
        '      "steps": [\n'
        "        {\n"
        '          "finding_id": "<id or description>",\n'
        '          "primitive": "<what this step achieves>",\n'
        '          "evidence": "<supporting evidence>"\n'
        "        }\n"
        "      ],\n"
        '      "confidence": 0.0-1.0,\n'
        '      "missing_evidence": ["<what would strengthen this chain>"]\n'
        "    }\n"
        "  ]\n"
        "}\n"
    )


def _parse_json_response(stdout: str) -> dict[str, object] | None:
    from .llm_driver import parse_json_from_llm_output

    return parse_json_from_llm_output(stdout)


def _truncate_json(data: object, *, max_chars: int = 6000) -> str:
    text = json.dumps(data, indent=2, ensure_ascii=True)
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


@dataclass(frozen=True)
class ChainConstructorStage:
    """Build exploit chains from individual findings."""

    no_llm: bool = False

    @property
    def name(self) -> str:
        return "chain_construction"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "chain_construction"
        out_json = stage_dir / "chains.json"

        assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        assert_under_dir(run_dir, out_json)

        limitations: list[str] = []

        # --- Load all findings from multiple sources ---
        findings: list[dict[str, object]] = []
        findings_sources = [
            run_dir / "stages" / "adversarial_triage" / "triaged_findings.json",
            run_dir / "stages" / "fp_verification" / "verified_alerts.json",
            run_dir / "stages" / "findings" / "findings.json",
        ]
        for fpath in findings_sources:
            fdata = _load_json_file(fpath)
            if not isinstance(fdata, dict):
                continue
            fd = cast(dict[str, object], fdata)
            for key in ("triaged_findings", "verified_alerts", "findings"):
                items_any = fd.get(key)
                if isinstance(items_any, list):
                    for item in cast(list[object], items_any):
                        if isinstance(item, dict):
                            findings.append(cast(dict[str, object], item))
                    break

        # Always load pattern_scan.json (has 62 findings with family/evidence)
        ps_path = run_dir / "stages" / "findings" / "pattern_scan.json"
        ps_data = _load_json_file(ps_path)
        if isinstance(ps_data, dict):
            ps_findings_any = cast(dict[str, object], ps_data).get("findings")
            if isinstance(ps_findings_any, list):
                for item in cast(list[object], ps_findings_any):
                    if not isinstance(item, dict):
                        continue
                    ps_item = cast(dict[str, object], item)
                    # Normalize: extract binary path from evidence[0].path
                    if "binary" not in ps_item:
                        ev_list = ps_item.get("evidence")
                        if isinstance(ev_list, list) and ev_list:
                            first_ev = ev_list[0]
                            if isinstance(first_ev, dict):
                                ev_path = cast(dict[str, object], first_ev).get("path")
                                if isinstance(ev_path, str) and ev_path:
                                    ps_item["binary"] = ev_path
                    findings.append(ps_item)

        # Always load exploit_candidates.json
        ec_path = run_dir / "stages" / "findings" / "exploit_candidates.json"
        ec_data = _load_json_file(ec_path)
        if isinstance(ec_data, dict):
            ec_items = cast(dict[str, object], ec_data).get("candidates")
            if isinstance(ec_items, list):
                for item in cast(list[object], ec_items):
                    if not isinstance(item, dict):
                        continue
                    ec_item = cast(dict[str, object], item)
                    # Normalize: use 'path' field as 'binary'
                    if "binary" not in ec_item:
                        path_any = ec_item.get("path")
                        if isinstance(path_any, str) and path_any:
                            ec_item["binary"] = path_any
                    findings.append(ec_item)

        # Fallback 1: taint_propagation alerts
        if not findings:
            taint_alerts_path = run_dir / "stages" / "taint_propagation" / "alerts.json"
            taint_alerts_data = _load_json_file(taint_alerts_path)
            if isinstance(taint_alerts_data, dict):
                ta_any = cast(dict[str, object], taint_alerts_data).get("alerts")
                if isinstance(ta_any, list):
                    for item in cast(list[object], ta_any):
                        if isinstance(item, dict):
                            findings.append(cast(dict[str, object], item))
                    if findings:
                        limitations.append(
                            "Using taint_propagation alerts as findings "
                            "(no findings/triage stages available)"
                        )

        # Fallback 2: enhanced_source sources
        if not findings:
            es_path = run_dir / "stages" / "enhanced_source" / "sources.json"
            es_data = _load_json_file(es_path)
            if isinstance(es_data, dict):
                es_any = cast(dict[str, object], es_data).get("sources")
                if isinstance(es_any, list):
                    for item in cast(list[object], es_any):
                        if isinstance(item, dict):
                            findings.append(cast(dict[str, object], item))
                    if findings:
                        limitations.append(
                            "Using enhanced_source data as findings "
                            "(no taint/findings stages available)"
                        )

        # Always load binary_analysis.json for cross-binary chain data
        ba_chain_path = run_dir / "stages" / "inventory" / "binary_analysis.json"
        ba_chain_data = _load_json_file(ba_chain_path)
        ba_binaries: list[dict[str, object]] = []
        if isinstance(ba_chain_data, dict):
            ba_hits_any = cast(dict[str, object], ba_chain_data).get("hits")
            if isinstance(ba_hits_any, list):
                for hit_any in cast(list[object], ba_hits_any):
                    if not isinstance(hit_any, dict):
                        continue
                    hit = cast(dict[str, object], hit_any)
                    syms: set[str] = set()
                    ms_any = hit.get("matched_symbols")
                    if isinstance(ms_any, list):
                        for s in cast(list[object], ms_any):
                            if isinstance(s, str):
                                syms.add(s)
                    sd_any = hit.get("symbol_details")
                    if isinstance(sd_any, list):
                        for sd_item in cast(list[object], sd_any):
                            if isinstance(sd_item, dict):
                                sn = cast(dict[str, object], sd_item).get("symbol")
                                if isinstance(sn, str):
                                    syms.add(sn)
                    if syms:
                        ba_binaries.append(
                            {
                                "binary": str(hit.get("path", "")),
                                "symbols": sorted(syms),
                                "arch": str(hit.get("arch", "unknown")),
                                "hardening": hit.get("hardening", {}),
                            }
                        )

        # Supplement findings from binary_analysis (always, not just fallback)
        if ba_binaries:
            existing_bins = {
                str(f.get("binary", "") or f.get("source_binary", "")) for f in findings
            }
            for bbin in ba_binaries:
                bin_path = str(bbin.get("binary", ""))
                bin_syms = set(cast(list[str], bbin.get("symbols", [])))
                sink_syms = bin_syms & {
                    "system",
                    "popen",
                    "execve",
                    "strcpy",
                    "sprintf",
                    "strcat",
                    "vsprintf",
                    "gets",
                }
                input_syms = bin_syms & {
                    "recv",
                    "recvfrom",
                    "read",
                    "fread",
                    "fgets",
                    "gets",
                    "getenv",
                    "scanf",
                    "sscanf",
                    "nvram_get",
                    "websGetVar",
                    "httpGetEnv",
                    "cJSON_GetObjectItem",
                }
                if sink_syms and bin_path not in existing_bins:
                    findings.append(
                        {
                            "source_binary": bin_path,
                            "binary": bin_path,
                            "sink_symbol": sorted(sink_syms)[0],
                            "source_api": sorted(input_syms)[0] if input_syms else "",
                            "matched_symbols": sorted(bin_syms),
                            "matched_input_apis": sorted(input_syms),
                            "matched_sink_apis": sorted(sink_syms),
                            "confidence": 0.40,
                            "method": "binary_analysis",
                            "hardening": bbin.get("hardening", {}),
                        }
                    )
                    existing_bins.add(bin_path)

        if not findings:
            limitations.append("No findings available for chain construction")

        # --- Load communication graph (IPC edges) ---
        graph_path = run_dir / "stages" / "graph" / "communication_graph.json"
        graph_data = _load_json_file(graph_path)
        ipc_edges: list[dict[str, object]] = []
        if isinstance(graph_data, dict):
            edges_any = cast(dict[str, object], graph_data).get("edges")
            if isinstance(edges_any, list):
                for edge in cast(list[object], edges_any):
                    if not isinstance(edge, dict):
                        continue
                    edge_obj = cast(dict[str, object], edge)
                    edge_type = str(edge_obj.get("type", ""))
                    if edge_type.lower() in _IPC_EDGE_TYPES:
                        ipc_edges.append(edge_obj)
        if not ipc_edges:
            limitations.append("No IPC edges found in communication graph")

        # --- Load source_sink_graph for additional path data ---
        ssg_chain_path = run_dir / "stages" / "surfaces" / "source_sink_graph.json"
        ssg_chain_data = _load_json_file(ssg_chain_path)
        ssg_chain_paths: list[dict[str, object]] = []
        if isinstance(ssg_chain_data, dict):
            ssg_p_any = cast(dict[str, object], ssg_chain_data).get("paths")
            if isinstance(ssg_p_any, list):
                for p in cast(list[object], ssg_p_any):
                    if isinstance(p, dict):
                        ssg_chain_paths.append(cast(dict[str, object], p))

        # --- Load taint propagation data ---
        taint_path = run_dir / "stages" / "taint_propagation" / "taint_results.json"
        taint_data = _load_json_file(taint_path)
        taint_results: list[dict[str, object]] = []
        if isinstance(taint_data, dict):
            results_any = cast(dict[str, object], taint_data).get("results")
            if isinstance(results_any, list):
                for r in cast(list[object], results_any):
                    if isinstance(r, dict):
                        taint_results.append(cast(dict[str, object], r))

        # Also use taint alerts as additional findings if available
        taint_alerts_chain = run_dir / "stages" / "taint_propagation" / "alerts.json"
        ta_chain_data = _load_json_file(taint_alerts_chain)
        if isinstance(ta_chain_data, dict):
            ta_items = cast(dict[str, object], ta_chain_data).get("alerts")
            if isinstance(ta_items, list):
                existing_bins = {
                    str(f.get("binary", "") or f.get("source_binary", ""))
                    for f in findings
                }
                for ta_item in cast(list[object], ta_items):
                    if isinstance(ta_item, dict):
                        ta_obj = cast(dict[str, object], ta_item)
                        ta_bin = str(ta_obj.get("source_binary", ""))
                        # Only add if this binary isn't already in findings
                        if ta_bin and ta_bin not in existing_bins:
                            findings.append(ta_obj)
                            existing_bins.add(ta_bin)

        # Known dangerous sink symbols
        _SINK_SYMBOLS: frozenset[str] = frozenset(
            {
                "system",
                "popen",
                "execve",
                "execv",
                "execl",
                "execlp",
                "strcpy",
                "strcat",
                "sprintf",
                "vsprintf",
                "gets",
                "doSystemCmd",
                "twsystem",
                "doSystem",
            }
        )
        # Known input source symbols
        _INPUT_SYMBOLS: frozenset[str] = frozenset(
            {
                "recv",
                "recvfrom",
                "recvmsg",
                "read",
                "fread",
                "fgets",
                "gets",
                "getenv",
                "scanf",
                "sscanf",
                "fscanf",
                "websGetVar",
                "httpGetEnv",
                "nvram_get",
                "acosNvramConfig_get",
                "json_object_get_string",
                "cJSON_GetObjectItem",
                "getParameter",
                "wp_getVar",
            }
        )
        # Finding families that indicate sink-like behavior
        _SINK_FAMILIES: frozenset[str] = frozenset(
            {
                "cmd_exec_injection_risk",
                "buffer_overflow",
                "format_string",
                "command_injection",
                "exec_sink",
                "unsafe_function",
            }
        )
        # Finding families that indicate source-like behavior
        _SOURCE_FAMILIES: frozenset[str] = frozenset(
            {
                "credential_material_exposure",
                "network_io",
                "input",
                "source",
                "user_input",
            }
        )

        def _is_source(f: dict[str, object]) -> bool:
            """Check if a finding represents an external input source."""
            if str(f.get("source_api", "")):
                return True
            f_type = str(f.get("type", "")).lower()
            if f_type in ("input", "source", "network_io"):
                return True
            # Check matched_input_apis
            input_apis = f.get("matched_input_apis")
            if isinstance(input_apis, list) and input_apis:
                return True
            # Check matched_symbols for input APIs
            msyms = f.get("matched_symbols")
            if isinstance(msyms, list):
                for sym in cast(list[object], msyms):
                    if isinstance(sym, str) and sym in _INPUT_SYMBOLS:
                        return True
            return False

        def _is_sink(f: dict[str, object]) -> bool:
            """Check if a finding represents a dangerous sink."""
            if str(f.get("sink_symbol", "")):
                return True
            f_type = str(f.get("type", "")).lower()
            if f_type in ("command_injection", "buffer_overflow", "exec_sink"):
                return True
            # Check family field from pattern_scan findings
            family = str(f.get("family", "")).lower()
            if family in _SINK_FAMILIES:
                return True
            # Check matched_sink_apis
            sink_apis = f.get("matched_sink_apis")
            if isinstance(sink_apis, list) and sink_apis:
                return True
            # Check matched_symbols for sink APIs
            msyms = f.get("matched_symbols")
            if isinstance(msyms, list):
                for sym in cast(list[object], msyms):
                    if isinstance(sym, str) and sym in _SINK_SYMBOLS:
                        return True
            return False

        def _finding_label(f: dict[str, object], role: str) -> str:
            """Extract a human-readable label for a finding."""
            if role == "source":
                api = str(f.get("source_api", ""))
                if api:
                    return api
                apis = f.get("matched_input_apis")
                if isinstance(apis, list) and apis:
                    return str(apis[0])
                return str(f.get("api", "input"))
            # sink
            sym = str(f.get("sink_symbol", ""))
            if sym:
                return sym
            family = str(f.get("family", ""))
            if family:
                return family
            apis = f.get("matched_sink_apis")
            if isinstance(apis, list) and apis:
                return str(apis[0])
            return "sink"

        def _finding_id(f: dict[str, object]) -> str:
            """Extract a finding identifier."""
            for key in ("finding_id", "id", "candidate_id"):
                v = f.get(key)
                if isinstance(v, str) and v:
                    return v
            return _finding_label(f, "sink")

        # --- Step 1: Same-binary chain assembly (always runs) ---
        # Group findings by binary
        findings_by_binary: dict[str, list[dict[str, object]]] = {}
        for finding in findings:
            binary = str(
                finding.get("binary", "")
                or finding.get("source_binary", "")
                or finding.get("target_binary", "")
            )
            if not binary:
                continue
            findings_by_binary.setdefault(binary, []).append(finding)

        static_chains: list[dict[str, JsonValue]] = []
        chain_id = 0
        for binary, bin_findings in findings_by_binary.items():
            # Classify findings as sources and sinks using robust detection
            sources = [f for f in bin_findings if _is_source(f)]
            sinks = [f for f in bin_findings if _is_sink(f)]

            # Build source->sink chains when both exist
            if sources and sinks:
                for src in sources[:3]:
                    for sink in sinks[:3]:
                        if chain_id >= _MAX_CHAINS:
                            break
                        chain_id += 1
                        # Match pre-existing behaviour: string confidences
                        # are treated as the default 0.5 baseline; numeric
                        # types (int/float/bool) are converted via ``float``.
                        # Fall through for dict/list/None -> also 0.5.
                        src_conf_raw = src.get("confidence", 0.5)
                        if isinstance(src_conf_raw, (int, float, bool)):
                            src_conf = float(src_conf_raw)
                        else:
                            src_conf = 0.5
                        sink_conf_raw = sink.get("confidence", 0.5)
                        if isinstance(sink_conf_raw, (int, float, bool)):
                            sink_conf = float(sink_conf_raw)
                        else:
                            sink_conf = 0.5
                        combined = _clamp01((src_conf + sink_conf) / 2.0 * 0.8)
                        src_label = _finding_label(src, "source")
                        sink_label = _finding_label(sink, "sink")
                        static_chains.append(
                            {
                                "id": f"chain_{chain_id:03d}",
                                "description": (
                                    f"Same-binary chain in {binary}: "
                                    f"{src_label} -> {sink_label}"
                                ),
                                "binary": binary,
                                "chain_type": "same_binary",
                                "steps": cast(
                                    list[JsonValue],
                                    cast(
                                        list[object],
                                        [
                                            {
                                                "finding_id": _finding_id(src),
                                                "primitive": "external_input",
                                                "evidence": str(
                                                    src.get(
                                                        "path_description",
                                                        "static_reference",
                                                    )
                                                ),
                                            },
                                            {
                                                "finding_id": _finding_id(sink),
                                                "primitive": sink_label,
                                                "evidence": str(
                                                    sink.get(
                                                        "path_description",
                                                        "static_reference",
                                                    )
                                                ),
                                            },
                                        ],
                                    ),
                                ),
                                "confidence": combined,
                                "missing_evidence": cast(
                                    list[JsonValue],
                                    cast(
                                        list[object],
                                        [
                                            "Dynamic validation of data flow",
                                            "Runtime confirmation of exploitability",
                                        ],
                                    ),
                                ),
                                "method": "static",
                            }
                        )

            # Build sink-only chains: vuln + weak hardening = exploitable
            elif sinks and not sources and len(sinks) >= 1:
                for sink in sinks[:3]:
                    if chain_id >= _MAX_CHAINS:
                        break
                    # Check hardening weakness
                    hardening = sink.get("hardening")
                    if not isinstance(hardening, dict):
                        # Try to find hardening from ba_binaries
                        for bbin in ba_binaries:
                            if str(bbin.get("binary", "")) == binary:
                                hardening = bbin.get("hardening", {})
                                break
                    if not isinstance(hardening, dict):
                        hardening = {}
                    h = cast(dict[str, object], hardening)
                    no_pie = not bool(h.get("pie", True))
                    no_canary = not bool(h.get("canary", True))

                    chain_id += 1
                    sink_label = _finding_label(sink, "sink")
                    weakness_parts: list[str] = []
                    if no_pie:
                        weakness_parts.append("no PIE")
                    if no_canary:
                        weakness_parts.append("no canary")
                    weakness_desc = (
                        " + ".join(weakness_parts)
                        if weakness_parts
                        else "default hardening"
                    )
                    # Match pre-existing behaviour: string -> 0.4 fallback;
                    # numeric -> float(); dict/list/None -> 0.4.
                    conf_raw = sink.get("confidence", 0.4)
                    if isinstance(conf_raw, (int, float, bool)):
                        base_conf = float(conf_raw)
                    else:
                        base_conf = 0.4
                    # Boost confidence for weak hardening
                    if no_pie and no_canary:
                        base_conf = min(base_conf + 0.10, 0.55)
                    elif no_pie or no_canary:
                        base_conf = min(base_conf + 0.05, 0.50)

                    steps: list[dict[str, object]] = [
                        {
                            "finding_id": _finding_id(sink),
                            "primitive": sink_label,
                            "evidence": str(
                                sink.get("path_description", "static_reference")
                            ),
                        },
                    ]
                    if weakness_parts:
                        steps.append(
                            {
                                "finding_id": f"hardening_{binary}",
                                "primitive": f"weak_hardening ({weakness_desc})",
                                "evidence": f"Binary hardening: {hardening}",
                            }
                        )

                    static_chains.append(
                        {
                            "id": f"chain_{chain_id:03d}",
                            "description": (
                                f"Sink+hardening chain in {binary}: "
                                f"{sink_label} + {weakness_desc}"
                            ),
                            "binary": binary,
                            "chain_type": "same_binary_sink_hardening",
                            "steps": cast(list[JsonValue], cast(list[object], steps)),
                            "confidence": _clamp01(base_conf),
                            "missing_evidence": cast(
                                list[JsonValue],
                                cast(
                                    list[object],
                                    [
                                        "Input source identification",
                                        "Dynamic data flow confirmation",
                                    ],
                                ),
                            ),
                            "method": "static_hardening",
                        }
                    )

        # --- Step 2: Cross-binary chains via IPC ---
        cross_binary_chains: list[dict[str, JsonValue]] = []

        # Step 2a: Graph-based IPC chains (from communication_graph.json)
        if ipc_edges:
            # Build adjacency from IPC edges
            ipc_adj: dict[str, list[dict[str, object]]] = {}
            for edge in ipc_edges:
                src_node = str(edge.get("source", ""))
                if src_node:
                    ipc_adj.setdefault(src_node, []).append(edge)

            # Build cross-binary chains from IPC-connected findings
            for src_binary, edges in ipc_adj.items():
                if chain_id >= _MAX_CHAINS:
                    break
                src_findings = findings_by_binary.get(src_binary, [])
                for edge in edges:
                    dst_binary = str(edge.get("target", ""))
                    dst_findings = findings_by_binary.get(dst_binary, [])
                    if src_findings and dst_findings:
                        chain_id += 1
                        ipc_type = str(edge.get("type", "ipc"))
                        cross_binary_chains.append(
                            {
                                "id": f"chain_{chain_id:03d}",
                                "description": (
                                    f"Cross-binary chain: {src_binary} "
                                    f"--[{ipc_type}]--> {dst_binary}"
                                ),
                                "chain_type": "cross_binary",
                                "ipc_type": ipc_type,
                                "steps": cast(
                                    list[JsonValue],
                                    cast(
                                        list[object],
                                        [
                                            {
                                                "finding_id": str(
                                                    src_findings[0].get(
                                                        "id", "src_finding"
                                                    )
                                                ),
                                                "primitive": "initial_access",
                                                "evidence": f"finding in {src_binary}",
                                            },
                                            {
                                                "finding_id": f"ipc_{ipc_type}",
                                                "primitive": f"lateral_movement_via_{ipc_type}",
                                                "evidence": (
                                                    f"IPC edge: {src_binary} -> {dst_binary}"
                                                ),
                                            },
                                            {
                                                "finding_id": str(
                                                    dst_findings[0].get(
                                                        "id", "dst_finding"
                                                    )
                                                ),
                                                "primitive": "code_execution",
                                                "evidence": f"finding in {dst_binary}",
                                            },
                                        ],
                                    ),
                                ),
                                "confidence": _clamp01(0.4),
                                "missing_evidence": cast(
                                    list[JsonValue],
                                    cast(
                                        list[object],
                                        [
                                            "IPC message format verification",
                                            "Cross-process data flow confirmation",
                                            "Dynamic validation",
                                        ],
                                    ),
                                ),
                                "method": "static_ipc",
                            }
                        )
                        if chain_id >= _MAX_CHAINS:
                            break

        # Step 2b: Independent cross-binary IPC detection via shared strings
        # This works even when graph stage has 0 IPC edges by detecting
        # shared .rodata strings, nvram patterns, socket paths, and file IPC.
        cross_binary_ipc_chains: list[dict[str, JsonValue]] = []

        # Build shared symbol/string map across all binaries
        shared_strings: dict[str, list[str]] = {}  # symbol -> [binaries]
        for bbin in ba_binaries:
            bin_name = str(bbin.get("binary", ""))
            bsyms = bbin.get("symbols")
            if isinstance(bsyms, list):
                for sym in cast(list[object], bsyms):
                    if isinstance(sym, str) and len(sym) >= 3:
                        shared_strings.setdefault(sym, []).append(bin_name)

        # Find strings shared across 2+ binaries
        cross_strings: dict[str, list[str]] = {
            s: sorted(set(bins))
            for s, bins in shared_strings.items()
            if len(set(bins)) >= 2
        }

        # Known IPC pattern detectors
        _NVRAM_SYMS: frozenset[str] = frozenset(
            {
                "nvram_get",
                "nvram_set",
                "nvram_safe_get",
                "nvram_bufget",
                "nvram_bufset",
                "acosNvramConfig_get",
                "acosNvramConfig_set",
            }
        )
        _SOCKET_PATH_PREFIXES: tuple[str, ...] = (
            "/tmp/",
            "/var/run/",
            "/dev/",
        )
        _FILE_IPC_PREFIXES: tuple[str, ...] = (
            "/tmp/",
            "/var/tmp/",
            "/dev/shm/",
        )
        _DBUS_PREFIXES: tuple[str, ...] = (
            "org.freedesktop.",
            "com.",
            "net.",
        )

        def _detect_ipc_mechanism(
            shared_sym: str,
            bins: list[str],
        ) -> tuple[str, str] | None:
            """Classify a shared symbol into an IPC mechanism.

            Returns (ipc_mechanism, shared_key) or None.
            """
            sym_lower = shared_sym.lower()

            # nvram-based IPC
            if sym_lower in {s.lower() for s in _NVRAM_SYMS}:
                return ("nvram_shared", shared_sym)

            # Unix socket IPC
            if any(shared_sym.startswith(p) for p in _SOCKET_PATH_PREFIXES):
                if ".sock" in sym_lower or "socket" in sym_lower:
                    return ("unix_socket", shared_sym)

            # File-based IPC via /tmp or /var paths
            if any(shared_sym.startswith(p) for p in _FILE_IPC_PREFIXES):
                return ("file_ipc", shared_sym)

            # D-Bus interface IPC
            if any(shared_sym.startswith(p) for p in _DBUS_PREFIXES):
                if "." in shared_sym and len(shared_sym) > 8:
                    return ("dbus", shared_sym)

            # Shared config keys that look like IPC
            if sym_lower in {
                "admin_pass",
                "admin_password",
                "http_passwd",
                "login_passwd",
                "wan_ipaddr",
                "lan_ipaddr",
                "wl_ssid",
                "wps_pin",
            }:
                return ("nvram_shared", shared_sym)

            return None

        # Also load string_hits.json for additional shared string data
        sh_path = run_dir / "stages" / "inventory" / "string_hits.json"
        sh_data = _load_json_file(sh_path)
        string_hit_samples: list[dict[str, object]] = []
        if isinstance(sh_data, dict):
            samples_any = cast(dict[str, object], sh_data).get("samples")
            if isinstance(samples_any, list):
                for s in cast(list[object], samples_any):
                    if isinstance(s, dict):
                        string_hit_samples.append(cast(dict[str, object], s))

        # Build file->strings map from string_hits for cross-binary detection
        file_strings: dict[str, set[str]] = {}
        for sh_sample in string_hit_samples:
            sh_file = str(sh_sample.get("file", ""))
            sh_match = str(sh_sample.get("match", ""))
            if sh_file and sh_match:
                file_strings.setdefault(sh_file, set()).add(sh_match)

        # Track seen binary pairs to avoid duplicates
        seen_pairs: set[tuple[str, str]] = set()

        # Strategy 1: Detect IPC via shared symbols across binaries
        for shared_sym, bins in cross_strings.items():
            if chain_id >= _MAX_CHAINS:
                break
            ipc_result = _detect_ipc_mechanism(shared_sym, bins)
            if ipc_result is None:
                continue

            ipc_mechanism, shared_key = ipc_result

            # Build chains between all pairs of binaries sharing this IPC
            for i, bin_a in enumerate(bins):
                if chain_id >= _MAX_CHAINS:
                    break
                for bin_b in bins[i + 1 :]:
                    if chain_id >= _MAX_CHAINS:
                        break
                    pair_key = (
                        min(bin_a, bin_b),
                        max(bin_a, bin_b),
                    )
                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)

                    findings_a = findings_by_binary.get(bin_a, [])
                    findings_b = findings_by_binary.get(bin_b, [])
                    if not findings_a and not findings_b:
                        continue

                    chain_id += 1
                    # Determine which binary is the "writer" (source)
                    # and which is the "reader" (sink)
                    a_has_source = any(_is_source(f) for f in findings_a)
                    b_has_sink = any(_is_sink(f) for f in findings_b)

                    if a_has_source and b_has_sink:
                        src_bin, dst_bin = bin_a, bin_b
                        src_f, dst_f = findings_a, findings_b
                    elif any(_is_source(f) for f in findings_b) and any(
                        _is_sink(f) for f in findings_a
                    ):
                        src_bin, dst_bin = bin_b, bin_a
                        src_f, dst_f = findings_b, findings_a
                    else:
                        src_bin, dst_bin = bin_a, bin_b
                        src_f, dst_f = findings_a, findings_b

                    src_label = _finding_label(src_f[0], "source") if src_f else "input"
                    dst_label = _finding_label(dst_f[0], "sink") if dst_f else "sink"

                    steps: list[dict[str, object]] = []
                    if src_f:
                        steps.append(
                            {
                                "finding_id": _finding_id(src_f[0]),
                                "binary": src_bin,
                                "primitive": f"input_via_{src_label}",
                                "evidence": (f"Source finding in {src_bin}"),
                            }
                        )
                    steps.append(
                        {
                            "ipc": (f"{ipc_mechanism}('{shared_key}')"),
                            "binary_a": src_bin,
                            "binary_b": dst_bin,
                            "primitive": f"ipc_via_{ipc_mechanism}",
                            "evidence": (
                                f"Shared {ipc_mechanism} key "
                                f"'{shared_key}' in both binaries"
                            ),
                        }
                    )
                    if dst_f:
                        steps.append(
                            {
                                "finding_id": _finding_id(dst_f[0]),
                                "binary": dst_bin,
                                "primitive": f"sink_via_{dst_label}",
                                "evidence": (f"Sink finding in {dst_bin}"),
                            }
                        )

                    # Higher confidence when both source and sink
                    # are confirmed
                    conf = 0.35
                    if src_f and dst_f:
                        conf = 0.45
                    if a_has_source and b_has_sink:
                        conf = 0.50

                    cross_binary_ipc_chains.append(
                        {
                            "id": f"chain_{chain_id:03d}",
                            "description": (
                                f"Cross-binary IPC chain: "
                                f"{src_bin} --[{ipc_mechanism}: "
                                f"{shared_key}]--> {dst_bin}"
                            ),
                            "chain_type": "cross_binary_ipc",
                            "binary_a": src_bin,
                            "binary_b": dst_bin,
                            "ipc_mechanism": ipc_mechanism,
                            "shared_key": shared_key,
                            "steps": cast(
                                list[JsonValue],
                                cast(list[object], steps),
                            ),
                            "confidence": _clamp01(conf),
                            "missing_evidence": cast(
                                list[JsonValue],
                                cast(
                                    list[object],
                                    [
                                        "IPC data flow dynamic verification",
                                        "Cross-process taint confirmation",
                                        "Runtime IPC channel monitoring",
                                    ],
                                ),
                            ),
                            "method": "shared_string_ipc",
                        }
                    )

        # Strategy 2: Detect nvram IPC across binaries that both
        # import nvram_get/nvram_set even without shared .rodata keys
        nvram_bins: list[str] = []
        for bbin in ba_binaries:
            bin_name = str(bbin.get("binary", ""))
            bsyms = bbin.get("symbols")
            if isinstance(bsyms, list):
                sym_set = {
                    str(s) for s in cast(list[object], bsyms) if isinstance(s, str)
                }
                if sym_set & _NVRAM_SYMS:
                    nvram_bins.append(bin_name)

        if len(nvram_bins) >= 2:
            # Find pairs where one has input APIs and the other has
            # sink APIs
            for i, nv_a in enumerate(nvram_bins):
                if chain_id >= _MAX_CHAINS:
                    break
                syms_a = set(
                    cast(
                        list[str],
                        next(
                            (
                                b.get("symbols", [])
                                for b in ba_binaries
                                if str(b.get("binary", "")) == nv_a
                            ),
                            [],
                        ),
                    )
                )
                a_input = bool(syms_a & _INPUT_SYMBOLS)
                a_sink = bool(syms_a & _SINK_SYMBOLS)

                for nv_b in nvram_bins[i + 1 :]:
                    if chain_id >= _MAX_CHAINS:
                        break
                    pair_key = (min(nv_a, nv_b), max(nv_a, nv_b))
                    if pair_key in seen_pairs:
                        continue

                    syms_b = set(
                        cast(
                            list[str],
                            next(
                                (
                                    b.get("symbols", [])
                                    for b in ba_binaries
                                    if str(b.get("binary", "")) == nv_b
                                ),
                                [],
                            ),
                        )
                    )
                    b_input = bool(syms_b & _INPUT_SYMBOLS)
                    b_sink = bool(syms_b & _SINK_SYMBOLS)

                    # Only build chain if there is a plausible
                    # input -> nvram -> sink flow
                    if (a_input and b_sink) or (b_input and a_sink):
                        seen_pairs.add(pair_key)
                        chain_id += 1
                        if a_input and b_sink:
                            src_bin, dst_bin = nv_a, nv_b
                        else:
                            src_bin, dst_bin = nv_b, nv_a

                        cross_binary_ipc_chains.append(
                            {
                                "id": f"chain_{chain_id:03d}",
                                "description": (
                                    f"Cross-binary nvram chain: "
                                    f"{src_bin} --[nvram]--> {dst_bin}"
                                ),
                                "chain_type": "cross_binary_ipc",
                                "binary_a": src_bin,
                                "binary_b": dst_bin,
                                "ipc_mechanism": "nvram_shared",
                                "shared_key": "nvram_api",
                                "steps": cast(
                                    list[JsonValue],
                                    cast(
                                        list[object],
                                        [
                                            {
                                                "primitive": "input_capture",
                                                "binary": src_bin,
                                                "evidence": (
                                                    f"{src_bin} imports input "
                                                    f"APIs + nvram_set"
                                                ),
                                            },
                                            {
                                                "ipc": "nvram_set → nvram_get",
                                                "primitive": "nvram_ipc",
                                                "evidence": (
                                                    "Both binaries import "
                                                    "nvram get/set APIs"
                                                ),
                                            },
                                            {
                                                "primitive": "sink_execution",
                                                "binary": dst_bin,
                                                "evidence": (
                                                    f"{dst_bin} imports sink "
                                                    f"APIs + nvram_get"
                                                ),
                                            },
                                        ],
                                    ),
                                ),
                                "confidence": _clamp01(0.40),
                                "missing_evidence": cast(
                                    list[JsonValue],
                                    cast(
                                        list[object],
                                        [
                                            "Specific nvram key identification",
                                            "Data flow from input to nvram_set",
                                            "Data flow from nvram_get to sink",
                                        ],
                                    ),
                                ),
                                "method": "nvram_api_ipc",
                            }
                        )

        if not cross_binary_ipc_chains and not cross_binary_chains:
            limitations.append(
                "No cross-binary IPC chains detected "
                "(graph IPC edges: 0, shared-string IPC: 0)"
            )

        all_chains = static_chains + cross_binary_chains + cross_binary_ipc_chains

        # Collect cross_strings for LLM prompt
        cross_strings_for_prompt: dict[str, list[str]] = {}
        if cross_strings:
            cross_strings_for_prompt = dict(list(cross_strings.items())[:10])

        # --- Step 3: LLM chain reasoning (opus) ---
        llm_chains: list[dict[str, JsonValue]] = []
        if not self.no_llm and findings:
            driver = resolve_driver()
            if driver.available():
                findings_subset = findings[:20]
                prompt = _build_chain_prompt(
                    _truncate_json(findings_subset),
                    _truncate_json(ipc_edges[:20]),
                    _truncate_json(cross_strings_for_prompt),
                )
                result = driver.execute(
                    prompt=prompt,
                    run_dir=run_dir,
                    timeout_s=_LLM_TIMEOUT_S,
                    max_attempts=_LLM_MAX_ATTEMPTS,
                    retryable_tokens=_RETRYABLE_TOKENS,
                    model_tier="opus",
                )
                if result.status == "ok":
                    parsed = _parse_json_response(result.stdout)
                    if parsed is not None:
                        chains_any = parsed.get("chains")
                        if isinstance(chains_any, list):
                            for ch in cast(list[object], chains_any):
                                if isinstance(ch, dict):
                                    ch_obj = cast(dict[str, object], ch)
                                    ch_obj["method"] = "llm_opus"
                                    llm_chains.append(
                                        cast(dict[str, JsonValue], ch_obj)
                                    )
                    else:
                        limitations.append(
                            "LLM chain construction response could not be parsed"
                        )
                else:
                    limitations.append(
                        f"LLM chain construction call failed: {result.status}"
                    )
            else:
                limitations.append("LLM driver not available for chain reasoning")
        elif self.no_llm:
            limitations.append("LLM chain reasoning skipped (no_llm mode)")

        all_chains.extend(llm_chains)

        # Cap chains
        if len(all_chains) > _MAX_CHAINS:
            limitations.append(f"Chains capped at {_MAX_CHAINS}")
            all_chains = all_chains[:_MAX_CHAINS]

        status: StageStatus = "ok" if all_chains else "partial"
        if not findings:
            status = "partial"

        payload: dict[str, JsonValue] = {
            "schema_version": _SCHEMA_VERSION,
            "status": status,
            "chains": cast(list[JsonValue], cast(list[object], all_chains)),
            "summary": {
                "total_chains": len(all_chains),
                "same_binary": len(static_chains),
                "cross_binary": len(cross_binary_chains),
                "cross_binary_ipc": len(cross_binary_ipc_chains),
                "llm_generated": len(llm_chains),
            },
            "limitations": cast(
                list[JsonValue], cast(list[object], sorted(set(limitations)))
            ),
        }
        out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        details: dict[str, JsonValue] = {
            "total_chains": len(all_chains),
            "same_binary": len(static_chains),
            "cross_binary": len(cross_binary_chains),
            "cross_binary_ipc": len(cross_binary_ipc_chains),
            "llm_generated": len(llm_chains),
        }
        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
