from __future__ import annotations

"""LLM-guided inter-procedural taint propagation stage.

Traces data flow from identified external input sources to dangerous
sink functions using decompiled code and optional LLM reasoning.
Skips entirely under ``--no-llm``.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .llm_driver import resolve_driver
from .path_safety import assert_under_dir
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus

_SCHEMA_VERSION = "taint-propagation-v1"
_LLM_TIMEOUT_S = 120.0
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

_SINK_SYMBOLS: frozenset[str] = frozenset({
    "system",
    "strcpy",
    "sprintf",
    "execve",
    "execvp",
    "execvpe",
    "execl",
    "execlp",
    "execle",
    "execv",
    "popen",
})

_MAX_PATHS = 200
_MAX_ALERTS = 100


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


def _truncate_text(text: str, *, max_chars: int = 6000) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def _hash_body(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()


def _build_taint_prompt(
    source_api: str,
    sink_symbol: str,
    function_bodies: list[dict[str, str]],
) -> str:
    code_blocks = ""
    for fb in function_bodies:
        fname = fb.get("name", "unknown")
        body = _truncate_text(fb.get("body", ""), max_chars=2000)
        code_blocks += f"\n### {fname}\n```c\n{body}\n```\n"

    return (
        "You are a firmware taint analysis expert.\n"
        f"Can data from the input API `{source_api}` reach the dangerous "
        f"sink `{sink_symbol}`?\n"
        "Trace the data flow through these decompiled functions:\n"
        f"{code_blocks}\n"
        "## Rules\n"
        "- Follow return values, pointer parameters, and global variables\n"
        "- Note any sanitization or validation along the path\n"
        "- If taint CANNOT reach the sink, explain why\n\n"
        "## Output Format\n"
        "Return ONLY a JSON object (no markdown fences):\n"
        "{\n"
        '  "taint_reaches_sink": true|false,\n'
        '  "confidence": 0.0-1.0,\n'
        '  "path_description": "<trace description>",\n'
        '  "sanitizers_found": ["<sanitizer_name>", ...],\n'
        '  "rationale": "<explanation>"\n'
        "}\n"
    )


def _build_http_taint_path(
    binary: str, input_api: str, sink: str, hardening: str,
) -> str:
    """Build a structured taint path description for web server binaries."""
    basename = binary.rsplit("/", 1)[-1] if "/" in binary else binary
    return (
        f"HTTP_REQUEST -> {basename}:{input_api}() -> ... -> {basename}:{sink}(). "
        f"Web server binary processes HTTP input via {input_api}() which may "
        f"reach dangerous sink {sink}() without sanitization. "
        f"Hardening: {hardening or 'unknown'}"
    )


def _parse_json_response(stdout: str) -> dict[str, object] | None:
    text = stdout.strip()
    if not text:
        return None
    fences = re.findall(
        r"```(?:json)?\s*\n(.*?)```",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    for fence in fences:
        try:
            obj = json.loads(fence)
            if isinstance(obj, dict):
                return cast(dict[str, object], obj)
        except (json.JSONDecodeError, ValueError):
            continue
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return cast(dict[str, object], obj)
    except (json.JSONDecodeError, ValueError):
        pass
    return None


@dataclass(frozen=True)
class TaintPropagationStage:
    """LLM-guided inter-procedural taint analysis."""

    no_llm: bool = False

    @property
    def name(self) -> str:
        return "taint_propagation"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "taint_propagation"
        results_json = stage_dir / "taint_results.json"
        alerts_json = stage_dir / "alerts.json"

        assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        assert_under_dir(run_dir, results_json)
        assert_under_dir(run_dir, alerts_json)

        limitations: list[str] = []
        taint_results: list[dict[str, JsonValue]] = []
        alerts: list[dict[str, JsonValue]] = []

        # --- Load sources from enhanced_source ---
        sources_path = run_dir / "stages" / "enhanced_source" / "sources.json"
        sources_data = _load_json_file(sources_path)
        source_list: list[dict[str, object]] = []
        if isinstance(sources_data, dict):
            src_any = cast(dict[str, object], sources_data).get("sources")
            if isinstance(src_any, list):
                for s in cast(list[object], src_any):
                    if isinstance(s, dict):
                        source_list.append(cast(dict[str, object], s))
        if not source_list:
            limitations.append("No sources from enhanced_source stage")

        # --- Fallback 1: source_sink_graph paths as source-sink pairs ---
        ss_path = run_dir / "stages" / "surfaces" / "source_sink_graph.json"
        ss_data = _load_json_file(ss_path)
        ss_paths: list[dict[str, object]] = []
        sink_binaries: list[dict[str, object]] = []
        if isinstance(ss_data, dict):
            paths_any = cast(dict[str, object], ss_data).get("paths")
            if isinstance(paths_any, list):
                for p in cast(list[object], paths_any):
                    if isinstance(p, dict):
                        p_obj = cast(dict[str, object], p)
                        ss_paths.append(p_obj)
                        sink_any = p_obj.get("sink")
                        if isinstance(sink_any, dict):
                            sink_binaries.append(cast(dict[str, object], sink_any))
        if not sink_binaries:
            limitations.append("No sinks from source_sink_graph")

        # --- Fallback 2: binary_analysis.json for binaries with both input+sink ---
        ba_path = run_dir / "stages" / "inventory" / "binary_analysis.json"
        ba_data = _load_json_file(ba_path)
        ba_pairs: list[dict[str, object]] = []
        if isinstance(ba_data, dict):
            ba_hits_any = cast(dict[str, object], ba_data).get("hits")
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
                    input_syms = {
                        s for s in syms
                        if s.lower() in {
                            "recv", "recvfrom", "recvmsg", "read", "fread",
                            "fgets", "gets", "getenv", "scanf", "sscanf",
                            "fscanf",
                        }
                    }
                    sink_syms = {
                        s for s in syms
                        if s.lower() in {
                            "system", "popen", "execve", "execv", "strcpy",
                            "sprintf", "strcat", "vsprintf", "gets",
                        }
                    }
                    if sink_syms:  # At minimum need sinks
                        ba_pairs.append({
                            "binary": str(hit.get("path", "")),
                            "input_syms": sorted(input_syms),
                            "sink_syms": sorted(sink_syms),
                            "arch": str(hit.get("arch", "unknown")),
                            "hardening": hit.get("hardening", {}),
                        })

        # --- Load decompiled functions from ghidra_analysis ---
        ghidra_dir = run_dir / "stages" / "ghidra_analysis"
        decompiled_path = ghidra_dir / "decompiled_functions.json"
        func_data = _load_json_file(decompiled_path)
        func_map: dict[str, dict[str, str]] = {}
        if isinstance(func_data, list):
            for f in cast(list[object], func_data):
                if isinstance(f, dict):
                    fd = cast(dict[str, object], f)
                    fname = str(fd.get("name", ""))
                    body = str(fd.get("body", ""))
                    if fname and body:
                        func_map[fname] = {"name": fname, "body": body}
        elif isinstance(func_data, dict):
            funcs_any = cast(dict[str, object], func_data).get("functions")
            if isinstance(funcs_any, list):
                for f in cast(list[object], funcs_any):
                    if isinstance(f, dict):
                        fd = cast(dict[str, object], f)
                        fname = str(fd.get("name", ""))
                        body = str(fd.get("body", ""))
                        if fname and body:
                            func_map[fname] = {"name": fname, "body": body}
        if not func_map:
            limitations.append("No decompiled function bodies available")

        # === STATIC TAINT INFERENCE (always runs, no LLM needed) ===
        # Infer taint paths from binaries that have both input and sink symbols
        trace_count = 0

        # From enhanced_source sources (which now contain matched_sink_apis)
        # Prioritize web server binaries so they don't get crowded out by _MAX_PATHS
        sorted_sources = sorted(
            source_list,
            key=lambda s: (not bool(s.get("web_server")), -float(s.get("confidence", 0))),
        )
        seen_static: set[tuple[str, str, str]] = set()
        for source in sorted_sources:
            src_api = str(source.get("api", ""))
            src_binary = str(source.get("binary", ""))
            sink_apis_any = source.get("matched_sink_apis")
            sink_list: list[str] = []
            if isinstance(sink_apis_any, list):
                for sa in cast(list[object], sink_apis_any):
                    if isinstance(sa, str):
                        sink_list.append(sa)

            for sink_sym in sink_list:
                dedup_key = (src_binary, src_api, sink_sym)
                if dedup_key in seen_static:
                    continue
                seen_static.add(dedup_key)
                if trace_count >= _MAX_PATHS:
                    break

                hardening_any = source.get("hardening")
                hardening_str = ""
                if isinstance(hardening_any, dict):
                    h = cast(dict[str, object], hardening_any)
                    parts: list[str] = []
                    if not h.get("canary"):
                        parts.append("no_canary")
                    if not h.get("nx"):
                        parts.append("no_nx")
                    if not h.get("pie"):
                        parts.append("no_pie")
                    hardening_str = ", ".join(parts) if parts else "hardened"

                conf = 0.45
                input_apis_any = source.get("matched_input_apis")
                has_real_input = (
                    isinstance(input_apis_any, list) and len(input_apis_any) > 0
                )
                if has_real_input:
                    conf = 0.55

                # HTTP-aware taint path for web server binaries
                source_type = str(source.get("source_type", ""))
                is_web = bool(source.get("web_server", False))
                if is_web:
                    conf = 0.60
                    path_desc = _build_http_taint_path(
                        src_binary, src_api, sink_sym, hardening_str,
                    )
                else:
                    path_desc = (
                        f"Static inference: {src_binary} imports both "
                        f"{src_api}() and {sink_sym}(). "
                        f"Hardening: {hardening_str or 'unknown'}"
                    )

                src_basename = (
                    src_binary.rsplit("/", 1)[-1]
                    if "/" in src_binary
                    else src_binary
                )
                call_chain: list[dict[str, str]] = []
                if is_web:
                    call_chain = [
                        {"step": "entry", "function": f"{src_basename}:main", "type": "http_handler"},
                        {"step": "input", "function": f"{src_basename}:{src_api}", "type": "http_param_read"},
                        {"step": "sink", "function": f"{src_basename}:{sink_sym}", "type": "command_execution"},
                    ]

                taint_entry: dict[str, JsonValue] = {
                    "source_api": src_api,
                    "source_binary": src_binary,
                    "sink_symbol": sink_sym,
                    "taint_reaches_sink": True,
                    "confidence": _clamp01(conf),
                    "path_description": path_desc,
                    "method": "static_inference",
                    "source_type": source_type or "generic",
                    "web_server": is_web,
                    "call_chain": cast(list[JsonValue], cast(list[object], call_chain)),
                }
                taint_results.append(taint_entry)
                alerts.append({
                    "source_api": src_api,
                    "source_binary": src_binary,
                    "source_address": str(source.get("address", "0x0")),
                    "sink_symbol": sink_sym,
                    "confidence": _clamp01(conf),
                    "path_description": path_desc,
                    "method": "static_inference",
                    "source_type": source_type or "generic",
                    "web_server": is_web,
                })
                trace_count += 1

        # From binary_analysis pairs (fallback if enhanced_source was sparse)
        for bp in ba_pairs:
            if trace_count >= _MAX_PATHS:
                break
            bp_binary = str(bp.get("binary", ""))
            bp_inputs = bp.get("input_syms", [])
            bp_sinks = bp.get("sink_syms", [])
            if not isinstance(bp_inputs, list):
                bp_inputs = []
            if not isinstance(bp_sinks, list):
                bp_sinks = []

            src_apis = bp_inputs if bp_inputs else bp_sinks
            for src_api_str in src_apis:
                if not isinstance(src_api_str, str):
                    continue
                for sink_str in bp_sinks:
                    if not isinstance(sink_str, str):
                        continue
                    dedup_key = (bp_binary, src_api_str, sink_str)
                    if dedup_key in seen_static:
                        continue
                    seen_static.add(dedup_key)
                    if trace_count >= _MAX_PATHS:
                        break

                    bp_conf = 0.50 if bp_inputs else 0.40
                    taint_entry_bp: dict[str, JsonValue] = {
                        "source_api": src_api_str,
                        "source_binary": bp_binary,
                        "sink_symbol": sink_str,
                        "taint_reaches_sink": True,
                        "confidence": _clamp01(bp_conf),
                        "path_description": (
                            f"Static inference from binary_analysis: "
                            f"{bp_binary} imports {src_api_str}() and "
                            f"{sink_str}()"
                        ),
                        "method": "static_inference_ba",
                    }
                    taint_results.append(taint_entry_bp)
                    alerts.append({
                        "source_api": src_api_str,
                        "source_binary": bp_binary,
                        "source_address": "0x0",
                        "sink_symbol": sink_str,
                        "confidence": _clamp01(bp_conf),
                        "path_description": cast(str, taint_entry_bp["path_description"]),
                        "method": "static_inference_ba",
                    })
                    trace_count += 1

        # From source_sink_graph paths
        for ssp in ss_paths:
            if trace_count >= _MAX_PATHS:
                break
            sink_any = ssp.get("sink")
            source_any = ssp.get("source")
            if not isinstance(sink_any, dict):
                continue
            sink_obj = cast(dict[str, object], sink_any)
            sink_bin = str(sink_obj.get("binary", ""))
            sink_syms_list: list[str] = []
            ss_any = sink_obj.get("symbols")
            if isinstance(ss_any, list):
                for s in cast(list[object], ss_any):
                    if isinstance(s, str):
                        sink_syms_list.append(s)
            src_type = ""
            if isinstance(source_any, dict):
                src_type = str(cast(dict[str, object], source_any).get("type", ""))
            ssp_conf_any = ssp.get("confidence")
            ssp_conf = (
                _clamp01(float(ssp_conf_any))
                if isinstance(ssp_conf_any, (int, float))
                else 0.40
            )

            for ss_sym in sink_syms_list:
                dedup_key = (sink_bin, src_type or "network", ss_sym)
                if dedup_key in seen_static:
                    continue
                seen_static.add(dedup_key)
                if trace_count >= _MAX_PATHS:
                    break
                taint_entry_ss: dict[str, JsonValue] = {
                    "source_api": src_type or "network_input",
                    "source_binary": sink_bin,
                    "sink_symbol": ss_sym,
                    "taint_reaches_sink": True,
                    "confidence": _clamp01(min(ssp_conf, 0.50)),
                    "path_description": (
                        f"Source-sink graph path: {src_type} source -> "
                        f"{sink_bin} -> {ss_sym}()"
                    ),
                    "method": "source_sink_graph",
                }
                taint_results.append(taint_entry_ss)
                alerts.append({
                    "source_api": src_type or "network_input",
                    "source_binary": sink_bin,
                    "source_address": "0x0",
                    "sink_symbol": ss_sym,
                    "confidence": _clamp01(min(ssp_conf, 0.50)),
                    "path_description": cast(str, taint_entry_ss["path_description"]),
                    "method": "source_sink_graph",
                })
                trace_count += 1

        # === LLM TAINT TRACE (when available and not --no-llm) ===
        if not self.no_llm and source_list and func_map:
            driver = resolve_driver()
            if not driver.available():
                limitations.append("LLM driver not available for taint analysis")
            else:
                # Collect unique sink symbols
                sink_symbols: set[str] = set()
                for sb in sink_binaries:
                    syms_any2 = sb.get("symbols")
                    if isinstance(syms_any2, list):
                        for sym in cast(list[object], syms_any2):
                            if isinstance(sym, str) and sym.lower() in {
                                s.lower() for s in _SINK_SYMBOLS
                            }:
                                sink_symbols.add(sym)
                if not sink_symbols:
                    sink_symbols = {"system", "popen", "strcpy"}

                body_cache: dict[str, dict[str, object]] = {}
                for source in source_list[:_MAX_PATHS]:
                    src_api = str(source.get("api", ""))
                    src_binary = str(source.get("binary", ""))
                    src_addr = str(source.get("address", "0x0"))

                    for sink_sym in sorted(sink_symbols):
                        if trace_count >= _MAX_PATHS:
                            limitations.append(
                                f"Taint trace capped at {_MAX_PATHS} paths"
                            )
                            break

                        relevant_funcs: list[dict[str, str]] = []
                        for fname, finfo in list(func_map.items())[:5]:
                            body = finfo["body"]
                            body_lower = body.lower()
                            if src_api.lower() in body_lower or sink_sym.lower() in body_lower:
                                relevant_funcs.append(finfo)

                        if not relevant_funcs:
                            continue

                        combined_hash = _hash_body(
                            "|".join(f["body"] for f in relevant_funcs)
                            + f"|{src_api}|{sink_sym}"
                        )
                        if combined_hash in body_cache:
                            cached = body_cache[combined_hash]
                            taint_results.append(
                                cast(dict[str, JsonValue], dict(cached))
                            )
                            if cached.get("taint_reaches_sink"):
                                alerts.append({
                                    "source_api": src_api,
                                    "source_binary": src_binary,
                                    "source_address": src_addr,
                                    "sink_symbol": sink_sym,
                                    "confidence": _clamp01(
                                        float(cached.get("confidence", 0.5))
                                    ),
                                    "path_description": str(
                                        cached.get("path_description", "")
                                    ),
                                    "method": "llm_taint_trace",
                                    "cached": True,
                                })
                            trace_count += 1
                            continue

                        prompt = _build_taint_prompt(
                            src_api, sink_sym, relevant_funcs
                        )
                        result = driver.execute(
                            prompt=prompt,
                            run_dir=run_dir,
                            timeout_s=_LLM_TIMEOUT_S,
                            max_attempts=_LLM_MAX_ATTEMPTS,
                            retryable_tokens=_RETRYABLE_TOKENS,
                            model_tier="sonnet",
                        )

                        trace_entry_llm: dict[str, object] = {
                            "source_api": src_api,
                            "source_binary": src_binary,
                            "sink_symbol": sink_sym,
                            "taint_reaches_sink": False,
                            "confidence": 0.0,
                            "path_description": "",
                            "llm_status": result.status,
                        }

                        if result.status == "ok":
                            parsed = _parse_json_response(result.stdout)
                            if parsed is not None:
                                reaches = bool(parsed.get("taint_reaches_sink", False))
                                conf_any = parsed.get("confidence", 0.5)
                                conf_val = (
                                    _clamp01(float(conf_any))
                                    if isinstance(conf_any, (int, float))
                                    else 0.5
                                )
                                path_desc = str(parsed.get("path_description", ""))
                                sanitizers = parsed.get("sanitizers_found", [])

                                trace_entry_llm["taint_reaches_sink"] = reaches
                                trace_entry_llm["confidence"] = conf_val
                                trace_entry_llm["path_description"] = path_desc
                                trace_entry_llm["sanitizers_found"] = sanitizers

                                if reaches:
                                    alerts.append({
                                        "source_api": src_api,
                                        "source_binary": src_binary,
                                        "source_address": src_addr,
                                        "sink_symbol": sink_sym,
                                        "confidence": conf_val,
                                        "path_description": path_desc,
                                        "sanitizers_found": cast(
                                            list[JsonValue],
                                            cast(list[object], sanitizers)
                                            if isinstance(sanitizers, list)
                                            else [],
                                        ),
                                        "method": "llm_taint_trace",
                                        "cached": False,
                                    })

                        body_cache[combined_hash] = trace_entry_llm
                        taint_results.append(
                            cast(dict[str, JsonValue], trace_entry_llm)
                        )
                        trace_count += 1

                    if trace_count >= _MAX_PATHS:
                        break
        elif self.no_llm:
            limitations.append("LLM taint tracing skipped (no_llm mode)")

        # Cap alerts
        if len(alerts) > _MAX_ALERTS:
            limitations.append(
                f"Alerts capped at {_MAX_ALERTS}"
            )
            alerts = alerts[:_MAX_ALERTS]

        _write_results(
            stage_dir, results_json, alerts_json,
            taint_results, alerts, limitations,
        )

        status: StageStatus = "ok" if alerts else "partial"
        if not source_list and not ba_pairs and not ss_paths:
            status = "partial"

        details: dict[str, JsonValue] = {
            "traces": len(taint_results),
            "alerts": len(alerts),
            "static_inferences": sum(
                1
                for t in taint_results
                if isinstance(t, dict) and str(t.get("method", "")).startswith("static")
            ),
        }
        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )


def _write_skipped(
    stage_dir: Path,
    results_json: Path,
    alerts_json: Path,
) -> None:
    for path, key in ((results_json, "results"), (alerts_json, "alerts")):
        payload: dict[str, JsonValue] = {
            "schema_version": _SCHEMA_VERSION,
            "status": "skipped",
            "reason": "no_llm_mode",
            key: [],
        }
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)
            + "\n",
            encoding="utf-8",
        )


def _write_results(
    stage_dir: Path,
    results_json: Path,
    alerts_json: Path,
    taint_results: list[dict[str, JsonValue]],
    alerts: list[dict[str, JsonValue]],
    limitations: list[str],
) -> None:
    results_payload: dict[str, JsonValue] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "ok" if taint_results else "partial",
        "total_traces": len(taint_results),
        "results": cast(
            list[JsonValue], cast(list[object], taint_results)
        ),
        "limitations": cast(
            list[JsonValue], cast(list[object], sorted(set(limitations)))
        ),
    }
    results_json.write_text(
        json.dumps(results_payload, indent=2, sort_keys=True, ensure_ascii=True)
        + "\n",
        encoding="utf-8",
    )

    alerts_payload: dict[str, JsonValue] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "ok" if alerts else "partial",
        "total_alerts": len(alerts),
        "alerts": cast(
            list[JsonValue], cast(list[object], alerts)
        ),
        "limitations": cast(
            list[JsonValue], cast(list[object], sorted(set(limitations)))
        ),
    }
    alerts_json.write_text(
        json.dumps(alerts_payload, indent=2, sort_keys=True, ensure_ascii=True)
        + "\n",
        encoding="utf-8",
    )
