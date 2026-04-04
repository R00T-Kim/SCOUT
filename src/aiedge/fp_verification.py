from __future__ import annotations

"""False-positive verification stage.

Removes false positives from taint alerts using three known FP patterns
(sanitizer, non-propagating, system-file) via LLM few-shot classification.
Enriches LLM prompts with Ghidra decompiled function bodies and xref-based
call chain evidence to improve precision.  Skips under ``--no-llm``.
"""

import json
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .llm_driver import resolve_driver
from .path_safety import assert_under_dir
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus

_SCHEMA_VERSION = "fp-verification-v1"
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

_CONFIDENCE_REDUCTION = 0.3

# Sanitizer functions that neutralize taint
_SANITIZER_NAMES: frozenset[str] = frozenset(
    [
        "atoi",
        "strtol",
        "strtoul",
        "strtoll",
        "strtoull",
        "strtod",
        "strtof",
        "isValidIpAddr",
        "inet_aton",
        "inet_addr",
        "inet_pton",
    ]
)


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


def _trace_call_chain(
    xref_map: dict[str, list[str]],
    source: str,
    sink: str,
    max_depth: int = 5,
) -> list[str] | None:
    """BFS through xref_map to find a call path from *source* to *sink*.

    Returns the path as a list of function names (inclusive), or None if no
    path exists within *max_depth* hops.
    """
    if not xref_map or not source or not sink:
        return None
    queue: deque[tuple[str, list[str]]] = deque([(source, [source])])
    visited: set[str] = {source}
    while queue:
        current, path = queue.popleft()
        if len(path) > max_depth:
            continue
        for callee in xref_map.get(current, []):
            if callee == sink:
                return path + [sink]
            if callee not in visited:
                visited.add(callee)
                queue.append((callee, path + [callee]))
    return None


def _check_constant_sink_in_context(
    decompiled_context: list[dict[str, str]],
    sink_sym: str,
) -> bool:
    """Return True if every call to *sink_sym* in *decompiled_context* passes
    only a string/integer literal as its first argument (constant-sink FP).

    Heuristic: look for `sink_sym("` or `sink_sym(0x` patterns, and ensure
    there is no variable reference pattern `sink_sym(var` / `sink_sym(buf`.
    """
    if not sink_sym:
        return False
    literal_pat = re.compile(
        r"\b" + re.escape(sink_sym) + r'\s*\(\s*(?:"[^"]*"|0x[0-9a-fA-F]+|\d+)',
    )
    variable_pat = re.compile(
        r"\b" + re.escape(sink_sym) + r"\s*\(\s*[a-zA-Z_]",
    )
    found_literal = False
    for finfo in decompiled_context:
        body = finfo.get("body", "")
        if literal_pat.search(body):
            found_literal = True
        if variable_pat.search(body):
            # At least one call with a variable argument — cannot be pure constant-sink
            return False
    return found_literal


def _check_sanitizer_in_context(
    decompiled_context: list[dict[str, str]],
    src_api: str,
    sink_sym: str,
) -> bool:
    """Return True if any sanitizer function appears in the relevant function
    bodies (between source and sink), suggesting taint may be neutralized.
    """
    for finfo in decompiled_context:
        body = finfo.get("body", "")
        for san in _SANITIZER_NAMES:
            if san + "(" in body or san + " (" in body:
                return True
    return False


def _build_fp_prompt(
    alert: dict[str, object],
    decompiled_context: list[dict[str, str]] | None = None,
    call_chain: list[str] | None = None,
) -> str:
    alert_json = json.dumps(alert, indent=2, ensure_ascii=True)

    code_section = ""
    if decompiled_context:
        code_section = "\n## Decompiled Function Context\n"
        for func in decompiled_context[:3]:  # max 3 functions
            body = func.get("body", "")[:1500]  # 1500-char limit per function
            binary_basename = func.get("binary", "").split("/")[-1]
            code_section += (
                f"\n### {func.get('name', '?')} ({binary_basename})\n"
                f"```c\n{body}\n```\n"
            )

    chain_section = ""
    if call_chain:
        chain_section = (
            "\n## Call Chain Evidence\n"
            f"`{'  ->  '.join(call_chain)}`\n"
        )

    return (
        "You are a firmware vulnerability false-positive analyst.\n"
        "Determine if the following taint alert is a FALSE POSITIVE or a\n"
        "TRUE POSITIVE by checking against these three known FP patterns:\n\n"
        "## Known False Positive Patterns\n\n"
        "### 1. Sanitizer Pattern\n"
        "If the tainted value passes through a sanitizing function such as\n"
        "atoi(), strtol(), strtoul(), isValidIpAddr(), inet_aton(),\n"
        "inet_addr(), or any integer-conversion function, the taint is\n"
        "neutralized and cannot reach the sink as attacker-controlled\n"
        "string data. Mark as FP.\n\n"
        "### 2. Non-Propagating Pattern\n"
        "If the tainted value is ONLY used in a branch condition that\n"
        "selects between constant values (e.g., `if (param == 1) cmd =\n"
        '"/bin/true"; else cmd = "/bin/false";`), the attacker cannot\n'
        "control the sink argument. Mark as FP.\n\n"
        "### 3. System File Pattern\n"
        'If the source is fopen("/etc/..."), fopen("/proc/..."),\n'
        'fopen("/sys/..."), or reading from a fixed system file path that\n'
        "is not attacker-writable, the data is not externally controlled.\n"
        "Mark as FP.\n\n"
        f"{code_section}"
        f"{chain_section}"
        "## Alert to Analyze\n"
        f"{alert_json}\n\n"
        "## Additional Instructions\n"
        "If decompiled code is provided, examine it carefully:\n"
        "- Check if the sink argument is a constant string (FP pattern 1)\n"
        "- Check if sanitization functions (atoi, strtol, inet_aton) exist\n"
        "  between source and sink\n"
        "- Check if the source data actually reaches the sink through the\n"
        "  call chain shown above\n\n"
        "## Output Format\n"
        "Return ONLY a JSON object (no markdown fences):\n"
        "{\n"
        '  "verdict": "FP"|"TP",\n'
        '  "fp_pattern": "<pattern_name or null>",\n'
        '  "confidence_adjustment": -0.3 for FP or 0.0 for TP,\n'
        '  "rationale": "<brief explanation>"\n'
        "}\n"
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
class FPVerificationStage:
    """Remove false positives using 3 known FP patterns."""

    no_llm: bool = False

    @property
    def name(self) -> str:
        return "fp_verification"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "fp_verification"
        out_json = stage_dir / "verified_alerts.json"

        assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        assert_under_dir(run_dir, out_json)

        limitations: list[str] = []

        # --- Skip under --no-llm ---
        if self.no_llm:
            payload: dict[str, JsonValue] = {
                "schema_version": _SCHEMA_VERSION,
                "status": "skipped",
                "reason": "no_llm_mode",
                "verified_alerts": [],
            }
            out_json.write_text(
                json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)
                + "\n",
                encoding="utf-8",
            )
            return StageOutcome(
                status="skipped",
                details=cast(dict[str, JsonValue], {"reason": "no_llm_mode"}),
                limitations=["no_llm_mode"],
            )

        # ---------------------------------------------------------------
        # Step 1: Load Ghidra decompiled functions → func_map
        # Pattern mirrors taint_propagation.py:304-326
        # ---------------------------------------------------------------
        ghidra_dir = run_dir / "stages" / "ghidra_analysis"
        decompiled_path = ghidra_dir / "decompiled_functions.json"
        func_data = _load_json_file(decompiled_path)
        func_map: dict[str, dict[str, str]] = {}
        if isinstance(func_data, dict):
            funcs_any = func_data.get("functions")
            if isinstance(funcs_any, list):
                for f in funcs_any:
                    if not isinstance(f, dict):
                        continue
                    fname = str(f.get("name", ""))
                    body = str(f.get("body", ""))
                    binary = str(f.get("binary", ""))
                    if fname and body:
                        func_map[fname] = {
                            "name": fname,
                            "body": body,
                            "binary": binary,
                        }

        # ---------------------------------------------------------------
        # Step 2: Load xref_graph → xref_map (caller → [callees])
        # ---------------------------------------------------------------
        xref_map: dict[str, list[str]] = {}
        for xref_file in ghidra_dir.rglob("xref_graph.json"):
            xref_data = _load_json_file(xref_file)
            if isinstance(xref_data, list):
                for entry in xref_data:
                    if not isinstance(entry, dict):
                        continue
                    caller = str(entry.get("caller", ""))
                    callee = str(entry.get("callee", ""))
                    if caller and callee:
                        xref_map.setdefault(caller, []).append(callee)

        # ---------------------------------------------------------------
        # Step 5: Load IPC communication graph for cross-binary context
        # ---------------------------------------------------------------
        ipc_edges: list[dict[str, object]] = []
        ipc_graph_path = run_dir / "stages" / "graph" / "communication_graph.json"
        ipc_data = _load_json_file(ipc_graph_path)
        _IPC_EDGE_TYPES = frozenset(
            [
                "ipc_unix_socket",
                "ipc_dbus",
                "ipc_shm",
                "ipc_pipe",
                "ipc_exec_chain",
            ]
        )
        if isinstance(ipc_data, dict):
            edges_any = ipc_data.get("edges")
            if isinstance(edges_any, list):
                for edge in edges_any:
                    if not isinstance(edge, dict):
                        continue
                    etype = str(edge.get("type", ""))
                    if etype in _IPC_EDGE_TYPES:
                        ipc_edges.append(cast(dict[str, object], edge))

        # --- Load alerts from taint_propagation, findings, or attack_surface ---
        alerts: list[dict[str, object]] = []

        # Try taint_propagation alerts first
        taint_alerts_path = (
            run_dir / "stages" / "taint_propagation" / "alerts.json"
        )
        taint_data = _load_json_file(taint_alerts_path)
        if isinstance(taint_data, dict):
            alerts_any = cast(dict[str, object], taint_data).get("alerts")
            if isinstance(alerts_any, list):
                for a in cast(list[object], alerts_any):
                    if isinstance(a, dict):
                        alerts.append(cast(dict[str, object], a))

        # Fallback 1: try findings
        if not alerts:
            findings_path = (
                run_dir / "stages" / "findings" / "findings.json"
            )
            findings_data = _load_json_file(findings_path)
            if isinstance(findings_data, dict):
                f_any = cast(dict[str, object], findings_data).get("findings")
                if isinstance(f_any, list):
                    for f in cast(list[object], f_any):
                        if isinstance(f, dict):
                            alerts.append(cast(dict[str, object], f))

        # Fallback 2: attack_surface entries with confidence > 0.3
        if not alerts:
            as_path = (
                run_dir / "stages" / "attack_surface" / "attack_surface.json"
            )
            as_data = _load_json_file(as_path)
            if isinstance(as_data, dict):
                as_entries = cast(dict[str, object], as_data).get("attack_surface")
                if isinstance(as_entries, list):
                    for entry_any in cast(list[object], as_entries):
                        if not isinstance(entry_any, dict):
                            continue
                        entry = cast(dict[str, object], entry_any)
                        conf_any = (
                            entry.get("confidence")
                            or entry.get("confidence_calibrated")
                        )
                        if isinstance(conf_any, (int, float)) and float(conf_any) > 0.3:
                            alert_entry: dict[str, object] = {
                                "source_api": str(entry.get("surface", "")),
                                "source_binary": str(
                                    entry.get("observation", "")
                                ),
                                "sink_symbol": str(
                                    entry.get("classification", "candidate")
                                ),
                                "confidence": float(conf_any),
                                "path_description": str(
                                    entry.get("edge_semantics", "")
                                ),
                                "method": "attack_surface_fallback",
                                "evidence_refs": entry.get("evidence_refs", []),
                            }
                            alerts.append(alert_entry)
                    if alerts:
                        limitations.append(
                            "Using attack_surface entries as fallback "
                            "(taint_propagation and findings unavailable)"
                        )

        if not alerts:
            limitations.append(
                "No alerts from taint_propagation, findings, or attack_surface"
            )
            payload = {
                "schema_version": _SCHEMA_VERSION,
                "status": "partial",
                "verified_alerts": [],
                "summary": {
                    "total_input": 0,
                    "false_positives": 0,
                    "true_positives": 0,
                },
                "limitations": cast(
                    list[JsonValue], cast(list[object], limitations)
                ),
            }
            out_json.write_text(
                json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)
                + "\n",
                encoding="utf-8",
            )
            return StageOutcome(
                status="partial",
                details=cast(dict[str, JsonValue], {"verified": 0}),
                limitations=limitations,
            )

        # --- Filter alerts with confidence >= 0.3 ---
        eligible = [
            a for a in alerts
            if isinstance(a.get("confidence"), (int, float))
            and float(a["confidence"]) >= 0.3
        ]
        # Pass-through alerts below threshold unchanged
        below_threshold = [
            a for a in alerts
            if not isinstance(a.get("confidence"), (int, float))
            or float(a["confidence"]) < 0.3
        ]

        # --- LLM FP verification ---
        driver = resolve_driver()
        verified: list[dict[str, JsonValue]] = []
        fp_count = 0
        tp_count = 0
        static_fp_count = 0  # pre-filter FPs (no LLM call)

        if not driver.available():
            limitations.append("LLM driver not available for FP verification")
            for a in alerts:
                verified.append(cast(dict[str, JsonValue], dict(a)))
        else:
            for alert in eligible:
                sink_sym = str(alert.get("sink_symbol", ""))
                src_binary = str(alert.get("source_binary", ""))
                src_api = str(alert.get("source_api", ""))

                # -------------------------------------------------------
                # Step 4: Build decompiled_context for this alert
                # Find functions that reference the sink symbol in the
                # same binary as the alert source.
                # -------------------------------------------------------
                binary_basename = src_binary.split("/")[-1] if src_binary else ""
                decompiled_context: list[dict[str, str]] = []
                for finfo in func_map.values():
                    if sink_sym and sink_sym in finfo.get("body", ""):
                        fb = finfo.get("binary", "")
                        # prefer same binary; accept any if basename matches or
                        # binary_basename is empty (fallback)
                        if not binary_basename or binary_basename in fb:
                            decompiled_context.append(finfo)
                            if len(decompiled_context) >= 3:
                                break

                # -------------------------------------------------------
                # Step 5 (cont.): IPC cross-binary context
                # If alert has IPC indicators, add decompiled functions
                # from the peer binary connected via IPC edges.
                # -------------------------------------------------------
                if ipc_edges and binary_basename:
                    for edge in ipc_edges:
                        src_node = str(edge.get("source", ""))
                        dst_node = str(edge.get("target", ""))
                        # Check if this binary is one side of an IPC edge
                        if binary_basename in src_node or binary_basename in dst_node:
                            peer = dst_node if binary_basename in src_node else src_node
                            peer_basename = peer.split("/")[-1]
                            # Add up to 2 decompiled functions from the peer binary
                            added = 0
                            for finfo in func_map.values():
                                if (
                                    sink_sym
                                    and sink_sym in finfo.get("body", "")
                                    and peer_basename in finfo.get("binary", "")
                                    and finfo not in decompiled_context
                                ):
                                    decompiled_context.append(finfo)
                                    added += 1
                                    if added >= 2:
                                        break
                            if added:
                                break  # one IPC peer is enough

                # -------------------------------------------------------
                # Step 4 (cont.): xref-based call chain source → sink
                # -------------------------------------------------------
                call_chain = _trace_call_chain(xref_map, src_api, sink_sym, max_depth=5)

                # -------------------------------------------------------
                # Step 6: Static pre-filters (skip LLM when possible)
                # -------------------------------------------------------
                alert_copy = dict(alert)

                if decompiled_context:
                    # Pre-filter 1: constant-sink
                    if _check_constant_sink_in_context(decompiled_context, sink_sym):
                        alert_copy["fp_verdict"] = "FP"
                        alert_copy["fp_pattern"] = "constant_sink"
                        alert_copy["fp_rationale"] = (
                            "Ghidra code confirms constant-sink pattern "
                            "(all sink arguments are literals)"
                        )
                        orig_conf = float(alert.get("confidence", 0.5))
                        alert_copy["original_confidence"] = orig_conf
                        alert_copy["confidence"] = _clamp01(
                            orig_conf - _CONFIDENCE_REDUCTION
                        )
                        alert_copy["static_prefilter"] = True
                        fp_count += 1
                        static_fp_count += 1
                        verified.append(cast(dict[str, JsonValue], alert_copy))
                        continue  # skip LLM

                    # Pre-filter 2: adjust confidence when sanitizer present
                    if _check_sanitizer_in_context(decompiled_context, src_api, sink_sym):
                        orig_conf = float(alert.get("confidence", 0.5))
                        alert_copy["confidence"] = _clamp01(orig_conf - 0.15)
                        alert_copy["original_confidence"] = orig_conf
                        alert_copy["sanitizer_detected"] = True

                # Pre-filter 3: xref loaded but no path source→sink
                if xref_map and src_api and sink_sym and call_chain is None:
                    alert_copy["fp_verdict"] = "FP"
                    alert_copy["fp_pattern"] = "no_call_path"
                    alert_copy["fp_rationale"] = (
                        "No call path from source to sink found in xref graph"
                    )
                    orig_conf = float(alert.get("confidence", 0.5))
                    alert_copy["original_confidence"] = orig_conf
                    alert_copy["confidence"] = _clamp01(
                        orig_conf - _CONFIDENCE_REDUCTION
                    )
                    alert_copy["static_prefilter"] = True
                    fp_count += 1
                    static_fp_count += 1
                    verified.append(cast(dict[str, JsonValue], alert_copy))
                    continue  # skip LLM

                # -------------------------------------------------------
                # LLM call with enriched prompt
                # -------------------------------------------------------
                prompt = _build_fp_prompt(
                    alert,
                    decompiled_context or None,
                    call_chain or None,
                )
                result = driver.execute(
                    prompt=prompt,
                    run_dir=run_dir,
                    timeout_s=_LLM_TIMEOUT_S,
                    max_attempts=_LLM_MAX_ATTEMPTS,
                    retryable_tokens=_RETRYABLE_TOKENS,
                    model_tier="sonnet",
                )

                if result.status == "ok":
                    parsed = _parse_json_response(result.stdout)
                    if parsed is not None:
                        verdict = str(parsed.get("verdict", "TP")).upper()
                        fp_pattern = parsed.get("fp_pattern")
                        rationale = str(parsed.get("rationale", ""))

                        if verdict == "FP":
                            orig_conf = float(alert.get("confidence", 0.5))
                            new_conf = _clamp01(
                                orig_conf - _CONFIDENCE_REDUCTION
                            )
                            alert_copy["confidence"] = new_conf
                            alert_copy["original_confidence"] = orig_conf
                            alert_copy["fp_verdict"] = "FP"
                            alert_copy["fp_pattern"] = fp_pattern
                            alert_copy["fp_rationale"] = rationale
                            fp_count += 1
                        else:
                            alert_copy["fp_verdict"] = "TP"
                            alert_copy["fp_rationale"] = rationale
                            tp_count += 1
                    else:
                        alert_copy["fp_verdict"] = "unverified"
                        alert_copy["fp_rationale"] = "LLM response parse failure"
                        limitations.append(
                            "One or more FP verification responses could not be parsed"
                        )
                else:
                    alert_copy["fp_verdict"] = "unverified"
                    alert_copy["fp_rationale"] = f"LLM call failed: {result.status}"

                verified.append(cast(dict[str, JsonValue], alert_copy))

            # Add below-threshold alerts unchanged
            for a in below_threshold:
                a_copy = dict(a)
                a_copy["fp_verdict"] = "below_threshold"
                verified.append(cast(dict[str, JsonValue], a_copy))

        status: StageStatus = "ok"
        if not verified:
            status = "partial"

        payload = {
            "schema_version": _SCHEMA_VERSION,
            "status": status,
            "verified_alerts": cast(
                list[JsonValue], cast(list[object], verified)
            ),
            "summary": {
                "total_input": len(alerts),
                "eligible_checked": len(eligible),
                "false_positives": fp_count,
                "true_positives": tp_count,
                "static_prefilter_fps": static_fp_count,
                "ghidra_functions_loaded": len(func_map),
                "xref_edges_loaded": sum(len(v) for v in xref_map.values()),
                "ipc_edges_loaded": len(ipc_edges),
            },
            "limitations": cast(
                list[JsonValue], cast(list[object], sorted(set(limitations)))
            ),
        }
        out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)
            + "\n",
            encoding="utf-8",
        )

        details: dict[str, JsonValue] = {
            "verified": len(verified),
            "false_positives": fp_count,
            "true_positives": tp_count,
            "static_prefilter_fps": static_fp_count,
        }
        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
