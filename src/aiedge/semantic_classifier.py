from __future__ import annotations

"""Semantic classification stage.

Classifies decompiled functions by semantic category using static
dangerous-API filtering and optional LLM-assisted classification.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .llm_driver import ModelTier, resolve_driver
from .path_safety import assert_under_dir
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus

_SCHEMA_VERSION = "semantic-classification-v1"
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

_DANGEROUS_APIS: frozenset[str] = frozenset({
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
    "gets",
    "recv",
    "read",
})

_SEMANTIC_CATEGORIES: tuple[str, ...] = (
    "auth_check",
    "command_handler",
    "input_validation",
    "crypto_operation",
    "network_io",
    "file_operation",
    "memory_management",
    "config_parser",
    "benign",
)

_HIGH_RISK_CATEGORIES: frozenset[str] = frozenset({
    "command_handler",
    "auth_check",
})


def _load_json_file(path: Path) -> object | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _truncate_text(text: str, *, max_chars: int = 8000) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def _static_filter(
    functions: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Keep only functions that reference dangerous APIs."""
    filtered: list[dict[str, object]] = []
    for func in functions:
        body = cast(str, func.get("body", ""))
        if not isinstance(body, str):
            continue
        body_lower = body.lower()
        matched_apis: list[str] = []
        for api in _DANGEROUS_APIS:
            if re.search(r"\b" + re.escape(api) + r"\b", body_lower):
                matched_apis.append(api)
        if matched_apis:
            func_copy = dict(func)
            func_copy["matched_dangerous_apis"] = matched_apis
            filtered.append(func_copy)
    return filtered


def _build_classify_prompt(functions_json: str) -> str:
    categories = ", ".join(_SEMANTIC_CATEGORIES)
    return (
        "You are a firmware binary analysis assistant.\n"
        "Classify each decompiled function into ONE of these categories:\n"
        f"  {categories}\n\n"
        "## Functions\n"
        f"{functions_json}\n\n"
        "## Output Format\n"
        "Return ONLY a JSON object (no markdown fences):\n"
        '{\n  "classifications": [\n'
        '    {"function_name": "<name>", "category": "<category>", '
        '"rationale": "<brief>"}\n  ]\n}\n'
    )


def _build_deep_analysis_prompt(func_name: str, body: str) -> str:
    return (
        "You are a firmware vulnerability analyst.\n"
        f"Deeply analyze this high-risk function '{func_name}' for "
        "exploitable patterns:\n\n"
        f"```c\n{_truncate_text(body)}\n```\n\n"
        "Identify:\n"
        "1. Command injection vectors\n"
        "2. Authentication bypass opportunities\n"
        "3. Buffer overflow potential\n"
        "4. Missing input validation\n\n"
        "## Output Format\n"
        "Return ONLY a JSON object (no markdown fences):\n"
        '{\n  "function_name": "<name>",\n'
        '  "risk_level": "critical"|"high"|"medium"|"low",\n'
        '  "vulnerabilities": [\n'
        '    {"type": "<vuln_type>", "description": "<desc>", '
        '"confidence": 0.0-1.0}\n'
        "  ],\n"
        '  "rationale": "<overall assessment>"\n}\n'
    )


def _parse_json_response(stdout: str) -> dict[str, object] | None:
    text = stdout.strip()
    if not text:
        return None
    # Try code-fenced JSON first
    import re

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
    # Try raw JSON
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return cast(dict[str, object], obj)
    except (json.JSONDecodeError, ValueError):
        pass
    return None


@dataclass(frozen=True)
class SemanticClassifierStage:
    """Classify decompiled functions by semantic category."""

    no_llm: bool = False

    @property
    def name(self) -> str:
        return "semantic_classification"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "semantic_classification"
        out_json = stage_dir / "classified_functions.json"

        assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        assert_under_dir(run_dir, out_json)

        limitations: list[str] = []

        # --- Load ghidra_analysis decompiled functions ---
        ghidra_dir = run_dir / "stages" / "ghidra_analysis"
        ghidra_stage = ghidra_dir / "stage.json"
        decompiled_path = ghidra_dir / "decompiled_functions.json"

        functions: list[dict[str, object]] = []
        ghidra_data = _load_json_file(decompiled_path)
        if ghidra_data is None:
            # Try stage.json for embedded decompilation data
            stage_data = _load_json_file(ghidra_stage)
            if isinstance(stage_data, dict):
                funcs_any = cast(dict[str, object], stage_data).get(
                    "decompiled_functions"
                )
                if isinstance(funcs_any, list):
                    for f in cast(list[object], funcs_any):
                        if isinstance(f, dict):
                            functions.append(cast(dict[str, object], f))
        elif isinstance(ghidra_data, list):
            for f in cast(list[object], ghidra_data):
                if isinstance(f, dict):
                    functions.append(cast(dict[str, object], f))
        elif isinstance(ghidra_data, dict):
            funcs_any = cast(dict[str, object], ghidra_data).get("functions")
            if isinstance(funcs_any, list):
                for f in cast(list[object], funcs_any):
                    if isinstance(f, dict):
                        functions.append(cast(dict[str, object], f))

        # --- Fallback: classify from binary_analysis.json when no ghidra ---
        if not functions:
            limitations.append(
                "No decompiled functions from ghidra_analysis; "
                "falling back to binary_analysis.json symbol-profile classification"
            )
            ba_path = run_dir / "stages" / "inventory" / "binary_analysis.json"
            classifications: list[dict[str, object]] = []
            ba_data = _load_json_file(ba_path)
            if isinstance(ba_data, dict):
                ba_hits_any = cast(dict[str, object], ba_data).get("hits")
                if isinstance(ba_hits_any, list):
                    for hit_any in cast(list[object], ba_hits_any):
                        if not isinstance(hit_any, dict):
                            continue
                        hit = cast(dict[str, object], hit_any)
                        bin_path = str(
                            hit.get("path", "") or hit.get("name", "")
                        )
                        if not bin_path:
                            continue
                        # Collect all symbols
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

                        if not syms:
                            continue

                        # Classify by symbol profile
                        syms_lower = {s.lower() for s in syms}
                        has_exec = bool(
                            syms_lower & {"system", "popen", "execve", "execv", "execvp"}
                        )
                        has_net_input = bool(
                            syms_lower & {"recv", "recvfrom", "recvmsg", "read"}
                        )
                        has_mem_unsafe = bool(
                            syms_lower & {"strcpy", "sprintf", "strcat", "vsprintf", "gets"}
                        )
                        has_auth = bool(
                            syms_lower & {"strcmp", "strncmp"}
                        )

                        if has_net_input and has_exec:
                            category = "command_handler"
                            risk = "critical"
                        elif has_exec and not has_auth:
                            category = "command_handler"
                            risk = "high"
                        elif has_net_input:
                            category = "network_io"
                            risk = "medium"
                        elif has_mem_unsafe and has_exec:
                            category = "command_handler"
                            risk = "high"
                        elif has_mem_unsafe:
                            category = "memory_management"
                            risk = "medium"
                        else:
                            category = "benign"
                            risk = "low"

                        hardening_any = hit.get("hardening")
                        hardening: dict[str, object] = (
                            cast(dict[str, object], hardening_any)
                            if isinstance(hardening_any, dict)
                            else {}
                        )
                        arch = str(hit.get("arch", "unknown"))

                        classifications.append({
                            "function_name": bin_path,
                            "category": category,
                            "risk_level": risk,
                            "rationale": "binary_symbol_profile",
                            "matched_apis": cast(
                                list[JsonValue],
                                cast(list[object], sorted(syms)),
                            ),
                            "hardening": cast(dict[str, JsonValue], hardening),
                            "arch": arch,
                            "method": "static_binary_profile",
                        })

            if not classifications:
                payload_empty: dict[str, JsonValue] = {
                    "schema_version": _SCHEMA_VERSION,
                    "status": "partial",
                    "classifications": [],
                    "deep_analyses": [],
                    "limitations": cast(
                        list[JsonValue], cast(list[object], sorted(set(limitations)))
                    ),
                }
                out_json.write_text(
                    json.dumps(payload_empty, indent=2, sort_keys=True, ensure_ascii=True)
                    + "\n",
                    encoding="utf-8",
                )
                return StageOutcome(
                    status="partial",
                    details=cast(dict[str, JsonValue], {"classified": 0}),
                    limitations=sorted(set(limitations)),
                )

            # Write binary-profile classifications and return
            status_bp: StageStatus = "ok"
            payload_bp: dict[str, JsonValue] = {
                "schema_version": _SCHEMA_VERSION,
                "status": status_bp,
                "total_functions_scanned": 0,
                "total_binaries_profiled": len(classifications),
                "dangerous_api_matches": len(classifications),
                "classifications": cast(
                    list[JsonValue], cast(list[object], classifications)
                ),
                "deep_analyses": [],
                "limitations": cast(
                    list[JsonValue], cast(list[object], sorted(set(limitations)))
                ),
            }
            out_json.write_text(
                json.dumps(payload_bp, indent=2, sort_keys=True, ensure_ascii=True)
                + "\n",
                encoding="utf-8",
            )
            details_bp: dict[str, JsonValue] = {
                "classified": len(classifications),
                "deep_analyses": 0,
                "dangerous_api_matches": len(classifications),
                "method": "binary_profile_fallback",
            }
            return StageOutcome(
                status=status_bp,
                details=details_bp,
                limitations=sorted(set(limitations)),
            )

        # --- Pass 1: Static filter ---
        filtered = _static_filter(functions)
        if not filtered:
            limitations.append(
                "No functions matched dangerous API filter"
            )

        # --- Pass 2: LLM classification (haiku) ---
        classifications: list[dict[str, JsonValue]] = []
        if filtered and not self.no_llm:
            driver = resolve_driver()
            if driver.available():
                # Prepare function summaries for LLM
                func_summaries: list[dict[str, str]] = []
                # Sort by matched API count (most dangerous first)
                filtered.sort(
                    key=lambda f: len(f.get("matched_dangerous_apis", [])),
                    reverse=True,
                )
                for func in filtered[:50]:  # Cap at 50 for LLM context
                    fname = str(func.get("name", "unknown"))
                    body = str(func.get("body", ""))
                    func_summaries.append({
                        "function_name": fname,
                        "body_snippet": _truncate_text(body, max_chars=2000),
                        "dangerous_apis": ", ".join(
                            cast(list[str], func.get("matched_dangerous_apis", []))
                        ),
                    })

                prompt = _build_classify_prompt(
                    json.dumps(func_summaries, indent=2, ensure_ascii=True)
                )
                model_tier: ModelTier = "haiku"
                result = driver.execute(
                    prompt=prompt,
                    run_dir=run_dir,
                    timeout_s=_LLM_TIMEOUT_S,
                    max_attempts=_LLM_MAX_ATTEMPTS,
                    retryable_tokens=_RETRYABLE_TOKENS,
                    model_tier=model_tier,
                )
                if result.status == "ok":
                    parsed = _parse_json_response(result.stdout)
                    if parsed is not None:
                        cls_list = parsed.get("classifications")
                        if isinstance(cls_list, list):
                            for item in cast(list[object], cls_list):
                                if isinstance(item, dict):
                                    classifications.append(
                                        cast(dict[str, JsonValue], item)
                                    )
                    else:
                        limitations.append(
                            "LLM classification response could not be parsed"
                        )
                else:
                    limitations.append(
                        f"LLM classification call failed: {result.status}"
                    )
            else:
                limitations.append("LLM driver not available for classification")
        elif self.no_llm:
            limitations.append("LLM classification skipped (no_llm mode)")

        # Build static-only classifications for functions without LLM results
        classified_names = {
            cast(str, c.get("function_name", ""))
            for c in classifications
        }
        for func in filtered:
            fname = str(func.get("name", "unknown"))
            if fname not in classified_names:
                classifications.append({
                    "function_name": fname,
                    "category": "command_handler"
                    if any(
                        api in ("system", "popen", "execve", "execvp")
                        for api in cast(
                            list[str], func.get("matched_dangerous_apis", [])
                        )
                    )
                    else "memory_management"
                    if any(
                        api in ("strcpy", "sprintf", "gets")
                        for api in cast(
                            list[str], func.get("matched_dangerous_apis", [])
                        )
                    )
                    else "network_io"
                    if any(
                        api in ("recv", "read")
                        for api in cast(
                            list[str], func.get("matched_dangerous_apis", [])
                        )
                    )
                    else "benign",
                    "rationale": "static_api_filter",
                    "matched_apis": cast(
                        list[JsonValue],
                        cast(
                            list[object],
                            func.get("matched_dangerous_apis", []),
                        ),
                    ),
                    "method": "static",
                })

        # --- Pass 3: Deep analysis for high-risk (sonnet) ---
        deep_analyses: list[dict[str, JsonValue]] = []
        if not self.no_llm:
            high_risk = [
                c
                for c in classifications
                if cast(str, c.get("category", "")) in _HIGH_RISK_CATEGORIES
            ]
            if high_risk:
                driver = resolve_driver()
                if driver.available():
                    for cls_entry in high_risk[:10]:  # Cap deep analysis
                        fname = cast(str, cls_entry.get("function_name", ""))
                        # Find the function body
                        body = ""
                        for func in filtered:
                            if str(func.get("name", "")) == fname:
                                body = str(func.get("body", ""))
                                break
                        if not body:
                            continue
                        deep_prompt = _build_deep_analysis_prompt(fname, body)
                        deep_result = driver.execute(
                            prompt=deep_prompt,
                            run_dir=run_dir,
                            timeout_s=_LLM_TIMEOUT_S,
                            max_attempts=_LLM_MAX_ATTEMPTS,
                            retryable_tokens=_RETRYABLE_TOKENS,
                            model_tier="sonnet",
                        )
                        if deep_result.status == "ok":
                            parsed_deep = _parse_json_response(
                                deep_result.stdout
                            )
                            if parsed_deep is not None:
                                deep_analyses.append(
                                    cast(dict[str, JsonValue], parsed_deep)
                                )

        status: StageStatus = "ok"
        if not classifications:
            status = "partial"

        payload = {
            "schema_version": _SCHEMA_VERSION,
            "status": status,
            "total_functions_scanned": len(functions),
            "dangerous_api_matches": len(filtered),
            "classifications": cast(
                list[JsonValue], cast(list[object], classifications)
            ),
            "deep_analyses": cast(
                list[JsonValue], cast(list[object], deep_analyses)
            ),
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
            "classified": len(classifications),
            "deep_analyses": len(deep_analyses),
            "dangerous_api_matches": len(filtered),
        }
        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
