from __future__ import annotations

"""Adversarial triage stage.

Uses an Advocate/Critic LLM debate pattern to reduce false-positive rate
by having two opposing perspectives argue exploitability for each finding.
Skips under ``--no-llm``.
"""

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .llm_driver import (
    LLMDriver,
    ModelTier,
    classify_llm_failure,
    resolve_driver,
    write_llm_trace,
)
from .llm_prompts import (
    ADVOCATE_SYSTEM,
    CRITIC_SYSTEM,
    REPAIR_SYSTEM,
    TEMPERATURE_ANALYTICAL,
    TEMPERATURE_DETERMINISTIC,
)
from .path_safety import assert_under_dir
from .reasoning_trail import ReasoningEntry, append_entry, redact_excerpt
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus

_SCHEMA_VERSION = "adversarial-triage-v1"
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

_CONFIDENCE_REDUCTION = 0.2

# Mitigations the critic may cite as strong rebuttals
_STRONG_MITIGATIONS: frozenset[str] = frozenset(
    {
        "chroot",
        "acl",
        "input filter",
        "input validation",
        "seccomp",
        "apparmor",
        "selinux",
        "sandboxing",
        "sandbox",
        "rate limit",
        "authentication required",
        "authorization check",
        "canary",
        "stack protector",
        "aslr",
        "nx bit",
        "pie",
    }
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


def _build_code_section(decompiled_context: list[dict[str, str]] | None) -> str:
    """Format decompiled function bodies for LLM prompts."""
    if not decompiled_context:
        return ""
    parts: list[str] = []
    for fc in decompiled_context[:3]:
        name = fc.get("name", "unknown")
        body = fc.get("body", "")[:2000]
        parts.append(f"### {name}\n```c\n{body}\n```")
    return "\n## Decompiled Code Evidence\n" + "\n".join(parts) + "\n"


def _build_analyst_hint_prefix(finding: dict[str, object]) -> str:
    """Return a prompt prefix for any analyst hints stored for this finding.

    PR #12 -- opt-in via ``AIEDGE_FEEDBACK_DIR``. When the env var is unset
    *or* no hints have been registered for this finding, returns an empty
    string so the advocate prompt is byte-identical to the pre-PR version
    (preserving the deterministic prompt path).
    """
    if not os.environ.get("AIEDGE_FEEDBACK_DIR"):
        return ""
    finding_id_any = finding.get("id") or finding.get("finding_id")
    if not isinstance(finding_id_any, str) or not finding_id_any:
        return ""
    try:
        from .terminator_feedback import get_analyst_hints

        hints = get_analyst_hints(finding_id_any)
    except Exception:
        return ""
    if not hints:
        return ""

    lines: list[str] = ["[Analyst hints from prior runs:"]
    _priority_order = {"high": 0, "medium": 1, "low": 2}
    sorted_hints = sorted(
        hints,
        key=lambda h: _priority_order.get(str(h.get("priority", "medium")).lower(), 1),
    )
    for hint in sorted_hints:
        priority = str(hint.get("priority", "medium"))
        text = str(hint.get("text", "")).strip()
        if not text:
            continue
        lines.append(f" - {priority}: {text}")
    lines.append("]\n\n")
    return "\n".join(lines)


def _build_advocate_prompt(
    finding: dict[str, object],
    decompiled_context: list[dict[str, str]] | None = None,
) -> str:
    finding_json = json.dumps(finding, indent=2, ensure_ascii=True)
    code_section = _build_code_section(decompiled_context)
    hint_prefix = _build_analyst_hint_prefix(finding)
    return (
        f"{hint_prefix}"
        "## Finding\n"
        f"{finding_json}\n\n"
        f"{code_section}"
        "## Rules\n"
        "- Focus on attacker-reachable input paths\n"
        "- Consider lack of input validation or sanitization\n"
        "- Note missing hardening (no PIE, no canary, no NX)\n"
        "- Consider chain potential with other vulnerabilities\n\n"
        "## Output Format\n"
        "Return ONLY a JSON object (no markdown fences):\n"
        "{\n"
        '  "exploitable": true,\n'
        '  "argument": "<detailed argument>",\n'
        '  "evidence_cited": ["<specific evidence points>"],\n'
        '  "attack_scenario": "<brief attack scenario>"\n'
        "}\n\n"
        "## Example Output\n"
        '{"exploitable": true, "argument": "The recv() call at 0x4012A0 reads user input into a stack buffer passed directly to system() at 0x4012F0 with no length check or sanitization.", "evidence_cited": ["recv() in handler_main", "system() call with user-controlled buffer", "no stack canary"], "attack_scenario": "Attacker sends crafted HTTP request to inject shell command via unsanitized CGI parameter."}\n'
    )


def _build_critic_prompt(
    finding: dict[str, object],
    advocate_argument: str,
    decompiled_context: list[dict[str, str]] | None = None,
) -> str:
    finding_json = json.dumps(finding, indent=2, ensure_ascii=True)
    code_section = _build_code_section(decompiled_context)
    return (
        "## Finding\n"
        f"{finding_json}\n\n"
        f"{code_section}"
        "## Advocate's Argument (opposing view)\n"
        f"{advocate_argument}\n\n"
        "## Rules\n"
        "- Consider specific mitigations: chroot, ACL, input filters,\n"
        "  seccomp, AppArmor, SELinux, sandboxing\n"
        "- Note binary hardening: canaries, ASLR, NX, PIE\n"
        "- Consider authentication/authorization requirements\n"
        "- Identify practical exploitation barriers\n\n"
        "## Output Format\n"
        "Return ONLY a JSON object (no markdown fences):\n"
        "{\n"
        '  "exploitable": false,\n'
        '  "rebuttal": "<detailed rebuttal>",\n'
        '  "mitigations_cited": ["<specific mitigations>"],\n'
        '  "exploitation_barriers": ["<practical barriers>"]\n'
        "}\n\n"
        "## Example Output\n"
        '{"exploitable": false, "rebuttal": "The sprintf call uses a format string from .rodata (constant) with integer arguments only. No user-controlled data reaches the format string or buffer size.", "evidence_cited": ["format string is constant literal", "arguments are integer return values from atoi()"], "missing_evidence": ["no network input path to this function"]}\n'
    )


def _parse_json_response(stdout: str) -> dict[str, object] | None:
    from .llm_driver import parse_json_from_llm_output

    return parse_json_from_llm_output(stdout)


def _repair_debate_response(
    *,
    driver: LLMDriver,
    run_dir: Path,
    stage_name: str,
    purpose: str,
    raw_stdout: str,
    model_tier: ModelTier,
    trace_refs: list[str],
) -> dict[str, object] | None:
    prompt = (
        "Convert the following security analysis output into a single valid JSON object. "
        "Return JSON only. Preserve meaning, omit unsupported fields, and do not invent evidence.\n\n"
        f"{raw_stdout}"
    )
    result = driver.execute(
        prompt=prompt,
        run_dir=run_dir,
        timeout_s=_LLM_TIMEOUT_S,
        max_attempts=1,
        retryable_tokens=_RETRYABLE_TOKENS,
        model_tier="haiku" if model_tier != "opus" else "sonnet",
        system_prompt=REPAIR_SYSTEM,
        temperature=TEMPERATURE_DETERMINISTIC,
    )
    trace_refs.append(
        write_llm_trace(
            run_dir=run_dir,
            stage_name=stage_name,
            purpose=f"{purpose}-repair",
            prompt=prompt,
            model_tier="haiku" if model_tier != "opus" else "sonnet",
            result=result,
            metadata={"repair_for": purpose},
        )
    )
    if result.status != "ok":
        return None
    return _parse_json_response(result.stdout)


def _has_strong_rebuttal(critic_response: dict[str, object]) -> bool:
    """Check if critic cited specific strong mitigations."""
    mitigations = critic_response.get("mitigations_cited", [])
    if not isinstance(mitigations, list):
        return False
    for mit in cast(list[object], mitigations):
        if isinstance(mit, str):
            mit_lower = mit.lower()
            for strong in _STRONG_MITIGATIONS:
                if strong in mit_lower:
                    return True

    barriers = critic_response.get("exploitation_barriers", [])
    if isinstance(barriers, list):
        for barrier in cast(list[object], barriers):
            if isinstance(barrier, str):
                barrier_lower = barrier.lower()
                for strong in _STRONG_MITIGATIONS:
                    if strong in barrier_lower:
                        return True
    return False


@dataclass(frozen=True)
class AdversarialTriageStage:
    """Advocate/Critic debate to reduce FPR."""

    no_llm: bool = False

    @property
    def name(self) -> str:
        return "adversarial_triage"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "adversarial_triage"
        out_json = stage_dir / "triaged_findings.json"

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
                "triaged_findings": [],
            }
            out_json.write_text(
                json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
            return StageOutcome(
                status="skipped",
                details=cast(dict[str, JsonValue], {"reason": "no_llm_mode"}),
                limitations=["no_llm_mode"],
            )

        # --- Load findings from multiple fallback sources ---
        findings: list[dict[str, object]] = []

        # Try fp_verification first
        fp_path = run_dir / "stages" / "fp_verification" / "verified_alerts.json"
        fp_data = _load_json_file(fp_path)
        if isinstance(fp_data, dict):
            v_any = cast(dict[str, object], fp_data).get("verified_alerts")
            if isinstance(v_any, list):
                for item in cast(list[object], v_any):
                    if isinstance(item, dict):
                        findings.append(cast(dict[str, object], item))

        # Fallback 1: taint_propagation alerts
        if not findings:
            taint_path = run_dir / "stages" / "taint_propagation" / "alerts.json"
            t_data = _load_json_file(taint_path)
            if isinstance(t_data, dict):
                t_any = cast(dict[str, object], t_data).get("alerts")
                if isinstance(t_any, list):
                    for item in cast(list[object], t_any):
                        if isinstance(item, dict):
                            findings.append(cast(dict[str, object], item))
                    if findings:
                        limitations.append(
                            "Using taint_propagation alerts directly "
                            "(fp_verification unavailable)"
                        )

        # Fallback 2: findings stage
        if not findings:
            findings_path = run_dir / "stages" / "findings" / "findings.json"
            f_data = _load_json_file(findings_path)
            if isinstance(f_data, dict):
                f_any = cast(dict[str, object], f_data).get("findings")
                if isinstance(f_any, list):
                    for item in cast(list[object], f_any):
                        if isinstance(item, dict):
                            findings.append(cast(dict[str, object], item))

        # Fallback 3: attack_surface entries
        if not findings:
            as_path = run_dir / "stages" / "attack_surface" / "attack_surface.json"
            as_data = _load_json_file(as_path)
            if isinstance(as_data, dict):
                as_entries = cast(dict[str, object], as_data).get("attack_surface")
                if isinstance(as_entries, list):
                    for entry_any in cast(list[object], as_entries):
                        if not isinstance(entry_any, dict):
                            continue
                        entry = cast(dict[str, object], entry_any)
                        conf_any = entry.get("confidence") or entry.get(
                            "confidence_calibrated"
                        )
                        if isinstance(conf_any, (int, float)) and float(conf_any) > 0.3:
                            finding_entry: dict[str, object] = {
                                "source_api": str(entry.get("surface", "")),
                                "source_binary": str(entry.get("observation", "")),
                                "sink_symbol": str(entry.get("classification", "")),
                                "confidence": float(conf_any),
                                "path_description": str(
                                    entry.get("edge_semantics", "")
                                ),
                                "method": "attack_surface_fallback",
                            }
                            findings.append(finding_entry)
                    if findings:
                        limitations.append(
                            "Using attack_surface entries as fallback "
                            "(fp_verification, taint_propagation, and "
                            "findings unavailable)"
                        )

        if not findings:
            limitations.append(
                "No findings from fp_verification, taint_propagation, "
                "findings, or attack_surface stages"
            )
            payload = {
                "schema_version": _SCHEMA_VERSION,
                "status": "partial",
                "triaged_findings": [],
                "summary": {
                    "total_input": 0,
                    "debated": 0,
                    "downgraded": 0,
                },
                "limitations": cast(list[JsonValue], cast(list[object], limitations)),
            }
            out_json.write_text(
                json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
            return StageOutcome(
                status="partial",
                details=cast(dict[str, JsonValue], {"triaged": 0}),
                limitations=limitations,
            )

        # --- Filter findings using original_confidence if available ---
        # fp_verification may reduce confidence but preserves the original
        # score in "original_confidence".  Use it for eligibility so that
        # FP-adjusted alerts still reach the advocate/critic debate.
        _AT_THRESHOLD = 0.40
        eligible = [
            f
            for f in findings
            if isinstance(f.get("confidence"), (int, float))
            and float(str(f.get("original_confidence", f["confidence"])))
            >= _AT_THRESHOLD
        ]
        below_threshold = [
            f
            for f in findings
            if not isinstance(f.get("confidence"), (int, float))
            or float(str(f.get("original_confidence", f["confidence"]))) < _AT_THRESHOLD
        ]

        # --- Load decompiled functions for code-backed debate ---
        ghidra_dir = run_dir / "stages" / "ghidra_analysis"
        decompiled_path = ghidra_dir / "decompiled_functions.json"
        _all_funcs: list[dict[str, str]] = []
        dec_data = _load_json_file(decompiled_path)
        if isinstance(dec_data, dict):
            funcs_any = dec_data.get("functions")
            if isinstance(funcs_any, list):
                for f in funcs_any:
                    if isinstance(f, dict):
                        fname = str(f.get("name", ""))
                        body = str(f.get("body", ""))
                        binary = str(f.get("binary", ""))
                        if fname and body:
                            _all_funcs.append(
                                {"name": fname, "body": body, "binary": binary}
                            )

        def _find_decompiled_for(
            finding: dict[str, object],
        ) -> list[dict[str, str]] | None:
            """Find decompiled functions relevant to a finding."""
            src_binary = str(finding.get("source_binary", ""))
            src_api = str(finding.get("source_api", ""))
            sink_sym = str(finding.get("sink_symbol", ""))
            if not _all_funcs or (not src_api and not sink_sym):
                return None
            basename = (
                src_binary.rsplit("/", 1)[-1] if "/" in src_binary else src_binary
            )
            matched: list[dict[str, str]] = []
            for fi in _all_funcs:
                fb = fi.get("binary", "")
                if basename and fb and basename not in fb:
                    continue
                bl = fi["body"].lower()
                if (src_api and src_api.lower() in bl) or (
                    sink_sym and sink_sym.lower() in bl
                ):
                    matched.append(fi)
                    if len(matched) >= 3:
                        break
            return matched or None

        # --- Advocate/Critic debate ---
        driver = resolve_driver()
        triaged: list[dict[str, JsonValue]] = []
        debated_count = 0
        downgraded_count = 0
        parsed_ok_count = 0
        parse_failure_count = 0
        llm_call_failure_count = 0
        trace_refs: list[str] = []

        if not driver.available():
            limitations.append("LLM driver not available for adversarial triage")
            for f in findings:
                triaged.append(cast(dict[str, JsonValue], dict(f)))
        else:
            _ADV_PARALLEL = int(os.environ.get("AIEDGE_ADV_PARALLEL", "8"))
            _trace_lock = threading.Lock()

            def _debate_one(finding: dict[str, object]) -> dict[str, object]:
                """Run advocate/critic debate for a single finding (thread-safe)."""
                finding_copy = dict(finding)
                dec_ctx = _find_decompiled_for(finding)
                local_traces: list[str] = []
                # PR #11 -- carry forward any existing trail from upstream
                # stages (e.g. fp_verification) and append advocate/critic/
                # decision entries below.
                _existing_trail_any: object = finding.get("reasoning_trail")
                local_trail: list[dict[str, JsonValue]]
                if isinstance(_existing_trail_any, list):
                    local_trail = [
                        cast(dict[str, JsonValue], _e)
                        for _e in cast(list[object], _existing_trail_any)
                        if isinstance(_e, dict)
                    ]
                else:
                    local_trail = []
                _ADVERSARIAL_STAGE_LABEL = "adversarial_triage"
                _ADVERSARIAL_MODEL_TIER: ModelTier = "sonnet"

                # Advocate
                advocate_prompt = _build_advocate_prompt(finding, dec_ctx)
                advocate_result = driver.execute(
                    prompt=advocate_prompt,
                    run_dir=run_dir,
                    timeout_s=_LLM_TIMEOUT_S,
                    max_attempts=_LLM_MAX_ATTEMPTS,
                    retryable_tokens=_RETRYABLE_TOKENS,
                    model_tier="sonnet",
                    system_prompt=ADVOCATE_SYSTEM,
                    temperature=TEMPERATURE_ANALYTICAL,
                )
                local_traces.append(
                    write_llm_trace(
                        run_dir=run_dir,
                        stage_name=self.name,
                        purpose="advocate",
                        prompt=advocate_prompt,
                        model_tier="sonnet",
                        result=advocate_result,
                    )
                )

                advocate_argument = ""
                advocate_parsed: dict[str, object] | None = None
                advocate_failure_kind: str | None = None
                advocate_failure_reason: str | None = None
                if advocate_result.status == "ok":
                    advocate_parsed = _parse_json_response(advocate_result.stdout)
                    if advocate_parsed is None:
                        advocate_parsed = _repair_debate_response(
                            driver=driver,
                            run_dir=run_dir,
                            stage_name=self.name,
                            purpose="advocate",
                            raw_stdout=advocate_result.stdout,
                            model_tier="sonnet",
                            trace_refs=local_traces,
                        )
                    if advocate_parsed is not None:
                        advocate_argument = str(advocate_parsed.get("argument", ""))
                else:
                    advocate_failure_kind, advocate_failure_reason = (
                        classify_llm_failure(advocate_result)
                    )

                # PR #11 -- record advocate step in reasoning trail
                if advocate_parsed is not None:
                    _exploitable = advocate_parsed.get("exploitable")
                    _adv_verdict = (
                        "exploit_path_plausible"
                        if _exploitable is True
                        else (
                            "exploit_path_rejected"
                            if _exploitable is False
                            else "reasoning"
                        )
                    )
                    _adv_rationale = str(advocate_parsed.get("argument", "")) or (
                        "Advocate produced no argument"
                    )
                elif advocate_result.status == "ok":
                    _adv_verdict = "parse_failure"
                    _adv_rationale = "Advocate response could not be parsed as JSON"
                else:
                    _adv_verdict = "llm_call_failed"
                    _adv_rationale = (
                        f"Advocate LLM call failed: "
                        f"{advocate_failure_kind or 'unknown_failure'}"
                    )
                local_trail = append_entry(
                    local_trail,
                    ReasoningEntry(
                        stage=_ADVERSARIAL_STAGE_LABEL,
                        step="advocate",
                        verdict=_adv_verdict,
                        rationale=_adv_rationale,
                        delta=0.0,
                        llm_model=_ADVERSARIAL_MODEL_TIER,
                        raw_response_excerpt=redact_excerpt(
                            advocate_result.stdout
                            if advocate_result.status == "ok"
                            else None
                        ),
                    ),
                )

                # Critic
                critic_prompt = _build_critic_prompt(
                    finding,
                    advocate_argument or "(advocate failed to respond)",
                    dec_ctx,
                )
                critic_result = driver.execute(
                    prompt=critic_prompt,
                    run_dir=run_dir,
                    timeout_s=_LLM_TIMEOUT_S,
                    max_attempts=_LLM_MAX_ATTEMPTS,
                    retryable_tokens=_RETRYABLE_TOKENS,
                    model_tier="sonnet",
                    system_prompt=CRITIC_SYSTEM,
                    temperature=TEMPERATURE_ANALYTICAL,
                )
                local_traces.append(
                    write_llm_trace(
                        run_dir=run_dir,
                        stage_name=self.name,
                        purpose="critic",
                        prompt=critic_prompt,
                        model_tier="sonnet",
                        result=critic_result,
                    )
                )

                critic_parsed: dict[str, object] | None = None
                critic_failure_kind: str | None = None
                critic_failure_reason: str | None = None
                if critic_result.status == "ok":
                    critic_parsed = _parse_json_response(critic_result.stdout)
                    if critic_parsed is None:
                        critic_parsed = _repair_debate_response(
                            driver=driver,
                            run_dir=run_dir,
                            stage_name=self.name,
                            purpose="critic",
                            raw_stdout=critic_result.stdout,
                            model_tier="sonnet",
                            trace_refs=local_traces,
                        )
                else:
                    critic_failure_kind, critic_failure_reason = classify_llm_failure(
                        critic_result
                    )

                # PR #11 -- record critic step in reasoning trail
                if critic_parsed is not None:
                    _crit_exploitable = critic_parsed.get("exploitable")
                    if _crit_exploitable is False:
                        _crit_verdict = "downgrade"
                    elif _crit_exploitable is True:
                        _crit_verdict = "maintain"
                    else:
                        _crit_verdict = "reasoning"
                    _crit_rationale = str(critic_parsed.get("rebuttal", "")) or (
                        "Critic produced no rebuttal"
                    )
                elif critic_result.status == "ok":
                    _crit_verdict = "parse_failure"
                    _crit_rationale = "Critic response could not be parsed as JSON"
                else:
                    _crit_verdict = "llm_call_failed"
                    _crit_rationale = (
                        f"Critic LLM call failed: "
                        f"{critic_failure_kind or 'unknown_failure'}"
                    )
                local_trail = append_entry(
                    local_trail,
                    ReasoningEntry(
                        stage=_ADVERSARIAL_STAGE_LABEL,
                        step="critic",
                        verdict=_crit_verdict,
                        rationale=_crit_rationale,
                        delta=0.0,
                        llm_model=_ADVERSARIAL_MODEL_TIER,
                        raw_response_excerpt=redact_excerpt(
                            critic_result.stdout
                            if critic_result.status == "ok"
                            else None
                        ),
                    ),
                )

                # Compare: strong rebuttal -> reduce confidence
                _local_downgraded = False
                _decision_delta = 0.0
                _decision_rationale = ""
                if critic_parsed is not None and _has_strong_rebuttal(critic_parsed):
                    orig_conf = float(str(finding.get("confidence", 0.5)))
                    new_conf = _clamp01(orig_conf - _CONFIDENCE_REDUCTION)
                    _decision_delta = new_conf - orig_conf
                    finding_copy["confidence"] = new_conf
                    finding_copy["original_confidence"] = orig_conf
                    finding_copy["triage_outcome"] = "downgraded"
                    _local_downgraded = True
                    _decision_rationale = (
                        "Critic cited a strong mitigation; confidence reduced "
                        f"from {orig_conf:.3f} to {new_conf:.3f}"
                    )
                else:
                    finding_copy["triage_outcome"] = "maintained"
                    _decision_rationale = (
                        "Critic did not cite a strong mitigation; "
                        "confidence maintained"
                    )

                # PR #11 -- record synthesizing decision entry
                local_trail = append_entry(
                    local_trail,
                    ReasoningEntry(
                        stage=_ADVERSARIAL_STAGE_LABEL,
                        step="decision",
                        verdict="downgrade" if _local_downgraded else "maintain",
                        rationale=_decision_rationale,
                        delta=_decision_delta,
                        llm_model=None,
                        raw_response_excerpt=None,
                    ),
                )

                advocate_payload: dict[str, JsonValue]
                if advocate_parsed is not None:
                    advocate_payload = cast(dict[str, JsonValue], advocate_parsed)
                elif advocate_result.status == "ok":
                    advocate_payload = {
                        "error": "parse_failure",
                        "status": advocate_result.status,
                    }
                else:
                    advocate_payload = {
                        "error": "llm_call_failed",
                        "status": advocate_result.status,
                        "failure_kind": advocate_failure_kind or "unknown_failure",
                        "failure_reason": advocate_failure_reason
                        or advocate_result.status,
                    }

                critic_payload: dict[str, JsonValue]
                if critic_parsed is not None:
                    critic_payload = cast(dict[str, JsonValue], critic_parsed)
                elif critic_result.status == "ok":
                    critic_payload = {
                        "error": "parse_failure",
                        "status": critic_result.status,
                    }
                else:
                    critic_payload = {
                        "error": "llm_call_failed",
                        "status": critic_result.status,
                        "failure_kind": critic_failure_kind or "unknown_failure",
                        "failure_reason": critic_failure_reason or critic_result.status,
                    }

                finding_copy["advocate_argument"] = advocate_payload
                finding_copy["critic_rebuttal"] = critic_payload
                finding_copy["trace_refs"] = cast(
                    list[JsonValue], cast(list[object], local_traces[-4:])
                )
                # PR #11 -- attach the reasoning trail (additive field)
                finding_copy["reasoning_trail"] = cast(
                    JsonValue, cast(list[object], local_trail)
                )
                _local_parsed_ok = (
                    advocate_parsed is not None and critic_parsed is not None
                )
                _local_llm_call_failure = (
                    advocate_result.status != "ok" or critic_result.status != "ok"
                )
                _local_parse_failure = (
                    not _local_parsed_ok and not _local_llm_call_failure
                )
                finding_copy["_parsed_ok"] = _local_parsed_ok
                finding_copy["_downgraded"] = _local_downgraded
                finding_copy["_parse_failure"] = _local_parse_failure
                finding_copy["_llm_call_failure"] = _local_llm_call_failure
                if _local_llm_call_failure:
                    failure_parts = []
                    if advocate_failure_kind is not None:
                        failure_parts.append(f"advocate:{advocate_failure_kind}")
                    if critic_failure_kind is not None:
                        failure_parts.append(f"critic:{critic_failure_kind}")
                    reason_parts = []
                    if advocate_failure_reason:
                        reason_parts.append(f"advocate:{advocate_failure_reason}")
                    if critic_failure_reason:
                        reason_parts.append(f"critic:{critic_failure_reason}")
                    finding_copy["triage_failure_kind"] = ", ".join(failure_parts)
                    finding_copy["triage_failure_reason"] = " | ".join(reason_parts)
                elif _local_parse_failure:
                    finding_copy["triage_failure_kind"] = "parse_failure"
                    finding_copy["triage_failure_reason"] = (
                        "One or more adversarial triage responses were unparseable"
                    )

                with _trace_lock:
                    trace_refs.extend(local_traces)

                return finding_copy

            with ThreadPoolExecutor(max_workers=_ADV_PARALLEL) as pool:
                futures = {pool.submit(_debate_one, f): f for f in eligible}
                for future in as_completed(futures):
                    result = future.result()
                    parsed_ok = bool(result.pop("_parsed_ok", False))
                    llm_call_failed = bool(result.pop("_llm_call_failure", False))
                    parse_failed = bool(result.pop("_parse_failure", False))
                    if parsed_ok:
                        parsed_ok_count += 1
                    elif llm_call_failed:
                        llm_call_failure_count += 1
                    elif parse_failed:
                        parse_failure_count += 1
                    if result.pop("_downgraded", False):
                        downgraded_count += 1
                    triaged.append(cast(dict[str, JsonValue], result))
                    debated_count += 1

            # Add below-threshold findings unchanged
            for f in below_threshold:
                f_copy = dict(f)
                f_copy["triage_outcome"] = "below_threshold"
                triaged.append(cast(dict[str, JsonValue], f_copy))

        status: StageStatus = "ok"
        if not triaged or (debated_count > 0 and parsed_ok_count < debated_count):
            status = "partial"
        if parse_failure_count > 0:
            limitations.append(
                "One or more adversarial triage responses could not be parsed"
            )
        if llm_call_failure_count > 0:
            limitations.append("One or more adversarial triage LLM calls failed")

        payload = {
            "schema_version": _SCHEMA_VERSION,
            "status": status,
            "triaged_findings": cast(list[JsonValue], cast(list[object], triaged)),
            "summary": {
                "total_input": len(findings),
                "eligible": len(eligible),
                "debated": debated_count,
                "downgraded": downgraded_count,
                "maintained": debated_count - downgraded_count,
                "parsed_ok": parsed_ok_count,
                "parse_failures": parse_failure_count,
                "llm_call_failures": llm_call_failure_count,
            },
            "trace_refs": cast(list[JsonValue], cast(list[object], trace_refs)),
            "limitations": cast(
                list[JsonValue], cast(list[object], sorted(set(limitations)))
            ),
        }
        out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        details: dict[str, JsonValue] = {
            "triaged": len(triaged),
            "debated": debated_count,
            "downgraded": downgraded_count,
            "parsed_ok": parsed_ok_count,
            "parse_failures": parse_failure_count,
            "llm_call_failures": llm_call_failure_count,
        }
        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
