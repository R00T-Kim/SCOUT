"""LLM-assisted finding triage stage.

Runs after ``findings`` to re-prioritise exploit candidates using LLM
judgment enriched with binary-hardening and attack-surface context.
Gracefully skips when ``--no-llm`` is active or when the LLM driver is
unavailable.
"""
from __future__ import annotations

import json
import os
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .llm_driver import (
    LLMDriver,
    LLMDriverResult,
    ModelTier,
    resolve_driver,
    write_llm_trace,
)
from .schema import JsonValue
from .stage import StageContext, StageOutcome

_TRIAGE_TIMEOUT_S = 120.0
_TRIAGE_MAX_ATTEMPTS = 3

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

_TRIAGE_SCHEMA_VERSION = "llm-triage-v1"


def _select_model_tier(candidate_count: int, has_chains: bool) -> ModelTier:
    """Select model tier based on candidate count and complexity."""
    if candidate_count > 50 or has_chains:
        return "opus"
    if candidate_count <= 10:
        return "haiku"
    return "sonnet"


def _load_json_file(path: Path) -> object | None:
    """Load a JSON file, returning *None* on any failure."""
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _build_triage_prompt(
    candidates: list[dict[str, object]],
    hardening_summary: dict[str, object] | None,
    attack_surface_summary: dict[str, object] | None,
) -> str:
    """Build the triage prompt sent to the LLM.

    The prompt instructs the model to act as a firmware vulnerability triage
    analyst and return a JSON object with ``rankings``.
    """
    candidates_json = json.dumps(candidates, indent=2, ensure_ascii=True)

    hardening_block = ""
    if hardening_summary:
        hardening_block = (
            "\n## Binary Hardening Summary\n"
            + json.dumps(hardening_summary, indent=2, ensure_ascii=True)
        )

    attack_surface_block = ""
    if attack_surface_summary:
        attack_surface_block = (
            "\n## Attack Surface Summary\n"
            + json.dumps(attack_surface_summary, indent=2, ensure_ascii=True)
        )

    return textwrap.dedent(
        f"""\
        You are a firmware vulnerability triage analyst.
        Given a list of exploit candidates from static analysis, re-prioritise
        them considering binary hardening posture and network attack surface.

        ## Candidates
        {candidates_json}
        {hardening_block}
        {attack_surface_block}

        ## Rules
        - Binaries with weaker hardening (no NX, no PIE, no canary) should be
          prioritised higher when the candidate targets that binary.
        - Network-exposed services (open ports, listening daemons) increase
          priority.
        - Consider chain potential: candidates that can be combined for
          privilege escalation or lateral movement should reference each other.
        - Assign priority: "critical", "high", "medium", or "low".

        ## Output Format
        Return ONLY a JSON object (no markdown fences):
        {{
          "rankings": [
            {{
              "candidate_id": "<id>",
              "priority": "critical"|"high"|"medium"|"low",
              "rationale": "<brief explanation>",
              "chain_potential": ["<other_candidate_id>", ...]
            }}
          ]
        }}
        """
    )


def _parse_triage_response(stdout: str) -> list[dict[str, object]] | None:
    """Extract rankings from LLM response.

    Tries code-fenced JSON first, then raw JSON, then regex extraction.
    Returns *None* on parse failure.
    """
    text = stdout.strip()
    if not text:
        return None

    # Stage 1: code-fenced JSON (lenient regex — no mandatory newline)
    fences = re.findall(
        r"```(?:json)?\s*(.*?)```",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    for fence in fences:
        parsed = _try_parse_rankings(fence.strip())
        if parsed is not None:
            return parsed

    # Stage 2: raw JSON
    result = _try_parse_rankings(text)
    if result is not None:
        return result

    # Stage 3: extract outermost JSON object via regex
    obj_match = re.search(r"\{[\s\S]*\}", text)
    if obj_match is not None:
        return _try_parse_rankings(obj_match.group(0).strip())
    return None


def _try_parse_rankings(text: str) -> list[dict[str, object]] | None:
    """Attempt to parse *text* as a JSON object with a ``rankings`` key."""
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    rankings = obj.get("rankings")
    if not isinstance(rankings, list):
        return None
    # Validate each ranking entry has required keys
    validated: list[dict[str, object]] = []
    for item in rankings:
        if not isinstance(item, dict):
            continue
        if "candidate_id" not in item or "priority" not in item:
            continue
        validated.append(cast(dict[str, object], item))
    return validated if validated else None


def _build_repair_prompt(raw_output: str) -> str:
    return textwrap.dedent(
        f"""\
        Convert the following model output into a valid JSON object with this exact schema:
        {{
          "rankings": [
            {{
              "candidate_id": "<id>",
              "priority": "critical"|"high"|"medium"|"low",
              "rationale": "<brief explanation>",
              "chain_potential": ["<other_candidate_id>", ...]
            }}
          ]
        }}

        Rules:
        - Return JSON only.
        - Preserve the original meaning; do not invent new candidates.
        - Use an empty list for chain_potential when absent.
        - If a required field is missing, omit that ranking entry instead of guessing.

        Model output to repair:
        {raw_output}
        """
    )


def _parse_or_repair_rankings(
    *,
    driver: LLMDriver,
    ctx: StageContext,
    raw_stdout: str,
    primary_tier: ModelTier,
    trace_refs: list[str],
) -> tuple[list[dict[str, object]] | None, bool]:
    rankings = _parse_triage_response(raw_stdout)
    if rankings is not None:
        return rankings, False

    repair_prompt = _build_repair_prompt(raw_stdout)
    repair_result = driver.execute(
        prompt=repair_prompt,
        run_dir=ctx.run_dir,
        timeout_s=_TRIAGE_TIMEOUT_S,
        max_attempts=1,
        retryable_tokens=_RETRYABLE_TOKENS,
        model_tier="haiku" if primary_tier != "opus" else "sonnet",
    )
    trace_refs.append(
        write_llm_trace(
            run_dir=ctx.run_dir,
            stage_name="llm_triage",
            purpose="repair",
            prompt=repair_prompt,
            model_tier="haiku" if primary_tier != "opus" else "sonnet",
            result=repair_result,
            metadata={"repair_for": "rankings"},
        )
    )
    if repair_result.status != "ok":
        return None, False
    repaired = _parse_triage_response(repair_result.stdout)
    return repaired, repaired is not None


@dataclass(frozen=True)
class LLMTriageStage:
    """Re-prioritises findings via LLM triage."""

    no_llm: bool = False

    @property
    def name(self) -> str:
        return "llm_triage"

    def run(self, ctx: StageContext) -> StageOutcome:
        stage_dir = ctx.run_dir / "stages" / "llm_triage"
        stage_dir.mkdir(parents=True, exist_ok=True)

        # --no-llm: skip gracefully
        if self.no_llm:
            _write_artifact(stage_dir, {
                "schema_version": _TRIAGE_SCHEMA_VERSION,
                "status": "skipped",
                "reason": "no_llm_mode",
                "rankings": [],
            })
            return StageOutcome(
                status="skipped",
                details=cast(dict[str, JsonValue], {"reason": "no_llm_mode"}),
                limitations=["no_llm_mode"],
            )

        # Load exploit candidates from findings stage
        candidates_path = ctx.run_dir / "stages" / "findings" / "exploit_candidates.json"
        candidates_data = _load_json_file(candidates_path)
        if not isinstance(candidates_data, dict):
            _write_artifact(stage_dir, {
                "schema_version": _TRIAGE_SCHEMA_VERSION,
                "status": "partial",
                "reason": "missing_exploit_candidates",
                "rankings": [],
            })
            return StageOutcome(
                status="partial",
                details=cast(dict[str, JsonValue], {"reason": "missing_exploit_candidates"}),
                limitations=["missing_exploit_candidates"],
            )

        candidates_list_any = cast(dict[str, object], candidates_data).get("candidates")
        if not isinstance(candidates_list_any, list) or not candidates_list_any:
            # Fallback: build candidates from findings.json
            findings_path = ctx.run_dir / "stages" / "findings" / "findings.json"
            findings_data = _load_json_file(findings_path)
            fallback_candidates: list[dict[str, object]] = []
            if isinstance(findings_data, list):
                for f in cast(list[object], findings_data):
                    if isinstance(f, dict):
                        fd = cast(dict[str, object], f)
                        conf = fd.get("confidence", 0)
                        if isinstance(conf, (int, float)) and float(conf) >= 0.3:
                            fallback_candidates.append(fd)
            elif isinstance(findings_data, dict):
                items = findings_data.get("findings", [])
                if isinstance(items, list):
                    for f in cast(list[object], items):
                        if isinstance(f, dict):
                            fd = cast(dict[str, object], f)
                            conf = fd.get("confidence", 0)
                            if isinstance(conf, (int, float)) and float(conf) >= 0.3:
                                fallback_candidates.append(fd)

            if not fallback_candidates:
                _write_artifact(stage_dir, {
                    "schema_version": _TRIAGE_SCHEMA_VERSION,
                    "status": "partial",
                    "reason": "no_candidates",
                    "rankings": [],
                })
                return StageOutcome(
                    status="partial",
                    details=cast(dict[str, JsonValue], {"reason": "no_candidates"}),
                    limitations=["no_candidates"],
                )
            candidates_list_any = fallback_candidates

        candidates = cast(list[dict[str, object]], candidates_list_any)

        # Load optional hardening summary
        binary_analysis_path = ctx.run_dir / "stages" / "inventory" / "binary_analysis.json"
        binary_data = _load_json_file(binary_analysis_path)
        hardening_summary: dict[str, object] | None = None
        if isinstance(binary_data, dict):
            hs = cast(dict[str, object], binary_data).get("hardening_summary")
            if isinstance(hs, dict):
                hardening_summary = cast(dict[str, object], hs)

        # Load optional attack surface summary
        attack_surface_path = ctx.run_dir / "stages" / "attack_surface" / "attack_surface.json"
        attack_surface_data = _load_json_file(attack_surface_path)
        attack_surface_summary: dict[str, object] | None = None
        if isinstance(attack_surface_data, dict):
            summary_any = cast(dict[str, object], attack_surface_data).get("summary")
            if isinstance(summary_any, dict):
                attack_surface_summary = cast(dict[str, object], summary_any)

        # Determine if any candidates are chain-backed
        has_chains = any(
            bool(c.get("chain_id"))
            for c in candidates
            if isinstance(c, dict)
        )
        tier = _select_model_tier(len(candidates), has_chains)

        # Build prompt
        prompt = _build_triage_prompt(candidates, hardening_summary, attack_surface_summary)

        # Execute LLM
        driver = resolve_driver()
        if not driver.available():
            _write_artifact(stage_dir, {
                "schema_version": _TRIAGE_SCHEMA_VERSION,
                "status": "partial",
                "reason": "llm_driver_unavailable",
                "rankings": [],
            })
            return StageOutcome(
                status="partial",
                details=cast(dict[str, JsonValue], {"reason": "llm_driver_unavailable"}),
                limitations=["llm_driver_unavailable"],
            )

        timeout_s = float(
            os.environ.get("AIEDGE_LLM_TRIAGE_TIMEOUT_S", str(_TRIAGE_TIMEOUT_S))
        )
        max_attempts = int(
            os.environ.get("AIEDGE_LLM_TRIAGE_MAX_ATTEMPTS", str(_TRIAGE_MAX_ATTEMPTS))
        )

        tiers_to_try: list[ModelTier] = [tier]
        if tier == "haiku":
            tiers_to_try.append("sonnet")

        trace_refs: list[str] = []
        attempted_tiers: list[str] = []
        rankings: list[dict[str, object]] | None = None
        repair_used = False
        selected_tier = tier
        last_result: LLMDriverResult | None = None

        for attempt_tier in tiers_to_try:
            attempted_tiers.append(attempt_tier)
            result = driver.execute(
                prompt=prompt,
                run_dir=ctx.run_dir,
                timeout_s=timeout_s,
                max_attempts=max(1, min(max_attempts, 8)),
                retryable_tokens=_RETRYABLE_TOKENS,
                model_tier=attempt_tier,
            )
            last_result = result
            trace_refs.append(
                write_llm_trace(
                    run_dir=ctx.run_dir,
                    stage_name=self.name,
                    purpose=f"rankings-{attempt_tier}",
                    prompt=prompt,
                    model_tier=attempt_tier,
                    result=result,
                    metadata={
                        "candidate_count": len(candidates),
                        "has_chains": has_chains,
                    },
                )
            )

            if result.status != "ok":
                continue

            parsed_rankings, repaired = _parse_or_repair_rankings(
                driver=driver,
                ctx=ctx,
                raw_stdout=result.stdout,
                primary_tier=attempt_tier,
                trace_refs=trace_refs,
            )
            if parsed_rankings is None:
                continue
            rankings = parsed_rankings
            repair_used = repaired
            selected_tier = attempt_tier
            break

        if rankings is None:
            if last_result is not None and last_result.status != "ok":
                reason = f"llm_{last_result.status}"
                limitations = [reason]
                llm_returncode = last_result.returncode
            else:
                reason = "unparseable_response"
                limitations = ["unparseable_llm_response"]
                llm_returncode = last_result.returncode if last_result is not None else -1
            _write_artifact(
                stage_dir,
                {
                    "schema_version": _TRIAGE_SCHEMA_VERSION,
                    "status": "partial",
                    "reason": reason,
                    "model_tier": tier,
                    "attempted_tiers": attempted_tiers,
                    "llm_returncode": llm_returncode,
                    "trace_refs": cast(list[object], trace_refs),
                    "rankings": [],
                },
            )
            return StageOutcome(
                status="partial",
                details=cast(
                    dict[str, JsonValue],
                    {
                        "reason": reason,
                        "model_tier": tier,
                    },
                ),
                limitations=limitations,
            )

        # Success
        artifact = {
            "schema_version": _TRIAGE_SCHEMA_VERSION,
            "status": "ok",
            "model_tier": selected_tier,
            "candidate_count": len(candidates),
            "ranking_count": len(rankings),
            "attempted_tiers": attempted_tiers,
            "repair_used": repair_used,
            "trace_refs": cast(list[object], trace_refs),
            "rankings": cast(list[object], rankings),
        }
        _write_artifact(stage_dir, artifact)

        return StageOutcome(
            status="ok",
            details=cast(dict[str, JsonValue], {
                "model_tier": selected_tier,
                "candidate_count": len(candidates),
                "ranking_count": len(rankings),
                "triage_path": "stages/llm_triage/triage.json",
            }),
        )


def _write_artifact(stage_dir: Path, payload: dict[str, object]) -> None:
    """Write triage.json to *stage_dir*."""
    out_path = stage_dir / "triage.json"
    _ = out_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
