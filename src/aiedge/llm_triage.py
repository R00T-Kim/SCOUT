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

from .llm_driver import ModelTier, resolve_driver
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
    if candidate_count > 10:
        return "sonnet"
    return "haiku"


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

    Tries code-fenced JSON first, then raw JSON.
    Returns *None* on parse failure.
    """
    text = stdout.strip()
    if not text:
        return None

    # Try code-fenced JSON
    fences = re.findall(
        r"```(?:json)?\s*\n(.*?)```",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    for fence in fences:
        parsed = _try_parse_rankings(fence)
        if parsed is not None:
            return parsed

    # Try raw JSON
    return _try_parse_rankings(text)


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

        timeout_s = float(os.environ.get("AIEDGE_LLM_TRIAGE_TIMEOUT_S", str(_TRIAGE_TIMEOUT_S)))
        max_attempts = int(os.environ.get("AIEDGE_LLM_TRIAGE_MAX_ATTEMPTS", str(_TRIAGE_MAX_ATTEMPTS)))

        result = driver.execute(
            prompt=prompt,
            run_dir=ctx.run_dir,
            timeout_s=timeout_s,
            max_attempts=max(1, min(max_attempts, 8)),
            retryable_tokens=_RETRYABLE_TOKENS,
            model_tier=tier,
        )

        if result.status != "ok":
            _write_artifact(stage_dir, {
                "schema_version": _TRIAGE_SCHEMA_VERSION,
                "status": "partial",
                "reason": f"llm_{result.status}",
                "model_tier": tier,
                "llm_returncode": result.returncode,
                "rankings": [],
            })
            return StageOutcome(
                status="partial",
                details=cast(dict[str, JsonValue], {
                    "reason": f"llm_{result.status}",
                    "model_tier": tier,
                }),
                limitations=[f"llm_{result.status}"],
            )

        # Parse response
        rankings = _parse_triage_response(result.stdout)
        if rankings is None:
            _write_artifact(stage_dir, {
                "schema_version": _TRIAGE_SCHEMA_VERSION,
                "status": "partial",
                "reason": "unparseable_response",
                "model_tier": tier,
                "raw_stdout_len": len(result.stdout),
                "rankings": [],
            })
            return StageOutcome(
                status="partial",
                details=cast(dict[str, JsonValue], {
                    "reason": "unparseable_response",
                    "model_tier": tier,
                }),
                limitations=["unparseable_llm_response"],
            )

        # Success
        artifact = {
            "schema_version": _TRIAGE_SCHEMA_VERSION,
            "status": "ok",
            "model_tier": tier,
            "candidate_count": len(candidates),
            "ranking_count": len(rankings),
            "rankings": cast(list[object], rankings),
        }
        _write_artifact(stage_dir, artifact)

        return StageOutcome(
            status="ok",
            details=cast(dict[str, JsonValue], {
                "model_tier": tier,
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
