from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .policy import AIEdgePolicyViolation
from .exploit_tiering import default_exploitability_tier
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus

_LLM_CHAIN_PROMPT_TEMPLATE_VERSION = "aiedge-llm-chain-builder-v1"
_LLM_CHAIN_TIMEOUT_S = 120.0
_LLM_CHAIN_MAX_INPUT_CANDIDATES = 12
_LLM_CHAIN_MAX_OUTPUT_CHAINS = 24
_LLM_CHAIN_RETRY_MAX_ATTEMPTS = 4
_LLM_CHAIN_RETRYABLE_STDERR_TOKENS: tuple[str, ...] = (
    "stream disconnected before completion",
    "error sending request",
    "connection reset by peer",
    "connection refused",
    "timed out",
    "timeout",
    "temporary failure",
    "503",
    "502",
    "429",
)


def _assert_under_dir(base_dir: Path, target: Path) -> None:
    base = base_dir.resolve()
    resolved = target.resolve()
    if not resolved.is_relative_to(base):
        raise AIEdgePolicyViolation(
            f"Refusing to write outside run dir: target={resolved} base={base}"
        )


def _rel_to_run_dir(run_dir: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(run_dir.resolve()))
    except Exception:
        return str(path)


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


def _sorted_unique_refs(refs: list[str], *, run_dir: Path) -> list[str]:
    out = {
        x.replace("\\", "/")
        for x in refs
        if _is_run_relative_path(x) and (run_dir / x).exists()
    }
    return sorted(out)


def _to_json_scalar(value: object) -> JsonValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return cast(JsonValue, value)
    return cast(JsonValue, str(value))


def _value_sort_key(value: JsonValue) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True)


def _safe_float01(value: object, default: float = 0.6) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        out = float(value)
    elif isinstance(value, str):
        try:
            out = float(value)
        except ValueError:
            return default
    else:
        return default
    if out < 0.0:
        return 0.0
    if out > 1.0:
        return 1.0
    return out


def _env_float(name: str, *, default: float, min_value: float, max_value: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except Exception:
        return default
    if value < min_value:
        return min_value
    if value > max_value:
        return max_value
    return value


def _env_int(name: str, *, default: int, min_value: int, max_value: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except Exception:
        return default
    if value < min_value:
        return min_value
    if value > max_value:
        return max_value
    return value


def _truncate_text(text: str, *, max_chars: int = 12000) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def _read_manifest_profile(run_dir: Path) -> str:
    manifest_obj = _load_json_object(run_dir / "manifest.json")
    if manifest_obj is None:
        return "analysis"
    profile_any = manifest_obj.get("profile")
    if isinstance(profile_any, str) and profile_any:
        return profile_any
    return "analysis"


def _safe_string_list(value: object, *, max_items: int = 8) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item_any in cast(list[object], value):
        if not isinstance(item_any, str):
            continue
        item = " ".join(item_any.split()).strip()
        if not item:
            continue
        out.append(item)
        if len(out) >= max_items:
            break
    return out


def _extract_json_payload(text: str) -> dict[str, object] | None:
    stripped = text.strip()
    if not stripped:
        return None
    candidates: list[str] = [stripped]
    fence_matches = re.findall(
        r"```(?:json)?\s*\n(.*?)```", stripped, flags=re.IGNORECASE | re.DOTALL
    )
    candidates.extend([m.strip() for m in fence_matches if m.strip()])
    obj_match = re.search(r"\{[\s\S]*\}", stripped)
    if obj_match is not None:
        obj_candidate = obj_match.group(0).strip()
        if obj_candidate:
            candidates.append(obj_candidate)
    for candidate in candidates:
        try:
            obj_any = cast(object, json.loads(candidate))
        except Exception:
            continue
        if isinstance(obj_any, dict):
            return cast(dict[str, object], obj_any)
    return None


def _run_codex_chain_builder_exec(
    *,
    run_dir: Path,
    prompt: str,
    timeout_s: float,
) -> dict[str, object]:
    if not shutil.which("codex"):
        return {
            "status": "missing_cli",
            "stdout": "",
            "stderr": "codex executable not found",
            "argv": [],
            "attempts": [],
            "returncode": -1,
        }

    timeout = _env_float(
        "AIEDGE_LLM_CHAIN_TIMEOUT_S",
        default=max(1.0, min(float(timeout_s), 180.0)),
        min_value=10.0,
        max_value=300.0,
    )
    base_argv = [
        "codex",
        "exec",
        "--ephemeral",
        "-s",
        "read-only",
        "-C",
        str(run_dir),
    ]
    argv = base_argv + [prompt]
    attempts: list[dict[str, object]] = []

    def _exec_once(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        cp = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        attempts.append(
            {
                "argv": list(cmd),
                "returncode": int(cp.returncode),
                "stdout": _truncate_text(cp.stdout or ""),
                "stderr": _truncate_text(cp.stderr or ""),
            }
        )
        return cp

    max_attempts = _env_int(
        "AIEDGE_LLM_CHAIN_MAX_ATTEMPTS",
        default=max(1, int(_LLM_CHAIN_RETRY_MAX_ATTEMPTS)),
        min_value=1,
        max_value=8,
    )
    cp: subprocess.CompletedProcess[str] | None = None
    use_skip_git_repo_check = False
    retryable_error_detected = False
    timeout_seen = False

    for attempt_idx in range(max_attempts):
        cmd = (
            base_argv + ["--skip-git-repo-check", prompt]
            if use_skip_git_repo_check
            else list(argv)
        )
        try:
            cp = _exec_once(cmd)
        except subprocess.TimeoutExpired as exc:
            timeout_seen = True
            attempts.append(
                {
                    "argv": list(cmd),
                    "returncode": -1,
                    "stdout": _truncate_text(
                        (exc.stdout if isinstance(exc.stdout, str) else "") or ""
                    ),
                    "stderr": _truncate_text(
                        (exc.stderr if isinstance(exc.stderr, str) else "") or ""
                    ),
                    "exception": "TimeoutExpired",
                }
            )
            if attempt_idx + 1 < max_attempts:
                continue
            return {
                "status": "timeout",
                "stdout": _truncate_text(
                    (exc.stdout if isinstance(exc.stdout, str) else "") or ""
                ),
                "stderr": _truncate_text(
                    (exc.stderr if isinstance(exc.stderr, str) else "") or ""
                ),
                "argv": list(cmd),
                "attempts": attempts,
                "returncode": -1,
            }
        except Exception as exc:
            return {
                "status": "error",
                "stdout": "",
                "stderr": f"{type(exc).__name__}: {exc}",
                "argv": list(cmd),
                "attempts": attempts,
                "returncode": -1,
            }

        stderr_lc = (cp.stderr or "").lower()
        if cp.returncode == 0:
            break

        if "skip-git-repo-check" in stderr_lc and not use_skip_git_repo_check:
            use_skip_git_repo_check = True
            continue

        retryable_error_detected = any(
            token in stderr_lc for token in _LLM_CHAIN_RETRYABLE_STDERR_TOKENS
        )
        if retryable_error_detected:
            continue

        break

    if cp is None:
        return {
            "status": "error",
            "stdout": "",
            "stderr": "codex chain-builder execution did not produce a process result",
            "argv": list(argv),
            "attempts": attempts,
            "returncode": -1,
        }

    status = "ok" if cp.returncode == 0 else "nonzero_exit"
    return {
        "status": status,
        "stdout": _truncate_text(cp.stdout or ""),
        "stderr": _truncate_text(cp.stderr or ""),
        "argv": list(attempts[-1]["argv"]) if attempts else list(argv),
        "attempts": attempts,
        "returncode": int(cp.returncode),
        "retryable_error_detected": bool(retryable_error_detected),
        "timeout_seen": bool(timeout_seen),
    }


def _load_chain_input_threat_fallback_candidates(
    run_dir: Path,
) -> list[dict[str, object]]:
    path = run_dir / "stages" / "threat_model" / "threat_model.json"
    obj = _load_json_object(path)
    if obj is None:
        return []
    threats_any = obj.get("threats")
    if not isinstance(threats_any, list):
        return []

    out: list[dict[str, object]] = []
    for idx, threat_any in enumerate(cast(list[object], threats_any), start=1):
        if not isinstance(threat_any, dict):
            continue
        threat = cast(dict[str, object], threat_any)
        refs = _safe_string_list(threat.get("evidence_refs"), max_items=6)
        if not refs:
            continue

        threat_id = str(threat.get("threat_id", "")).strip() or f"tm-{idx:04d}"
        category = str(threat.get("category", "")).strip().lower()
        title = " ".join(str(threat.get("title", "")).split()).strip()
        description = " ".join(str(threat.get("description", "")).split()).strip()
        hypothesis = description or title or "Threat-model derived abuse path hypothesis."
        family = f"threat_model_{category}" if category else "threat_model_signal"
        summary = title or (
            hypothesis[:120] if len(hypothesis) <= 120 else hypothesis[:117] + "..."
        )
        chain_token = re.sub(r"[^A-Za-z0-9._:-]", "_", threat_id)
        candidate_id = "candidate:threat-fallback:" + chain_token
        chain_id = "llm_threat_chain:" + chain_token

        out.append(
            {
                "candidate_id": candidate_id,
                "chain_id": chain_id,
                "score": 0.52,
                "priority": "medium",
                "families": [family],
                "path": "",
                "summary": summary,
                "attack_hypothesis": hypothesis,
                "expected_impact": [
                    "Potential compromise path inferred from threat-model context."
                ],
                "validation_plan": [
                    "Map endpoint/service ownership and trust boundary crossing.",
                    "Confirm attacker-controlled input path to relevant sink.",
                ],
                "evidence_refs": refs,
                "source": "threat_model_fallback",
            }
        )
        if len(out) >= int(_LLM_CHAIN_MAX_INPUT_CANDIDATES):
            break

    return out


def _load_chain_input_candidates(run_dir: Path) -> list[dict[str, object]]:
    path = run_dir / "stages" / "findings" / "exploit_candidates.json"
    obj = _load_json_object(path)
    out: list[dict[str, object]] = []
    if obj is not None:
        candidates_any = obj.get("candidates")
        if isinstance(candidates_any, list):
            for item_any in cast(list[object], candidates_any):
                if not isinstance(item_any, dict):
                    continue
                item = cast(dict[str, object], item_any)
                score = _safe_float01(item.get("score"), default=0.0)
                if score < 0.45:
                    continue
                out.append(item)

    if not out:
        out = _load_chain_input_threat_fallback_candidates(run_dir)

    out = sorted(
        out,
        key=lambda c: (
            -_safe_float01(c.get("score"), default=0.0),
            str(c.get("candidate_id", "")),
        ),
    )
    return out[: int(_LLM_CHAIN_MAX_INPUT_CANDIDATES)]


def _build_chain_prompt_payload(
    *,
    source_data: dict[str, dict[str, object]],
    source_rel_paths: dict[str, str],
    chain_candidates: list[dict[str, object]],
) -> dict[str, JsonValue]:
    simple_candidates: list[JsonValue] = []
    for item in chain_candidates:
        refs_any = item.get("evidence_refs")
        refs = _safe_string_list(refs_any, max_items=6)
        simple_candidates.append(
            {
                "candidate_id": str(item.get("candidate_id", "")),
                "chain_id": str(item.get("chain_id", "")),
                "score": _safe_float01(item.get("score"), default=0.0),
                "priority": str(item.get("priority", "")),
                "families": _safe_string_list(item.get("families"), max_items=6),
                "path": str(item.get("path", "")),
                "summary": str(item.get("summary", "")),
                "attack_hypothesis": str(item.get("attack_hypothesis", "")),
                "expected_impact": _safe_string_list(item.get("expected_impact"), max_items=4),
                "validation_plan": _safe_string_list(item.get("validation_plan"), max_items=4),
                "evidence_refs": cast(list[JsonValue], cast(list[object], refs)),
            }
        )

    attack_surface_summary_any = source_data.get("attack_surface", {}).get("summary")
    attack_surface_summary = (
        cast(dict[str, object], attack_surface_summary_any)
        if isinstance(attack_surface_summary_any, dict)
        else {}
    )
    threat_summary_any = source_data.get("threat_model", {}).get("summary")
    threat_summary = (
        cast(dict[str, object], threat_summary_any)
        if isinstance(threat_summary_any, dict)
        else {}
    )

    return {
        "prompt_template_version": _LLM_CHAIN_PROMPT_TEMPLATE_VERSION,
        "sources": cast(JsonValue, source_rel_paths),
        "attack_surface_summary": cast(JsonValue, attack_surface_summary),
        "threat_model_summary": cast(JsonValue, threat_summary),
        "exploit_candidates": cast(list[JsonValue], cast(list[object], simple_candidates)),
    }


def _build_chain_prompt(payload: dict[str, JsonValue]) -> str:
    payload_json = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)
    return (
        "You are a firmware exploit-chain analyst.\n"
        "From the sanitized inputs, propose realistic exploit-chain claims.\n"
        "Output JSON only with this schema:\n"
        "{ \"chains\": [ {\"chain_id\": string, \"hypothesis\": string, "
        "\"preconditions\": [string], \"attack_steps\": [string], "
        "\"impact\": string, \"confidence\": number(0..1), "
        "\"evidence_refs\": [run_relative_path_string] } ] }\n"
        "Rules:\n"
        "- Use only provided evidence refs.\n"
        "- Do not fabricate files or endpoints.\n"
        f"- Return at most {_LLM_CHAIN_MAX_OUTPUT_CHAINS} chains.\n\n"
        "sanitized_input_json:\n"
        f"{payload_json}\n"
    )


def _normalize_llm_chain_candidates(
    *,
    run_dir: Path,
    payload: dict[str, object] | None,
    fallback_refs: list[str],
) -> tuple[list[dict[str, JsonValue]], list[str]]:
    if payload is None:
        return [], ["llm_chain_builder_output_invalid_json"]

    chains_any = payload.get("chains")
    if not isinstance(chains_any, list):
        return [], ["llm_chain_builder_output_missing_chains"]

    normalized: list[dict[str, JsonValue]] = []
    limits: list[str] = []
    for idx, chain_any in enumerate(cast(list[object], chains_any), start=1):
        if not isinstance(chain_any, dict):
            continue
        chain = cast(dict[str, object], chain_any)
        chain_id_raw = str(chain.get("chain_id", "")).strip() or f"llm-chain-{idx}"
        chain_id = re.sub(r"[^A-Za-z0-9._:-]", "_", chain_id_raw)[:120]
        hypothesis = " ".join(str(chain.get("hypothesis", "")).split()).strip()
        if not hypothesis:
            limits.append(f"llm_chain_missing_hypothesis:{chain_id}")
            continue
        preconditions = _safe_string_list(chain.get("preconditions"), max_items=8)
        attack_steps = _safe_string_list(chain.get("attack_steps"), max_items=8)
        impact = " ".join(str(chain.get("impact", "")).split()).strip()
        confidence = _safe_float01(chain.get("confidence"), default=0.65)
        refs_any = chain.get("evidence_refs")
        refs = _safe_string_list(refs_any, max_items=12)
        refs_norm = _sorted_unique_refs(
            refs if refs else list(fallback_refs),
            run_dir=run_dir,
        )
        if not refs_norm:
            limits.append(f"llm_chain_missing_refs:{chain_id}")
            continue
        normalized.append(
            {
                "chain_id": chain_id,
                "hypothesis": hypothesis,
                "preconditions": cast(list[JsonValue], cast(list[object], preconditions)),
                "attack_steps": cast(list[JsonValue], cast(list[object], attack_steps)),
                "impact": impact,
                "confidence": float(confidence),
                "evidence_refs": cast(list[JsonValue], cast(list[object], refs_norm)),
            }
        )

    normalized = sorted(
        normalized,
        key=lambda c: (
            -_safe_float01(c.get("confidence"), default=0.0),
            str(c.get("chain_id", "")),
        ),
    )
    if len(normalized) > int(_LLM_CHAIN_MAX_OUTPUT_CHAINS):
        limits.append(
            f"llm_chain_builder_output_capped:{_LLM_CHAIN_MAX_OUTPUT_CHAINS}"
        )
        normalized = normalized[: int(_LLM_CHAIN_MAX_OUTPUT_CHAINS)]

    return normalized, sorted(set(limits))


@dataclass(frozen=True)
class LLMSynthesisStage:
    no_llm: bool = False
    max_claims: int = 120

    @property
    def name(self) -> str:
        return "llm_synthesis"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "llm_synthesis"
        out_json = stage_dir / "llm_synthesis.json"

        _assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(stage_dir, out_json)

        if self.no_llm:
            skipped_payload: dict[str, JsonValue] = {
                "status": "skipped",
                "summary": {
                    "input_artifacts": 0,
                    "candidate_claims": 0,
                    "claims_emitted": 0,
                    "claims_dropped": 0,
                    "max_claims": int(self.max_claims),
                    "bounded_output": True,
                },
                "claims": [],
                "limitations": ["LLM synthesis skipped: disabled by --no-llm"],
                "reason": "disabled by --no-llm",
                "note": "Deterministic skip artifact emitted for no-llm mode.",
            }
            _ = out_json.write_text(
                json.dumps(skipped_payload, indent=2, sort_keys=True, ensure_ascii=True)
                + "\n",
                encoding="utf-8",
            )
            return StageOutcome(
                status="skipped",
                details={
                    "summary": cast(dict[str, JsonValue], skipped_payload["summary"]),
                    "claims": cast(list[JsonValue], skipped_payload["claims"]),
                    "llm_synthesis_json": _rel_to_run_dir(run_dir, out_json),
                    "evidence": cast(
                        list[JsonValue],
                        cast(
                            list[object], [{"path": _rel_to_run_dir(run_dir, out_json)}]
                        ),
                    ),
                    "reason": "disabled by --no-llm",
                },
                limitations=["LLM synthesis skipped: disabled by --no-llm"],
            )

        source_paths: dict[str, Path] = {
            "attribution": run_dir / "stages" / "attribution" / "attribution.json",
            "surfaces": run_dir / "stages" / "surfaces" / "surfaces.json",
            "endpoints": run_dir / "stages" / "endpoints" / "endpoints.json",
            "graph": run_dir / "stages" / "graph" / "comm_graph.json",
            "attack_surface": run_dir
            / "stages"
            / "attack_surface"
            / "attack_surface.json",
            "threat_model": run_dir / "stages" / "threat_model" / "threat_model.json",
            "functional_spec": run_dir
            / "stages"
            / "functional_spec"
            / "functional_spec.json",
        }

        source_rel_paths: dict[str, str] = {}
        source_data: dict[str, dict[str, object]] = {}
        limitations: list[str] = []

        for stage_name, stage_path in source_paths.items():
            rel = _rel_to_run_dir(run_dir, stage_path)
            source_rel_paths[stage_name] = rel
            obj = _load_json_object(stage_path)
            if obj is None:
                limitations.append(f"Missing or invalid source artifact: {rel}")
                continue
            source_data[stage_name] = obj

        claims: list[dict[str, JsonValue]] = []
        candidate_claims = 0
        dropped_claims = 0
        llm_chain_attempted = False
        llm_chain_status = "skipped"
        llm_chain_raw = 0
        llm_chain_added = 0
        llm_chain_limits: list[str] = []
        llm_chain_meta_rel = ""
        llm_chain_prompt_rel = ""
        llm_chain_raw_rel = ""
        llm_chain_evidence_paths: list[str] = []

        def add_claim(
            *,
            claim_type: str,
            value: JsonValue,
            confidence: float,
            refs: list[str],
            alternatives: list[str] | None = None,
            unknowns: list[str] | None = None,
        ) -> None:
            nonlocal candidate_claims, dropped_claims
            candidate_claims += 1

            norm_refs = _sorted_unique_refs(refs, run_dir=run_dir)
            if not norm_refs:
                dropped_claims += 1
                limitations.append(
                    f"Dropped uncited claim '{claim_type}' due to empty/non-existent evidence_refs"
                )
                return

            claim: dict[str, JsonValue] = {
                "claim_type": claim_type,
                "value": value,
                "confidence": _safe_float01(confidence),
                "exploitability_tier": default_exploitability_tier(
                    disposition="confirmed"
                ),
                "evidence_refs": cast(list[JsonValue], cast(list[object], norm_refs)),
            }
            if alternatives:
                alt_sorted = sorted({x for x in alternatives if x})
                if alt_sorted:
                    claim["alternatives_considered"] = cast(
                        list[JsonValue], cast(list[object], alt_sorted)
                    )
            if unknowns:
                unknowns_sorted = sorted({x for x in unknowns if x})
                if unknowns_sorted:
                    claim["unknowns"] = cast(
                        list[JsonValue], cast(list[object], unknowns_sorted)
                    )
            claims.append(claim)

        manifest_profile = _read_manifest_profile(run_dir)
        if manifest_profile == "exploit" and not self.no_llm:
            llm_chain_attempted = True
            llm_chain_status = "running"
            llm_dir = stage_dir / "llm_chain_builder"
            llm_dir.mkdir(parents=True, exist_ok=True)

            chain_candidates = _load_chain_input_candidates(run_dir)
            if chain_candidates:
                chain_payload = _build_chain_prompt_payload(
                    source_data=source_data,
                    source_rel_paths=source_rel_paths,
                    chain_candidates=chain_candidates,
                )
                chain_prompt = _build_chain_prompt(chain_payload)
                prompt_path = llm_dir / "chain_builder.prompt.txt"
                raw_path = llm_dir / "chain_builder.raw.txt"
                meta_path = llm_dir / "chain_builder.meta.json"
                _ = prompt_path.write_text(chain_prompt, encoding="utf-8")

                exec_result = _run_codex_chain_builder_exec(
                    run_dir=run_dir,
                    prompt=chain_prompt,
                    timeout_s=float(_LLM_CHAIN_TIMEOUT_S),
                )
                llm_chain_status = str(exec_result.get("status", "error"))
                stdout_s = str(exec_result.get("stdout", ""))
                stderr_s = str(exec_result.get("stderr", ""))
                _ = raw_path.write_text(
                    "\n".join(
                        [
                            "### stdout",
                            stdout_s,
                            "",
                            "### stderr",
                            stderr_s,
                            "",
                        ]
                    ),
                    encoding="utf-8",
                )

                parsed_payload = _extract_json_payload(stdout_s)
                if parsed_payload is None:
                    parsed_payload = _extract_json_payload(stderr_s)
                fallback_refs = [x for x in source_rel_paths.values() if x]
                llm_chains, llm_norm_limits = _normalize_llm_chain_candidates(
                    run_dir=run_dir,
                    payload=parsed_payload,
                    fallback_refs=fallback_refs,
                )
                llm_chain_raw = len(
                    cast(list[object], parsed_payload.get("chains", []))
                ) if isinstance(parsed_payload, dict) and isinstance(parsed_payload.get("chains"), list) else 0
                llm_chain_limits.extend(llm_norm_limits)

                for chain in llm_chains:
                    chain_id = str(chain.get("chain_id", "llm-chain"))
                    chain_refs_any = chain.get("evidence_refs")
                    chain_refs = (
                        [x for x in cast(list[object], chain_refs_any) if isinstance(x, str)]
                        if isinstance(chain_refs_any, list)
                        else []
                    )
                    chain_value: dict[str, JsonValue] = {
                        "chain_id": chain_id,
                        "hypothesis": cast(JsonValue, str(chain.get("hypothesis", ""))),
                        "preconditions": cast(
                            list[JsonValue],
                            cast(
                                list[object],
                                list(cast(list[object], chain.get("preconditions", []))),
                            ),
                        )
                        if isinstance(chain.get("preconditions"), list)
                        else cast(list[JsonValue], cast(list[object], [])),
                        "attack_steps": cast(
                            list[JsonValue],
                            cast(
                                list[object],
                                list(cast(list[object], chain.get("attack_steps", []))),
                            ),
                        )
                        if isinstance(chain.get("attack_steps"), list)
                        else cast(list[JsonValue], cast(list[object], [])),
                        "impact": cast(JsonValue, str(chain.get("impact", ""))),
                        "source": "llm_chain_builder",
                    }
                    add_claim(
                        claim_type=f"llm_chain.{chain_id}",
                        value=cast(JsonValue, chain_value),
                        confidence=_safe_float01(chain.get("confidence"), default=0.7),
                        refs=chain_refs,
                    )
                    llm_chain_added += 1

                meta_obj: dict[str, JsonValue] = {
                    "status": llm_chain_status,
                    "prompt_template_version": _LLM_CHAIN_PROMPT_TEMPLATE_VERSION,
                    "candidate_inputs": len(chain_candidates),
                    "raw_chain_count": int(llm_chain_raw),
                    "normalized_chain_count": int(llm_chain_added),
                    "returncode": cast(JsonValue, exec_result.get("returncode", -1))
                    if isinstance(exec_result.get("returncode"), int)
                    else -1,
                    "argv": cast(
                        list[JsonValue],
                        cast(list[object], list(cast(list[object], exec_result.get("argv", [])))),
                    )
                    if isinstance(exec_result.get("argv"), list)
                    else cast(list[JsonValue], cast(list[object], [])),
                    "attempt_count": int(
                        len(cast(list[object], exec_result.get("attempts", [])))
                        if isinstance(exec_result.get("attempts"), list)
                        else 0
                    ),
                    "limitations": cast(
                        list[JsonValue],
                        cast(list[object], sorted(set(llm_chain_limits))),
                    ),
                    "prompt_path": _rel_to_run_dir(run_dir, prompt_path),
                    "raw_path": _rel_to_run_dir(run_dir, raw_path),
                }
                _ = meta_path.write_text(
                    json.dumps(meta_obj, indent=2, sort_keys=True, ensure_ascii=True)
                    + "\n",
                    encoding="utf-8",
                )
                llm_chain_prompt_rel = _rel_to_run_dir(run_dir, prompt_path)
                llm_chain_raw_rel = _rel_to_run_dir(run_dir, raw_path)
                llm_chain_meta_rel = _rel_to_run_dir(run_dir, meta_path)
                llm_chain_evidence_paths.extend(
                    [llm_chain_prompt_rel, llm_chain_raw_rel, llm_chain_meta_rel]
                )

                if llm_chain_status != "ok":
                    if parsed_payload is None:
                        llm_chain_limits.append(
                            f"llm_chain_builder_exec_failed:{llm_chain_status}"
                        )
                    else:
                        llm_chain_limits.append(
                            f"llm_chain_builder_exec_nonzero_used_payload:{llm_chain_status}"
                        )
            else:
                llm_chain_status = "skipped_no_candidates"
        if llm_chain_limits:
            limitations.extend(sorted(set(llm_chain_limits)))

        for stage_name in sorted(source_paths.keys()):
            rel = source_rel_paths[stage_name]
            obj = source_data.get(stage_name)
            if obj is None:
                continue
            status_any = obj.get("status")
            stage_status = (
                status_any if isinstance(status_any, str) and status_any else "unknown"
            )
            add_claim(
                claim_type=f"stage_status.{stage_name}",
                value=stage_status,
                confidence=1.0,
                refs=[rel],
            )

            summary_any = obj.get("summary")
            if isinstance(summary_any, dict):
                summary_obj = cast(dict[str, object], summary_any)
                for field_name in sorted(summary_obj.keys()):
                    field_value = summary_obj.get(field_name)
                    if isinstance(field_value, bool):
                        scalar = cast(JsonValue, field_value)
                    elif (
                        isinstance(field_value, (int, float, str))
                        or field_value is None
                    ):
                        scalar = _to_json_scalar(field_value)
                    else:
                        continue
                    add_claim(
                        claim_type=f"summary.{stage_name}.{field_name}",
                        value=scalar,
                        confidence=0.9,
                        refs=[rel],
                    )

        attribution_obj = source_data.get("attribution")
        if attribution_obj is not None:
            claims_any = attribution_obj.get("claims")
            if isinstance(claims_any, list):
                for claim_any in cast(list[object], claims_any):
                    if not isinstance(claim_any, dict):
                        continue
                    claim_obj = cast(dict[str, object], claim_any)
                    claim_type_any = claim_obj.get("claim_type")
                    if not isinstance(claim_type_any, str) or not claim_type_any:
                        continue
                    value = _to_json_scalar(claim_obj.get("value"))
                    confidence = _safe_float01(claim_obj.get("confidence"), default=0.7)
                    refs_any = claim_obj.get("evidence_refs")
                    refs: list[str] = []
                    if isinstance(refs_any, list):
                        refs = [
                            cast(str, x)
                            for x in cast(list[object], refs_any)
                            if _is_run_relative_path(x)
                        ]
                    alternatives_any = claim_obj.get("alternatives_considered")
                    alternatives = (
                        [
                            x
                            for x in cast(list[object], alternatives_any)
                            if isinstance(x, str) and x
                        ]
                        if isinstance(alternatives_any, list)
                        else None
                    )
                    unknowns_any = claim_obj.get("unknowns")
                    unknowns = (
                        [
                            x
                            for x in cast(list[object], unknowns_any)
                            if isinstance(x, str) and x
                        ]
                        if isinstance(unknowns_any, list)
                        else None
                    )
                    add_claim(
                        claim_type=f"attribution.{claim_type_any}",
                        value=value,
                        confidence=confidence,
                        refs=refs,
                        alternatives=alternatives,
                        unknowns=unknowns,
                    )

        claims_sorted = sorted(
            claims,
            key=lambda c: (
                str(c.get("claim_type", "")),
                _value_sort_key(c.get("value")),
                ",".join(cast(list[str], c.get("evidence_refs", []))),
            ),
        )

        deduped: list[dict[str, JsonValue]] = []
        seen: set[tuple[str, str, str]] = set()
        for claim in claims_sorted:
            key = (
                str(claim.get("claim_type", "")),
                _value_sort_key(claim.get("value")),
                ",".join(cast(list[str], claim.get("evidence_refs", []))),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(claim)

        if len(deduped) > int(self.max_claims):
            limitations.append(
                f"LLM synthesis reached max_claims cap ({int(self.max_claims)}); additional claims were skipped"
            )
            deduped = deduped[: int(self.max_claims)]

        summary: dict[str, JsonValue] = {
            "input_artifacts": len(source_data),
            "candidate_claims": candidate_claims,
            "claims_emitted": len(deduped),
            "claims_dropped": dropped_claims,
            "llm_chain_attempted": bool(llm_chain_attempted),
            "llm_chain_status": llm_chain_status,
            "llm_chain_raw_chains": int(llm_chain_raw),
            "llm_chain_claims": int(llm_chain_added),
            "max_claims": int(self.max_claims),
            "bounded_output": True,
        }

        status: StageStatus = "ok"
        if limitations:
            status = "partial"
        if not deduped:
            status = "partial"
            limitations.append("No evidence-linked synthesis claims were produced")

        payload: dict[str, JsonValue] = {
            "status": status,
            "summary": summary,
            "claims": cast(list[JsonValue], cast(list[object], deduped)),
            "limitations": cast(
                list[JsonValue], cast(list[object], sorted(set(limitations)))
            ),
            "note": (
                "Grounded synthesis from prior stage artifacts with optional exploit-profile "
                "LLM chain-builder augmentation; uncited claims are dropped."
            ),
        }
        _ = out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        artifact_rel = _rel_to_run_dir(run_dir, out_json)
        evidence_paths = _sorted_unique_refs(
            [artifact_rel]
            + list(source_rel_paths.values())
            + llm_chain_evidence_paths,
            run_dir=run_dir,
        )
        details: dict[str, JsonValue] = {
            "summary": summary,
            "claims": cast(list[JsonValue], cast(list[object], deduped)),
            "llm_synthesis_json": artifact_rel,
            "evidence": cast(
                list[JsonValue],
                cast(list[object], [{"path": p} for p in evidence_paths]),
            ),
            "classification": (
                "llm_chain_augmented"
                if llm_chain_added > 0
                else "grounded_deterministic"
            ),
            "observation": (
                "llm_chain_builder+artifact_linked_claim_synthesis"
                if llm_chain_added > 0
                else "artifact_linked_claim_synthesis"
            ),
            "caps": {
                "max_claims": int(self.max_claims),
            },
            "llm_chain_builder": {
                "attempted": bool(llm_chain_attempted),
                "status": llm_chain_status,
                "raw_chain_count": int(llm_chain_raw),
                "normalized_chain_count": int(llm_chain_added),
                "meta_path": llm_chain_meta_rel,
                "prompt_path": llm_chain_prompt_rel,
                "raw_path": llm_chain_raw_rel,
            },
        }

        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
