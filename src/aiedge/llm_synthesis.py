from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .policy import AIEdgePolicyViolation
from .exploit_tiering import default_exploitability_tier
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus


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
            "note": "Grounded deterministic synthesis from prior stage artifacts only; uncited claims are dropped.",
        }
        _ = out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        artifact_rel = _rel_to_run_dir(run_dir, out_json)
        evidence_paths = _sorted_unique_refs(
            [artifact_rel] + list(source_rel_paths.values()), run_dir=run_dir
        )
        details: dict[str, JsonValue] = {
            "summary": summary,
            "claims": cast(list[JsonValue], cast(list[object], deduped)),
            "llm_synthesis_json": artifact_rel,
            "evidence": cast(
                list[JsonValue],
                cast(list[object], [{"path": p} for p in evidence_paths]),
            ),
            "classification": "grounded_deterministic",
            "observation": "artifact_linked_claim_synthesis",
            "caps": {
                "max_claims": int(self.max_claims),
            },
        }

        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
