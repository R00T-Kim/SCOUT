from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .policy import AIEdgePolicyViolation
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


def _sorted_unique_refs(refs: list[str]) -> list[str]:
    return sorted({x.replace("\\", "/") for x in refs if _is_run_relative_path(x)})


def _threat_sort_key(item: dict[str, JsonValue]) -> tuple[str, str, str, str]:
    category_any = item.get("category")
    surface_any = item.get("surface")
    endpoint_any = item.get("endpoint")
    threat_id_any = item.get("threat_id")

    surface_component = ""
    if isinstance(surface_any, dict):
        surface_component_any = cast(dict[str, object], surface_any).get("component")
        if isinstance(surface_component_any, str):
            surface_component = surface_component_any

    endpoint_value = ""
    if isinstance(endpoint_any, dict):
        endpoint_value_any = cast(dict[str, object], endpoint_any).get("value")
        if isinstance(endpoint_value_any, str):
            endpoint_value = endpoint_value_any

    return (
        str(category_any) if isinstance(category_any, str) else "",
        surface_component,
        endpoint_value,
        str(threat_id_any) if isinstance(threat_id_any, str) else "",
    )


def _unknown_sort_key(item: dict[str, JsonValue]) -> tuple[str, str]:
    endpoint_any = item.get("endpoint")
    if not isinstance(endpoint_any, dict):
        return ("", "")
    endpoint = cast(dict[str, object], endpoint_any)
    endpoint_type_any = endpoint.get("type")
    endpoint_value_any = endpoint.get("value")
    endpoint_type = endpoint_type_any if isinstance(endpoint_type_any, str) else ""
    endpoint_value = endpoint_value_any if isinstance(endpoint_value_any, str) else ""
    return (endpoint_type, endpoint_value)


_TAXONOMY_ORDER: tuple[str, ...] = (
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
)

_TAXONOMY_RANK = {name: i for i, name in enumerate(_TAXONOMY_ORDER)}

_MITIGATION_LIBRARY: dict[str, tuple[str, str]] = {
    "spoofing": (
        "Authenticate endpoint identity with pinned keys or mutual TLS.",
        "Reject unauthenticated host/domain changes at update time.",
    ),
    "tampering": (
        "Enforce signed artifacts and verified boot/update chains.",
        "Apply integrity checks for writable config and OTA metadata.",
    ),
    "repudiation": (
        "Emit tamper-evident logs for security-relevant actions.",
        "Correlate request identity with immutable audit trails.",
    ),
    "information_disclosure": (
        "Minimize sensitive data in transit and at rest.",
        "Protect secrets via scoped credentials and storage hardening.",
    ),
    "denial_of_service": (
        "Rate-limit and bound request/resource consumption.",
        "Fail closed with backoff and watchdog recovery paths.",
    ),
    "elevation_of_privilege": (
        "Apply least-privilege service permissions and sandboxing.",
        "Harden management/debug interfaces behind explicit authorization.",
    ),
}


def _infer_category(
    *, surface_type: str, endpoint_type: str, endpoint_value: str
) -> str:
    st = surface_type.lower()
    et = endpoint_type.lower()
    ev = endpoint_value.lower()

    if any(k in ev for k in ("admin", "debug", "shell", "root", "telnet", "ssh")):
        return "elevation_of_privilege"
    if any(k in st for k in ("admin", "debug", "management", "cli")):
        return "elevation_of_privilege"
    if any(k in ev for k in ("firmware", "update", "upgrade", "ota")):
        return "tampering"
    if any(k in st for k in ("update", "ota", "firmware", "storage")):
        return "tampering"
    if et in {"domain", "host", "hostname"}:
        return "spoofing"
    if et in {"mqtt", "coap", "tcp", "udp", "ws", "wss"}:
        return "denial_of_service"
    if et in {"url", "uri", "ip", "ipv4", "ipv6", "domain"}:
        return "information_disclosure"
    if st in {"web", "api", "network"}:
        return "information_disclosure"
    return "repudiation"


_HIGH_RISK_UNKNOWN_RE = re.compile(
    r"(admin|login|auth|token|session|debug|diag|shell|cgi|api|rpc|update|upgrade|firmware|ota|config|backup|restore|ssh|telnet|dropbear|ftp|mqtt|coap)",
    re.IGNORECASE,
)


def _unknown_risk_score(
    *,
    endpoint_type: str,
    endpoint_value: str,
    reason: str,
) -> float:
    et = endpoint_type.lower()
    ev = endpoint_value.lower()
    reason_l = reason.lower()
    score = 0.2
    if et in {"url", "uri", "ipv4", "ipv6", "ip", "host", "hostname"}:
        score += 0.45
    elif et == "domain":
        score += 0.25
    if _HIGH_RISK_UNKNOWN_RE.search(ev):
        score += 0.35
    if "no communication-graph" in reason_l or "no deterministic mapping" in reason_l:
        score += 0.1
    if ev.startswith("http://") or ev.startswith("https://"):
        score += 0.1
    return max(0.0, min(1.0, score))


def _is_actionable_unknown(
    *,
    endpoint_type: str,
    endpoint_value: str,
    reason: str,
) -> bool:
    score = _unknown_risk_score(
        endpoint_type=endpoint_type,
        endpoint_value=endpoint_value,
        reason=reason,
    )
    et = endpoint_type.lower()
    if et in {"url", "uri", "ipv4", "ipv6", "ip", "host", "hostname"}:
        return score >= 0.5
    if et == "domain":
        return bool(_HIGH_RISK_UNKNOWN_RE.search(endpoint_value)) or score >= 0.75
    return score >= 0.8


@dataclass(frozen=True)
class ThreatModelStage:
    max_threats: int = 1000
    max_unknowns: int = 300

    @property
    def name(self) -> str:
        return "threat_model"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "threat_model"
        out_json = stage_dir / "threat_model.json"

        _assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(stage_dir, out_json)

        attack_surface_path = (
            run_dir / "stages" / "attack_surface" / "attack_surface.json"
        )

        limitations: list[str] = []
        evidence_paths: list[str] = []

        if attack_surface_path.is_file():
            evidence_paths.append(_rel_to_run_dir(run_dir, attack_surface_path))

        attack_surface_obj = _load_json_object(attack_surface_path)
        if attack_surface_obj is None:
            limitations.append(
                "Attack-surface output missing or invalid: stages/attack_surface/attack_surface.json"
            )

        items_any = (
            None
            if attack_surface_obj is None
            else attack_surface_obj.get("attack_surface")
        )
        non_promoted_any = (
            None if attack_surface_obj is None else attack_surface_obj.get("non_promoted")
        )
        unknowns_any = (
            None if attack_surface_obj is None else attack_surface_obj.get("unknowns")
        )

        source_items: list[dict[str, object]] = []
        if isinstance(items_any, list):
            for item_any in cast(list[object], items_any):
                if isinstance(item_any, dict):
                    source_items.append(cast(dict[str, object], item_any))
        elif attack_surface_obj is not None:
            limitations.append(
                "Attack-surface output missing list field: attack_surface"
            )

        source_non_promoted: list[dict[str, object]] = []
        if isinstance(non_promoted_any, list):
            for item_any in cast(list[object], non_promoted_any):
                if isinstance(item_any, dict):
                    source_non_promoted.append(cast(dict[str, object], item_any))
        elif attack_surface_obj is not None:
            limitations.append("Attack-surface output missing list field: non_promoted")

        source_unknowns: list[dict[str, object]] = []
        if isinstance(unknowns_any, list):
            for item_any in cast(list[object], unknowns_any):
                if isinstance(item_any, dict):
                    source_unknowns.append(cast(dict[str, object], item_any))
        elif attack_surface_obj is not None:
            limitations.append("Attack-surface output missing list field: unknowns")

        threats: list[dict[str, JsonValue]] = []
        category_refs: dict[str, list[str]] = {name: [] for name in _TAXONOMY_ORDER}
        threat_source_entries: list[tuple[str, dict[str, object]]] = []
        for source in source_items:
            threat_source_entries.append(("attack_surface", source))

        non_promoted_used = 0
        if not source_items and source_non_promoted:
            limitations.append(
                "Attack-surface runtime-linked items empty; falling back to non_promoted reference-only items"
            )
            for source in source_non_promoted:
                threat_source_entries.append(("non_promoted", source))
            non_promoted_used = len(source_non_promoted)

        threat_keys_seen: set[tuple[str, str, str, str]] = set()

        for source_kind, source in threat_source_entries:
            surface_any = source.get("surface")
            endpoint_any = source.get("endpoint")
            refs_any = source.get("evidence_refs")
            if not isinstance(surface_any, dict) or not isinstance(endpoint_any, dict):
                continue

            surface = cast(dict[str, object], surface_any)
            endpoint = cast(dict[str, object], endpoint_any)
            surface_type_any = surface.get("surface_type")
            component_any = surface.get("component")
            endpoint_type_any = endpoint.get("type")
            endpoint_value_any = endpoint.get("value")
            if not isinstance(surface_type_any, str) or not surface_type_any:
                continue
            if not isinstance(component_any, str) or not component_any:
                continue
            if not isinstance(endpoint_type_any, str) or not endpoint_type_any:
                continue
            if not isinstance(endpoint_value_any, str) or not endpoint_value_any:
                continue
            threat_key = (
                surface_type_any,
                component_any,
                endpoint_type_any,
                endpoint_value_any,
            )
            if threat_key in threat_keys_seen:
                continue

            threat_refs: list[str] = []
            if isinstance(refs_any, list):
                threat_refs = [
                    cast(str, r)
                    for r in cast(list[object], refs_any)
                    if _is_run_relative_path(r)
                ]
            threat_refs = _sorted_unique_refs(threat_refs)
            if not threat_refs:
                limitations.append(
                    "Threat candidate skipped due to missing evidence_refs in attack_surface item"
                )
                continue

            category = _infer_category(
                surface_type=surface_type_any,
                endpoint_type=endpoint_type_any,
                endpoint_value=endpoint_value_any,
            )
            category_refs[category].extend(threat_refs)
            threat_keys_seen.add(threat_key)
            source_note = (
                "derived from runtime-linked attack_surface item"
                if source_kind == "attack_surface"
                else "derived from non_promoted static-reference fallback item"
            )

            threats.append(
                {
                    "category": category,
                    "title": f"{category.replace('_', ' ').title()} risk on {surface_type_any}:{component_any}",
                    "description": (
                        "Static attack-surface evidence indicates this endpoint may be abused "
                        "without additional runtime controls."
                    ),
                    "source": source_kind,
                    "source_note": source_note,
                    "surface": {
                        "surface_type": surface_type_any,
                        "component": component_any,
                    },
                    "endpoint": {
                        "type": endpoint_type_any,
                        "value": endpoint_value_any,
                    },
                    "evidence_refs": cast(
                        list[JsonValue], cast(list[object], threat_refs)
                    ),
                }
            )

        unknowns_all: list[dict[str, JsonValue]] = []
        inferred_unknown_threats = 0
        for item in source_unknowns:
            endpoint_any = item.get("endpoint")
            refs_any = item.get("evidence_refs")
            reason_any = item.get("reason")
            if not isinstance(endpoint_any, dict):
                continue
            endpoint = cast(dict[str, object], endpoint_any)
            endpoint_type_any = endpoint.get("type")
            endpoint_value_any = endpoint.get("value")
            if not isinstance(endpoint_type_any, str) or not endpoint_type_any:
                continue
            if not isinstance(endpoint_value_any, str) or not endpoint_value_any:
                continue

            unknown_refs: list[str] = []
            if isinstance(refs_any, list):
                unknown_refs = [
                    cast(str, r)
                    for r in cast(list[object], refs_any)
                    if _is_run_relative_path(r)
                ]
            unknown_refs = _sorted_unique_refs(unknown_refs)
            if not unknown_refs:
                continue
            reason = (
                reason_any
                if isinstance(reason_any, str) and reason_any
                else "Attack-surface unknown mapping requires manual review"
            )
            risk_score = _unknown_risk_score(
                endpoint_type=endpoint_type_any,
                endpoint_value=endpoint_value_any,
                reason=reason,
            )
            unknown_item: dict[str, JsonValue] = {
                "reason": reason,
                "endpoint": {
                    "type": endpoint_type_any,
                    "value": endpoint_value_any,
                },
                "risk_score": round(float(risk_score), 4),
                "evidence_refs": cast(
                    list[JsonValue], cast(list[object], unknown_refs)
                ),
            }
            unknowns_all.append(unknown_item)

            if (
                len(threats) < int(self.max_threats)
                and _is_actionable_unknown(
                    endpoint_type=endpoint_type_any,
                    endpoint_value=endpoint_value_any,
                    reason=reason,
                )
            ):
                category = _infer_category(
                    surface_type="unknown_surface",
                    endpoint_type=endpoint_type_any,
                    endpoint_value=endpoint_value_any,
                )
                threat_key = (
                    "unknown_surface",
                    "unmapped_endpoint",
                    endpoint_type_any,
                    endpoint_value_any,
                )
                if threat_key not in threat_keys_seen:
                    threat_keys_seen.add(threat_key)
                    category_refs[category].extend(unknown_refs)
                    threats.append(
                        {
                            "category": category,
                            "title": (
                                f"{category.replace('_', ' ').title()} risk on "
                                "unknown_surface:unmapped_endpoint"
                            ),
                            "description": (
                                "Unknown endpoint has no deterministic component mapping; "
                                "treated as suspicious exposed surface candidate."
                            ),
                            "source": "unknown_inference",
                            "source_note": "derived from attack_surface unknown endpoint",
                            "surface": {
                                "surface_type": "unknown_surface",
                                "component": "unmapped_endpoint",
                            },
                            "endpoint": {
                                "type": endpoint_type_any,
                                "value": endpoint_value_any,
                            },
                            "evidence_refs": cast(
                                list[JsonValue], cast(list[object], unknown_refs)
                            ),
                        }
                    )
                    inferred_unknown_threats += 1

        unknowns_all = sorted(
            unknowns_all,
            key=lambda item: (
                -float(item.get("risk_score", 0.0))
                if isinstance(item.get("risk_score"), (int, float))
                else 0.0,
                _unknown_sort_key(item),
            ),
        )
        unknowns_truncated = max(0, len(unknowns_all) - int(self.max_unknowns))
        unknowns = unknowns_all[: int(self.max_unknowns)]
        if unknowns_truncated > 0:
            limitations.append(
                f"Threat-model extraction reached max_unknowns cap ({int(self.max_unknowns)}); {unknowns_truncated} unknown entries were skipped"
            )

        threats = sorted(
            threats,
            key=lambda t: (
                _TAXONOMY_RANK.get(str(t.get("category", "")), len(_TAXONOMY_ORDER)),
                _threat_sort_key(t),
            ),
        )
        if len(threats) > int(self.max_threats):
            skipped = len(threats) - int(self.max_threats)
            limitations.append(
                f"Threat-model extraction reached max_threats cap ({int(self.max_threats)}); {skipped} threats were skipped"
            )
            threats = threats[: int(self.max_threats)]

        for i, threat in enumerate(threats, start=1):
            category = str(threat.get("category", "repudiation"))
            threat["threat_id"] = f"tm.{category}.{i:04d}"

        assumptions: list[dict[str, JsonValue]] = [
            {
                "id": "tm.assumption.static-only",
                "statement": "Threat model is derived from static attack-surface evidence and does not assert runtime exploitability.",
                "evidence_refs": cast(
                    list[JsonValue],
                    cast(list[object], _sorted_unique_refs(list(evidence_paths))),
                ),
            }
        ]

        mitigations: list[dict[str, JsonValue]] = []
        for category in _TAXONOMY_ORDER:
            refs = _sorted_unique_refs(category_refs.get(category, []))
            if not refs:
                continue
            mitigations.append(
                {
                    "category": category,
                    "controls": cast(
                        list[JsonValue],
                        cast(list[object], list(_MITIGATION_LIBRARY[category])),
                    ),
                    "evidence_refs": cast(list[JsonValue], cast(list[object], refs)),
                }
            )

        if (not source_items) and non_promoted_used == 0:
            limitations.append(
                "No attack-surface items available for deterministic threat modeling"
            )
        if not threats:
            limitations.append(
                "No threats produced from attack-surface inputs with non-empty evidence_refs"
            )

        summary: dict[str, JsonValue] = {
            "taxonomy": cast(
                list[JsonValue], cast(list[object], list(_TAXONOMY_ORDER))
            ),
            "attack_surface_items": len(source_items),
            "non_promoted_items": len(source_non_promoted),
            "non_promoted_used_for_threats": int(non_promoted_used),
            "unknowns_input": len(source_unknowns),
            "unknowns_truncated": int(unknowns_truncated),
            "unknown_inferred_threats": int(inferred_unknown_threats),
            "threats": len(threats),
            "assumptions": len(assumptions),
            "mitigations": len(mitigations),
            "unknowns": len(unknowns),
            "classification": "candidate",
            "observation": "deterministic_static_inference",
        }

        status: StageStatus = "ok"
        if limitations:
            status = "partial"

        payload: dict[str, JsonValue] = {
            "status": status,
            "summary": summary,
            "threats": cast(list[JsonValue], cast(list[object], threats)),
            "assumptions": cast(list[JsonValue], cast(list[object], assumptions)),
            "mitigations": cast(list[JsonValue], cast(list[object], mitigations)),
            "unknowns": cast(list[JsonValue], cast(list[object], unknowns)),
            "limitations": cast(
                list[JsonValue], cast(list[object], sorted(set(limitations)))
            ),
            "note": (
                "Threat model uses deterministic STRIDE-like categorization from attack_surface "
                "evidence with optional non_promoted fallback and unknown-endpoint inference."
            ),
        }
        _ = out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        artifact_rel = _rel_to_run_dir(run_dir, out_json)
        evidence_paths.append(artifact_rel)
        details: dict[str, JsonValue] = {
            "summary": summary,
            "threats": cast(list[JsonValue], cast(list[object], threats)),
            "assumptions": cast(list[JsonValue], cast(list[object], assumptions)),
            "mitigations": cast(list[JsonValue], cast(list[object], mitigations)),
            "unknowns": cast(list[JsonValue], cast(list[object], unknowns)),
            "threat_model_json": artifact_rel,
            "evidence": cast(
                list[JsonValue],
                cast(
                    list[object],
                    [{"path": p} for p in _sorted_unique_refs(evidence_paths)],
                ),
            ),
            "classification": "candidate",
            "observation": "deterministic_static_inference",
        }

        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
