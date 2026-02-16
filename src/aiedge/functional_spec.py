from __future__ import annotations

import json
from dataclasses import dataclass, field
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


def _clamp01(v: float) -> float:
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return float(v)


@dataclass(frozen=True)
class _EndpointRecord:
    endpoint_type: str
    value: str
    confidence: float
    refs: tuple[str, ...]


@dataclass
class _ComponentState:
    name: str
    input_types: set[str] = field(default_factory=set)
    refs: set[str] = field(default_factory=set)
    conf_scores: list[float] = field(default_factory=list)
    endpoints: list[_EndpointRecord] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)


def _component_aliases(name: str) -> set[str]:
    out = {name}
    if ":" in name:
        out.add(name.split(":", 1)[1])
    return out


def _endpoint_sort_key(item: dict[str, JsonValue]) -> tuple[str, str]:
    endpoint_type_any = item.get("type")
    value_any = item.get("value")
    endpoint_type = endpoint_type_any if isinstance(endpoint_type_any, str) else ""
    value = value_any if isinstance(value_any, str) else ""
    return endpoint_type, value


@dataclass(frozen=True)
class FunctionalSpecStage:
    max_components: int = 300
    max_endpoints_per_component: int = 25
    max_refs_per_component: int = 200
    max_unknowns_per_component: int = 20

    @property
    def name(self) -> str:
        return "functional_spec"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "functional_spec"
        out_json = stage_dir / "functional_spec.json"

        _assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(stage_dir, out_json)

        surfaces_path = run_dir / "stages" / "surfaces" / "surfaces.json"
        inventory_path = run_dir / "stages" / "inventory" / "inventory.json"
        endpoints_path = run_dir / "stages" / "endpoints" / "endpoints.json"

        limitations: list[str] = []
        evidence_paths: list[str] = []
        for dep in (surfaces_path, inventory_path, endpoints_path):
            if dep.is_file():
                evidence_paths.append(_rel_to_run_dir(run_dir, dep))

        surfaces_obj = _load_json_object(surfaces_path)
        inventory_obj = _load_json_object(inventory_path)
        endpoints_obj = _load_json_object(endpoints_path)

        if surfaces_obj is None:
            limitations.append(
                "Surfaces output missing or invalid: stages/surfaces/surfaces.json"
            )
        if inventory_obj is None:
            limitations.append(
                "Inventory output missing or invalid: stages/inventory/inventory.json"
            )
        if endpoints_obj is None:
            limitations.append(
                "Endpoints output missing or invalid: stages/endpoints/endpoints.json"
            )

        components: dict[str, _ComponentState] = {}
        alias_to_component: dict[str, set[str]] = {}

        def ensure_component(name: str) -> _ComponentState:
            existing = components.get(name)
            if existing is not None:
                return existing
            st = _ComponentState(name=name)
            components[name] = st
            for alias in _component_aliases(name):
                alias_to_component.setdefault(alias, set()).add(name)
            return st

        surfaces_any = None if surfaces_obj is None else surfaces_obj.get("surfaces")
        if isinstance(surfaces_any, list):
            for surface_any in cast(list[object], surfaces_any):
                if not isinstance(surface_any, dict):
                    continue
                surface = cast(dict[str, object], surface_any)
                surface_type_any = surface.get("surface_type")
                component_any = surface.get("component")
                conf_any = surface.get("confidence")
                refs_any = surface.get("evidence_refs")
                if not isinstance(surface_type_any, str) or not surface_type_any:
                    continue
                if not isinstance(component_any, str) or not component_any:
                    continue
                st = ensure_component(component_any)
                st.input_types.add(surface_type_any)
                if isinstance(conf_any, (int, float)):
                    st.conf_scores.append(_clamp01(float(conf_any)))
                if isinstance(refs_any, list):
                    st.refs.update(
                        cast(str, r)
                        for r in cast(list[object], refs_any)
                        if _is_run_relative_path(r)
                    )
        elif surfaces_obj is not None:
            limitations.append("Surfaces output missing list field: surfaces")

        candidates_any = (
            None if inventory_obj is None else inventory_obj.get("service_candidates")
        )
        if isinstance(candidates_any, list):
            for candidate_any in cast(list[object], candidates_any):
                if not isinstance(candidate_any, dict):
                    continue
                candidate = cast(dict[str, object], candidate_any)
                name_any = candidate.get("name")
                conf_any = candidate.get("confidence")
                ev_any = candidate.get("evidence")
                if not isinstance(name_any, str) or not name_any:
                    continue

                owners = sorted(alias_to_component.get(name_any, set()))
                if owners:
                    target = ensure_component(owners[0])
                else:
                    target = ensure_component(name_any)

                if isinstance(conf_any, (int, float)):
                    target.conf_scores.append(_clamp01(float(conf_any)))

                if isinstance(ev_any, list):
                    for ev_item_any in cast(list[object], ev_any):
                        if not isinstance(ev_item_any, dict):
                            continue
                        path_any = cast(dict[str, object], ev_item_any).get("path")
                        if _is_run_relative_path(path_any):
                            target.refs.add(cast(str, path_any).replace("\\", "/"))
        elif inventory_obj is not None:
            limitations.append(
                "Inventory output missing list field: service_candidates"
            )

        endpoints_records: list[_EndpointRecord] = []
        endpoints_any = (
            None if endpoints_obj is None else endpoints_obj.get("endpoints")
        )
        if isinstance(endpoints_any, list):
            for endpoint_any in cast(list[object], endpoints_any):
                if not isinstance(endpoint_any, dict):
                    continue
                endpoint = cast(dict[str, object], endpoint_any)
                endpoint_type_any = endpoint.get("type")
                value_any = endpoint.get("value")
                conf_any = endpoint.get("confidence")
                refs_any = endpoint.get("evidence_refs")
                if not isinstance(endpoint_type_any, str) or not endpoint_type_any:
                    continue
                if not isinstance(value_any, str) or not value_any:
                    continue
                refs: list[str] = []
                if isinstance(refs_any, list):
                    refs = [
                        cast(str, r)
                        for r in cast(list[object], refs_any)
                        if _is_run_relative_path(r)
                    ]
                endpoints_records.append(
                    _EndpointRecord(
                        endpoint_type=endpoint_type_any,
                        value=value_any,
                        confidence=_clamp01(float(conf_any))
                        if isinstance(conf_any, (int, float))
                        else 0.5,
                        refs=tuple(_sorted_unique_refs(refs)),
                    )
                )
        elif endpoints_obj is not None:
            limitations.append("Endpoints output missing list field: endpoints")

        for endpoint in sorted(
            endpoints_records, key=lambda e: (e.endpoint_type, e.value, e.refs)
        ):
            endpoint_refs = set(endpoint.refs)
            if not endpoint_refs:
                continue
            for component_name in sorted(components.keys()):
                st = components[component_name]
                if endpoint_refs.intersection(st.refs):
                    st.endpoints.append(endpoint)
                    st.refs.update(endpoint.refs)
                    st.conf_scores.append(endpoint.confidence)

        component_specs: list[dict[str, JsonValue]] = []
        for component_name in sorted(components.keys()):
            st = components[component_name]
            refs = _sorted_unique_refs(list(st.refs))
            if not refs:
                if evidence_paths:
                    refs = _sorted_unique_refs([evidence_paths[0]])
                    st.unknowns.append(
                        "No direct component evidence_refs; fell back to stage dependency evidence."
                    )
                else:
                    limitations.append(
                        f"Component '{component_name}' skipped due to empty evidence_refs"
                    )
                    continue

            endpoints_payload: list[dict[str, JsonValue]] = []
            for endpoint in sorted(
                st.endpoints, key=lambda e: (e.endpoint_type, e.value, e.refs)
            )[: int(self.max_endpoints_per_component)]:
                endpoints_payload.append(
                    {
                        "type": endpoint.endpoint_type,
                        "value": endpoint.value,
                        "evidence_refs": cast(
                            list[JsonValue],
                            cast(list[object], list(endpoint.refs)),
                        ),
                    }
                )

            inputs = sorted(st.input_types)
            if not inputs:
                st.unknowns.append(
                    "No surface-derived inputs available; inferred from service candidate evidence only."
                )

            output_types: set[str] = set()
            for item in endpoints_payload:
                endpoint_type_any = item.get("type")
                if isinstance(endpoint_type_any, str) and endpoint_type_any:
                    output_types.add(endpoint_type_any)
            outputs = sorted(output_types)
            if not outputs:
                st.unknowns.append(
                    "No endpoint evidence overlap found; output channels are unknown."
                )

            unknowns = sorted(set(st.unknowns))[: int(self.max_unknowns_per_component)]

            confidence = 0.5
            if st.conf_scores:
                confidence = _clamp01(sum(st.conf_scores) / len(st.conf_scores))

            component_specs.append(
                {
                    "component": component_name,
                    "inputs": cast(list[JsonValue], cast(list[object], inputs)),
                    "outputs": cast(list[JsonValue], cast(list[object], outputs)),
                    "endpoints_referenced": cast(
                        list[JsonValue],
                        cast(
                            list[object],
                            sorted(endpoints_payload, key=_endpoint_sort_key),
                        ),
                    ),
                    "trust_boundaries": cast(
                        list[JsonValue],
                        cast(
                            list[object],
                            [
                                "device_boundary",
                                "network_boundary",
                            ],
                        ),
                    ),
                    "unknowns": cast(list[JsonValue], cast(list[object], unknowns)),
                    "evidence_refs": cast(
                        list[JsonValue],
                        cast(
                            list[object],
                            refs[: int(self.max_refs_per_component)],
                        ),
                    ),
                    "confidence": round(confidence, 4),
                    "classification": "candidate",
                    "observation": "deterministic_static_inference",
                }
            )

        if len(component_specs) > int(self.max_components):
            limitations.append(
                f"Functional-spec extraction reached max_components cap ({int(self.max_components)}); additional components were skipped"
            )
            component_specs = component_specs[: int(self.max_components)]

        if not component_specs:
            limitations.append(
                "No functional component specifications produced from available stage artifacts"
            )

        status: StageStatus = "ok"
        if limitations:
            status = "partial"

        summary: dict[str, JsonValue] = {
            "components": len(component_specs),
            "components_with_inputs": sum(
                1
                for item in component_specs
                if isinstance(item.get("inputs"), list) and bool(item.get("inputs"))
            ),
            "components_with_endpoints": sum(
                1
                for item in component_specs
                if isinstance(item.get("endpoints_referenced"), list)
                and bool(item.get("endpoints_referenced"))
            ),
            "classification": "candidate",
            "observation": "deterministic_static_inference",
        }

        payload: dict[str, JsonValue] = {
            "status": status,
            "summary": summary,
            "functional_spec": cast(
                list[JsonValue],
                cast(list[object], component_specs),
            ),
            "limitations": cast(
                list[JsonValue],
                cast(list[object], sorted(set(limitations))),
            ),
            "note": "Functional specification is deterministic and derived from static surfaces, inventory candidates, and endpoint evidence overlap.",
        }
        _ = out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        artifact_rel = _rel_to_run_dir(run_dir, out_json)
        evidence_paths.append(artifact_rel)
        details: dict[str, JsonValue] = {
            "summary": summary,
            "functional_spec": cast(
                list[JsonValue],
                cast(list[object], component_specs),
            ),
            "functional_spec_json": artifact_rel,
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
