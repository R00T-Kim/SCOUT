from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .confidence_caps import calibrated_confidence, evidence_level
from .policy import AIEdgePolicyViolation
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus


def _assert_under_dir(base_dir: Path, target: Path) -> None:
    base = _safe_resolve(base_dir) or base_dir.absolute()
    resolved = _safe_resolve(target) or target.absolute()
    if not resolved.is_relative_to(base):
        raise AIEdgePolicyViolation(
            f"Refusing to write outside run dir: target={resolved} base={base}"
        )


def _safe_resolve(path: Path) -> Path | None:
    try:
        return path.resolve()
    except OSError:
        return None


def _safe_non_absolute_rel(value: str, *, fallback: str = "unresolved_path") -> str:
    norm = value.replace("\\", "/").strip()
    if not norm:
        return fallback
    if norm.startswith("/"):
        norm = norm.lstrip("/")
    if not norm or norm.startswith("../") or "/home/" in norm:
        return fallback
    return norm


def _rel_to_run_dir(run_dir: Path, path: Path) -> str:
    run_resolved = _safe_resolve(run_dir) or run_dir.absolute()
    path_resolved = _safe_resolve(path)
    if isinstance(path_resolved, Path):
        try:
            return _safe_non_absolute_rel(str(path_resolved.relative_to(run_resolved)))
        except Exception:
            pass
    try:
        return _safe_non_absolute_rel(str(path.relative_to(run_resolved)))
    except Exception:
        try:
            return _safe_non_absolute_rel(
                os.path.relpath(str(path), start=str(run_resolved))
            )
        except Exception:
            return _safe_non_absolute_rel(path.name)


def _clamp01(v: float) -> float:
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return float(v)


def _is_run_relative_path(path: object) -> bool:
    if not isinstance(path, str) or not path:
        return False
    return not path.startswith("/")


def _surface_type_from_name(name: str) -> str:
    lowered = name.lower()
    if any(x in lowered for x in ("httpd", "nginx", "lighttpd", "uhttpd")):
        return "web"
    if any(x in lowered for x in ("dropbear", "sshd")):
        return "ssh"
    if any(x in lowered for x in ("telnetd", "in.telnetd")):
        return "telnet"
    if any(x in lowered for x in ("dnsmasq", "udhcpd", "dhcpd")):
        return "dns_dhcp"
    return "service"


def _surface_confidence(base: float, surface_type: str) -> float:
    offsets: dict[str, float] = {
        "web": 0.1,
        "ssh": 0.08,
        "telnet": 0.04,
        "dns_dhcp": 0.06,
        "service": 0.0,
    }
    return _clamp01(base + offsets.get(surface_type, 0.0))


def _load_json_object(path: Path) -> dict[str, object] | None:
    try:
        raw = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None
    return cast(dict[str, object], raw)


@dataclass(frozen=True)
class SurfacesStage:
    max_surfaces: int = 200
    max_unknowns: int = 200

    @property
    def name(self) -> str:
        return "surfaces"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "surfaces"
        out_json = stage_dir / "surfaces.json"

        _assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(stage_dir, out_json)

        inventory_path = run_dir / "stages" / "inventory" / "inventory.json"
        endpoints_path = run_dir / "stages" / "endpoints" / "endpoints.json"

        limitations: list[str] = []
        unknowns: list[dict[str, JsonValue]] = []
        evidence: list[dict[str, JsonValue]] = []

        inventory_obj = _load_json_object(inventory_path)
        inventory_present = inventory_path.is_file()
        if inventory_present:
            evidence.append({"path": _rel_to_run_dir(run_dir, inventory_path)})
        else:
            limitations.append(
                "Inventory output missing: stages/inventory/inventory.json"
            )

        candidates_any: object = None
        if inventory_obj is None:
            if inventory_present:
                limitations.append(
                    "Inventory output unreadable or invalid; expected JSON object"
                )
        else:
            candidates_any = inventory_obj.get("service_candidates")

        candidates_raw: list[object] = []
        if isinstance(candidates_any, list):
            candidates_raw = cast(list[object], candidates_any)
        elif inventory_obj is not None:
            limitations.append("Inventory service_candidates missing or invalid")

        name_kind_counts: dict[str, set[str]] = {}
        parsed_candidates: list[dict[str, object]] = []
        for candidate_any in candidates_raw:
            if not isinstance(candidate_any, dict):
                continue
            candidate = cast(dict[str, object], candidate_any)
            name_any = candidate.get("name")
            kind_any = candidate.get("kind")
            conf_any = candidate.get("confidence")
            evidence_any = candidate.get("evidence")
            if not isinstance(name_any, str) or not name_any:
                continue
            if not isinstance(kind_any, str) or not kind_any:
                continue
            if not isinstance(conf_any, (int, float)):
                continue
            refs: set[str] = set()
            if isinstance(evidence_any, list):
                for item_any in cast(list[object], evidence_any):
                    if not isinstance(item_any, dict):
                        continue
                    path_any = cast(dict[str, object], item_any).get("path")
                    if _is_run_relative_path(path_any):
                        refs.add(cast(str, path_any).replace("\\", "/"))
            if not refs:
                continue
            parsed_candidates.append(
                {
                    "name": name_any,
                    "kind": kind_any,
                    "confidence": _clamp01(float(conf_any)),
                    "evidence_refs": sorted(refs),
                }
            )
            name_kind_counts.setdefault(name_any.lower(), set()).add(kind_any.lower())

        merged: dict[tuple[str, str], dict[str, object]] = {}
        for candidate in parsed_candidates:
            name = cast(str, candidate["name"])
            kind = cast(str, candidate["kind"])
            base_conf = cast(float, candidate["confidence"])
            evidence_refs = cast(list[str], candidate["evidence_refs"])
            collision = len(name_kind_counts.get(name.lower(), set())) > 1
            component = f"{kind}:{name}" if collision else name
            surface_type = _surface_type_from_name(name)
            confidence = _surface_confidence(base_conf, surface_type)
            key = (surface_type, component)

            existing = merged.get(key)
            if existing is None:
                merged[key] = {
                    "surface_type": surface_type,
                    "component": component,
                    "confidence": confidence,
                    "evidence_refs": set(evidence_refs),
                }
                continue

            existing["confidence"] = max(
                cast(float, existing["confidence"]),
                confidence,
            )
            cast(set[str], existing["evidence_refs"]).update(evidence_refs)

        surfaces: list[dict[str, JsonValue]] = []
        for key in sorted(merged.keys(), key=lambda item: (item[0], item[1])):
            item = merged[key]
            item_refs = sorted(cast(set[str], item["evidence_refs"]))
            if not item_refs:
                continue
            confidence = _clamp01(cast(float, item["confidence"]))
            observation = "static_reference"
            surfaces.append(
                {
                    "surface_type": cast(str, item["surface_type"]),
                    "component": cast(str, item["component"]),
                    "confidence": confidence,
                    "confidence_calibrated": calibrated_confidence(
                        confidence=confidence,
                        observation=observation,
                        evidence_refs=item_refs,
                    ),
                    "evidence_refs": cast(
                        list[JsonValue], cast(list[object], item_refs)
                    ),
                    "classification": "candidate",
                    "observation": observation,
                    "evidence_level": evidence_level(observation, item_refs),
                }
            )

        if len(surfaces) > int(self.max_surfaces):
            limitations.append(
                f"Surface extraction reached max_surfaces cap ({int(self.max_surfaces)}); additional items were skipped"
            )
            surfaces = surfaces[: int(self.max_surfaces)]

        endpoints_obj = _load_json_object(endpoints_path)
        endpoints_count = 0
        if endpoints_obj is not None:
            evidence.append({"path": _rel_to_run_dir(run_dir, endpoints_path)})
            endpoints_any = endpoints_obj.get("endpoints")
            if isinstance(endpoints_any, list):
                endpoints_count = len(cast(list[object], endpoints_any))

        if endpoints_count > 0 and not surfaces:
            unknowns.append(
                {
                    "reason": "Endpoints were identified but no owning service candidates were inferred",
                    "evidence_refs": cast(
                        list[JsonValue],
                        cast(list[object], [_rel_to_run_dir(run_dir, endpoints_path)]),
                    ),
                }
            )

        if not parsed_candidates:
            limitations.append(
                "No service candidates available to infer input surfaces"
            )

        if len(unknowns) > int(self.max_unknowns):
            limitations.append(
                f"Surface extraction reached max_unknowns cap ({int(self.max_unknowns)}); additional unknown notes were skipped"
            )
            unknowns = unknowns[: int(self.max_unknowns)]

        summary: dict[str, JsonValue] = {
            "service_candidates_seen": len(parsed_candidates),
            "surfaces": len(surfaces),
            "unknowns": len(unknowns),
            "classification": "candidate",
            "observation": "static_reference",
        }

        status: StageStatus = "ok"
        if not inventory_present or not parsed_candidates:
            status = "partial"

        payload: dict[str, JsonValue] = {
            "status": status,
            "summary": summary,
            "surfaces": cast(list[JsonValue], cast(list[object], surfaces)),
            "unknowns": cast(list[JsonValue], cast(list[object], unknowns)),
            "limitations": cast(
                list[JsonValue],
                cast(list[object], sorted(set(limitations))),
            ),
            "note": "Static candidate input surfaces inferred from inventory service candidates; no runtime interaction evidence.",
        }
        _ = out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        evidence.append({"path": _rel_to_run_dir(run_dir, out_json)})
        details: dict[str, JsonValue] = {
            "summary": summary,
            "surfaces": cast(list[JsonValue], cast(list[object], surfaces)),
            "unknowns": cast(list[JsonValue], cast(list[object], unknowns)),
            "evidence": cast(list[JsonValue], cast(list[object], evidence)),
            "surfaces_json": _rel_to_run_dir(run_dir, out_json),
            "classification": "candidate",
            "observation": "static_reference",
        }

        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
