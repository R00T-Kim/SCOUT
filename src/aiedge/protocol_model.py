from __future__ import annotations

"""Run-local protocol/input model stage for exploit proof planning.

The stage does not generate payloads. It converts SCOUT's attack-surface,
finding, and dossier artifacts into a compact protocol model plus a safe encoder
skeleton that later proof stages can use inside the gated lab lane.
"""

import json
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .llm_driver import parse_json_from_llm_output, resolve_driver, write_llm_trace
from .path_safety import assert_under_dir
from .schema import JsonValue
from .stage import StageContext, StageOutcome

SCHEMA_VERSION = "protocol-model-v1"
_MAX_MODELS = 30
_MAX_RAG_ITEMS = 24
_FIELD_RE = re.compile(r"[?&;]([A-Za-z_][A-Za-z0-9_.-]{0,48})=")


@dataclass(frozen=True)
class _Surface:
    surface_id: str
    surface_type: str
    endpoint_type: str
    endpoint_value: str
    component: str
    evidence_refs: tuple[str, ...]
    confidence: float


@dataclass(frozen=True)
class _Decision:
    candidate_id: str
    title: str
    binary: str
    source: str
    sink: str
    field: str
    bug_class: str
    verdict: str
    score: float
    evidence_refs: tuple[str, ...]


def _load_json(path: Path) -> dict[str, object] | None:
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return cast(dict[str, object], raw) if isinstance(raw, dict) else None


def _write_json(path: Path, payload: dict[str, JsonValue]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _clean_str(value: object, default: str = "") -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    return default


def _clean_float(value: object, default: float = 0.0) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0.0, min(1.0, float(value)))
    if isinstance(value, str):
        try:
            return max(0.0, min(1.0, float(value)))
        except ValueError:
            return default
    return default


def _clean_refs(value: object, *, max_items: int = 10) -> tuple[str, ...]:
    if not isinstance(value, list):
        return tuple()
    out: list[str] = []
    for item in cast(list[object], value):
        if not isinstance(item, str):
            continue
        s = item.strip()
        if not s or s.startswith("/") or ":\\" in s:
            continue
        if s not in out:
            out.append(s)
        if len(out) >= max_items:
            break
    return tuple(out)


def _dict(value: object) -> dict[str, object]:
    return cast(dict[str, object], value) if isinstance(value, dict) else {}


def _list_dict(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [cast(dict[str, object], item) for item in cast(list[object], value) if isinstance(item, dict)]


def _transport(surface_type: str, endpoint_type: str, endpoint_value: str) -> str:
    text = f"{surface_type} {endpoint_type} {endpoint_value}".lower()
    if any(token in text for token in ("http", "cgi", "url", "web")):
        return "http"
    if "udp" in text:
        return "udp"
    if "tcp" in text or "socket" in text:
        return "tcp"
    if "serial" in text:
        return "serial"
    return "unknown"


def _guess_fields(endpoint_value: str, decision: _Decision | None) -> list[dict[str, JsonValue]]:
    names: list[str] = []
    for match in _FIELD_RE.finditer(endpoint_value):
        name = match.group(1)
        if name not in names:
            names.append(name)
    if decision is not None:
        for raw in (decision.field, decision.source, decision.sink):
            cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", raw.strip())[:48]
            if cleaned and cleaned.lower() not in {"unknown", "none"} and cleaned not in names:
                names.append(cleaned)
        text = f"{decision.title} {decision.bug_class} {decision.sink}".lower()
        if any(token in text for token in ("cmd", "command", "exec", "popen", "system")):
            for name in ("cmd", "command", "action"):
                if name not in names:
                    names.append(name)
        if any(token in text for token in ("file", "path", "traversal", "read")):
            for name in ("file", "path", "filename"):
                if name not in names:
                    names.append(name)
        if any(token in text for token in ("overflow", "memcpy", "strcpy", "stack", "heap")):
            for name in ("data", "payload", "length"):
                if name not in names:
                    names.append(name)
    if not names:
        names.append("payload")
    return [
        {
            "name": name,
            "role": "attacker_controlled_candidate",
            "type": "string_or_bytes",
            "constraints": {"known": False, "needs_dynamic_validation": True},
        }
        for name in names[:12]
    ]


def _collect_surfaces(run_dir: Path, limitations: list[str]) -> list[_Surface]:
    obj = _load_json(run_dir / "stages" / "attack_surface" / "attack_surface.json")
    if obj is None:
        limitations.append("protocol_model: attack_surface artifact missing")
        return []
    out: list[_Surface] = []
    for idx, item in enumerate(_list_dict(obj.get("attack_surface"))[:_MAX_MODELS], start=1):
        surface = _dict(item.get("surface"))
        endpoint = _dict(item.get("endpoint"))
        surface_type = _clean_str(surface.get("surface_type"), "unknown") or "unknown"
        endpoint_type = _clean_str(endpoint.get("type"), "unknown") or "unknown"
        endpoint_value = _clean_str(endpoint.get("value"), "unknown") or "unknown"
        component = _clean_str(surface.get("component"), "unknown") or "unknown"
        out.append(
            _Surface(
                surface_id=f"surface-{idx:03d}",
                surface_type=surface_type,
                endpoint_type=endpoint_type,
                endpoint_value=endpoint_value,
                component=component,
                evidence_refs=_clean_refs(item.get("evidence_refs")),
                confidence=_clean_float(item.get("confidence_calibrated"), _clean_float(item.get("confidence"), 0.0)),
            )
        )
    if not out:
        limitations.append("protocol_model: no attack surface entries available")
    return out


def _collect_decisions(run_dir: Path, limitations: list[str]) -> list[_Decision]:
    obj = _load_json(run_dir / "stages" / "exploitability_dossier" / "exploitability_dossier.json")
    if obj is None:
        limitations.append("protocol_model: exploitability_dossier artifact missing")
        return []
    out: list[_Decision] = []
    for idx, item in enumerate(_list_dict(obj.get("decision_logs"))[:_MAX_MODELS], start=1):
        finding = _dict(item.get("finding"))
        score = 0.0
        score_obj = _dict(item.get("score_breakdown"))
        raw_total = score_obj.get("total")
        if isinstance(raw_total, (int, float)) and not isinstance(raw_total, bool):
            score = max(0.0, min(100.0, float(raw_total)))
        out.append(
            _Decision(
                candidate_id=_clean_str(finding.get("finding_id"), f"candidate:{idx}"),
                title=_clean_str(finding.get("title"), "Exploitability candidate"),
                binary=_clean_str(finding.get("binary"), "unknown"),
                source=_clean_str(finding.get("source"), "unknown"),
                sink=_clean_str(finding.get("sink"), "unknown"),
                field=_clean_str(finding.get("field"), "unknown"),
                bug_class=_clean_str(finding.get("bug_class"), "unknown"),
                verdict=_clean_str(item.get("verdict"), "unknown"),
                score=score,
                evidence_refs=_clean_refs(item.get("evidence_refs")),
            )
        )
    return out


def _surface_for_decision(decision: _Decision, surfaces: list[_Surface]) -> _Surface | None:
    haystack = f"{decision.binary} {decision.title} {decision.source} {decision.sink}".lower()
    best: tuple[int, _Surface | None] = (0, None)
    for surface in surfaces:
        score = 0
        for token in (surface.component, surface.endpoint_value):
            token_l = token.lower().strip("/")
            if token_l and token_l != "unknown" and token_l in haystack:
                score += 2
        if surface.surface_type.lower() in haystack:
            score += 1
        if score > best[0]:
            best = (score, surface)
    if best[1] is not None:
        return best[1]
    return surfaces[0] if surfaces else None


def _build_models(surfaces: list[_Surface], decisions: list[_Decision]) -> list[dict[str, JsonValue]]:
    models: list[dict[str, JsonValue]] = []
    used_surfaces: set[str] = set()
    for idx, decision in enumerate(decisions[:_MAX_MODELS], start=1):
        surface = _surface_for_decision(decision, surfaces)
        endpoint_value = surface.endpoint_value if surface is not None else "unknown"
        transport = _transport(
            surface.surface_type if surface is not None else "unknown",
            surface.endpoint_type if surface is not None else "unknown",
            endpoint_value,
        )
        if surface is not None:
            used_surfaces.add(surface.surface_id)
        refs = list(dict.fromkeys([*decision.evidence_refs, *((surface.evidence_refs if surface else tuple()))]))
        model_id = f"protocol-{idx:03d}"
        models.append(
            {
                "protocol_id": model_id,
                "candidate_id": decision.candidate_id,
                "source": "exploitability_dossier",
                "transport": transport,
                "entry_component": surface.component if surface is not None else decision.binary,
                "endpoint": {
                    "type": surface.endpoint_type if surface is not None else "unknown",
                    "value": endpoint_value,
                },
                "parser": {
                    "binary": decision.binary,
                    "function": "unknown",
                    "source": decision.source,
                    "sink": decision.sink,
                    "bug_class": decision.bug_class,
                },
                "fields": cast(JsonValue, _guess_fields(endpoint_value, decision)),
                "constraints": {
                    "bad_bytes": ["\\x00"],
                    "delimiter_candidates": ["&", "=", "\\r\\n"] if transport == "http" else [],
                    "max_lengths": {},
                    "needs_dynamic_confirmation": True,
                },
                "reachability": {
                    "trust_boundary": f"external {transport} input -> {decision.binary}",
                    "surface_id": surface.surface_id if surface is not None else "unknown",
                    "surface_confidence": surface.confidence if surface is not None else 0.0,
                },
                "score": decision.score,
                "evidence_refs": refs[:14],
            }
        )

    for surface in surfaces:
        if surface.surface_id in used_surfaces or len(models) >= _MAX_MODELS:
            continue
        transport = _transport(surface.surface_type, surface.endpoint_type, surface.endpoint_value)
        models.append(
            {
                "protocol_id": f"protocol-{len(models) + 1:03d}",
                "candidate_id": "surface-only",
                "source": "attack_surface",
                "transport": transport,
                "entry_component": surface.component,
                "endpoint": {"type": surface.endpoint_type, "value": surface.endpoint_value},
                "parser": {
                    "binary": surface.component,
                    "function": "unknown",
                    "source": "external_input",
                    "sink": "unknown",
                    "bug_class": "surface_reachability",
                },
                "fields": cast(JsonValue, _guess_fields(surface.endpoint_value, None)),
                "constraints": {
                    "bad_bytes": ["\\x00"],
                    "delimiter_candidates": ["&", "=", "\\r\\n"] if transport == "http" else [],
                    "max_lengths": {},
                    "needs_dynamic_confirmation": True,
                },
                "reachability": {
                    "trust_boundary": f"external {transport} input -> {surface.component}",
                    "surface_id": surface.surface_id,
                    "surface_confidence": surface.confidence,
                },
                "score": 0.0,
                "evidence_refs": list(surface.evidence_refs),
            }
        )
    return models


def _rag_items(run_dir: Path, models: list[dict[str, JsonValue]]) -> list[dict[str, JsonValue]]:
    refs: list[str] = [
        "stages/exploitability_dossier/exploitability_dossier.json",
        "stages/attack_surface/attack_surface.json",
        "stages/inventory/binary_analysis.json",
        "stages/findings/exploit_candidates.json",
        "stages/chain_construction/chains.json",
    ]
    for model in models:
        ev = model.get("evidence_refs")
        if isinstance(ev, list):
            for item in cast(list[object], ev):
                if isinstance(item, str) and item not in refs and not item.startswith("/"):
                    refs.append(item)
    out: list[dict[str, JsonValue]] = []
    for ref in refs[:_MAX_RAG_ITEMS]:
        path = run_dir / ref
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:1200]
        except Exception:
            continue
        out.append({"path": ref, "excerpt": text, "sha256_note": "hash anchored by run manifest"})
    return out


def _encoder_skeleton() -> str:
    return textwrap.dedent(
        '''\
        """SCOUT generated safe protocol encoder skeleton.

        This helper is intentionally non-weaponized. It builds bounded lab probes
        from protocol_model.json. Downstream exploit-profile stages may import or
        copy the shape, but verified exploit proof must come from exploit_runner
        evidence bundles.
        """

        from __future__ import annotations

        import urllib.parse


        def build_probe(model: dict[str, object], *, marker: str = "SCOUT_PROOF") -> bytes:
            transport = str(model.get("transport", "unknown")).lower()
            endpoint = model.get("endpoint", {})
            endpoint_value = "/" if not isinstance(endpoint, dict) else str(endpoint.get("value", "/"))
            fields = model.get("fields", [])
            names: list[str] = []
            if isinstance(fields, list):
                for item in fields:
                    if isinstance(item, dict):
                        name = str(item.get("name", "")).strip()
                        if name and name not in names:
                            names.append(name)
            if transport == "http":
                path = endpoint_value if endpoint_value.startswith("/") else "/" + endpoint_value
                sep = "&" if "?" in path else "?"
                query = urllib.parse.urlencode({(names[0] if names else "probe"): marker})
                return (f"GET {path}{sep}{query} HTTP/1.1\\r\\nHost: target\\r\\nConnection: close\\r\\n\\r\\n").encode()
            return (marker + "\\n").encode()
        '''
    )


def _llm_prompt(models: list[dict[str, JsonValue]], rag: list[dict[str, JsonValue]]) -> str:
    return (
        "You are helping an authorized firmware analyst build a protocol/input model.\n"
        "Return ONLY JSON with key field_hints. Do not include exploit payloads.\n"
        "For each protocol_id, suggest field roles, delimiter guesses, and missing dynamic evidence.\n\n"
        f"Protocol models:\n{json.dumps(models[:8], indent=2, ensure_ascii=True)}\n\n"
        f"Run-local RAG excerpts:\n{json.dumps(rag[:8], indent=2, ensure_ascii=True)}\n"
    )


@dataclass(frozen=True)
class ProtocolModelStage:
    no_llm: bool = False
    llm_timeout_s: float = 45.0

    @property
    def name(self) -> str:
        return "protocol_model"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "protocol_model"
        assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        out_json = stage_dir / "protocol_model.json"
        encoder_path = stage_dir / "encoder_skeleton.py"
        limitations: list[str] = []

        surfaces = _collect_surfaces(run_dir, limitations)
        decisions = _collect_decisions(run_dir, limitations)
        models = _build_models(surfaces, decisions)
        rag = _rag_items(run_dir, models)

        llm_result: dict[str, JsonValue] = {
            "enabled": False,
            "status": "skipped",
            "reason": "no_llm enabled" if self.no_llm else "driver unavailable",
        }
        if not self.no_llm:
            driver = resolve_driver()
            if driver.available():
                prompt = _llm_prompt(models, rag)
                result = driver.execute(prompt=prompt, run_dir=run_dir, timeout_s=self.llm_timeout_s, max_attempts=1)
                trace_rel = write_llm_trace(
                    run_dir=run_dir,
                    stage_name="protocol_model",
                    purpose="protocol-field-hints",
                    prompt=prompt,
                    model_tier="sonnet",
                    result=result,
                    metadata={"driver": driver.name},
                )
                parsed = parse_json_from_llm_output(result.stdout)
                llm_result = {
                    "enabled": True,
                    "driver": driver.name,
                    "status": result.status,
                    "trace": trace_rel,
                    "field_hints": cast(JsonValue, _dict(parsed.get("field_hints") if parsed else None)),
                }
                if result.status != "ok":
                    limitations.append(f"protocol_model LLM hinting did not complete: {result.status}")
            else:
                limitations.append("protocol_model LLM hinting skipped: no configured driver available")

        encoder_path.write_text(_encoder_skeleton(), encoding="utf-8")
        payload: dict[str, JsonValue] = {
            "schema_version": SCHEMA_VERSION,
            "status": "ok" if models else "partial",
            "generated_at": "run-local",
            "claim_boundary": "protocol/input model only; exploit proof requires lab gate and verifier evidence",
            "models": cast(JsonValue, models),
            "rag_context": cast(JsonValue, rag),
            "encoder_skeleton": "stages/protocol_model/encoder_skeleton.py",
            "external_design_refs": [
                "https://docs.pwntools.com/en/stable/util/cyclic.html",
                "https://sourceware.org/gdb/current/onlinedocs/gdb.html/Registers-In-Python.html",
                "https://boofuzz.readthedocs.io/en/stable/user/quickstart.html",
                "https://www.qemu.org/docs/master/user/main.html",
                "https://github.com/JonathanSalwan/ROPgadget",
            ],
            "llm_hints": cast(JsonValue, llm_result),
            "summary": {
                "model_count": len(models),
                "surface_count": len(surfaces),
                "decision_count": len(decisions),
                "rag_item_count": len(rag),
            },
            "limitations": cast(JsonValue, limitations),
        }
        _write_json(out_json, payload)
        return StageOutcome(
            status="ok" if models else "partial",
            details={
                "summary": cast(JsonValue, payload["summary"]),
                "evidence": [
                    {"path": "stages/protocol_model/protocol_model.json"},
                    {"path": "stages/protocol_model/encoder_skeleton.py"},
                ],
            },
            limitations=limitations,
        )
