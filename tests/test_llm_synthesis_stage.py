from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from aiedge.llm_synthesis import LLMSynthesisStage
from aiedge.run import create_run, run_subset
from aiedge.stage import StageContext


def _ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    input_dir = run_dir / "input"
    logs_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    input_dir.mkdir(parents=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _seed_sources(run_dir: Path, *, include_uncited_claim: bool = False) -> None:
    valid_ref = run_dir / "stages" / "inventory" / "svc" / "vendor.conf"
    valid_ref.parent.mkdir(parents=True, exist_ok=True)
    _ = valid_ref.write_text("vendor=Acme\n", encoding="utf-8")

    attribution_claims: list[dict[str, object]] = [
        {
            "claim_type": "vendor",
            "value": "Acme",
            "confidence": 0.9,
            "evidence_refs": ["stages/inventory/svc/vendor.conf"],
        }
    ]
    if include_uncited_claim:
        attribution_claims.append(
            {
                "claim_type": "platform",
                "value": "linux",
                "confidence": 0.7,
                "evidence_refs": ["stages/does-not-exist/nope.txt"],
            }
        )

    _write_json(
        run_dir / "stages" / "attribution" / "attribution.json",
        {
            "status": "ok",
            "summary": {"claims": len(attribution_claims)},
            "claims": attribution_claims,
        },
    )
    _write_json(
        run_dir / "stages" / "surfaces" / "surfaces.json",
        {
            "status": "ok",
            "summary": {"surfaces": 1, "unknowns": 0},
            "surfaces": [],
            "unknowns": [],
        },
    )
    _write_json(
        run_dir / "stages" / "endpoints" / "endpoints.json",
        {
            "status": "ok",
            "summary": {"endpoints": 1},
            "endpoints": [],
        },
    )
    _write_json(
        run_dir / "stages" / "graph" / "comm_graph.json",
        {
            "status": "ok",
            "summary": {"nodes": 2, "edges": 1},
            "nodes": [],
            "edges": [],
        },
    )
    _write_json(
        run_dir / "stages" / "attack_surface" / "attack_surface.json",
        {
            "status": "ok",
            "summary": {"attack_surface_items": 1, "unknowns": 0},
            "attack_surface": [],
            "unknowns": [],
        },
    )
    _write_json(
        run_dir / "stages" / "threat_model" / "threat_model.json",
        {
            "status": "ok",
            "summary": {"threats": 1, "mitigations": 1, "unknowns": 0},
            "threats": [],
            "assumptions": [],
            "mitigations": [],
            "unknowns": [],
        },
    )
    _write_json(
        run_dir / "stages" / "functional_spec" / "functional_spec.json",
        {
            "status": "ok",
            "summary": {"components": 1, "components_with_endpoints": 1},
            "functional_spec": [],
        },
    )


def _read_json(path: Path) -> dict[str, object]:
    raw = cast(object, json.loads(path.read_text(encoding="utf-8")))
    assert isinstance(raw, dict)
    return cast(dict[str, object], raw)


def test_llm_synthesis_stage_deterministic_and_evidence_linked(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    _seed_sources(ctx.run_dir)

    stage = LLMSynthesisStage(no_llm=False)
    out1 = stage.run(ctx)
    assert out1.status == "ok"

    out_path = ctx.run_dir / "stages" / "llm_synthesis" / "llm_synthesis.json"
    text1 = out_path.read_text(encoding="utf-8")

    out2 = stage.run(ctx)
    assert out2.status == "ok"
    text2 = out_path.read_text(encoding="utf-8")
    assert text1 == text2

    payload = _read_json(out_path)
    claims_any = payload.get("claims")
    assert isinstance(claims_any, list)
    claims = cast(list[object], claims_any)
    assert claims
    for claim_any in claims:
        assert isinstance(claim_any, dict)
        claim = cast(dict[str, object], claim_any)
        refs_any = claim.get("evidence_refs")
        assert isinstance(refs_any, list) and refs_any
        for ref_any in cast(list[object], refs_any):
            assert isinstance(ref_any, str)
            assert not ref_any.startswith("/")
            assert (ctx.run_dir / ref_any).exists()


def test_llm_synthesis_drops_uncited_claims(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    _seed_sources(ctx.run_dir, include_uncited_claim=True)

    out = LLMSynthesisStage(no_llm=False).run(ctx)
    assert out.status == "partial"
    assert any("Dropped uncited claim" in x for x in out.limitations)

    payload = _read_json(
        ctx.run_dir / "stages" / "llm_synthesis" / "llm_synthesis.json"
    )
    claims_any = payload.get("claims")
    assert isinstance(claims_any, list)
    claim_types = {
        cast(str, cast(dict[str, object], c).get("claim_type"))
        for c in cast(list[object], claims_any)
        if isinstance(c, dict)
    }
    assert "attribution.platform" not in claim_types


def test_llm_synthesis_stage_no_llm_emits_deterministic_skip(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)

    stage = LLMSynthesisStage(no_llm=True)
    out1 = stage.run(ctx)
    out2 = stage.run(ctx)
    assert out1.status == "skipped"
    assert out2.status == "skipped"

    out_path = ctx.run_dir / "stages" / "llm_synthesis" / "llm_synthesis.json"
    payload = _read_json(out_path)
    assert payload.get("status") == "skipped"
    assert payload.get("reason") == "disabled by --no-llm"


def test_run_subset_with_llm_synthesis_populates_report(tmp_path: Path) -> None:
    fw = tmp_path / "firmware.bin"
    _ = fw.write_bytes(b"llm-synthesis-subset")
    info = create_run(
        str(fw),
        case_id="case-llm-synthesis-subset",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _seed_sources(info.run_dir)

    rep = run_subset(info, ["llm_synthesis"], time_budget_s=10, no_llm=False)
    assert [r.stage for r in rep.stage_results] == ["llm_synthesis"]

    report = _read_json(info.report_json_path)
    section_any = report.get("llm_synthesis")
    assert isinstance(section_any, dict)
    section = cast(dict[str, object], section_any)
    assert section.get("status") == "ok"
    claims_any = section.get("claims")
    assert isinstance(claims_any, list)
    assert claims_any
