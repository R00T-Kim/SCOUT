from __future__ import annotations

import json
from types import SimpleNamespace
from pathlib import Path
from typing import cast

import pytest

from aiedge.llm_synthesis import LLMSynthesisStage
from aiedge.run import analyze_run, create_run, run_subset
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


def _seed_sources(
    run_dir: Path, *, include_uncited_claim: bool = False, include_chain_candidates: bool = False
) -> None:
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
    if include_chain_candidates:
        _write_json(
            run_dir / "stages" / "findings" / "exploit_candidates.json",
            {
                "status": "ok",
                "summary": {"candidate_count": 1, "high": 0, "medium": 1, "low": 0},
                "candidates": [
                    {
                        "candidate_id": "candidate:test-chain",
                        "chain_id": "chain:test",
                        "priority": "medium",
                        "score": 0.81,
                        "families": ["cmd_exec_injection_risk"],
                        "path": "stages/inventory/svc/vendor.conf",
                        "summary": "candidate summary",
                        "attack_hypothesis": "hypothesis",
                        "expected_impact": ["impact"],
                        "validation_plan": ["step"],
                        "evidence_refs": ["stages/inventory/svc/vendor.conf"],
                    }
                ],
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


def test_llm_synthesis_exploit_profile_uses_llm_chain_builder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path)
    _seed_sources(ctx.run_dir, include_chain_candidates=True)
    _write_json(ctx.run_dir / "manifest.json", {"profile": "exploit"})

    def fake_llm_chain_builder(**kwargs: object) -> dict[str, object]:
        _ = kwargs
        return {
            "status": "ok",
            "stdout": json.dumps(
                {
                    "chains": [
                        {
                            "chain_id": "chain-cmd-web",
                            "hypothesis": "web input reaches command sink in service script",
                            "preconditions": ["reachable admin endpoint"],
                            "attack_steps": [
                                "send crafted parameter",
                                "observe command execution side effect",
                            ],
                            "impact": "remote command execution in service context",
                            "confidence": 0.81,
                            "evidence_refs": ["stages/inventory/svc/vendor.conf"],
                        }
                    ]
                },
                sort_keys=True,
            ),
            "stderr": "",
            "argv": ["codex", "exec"],
            "attempts": [],
            "returncode": 0,
        }

    monkeypatch.setattr(
        "aiedge.llm_synthesis._run_codex_chain_builder_exec",
        fake_llm_chain_builder,
    )

    out = LLMSynthesisStage(no_llm=False).run(ctx)
    assert out.status == "ok"

    payload = _read_json(
        ctx.run_dir / "stages" / "llm_synthesis" / "llm_synthesis.json"
    )
    summary = cast(dict[str, object], payload["summary"])
    assert summary.get("llm_chain_attempted") is True
    assert summary.get("llm_chain_status") == "ok"
    assert cast(int, summary.get("llm_chain_claims", 0)) >= 1

    claims_any = payload.get("claims")
    assert isinstance(claims_any, list)
    claim_types = {
        cast(str, cast(dict[str, object], c).get("claim_type"))
        for c in cast(list[object], claims_any)
        if isinstance(c, dict)
    }
    assert any(ct.startswith("llm_chain.") for ct in claim_types)


def test_llm_synthesis_exploit_profile_fallback_on_llm_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path)
    _seed_sources(ctx.run_dir, include_chain_candidates=True)
    _write_json(ctx.run_dir / "manifest.json", {"profile": "exploit"})

    def fake_llm_chain_builder(**kwargs: object) -> dict[str, object]:
        _ = kwargs
        return {
            "status": "missing_cli",
            "stdout": "",
            "stderr": "codex executable not found",
            "argv": [],
            "attempts": [],
            "returncode": -1,
        }

    monkeypatch.setattr(
        "aiedge.llm_synthesis._run_codex_chain_builder_exec",
        fake_llm_chain_builder,
    )

    out = LLMSynthesisStage(no_llm=False).run(ctx)
    assert out.status == "partial"
    assert any("llm_chain_builder_exec_failed:missing_cli" in x for x in out.limitations)

    payload = _read_json(
        ctx.run_dir / "stages" / "llm_synthesis" / "llm_synthesis.json"
    )
    summary = cast(dict[str, object], payload["summary"])
    assert summary.get("llm_chain_attempted") is True
    assert summary.get("llm_chain_status") == "missing_cli"
    assert summary.get("llm_chain_claims") == 0
    claims_any = payload.get("claims")
    assert isinstance(claims_any, list) and claims_any
    claim_types = {
        cast(str, cast(dict[str, object], c).get("claim_type"))
        for c in cast(list[object], claims_any)
        if isinstance(c, dict)
    }
    assert "attribution.vendor" in claim_types


def test_llm_synthesis_accepts_nonzero_exec_payload_when_json_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path)
    _seed_sources(ctx.run_dir, include_chain_candidates=True)
    _write_json(ctx.run_dir / "manifest.json", {"profile": "exploit"})

    def fake_llm_chain_builder(**kwargs: object) -> dict[str, object]:
        _ = kwargs
        return {
            "status": "nonzero_exit",
            "stdout": json.dumps(
                {
                    "chains": [
                        {
                            "chain_id": "chain-from-nonzero",
                            "hypothesis": "payload still emitted despite nonzero exit",
                            "preconditions": ["precondition-1"],
                            "attack_steps": ["step-1"],
                            "impact": "impact",
                            "confidence": 0.74,
                            "evidence_refs": ["stages/inventory/svc/vendor.conf"],
                        }
                    ]
                },
                sort_keys=True,
            ),
            "stderr": "transient transport error",
            "argv": ["codex", "exec"],
            "attempts": [],
            "returncode": 1,
        }

    monkeypatch.setattr(
        "aiedge.llm_synthesis._run_codex_chain_builder_exec",
        fake_llm_chain_builder,
    )

    out = LLMSynthesisStage(no_llm=False).run(ctx)
    assert out.status == "partial"
    assert any(
        "llm_chain_builder_exec_nonzero_used_payload:nonzero_exit" in x
        for x in out.limitations
    )

    payload = _read_json(
        ctx.run_dir / "stages" / "llm_synthesis" / "llm_synthesis.json"
    )
    summary = cast(dict[str, object], payload["summary"])
    assert summary.get("llm_chain_status") == "nonzero_exit"
    assert cast(int, summary.get("llm_chain_claims", 0)) >= 1


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


def test_analyze_run_reruns_llm_synthesis_after_findings_for_exploit_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fw = tmp_path / "firmware.bin"
    _ = fw.write_bytes(b"llm-synthesis-rerun")
    info = create_run(
        str(fw),
        case_id="case-llm-synthesis-rerun",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    manifest = cast(
        dict[str, object],
        json.loads(info.manifest_path.read_text(encoding="utf-8")),
    )
    manifest["profile"] = "exploit"
    _ = info.manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    def fake_run_findings(ctx: StageContext, *, firmware_name: str = "firmware.bin") -> SimpleNamespace:
        _ = firmware_name
        _seed_sources(ctx.run_dir, include_chain_candidates=True)
        return SimpleNamespace(findings=[])

    def fake_apply_llm_exec_step(*, info: object, report: object, no_llm: bool) -> dict[str, object]:
        _ = info, report, no_llm
        return {"status": "skipped", "reason": "test_stub"}

    def fake_llm_chain_builder(**kwargs: object) -> dict[str, object]:
        _ = kwargs
        return {
            "status": "ok",
            "stdout": json.dumps(
                {
                    "chains": [
                        {
                            "chain_id": "rerun-chain",
                            "hypothesis": "rerun should consume findings candidates",
                            "preconditions": ["reachable service"],
                            "attack_steps": ["probe"],
                            "impact": "impact",
                            "confidence": 0.77,
                            "evidence_refs": ["stages/inventory/svc/vendor.conf"],
                        }
                    ]
                },
                sort_keys=True,
            ),
            "stderr": "",
            "argv": ["codex", "exec"],
            "attempts": [],
            "returncode": 0,
        }

    monkeypatch.setattr("aiedge.run.run_findings", fake_run_findings)
    monkeypatch.setattr("aiedge.run._apply_llm_exec_step", fake_apply_llm_exec_step)
    monkeypatch.setattr(
        "aiedge.llm_synthesis._run_codex_chain_builder_exec",
        fake_llm_chain_builder,
    )

    _ = analyze_run(info, time_budget_s=0, no_llm=False)

    payload = _read_json(
        info.run_dir / "stages" / "llm_synthesis" / "llm_synthesis.json"
    )
    summary = cast(dict[str, object], payload["summary"])
    assert summary.get("llm_chain_attempted") is True
    assert summary.get("llm_chain_status") == "ok"
    assert cast(int, summary.get("llm_chain_claims", 0)) >= 1
