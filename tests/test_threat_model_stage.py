from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from aiedge.run import create_run, run_subset
from aiedge.stage import StageContext
from aiedge.threat_model import ThreatModelStage


def _ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    input_dir = run_dir / "input"
    logs_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    input_dir.mkdir(parents=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


def _read_json_obj(path: Path) -> dict[str, object]:
    raw = cast(object, json.loads(path.read_text(encoding="utf-8")))
    assert isinstance(raw, dict)
    return cast(dict[str, object], raw)


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _seed_attack_surface(run_dir: Path) -> None:
    _write_json(
        run_dir / "stages" / "attack_surface" / "attack_surface.json",
        {
            "status": "ok",
            "summary": {
                "attack_surface_items": 2,
                "unknowns": 1,
            },
            "attack_surface": [
                {
                    "surface": {"surface_type": "web", "component": "httpd"},
                    "endpoint": {"type": "url", "value": "https://api.example.test/v1"},
                    "evidence_refs": ["stages/inventory/svc/httpd.conf"],
                },
                {
                    "surface": {"surface_type": "cloud", "component": "updater"},
                    "endpoint": {
                        "type": "domain",
                        "value": "firmware-update.example.test",
                    },
                    "evidence_refs": ["stages/inventory/svc/updater.conf"],
                },
            ],
            "unknowns": [
                {
                    "reason": "Endpoint exists but no deterministic mapping path was found",
                    "endpoint": {"type": "domain", "value": "orphan.example.test"},
                    "evidence_refs": ["stages/inventory/svc/orphan.conf"],
                }
            ],
            "non_promoted": [
                {
                    "reason": "Reference-only linkage without runtime communication evidence",
                    "surface": {"surface_type": "web", "component": "httpd"},
                    "endpoint": {"type": "domain", "value": "ref-only.example.test"},
                    "evidence_refs": ["stages/inventory/svc/ref-only.conf"],
                }
            ],
        },
    )


def _seed_attack_surface_ref_only(run_dir: Path) -> None:
    _write_json(
        run_dir / "stages" / "attack_surface" / "attack_surface.json",
        {
            "status": "partial",
            "summary": {
                "attack_surface_items": 0,
                "unknowns": 0,
                "non_promoted": 1,
            },
            "attack_surface": [],
            "unknowns": [],
            "non_promoted": [
                {
                    "reason": "Reference-only linkage without runtime communication evidence",
                    "surface": {"surface_type": "cloud", "component": "updater"},
                    "endpoint": {
                        "type": "domain",
                        "value": "firmware-update.example.test",
                    },
                    "evidence_refs": ["stages/inventory/svc/updater.conf"],
                }
            ],
        },
    )


def test_threat_model_stage_deterministic_and_evidence_non_empty(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    _seed_attack_surface(ctx.run_dir)

    stage = ThreatModelStage()
    out1 = stage.run(ctx)
    assert out1.status == "ok"
    out_path = ctx.run_dir / "stages" / "threat_model" / "threat_model.json"
    text1 = out_path.read_text(encoding="utf-8")

    out2 = stage.run(ctx)
    assert out2.status == "ok"
    text2 = out_path.read_text(encoding="utf-8")
    assert text1 == text2

    payload = _read_json_obj(out_path)
    threats_any = payload.get("threats")
    assert isinstance(threats_any, list)
    threats = cast(list[object], threats_any)
    assert threats

    for threat_any in threats:
        assert isinstance(threat_any, dict)
        threat = cast(dict[str, object], threat_any)
        refs_any = threat.get("evidence_refs")
        assert isinstance(refs_any, list) and refs_any
        for ref in cast(list[object], refs_any):
            assert isinstance(ref, str)
            assert not ref.startswith("/")


def test_threat_model_stage_partial_without_attack_surface_input(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)

    outcome = ThreatModelStage().run(ctx)
    assert outcome.status == "partial"
    assert any(
        "Attack-surface output missing or invalid" in x for x in outcome.limitations
    )

    out_path = ctx.run_dir / "stages" / "threat_model" / "threat_model.json"
    payload = _read_json_obj(out_path)
    assert payload.get("status") == "partial"
    threats_any = payload.get("threats")
    assert isinstance(threats_any, list)
    assert not cast(list[object], threats_any)


def test_threat_model_stage_compatible_with_empty_promoted_attack_surface(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    _seed_attack_surface_ref_only(ctx.run_dir)

    outcome = ThreatModelStage().run(ctx)
    assert outcome.status == "partial"
    assert any(
        "No attack-surface items available for deterministic threat modeling" in x
        for x in outcome.limitations
    )

    out_path = ctx.run_dir / "stages" / "threat_model" / "threat_model.json"
    payload = _read_json_obj(out_path)
    assert payload.get("status") == "partial"
    summary_any = payload.get("summary")
    assert isinstance(summary_any, dict)
    summary = cast(dict[str, object], summary_any)
    assert summary.get("attack_surface_items") == 0
    threats_any = payload.get("threats")
    assert isinstance(threats_any, list)
    assert not cast(list[object], threats_any)


def test_run_subset_with_threat_model_populates_report(tmp_path: Path) -> None:
    firmware = tmp_path / "firmware.bin"
    _ = firmware.write_bytes(b"threat-model-subset")
    info = create_run(
        str(firmware),
        case_id="case-threat-model-subset",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _seed_attack_surface(info.run_dir)

    rep = run_subset(info, ["threat_model"], time_budget_s=10, no_llm=True)
    assert [r.stage for r in rep.stage_results] == ["threat_model"]

    report = _read_json_obj(info.report_json_path)
    threat_model_obj = report.get("threat_model")
    assert isinstance(threat_model_obj, dict)
    section = cast(dict[str, object], threat_model_obj)
    assert section.get("status") == "ok"
    threats_any = section.get("threats")
    assert isinstance(threats_any, list)
    assert threats_any
