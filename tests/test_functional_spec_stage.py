from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from aiedge.functional_spec import FunctionalSpecStage
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


def _seed_functional_spec_inputs(run_dir: Path) -> None:
    _write_json(
        run_dir / "stages" / "surfaces" / "surfaces.json",
        {
            "status": "ok",
            "surfaces": [
                {
                    "surface_type": "web",
                    "component": "httpd",
                    "confidence": 0.82,
                    "classification": "candidate",
                    "observation": "static_reference",
                    "evidence_refs": ["stages/inventory/svc/httpd.conf"],
                },
                {
                    "surface_type": "dns_dhcp",
                    "component": "dnsmasq",
                    "confidence": 0.74,
                    "classification": "candidate",
                    "observation": "static_reference",
                    "evidence_refs": ["stages/inventory/svc/dnsmasq.conf"],
                },
            ],
        },
    )
    _write_json(
        run_dir / "stages" / "inventory" / "inventory.json",
        {
            "status": "ok",
            "service_candidates": [
                {
                    "name": "httpd",
                    "kind": "init_script",
                    "confidence": 0.71,
                    "evidence": [{"path": "stages/carving/root/etc/init.d/httpd"}],
                },
                {
                    "name": "watchdogd",
                    "kind": "systemd_unit",
                    "confidence": 0.69,
                    "evidence": [
                        {
                            "path": "stages/carving/root/usr/lib/systemd/watchdogd.service"
                        }
                    ],
                },
            ],
        },
    )
    _write_json(
        run_dir / "stages" / "endpoints" / "endpoints.json",
        {
            "status": "ok",
            "endpoints": [
                {
                    "type": "url",
                    "value": "https://api.example.test/v1",
                    "confidence": 0.8,
                    "classification": "candidate",
                    "observation": "static_reference",
                    "evidence_refs": ["stages/inventory/svc/httpd.conf"],
                },
                {
                    "type": "domain",
                    "value": "dns.example.test",
                    "confidence": 0.7,
                    "classification": "candidate",
                    "observation": "static_reference",
                    "evidence_refs": ["stages/inventory/svc/dnsmasq.conf"],
                },
            ],
        },
    )


def test_functional_spec_stage_deterministic_and_evidence_non_empty(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    _seed_functional_spec_inputs(ctx.run_dir)

    stage = FunctionalSpecStage()
    out1 = stage.run(ctx)
    assert out1.status == "ok"
    out_path = ctx.run_dir / "stages" / "functional_spec" / "functional_spec.json"
    text1 = out_path.read_text(encoding="utf-8")

    out2 = stage.run(ctx)
    assert out2.status == "ok"
    text2 = out_path.read_text(encoding="utf-8")
    assert text1 == text2

    payload = _read_json_obj(out_path)
    spec_any = payload.get("functional_spec")
    assert isinstance(spec_any, list)
    specs = cast(list[object], spec_any)
    assert specs

    for item_any in specs:
        assert isinstance(item_any, dict)
        item = cast(dict[str, object], item_any)
        assert isinstance(item.get("component"), str) and item.get("component")
        assert isinstance(item.get("inputs"), list)
        assert isinstance(item.get("outputs"), list)
        trust_any = item.get("trust_boundaries")
        assert isinstance(trust_any, list)
        assert "device_boundary" in cast(list[object], trust_any)
        assert "network_boundary" in cast(list[object], trust_any)
        refs_any = item.get("evidence_refs")
        assert isinstance(refs_any, list) and refs_any
        for ref in cast(list[object], refs_any):
            assert isinstance(ref, str)
            assert not ref.startswith("/")


def test_run_subset_with_functional_spec_populates_report(tmp_path: Path) -> None:
    firmware = tmp_path / "firmware.bin"
    _ = firmware.write_bytes(b"functional-spec-subset")
    info = create_run(
        str(firmware),
        case_id="case-functional-spec-subset",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _seed_functional_spec_inputs(info.run_dir)

    rep = run_subset(info, ["functional_spec"], time_budget_s=10, no_llm=True)
    assert [r.stage for r in rep.stage_results] == ["functional_spec"]

    report = _read_json_obj(info.report_json_path)
    section_any = report.get("functional_spec")
    assert isinstance(section_any, dict)
    section = cast(dict[str, object], section_any)
    assert section.get("status") == "ok"
    items_any = section.get("functional_spec")
    assert isinstance(items_any, list)
    assert items_any


def test_functional_spec_stage_partial_when_surface_inputs_missing(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    _write_json(
        ctx.run_dir / "stages" / "inventory" / "inventory.json",
        {
            "status": "ok",
            "service_candidates": [
                {
                    "name": "watchdogd",
                    "kind": "systemd_unit",
                    "confidence": 0.69,
                    "evidence": [
                        {
                            "path": "stages/carving/root/usr/lib/systemd/watchdogd.service"
                        }
                    ],
                }
            ],
        },
    )
    _write_json(
        ctx.run_dir / "stages" / "endpoints" / "endpoints.json",
        {
            "status": "ok",
            "endpoints": [
                {
                    "type": "domain",
                    "value": "orphan.example.test",
                    "confidence": 0.7,
                    "classification": "candidate",
                    "observation": "static_reference",
                    "evidence_refs": ["stages/inventory/svc/orphan.conf"],
                }
            ],
        },
    )

    outcome = FunctionalSpecStage().run(ctx)
    assert outcome.status == "partial"
    assert any("Surfaces output missing or invalid" in x for x in outcome.limitations)

    payload = _read_json_obj(
        ctx.run_dir / "stages" / "functional_spec" / "functional_spec.json"
    )
    assert payload.get("status") == "partial"
    spec_any = payload.get("functional_spec")
    assert isinstance(spec_any, list)
    specs = cast(list[object], spec_any)
    assert specs
    first = cast(dict[str, object], specs[0])
    inputs_any = first.get("inputs")
    assert isinstance(inputs_any, list)
    assert not cast(list[object], inputs_any)
