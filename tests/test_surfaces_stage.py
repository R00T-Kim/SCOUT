from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from aiedge.confidence_caps import EVIDENCE_LEVELS, STATIC_ONLY_CAP
from aiedge.run import create_run, run_subset
from aiedge.stage import StageContext
from aiedge.surfaces import SurfacesStage


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


def _write_inventory(
    ctx: StageContext, *, service_candidates: list[dict[str, object]]
) -> None:
    inv_path = ctx.run_dir / "stages" / "inventory" / "inventory.json"
    inv_path.parent.mkdir(parents=True, exist_ok=True)
    _ = inv_path.write_text(
        json.dumps(
            {
                "status": "ok",
                "service_candidates": service_candidates,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_endpoints(ctx: StageContext, *, endpoints: list[dict[str, object]]) -> None:
    endpoints_path = ctx.run_dir / "stages" / "endpoints" / "endpoints.json"
    endpoints_path.parent.mkdir(parents=True, exist_ok=True)
    _ = endpoints_path.write_text(
        json.dumps(
            {
                "status": "ok",
                "summary": {
                    "roots_scanned": 1,
                    "files_scanned": 1,
                    "endpoints": len(endpoints),
                    "matches_seen": len(endpoints),
                    "classification": "candidate",
                    "observation": "static_reference",
                },
                "endpoints": endpoints,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def test_surfaces_stage_is_deterministic_and_contract_safe(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory(
        ctx,
        service_candidates=[
            {
                "name": "dropbear",
                "kind": "init_script",
                "confidence": 0.62,
                "evidence": [{"path": "stages/carving/root/etc/init.d/dropbear"}],
            },
            {
                "name": "dropbear",
                "kind": "init_script",
                "confidence": 0.64,
                "evidence": [{"path": "stages/carving/root/etc/default/dropbear"}],
            },
            {
                "name": "nginx",
                "kind": "init_script",
                "confidence": 0.72,
                "evidence": [{"path": "stages/carving/root/etc/init.d/nginx"}],
            },
            {
                "name": "nginx",
                "kind": "systemd_unit",
                "confidence": 0.81,
                "evidence": [
                    {"path": "stages/carving/root/usr/lib/systemd/nginx.service"}
                ],
            },
            {
                "name": "telemetry-agent",
                "kind": "supervisor_conf",
                "confidence": 0.51,
                "evidence": [
                    {"path": "stages/carving/root/etc/supervisor/telemetry.conf"}
                ],
            },
        ],
    )

    stage = SurfacesStage()
    out1 = stage.run(ctx)
    assert out1.status == "ok"
    surfaces_json = ctx.run_dir / "stages" / "surfaces" / "surfaces.json"
    text1 = surfaces_json.read_text(encoding="utf-8")

    out2 = stage.run(ctx)
    assert out2.status == "ok"
    text2 = surfaces_json.read_text(encoding="utf-8")
    assert text1 == text2

    payload = _read_json_obj(surfaces_json)
    assert payload.get("status") == "ok"
    surfaces_any = payload.get("surfaces")
    assert isinstance(surfaces_any, list)
    surfaces = cast(list[object], surfaces_any)
    assert surfaces

    tuples: list[tuple[str, str]] = []
    components: set[str] = set()
    for surface_any in surfaces:
        assert isinstance(surface_any, dict)
        surface = cast(dict[str, object], surface_any)
        surface_type = surface.get("surface_type")
        component = surface.get("component")
        confidence = surface.get("confidence")
        confidence_calibrated = surface.get("confidence_calibrated")
        evidence_level_value = surface.get("evidence_level")
        observation = surface.get("observation")
        refs_any = surface.get("evidence_refs")
        assert isinstance(surface_type, str) and surface_type
        assert isinstance(component, str) and component
        assert isinstance(confidence, (int, float))
        assert 0.0 <= float(confidence) <= 1.0
        assert isinstance(confidence_calibrated, (int, float))
        assert 0.0 <= float(confidence_calibrated) <= 1.0
        assert isinstance(evidence_level_value, str)
        assert evidence_level_value in EVIDENCE_LEVELS
        assert surface.get("classification") == "candidate"
        assert observation == "static_reference"
        assert float(confidence_calibrated) <= STATIC_ONLY_CAP
        assert isinstance(refs_any, list) and refs_any
        for ref in cast(list[object], refs_any):
            assert isinstance(ref, str) and ref
            assert not ref.startswith("/")
        tuples.append((surface_type, component))
        components.add(component)

    assert tuples == sorted(tuples, key=lambda item: (item[0], item[1]))
    assert "init_script:nginx" in components
    assert "systemd_unit:nginx" in components


def test_surfaces_stage_unknowns_when_endpoints_exist_without_service_owner(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory(ctx, service_candidates=[])
    _write_endpoints(
        ctx,
        endpoints=[
            {
                "type": "url",
                "value": "https://api.example.test/v1",
                "confidence": 0.8,
                "classification": "candidate",
                "observation": "static_reference",
                "evidence_refs": ["stages/carving/root/etc/config.txt"],
            }
        ],
    )

    outcome = SurfacesStage().run(ctx)
    assert outcome.status == "partial"

    payload = _read_json_obj(ctx.run_dir / "stages" / "surfaces" / "surfaces.json")
    assert payload.get("status") == "partial"
    unknowns_any = payload.get("unknowns")
    assert isinstance(unknowns_any, list)
    unknowns = cast(list[object], unknowns_any)
    assert unknowns
    first_unknown = cast(dict[str, object], unknowns[0])
    refs_any = first_unknown.get("evidence_refs")
    assert isinstance(refs_any, list) and refs_any
    assert "stages/endpoints/endpoints.json" in cast(list[object], refs_any)


def test_run_subset_with_surfaces_populates_report(tmp_path: Path) -> None:
    firmware = tmp_path / "firmware.bin"
    _ = firmware.write_bytes(b"surfaces-subset")
    info = create_run(
        str(firmware),
        case_id="case-surfaces-subset",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    inv_path = info.run_dir / "stages" / "inventory" / "inventory.json"
    inv_path.parent.mkdir(parents=True, exist_ok=True)
    _ = inv_path.write_text(
        json.dumps(
            {
                "status": "ok",
                "service_candidates": [
                    {
                        "name": "dnsmasq",
                        "kind": "init_script",
                        "confidence": 0.7,
                        "evidence": [
                            {"path": "stages/carving/roots/root0/etc/init.d/dnsmasq"}
                        ],
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    rep = run_subset(info, ["surfaces"], time_budget_s=10, no_llm=True)
    assert [r.stage for r in rep.stage_results] == ["surfaces"]

    report = _read_json_obj(info.report_json_path)
    surfaces_obj = report.get("surfaces")
    assert isinstance(surfaces_obj, dict)
    surfaces_section = cast(dict[str, object], surfaces_obj)
    assert surfaces_section.get("status") == "ok"
    surfaces_list_any = surfaces_section.get("surfaces")
    assert isinstance(surfaces_list_any, list)
    assert surfaces_list_any


def test_surfaces_stage_applies_surface_cap_deterministically(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory(
        ctx,
        service_candidates=[
            {
                "name": "dropbear",
                "kind": "init_script",
                "confidence": 0.6,
                "evidence": [{"path": "stages/r0/dropbear"}],
            },
            {
                "name": "nginx",
                "kind": "init_script",
                "confidence": 0.7,
                "evidence": [{"path": "stages/r0/nginx"}],
            },
        ],
    )

    outcome = SurfacesStage(max_surfaces=1).run(ctx)
    assert outcome.status == "ok"
    assert any("max_surfaces cap" in x for x in outcome.limitations)

    payload = _read_json_obj(ctx.run_dir / "stages" / "surfaces" / "surfaces.json")
    surfaces_any = payload.get("surfaces")
    assert isinstance(surfaces_any, list)
    assert len(cast(list[object], surfaces_any)) == 1
