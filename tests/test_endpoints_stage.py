from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from aiedge.confidence_caps import EVIDENCE_LEVELS, STATIC_ONLY_CAP
from aiedge.endpoints import EndpointsStage
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


def _write_inventory(
    ctx: StageContext, *, roots: list[str], extracted_dir: str
) -> None:
    inv_path = ctx.run_dir / "stages" / "inventory" / "inventory.json"
    inv_path.parent.mkdir(parents=True, exist_ok=True)
    _ = inv_path.write_text(
        json.dumps(
            {
                "status": "ok",
                "roots": roots,
                "extracted_dir": extracted_dir,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def test_endpoints_stage_extracts_candidates_deterministically(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    root_dir = ctx.run_dir / "stages" / "carving" / "roots" / "root0"
    etc_dir = root_dir / "etc"
    etc_dir.mkdir(parents=True)
    _ = (etc_dir / "config.txt").write_text(
        "\n".join(
            [
                "call https://user:pass@example.com/api/v1",
                "host api.example.org",
                "email Ops@Example.com",
                "ip 192.168.1.22",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _ = (root_dir / "proc" / "net").mkdir(parents=True)
    _ = (root_dir / "proc" / "net" / "trace.txt").write_text(
        "https://ignored.proc.example.com\n",
        encoding="utf-8",
    )
    _ = (etc_dir / "shadow").write_text(
        "https://ignored.shadow.example.com\n",
        encoding="utf-8",
    )

    _write_inventory(
        ctx,
        roots=["stages/carving/roots/root0"],
        extracted_dir="stages/extraction/_firmware.bin.extracted",
    )

    stage = EndpointsStage()
    out1 = stage.run(ctx)
    assert out1.status == "ok"
    endpoints_json = ctx.run_dir / "stages" / "endpoints" / "endpoints.json"
    text1 = endpoints_json.read_text(encoding="utf-8")

    out2 = stage.run(ctx)
    assert out2.status == "ok"
    text2 = endpoints_json.read_text(encoding="utf-8")
    assert text1 == text2

    payload = _read_json_obj(endpoints_json)
    assert payload.get("status") == "ok"
    endpoints_any = payload.get("endpoints")
    assert isinstance(endpoints_any, list)
    endpoints = cast(list[object], endpoints_any)
    assert endpoints

    tuples: list[tuple[str, str]] = []
    saw_sanitized_url = False
    for endpoint_any in endpoints:
        assert isinstance(endpoint_any, dict)
        endpoint = cast(dict[str, object], endpoint_any)
        endpoint_type = endpoint.get("type")
        value = endpoint.get("value")
        confidence = endpoint.get("confidence")
        confidence_calibrated = endpoint.get("confidence_calibrated")
        classification = endpoint.get("classification")
        observation = endpoint.get("observation")
        evidence_level_value = endpoint.get("evidence_level")
        refs_any = endpoint.get("evidence_refs")

        assert isinstance(endpoint_type, str) and endpoint_type
        assert isinstance(value, str) and value
        assert isinstance(confidence, (int, float))
        assert 0.0 <= float(confidence) <= 1.0
        assert isinstance(confidence_calibrated, (int, float))
        assert 0.0 <= float(confidence_calibrated) <= 1.0
        assert classification == "candidate"
        assert observation == "static_reference"
        assert isinstance(evidence_level_value, str)
        assert evidence_level_value in EVIDENCE_LEVELS
        assert float(confidence_calibrated) <= STATIC_ONLY_CAP
        assert isinstance(refs_any, list) and refs_any
        for ref in cast(list[object], refs_any):
            assert isinstance(ref, str) and ref
            assert not ref.startswith("/")

        if endpoint_type == "url" and value.startswith("https://example.com"):
            assert "@" not in value
            saw_sanitized_url = True

        tuples.append((endpoint_type, value))

    assert saw_sanitized_url
    assert tuples == sorted(tuples, key=lambda item: (item[0], item[1]))


def test_endpoints_stage_falls_back_to_inventory_extracted_dir(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    extracted_root = ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted"
    extracted_root.mkdir(parents=True)
    _ = (extracted_root / "hosts.txt").write_text(
        "service.fallback.example.net\n",
        encoding="utf-8",
    )

    _write_inventory(
        ctx,
        roots=[],
        extracted_dir="stages/extraction/_firmware.bin.extracted",
    )

    out = EndpointsStage().run(ctx)
    assert out.status == "ok"
    assert any("fell back to inventory extracted_dir" in x for x in out.limitations)

    payload = _read_json_obj(ctx.run_dir / "stages" / "endpoints" / "endpoints.json")
    endpoints_any = payload.get("endpoints")
    assert isinstance(endpoints_any, list)
    endpoints = cast(list[object], endpoints_any)
    assert any(
        isinstance(item, dict)
        and cast(dict[str, object], item).get("value") == "service.fallback.example.net"
        for item in endpoints
    )


def test_run_subset_with_endpoints_populates_report(tmp_path: Path) -> None:
    firmware = tmp_path / "firmware.bin"
    _ = firmware.write_bytes(b"endpoints-subset")
    info = create_run(
        str(firmware),
        case_id="case-endpoints-subset",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    root_dir = info.run_dir / "stages" / "carving" / "roots" / "root0"
    root_dir.mkdir(parents=True)
    _ = (root_dir / "net.txt").write_text("10.1.2.3\n", encoding="utf-8")
    inv_path = info.run_dir / "stages" / "inventory" / "inventory.json"
    inv_path.parent.mkdir(parents=True, exist_ok=True)
    _ = inv_path.write_text(
        json.dumps(
            {
                "status": "ok",
                "roots": ["stages/carving/roots/root0"],
                "extracted_dir": "stages/extraction/_firmware.bin.extracted",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    rep = run_subset(info, ["endpoints"], time_budget_s=10, no_llm=True)
    assert [r.stage for r in rep.stage_results] == ["endpoints"]

    report = _read_json_obj(info.report_json_path)
    endpoints_obj = report.get("endpoints")
    assert isinstance(endpoints_obj, dict)
    endpoints_section = cast(dict[str, object], endpoints_obj)
    assert endpoints_section.get("status") == "ok"
    endpoint_list_any = endpoints_section.get("endpoints")
    assert isinstance(endpoint_list_any, list)
    assert endpoint_list_any


def test_endpoints_stage_false_positive_controls_for_dotted_noise(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    root_dir = ctx.run_dir / "stages" / "carving" / "roots" / "root0"
    root_dir.mkdir(parents=True)
    _ = (root_dir / "symbols.txt").write_text(
        "\n".join(
            [
                "foo.ko",
                "accountmsg.ko",
                "configblob.ko",
                "authority.runtime",
                "api.example.org",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    _write_inventory(
        ctx,
        roots=["stages/carving/roots/root0"],
        extracted_dir="stages/extraction/_firmware.bin.extracted",
    )

    out = EndpointsStage().run(ctx)
    assert out.status == "ok"

    payload = _read_json_obj(ctx.run_dir / "stages" / "endpoints" / "endpoints.json")
    endpoints_any = payload.get("endpoints")
    assert isinstance(endpoints_any, list)
    endpoints = cast(list[object], endpoints_any)

    domain_values: list[str] = []
    endpoint_tuples: list[tuple[str, str]] = []
    for endpoint_any in endpoints:
        assert isinstance(endpoint_any, dict)
        endpoint = cast(dict[str, object], endpoint_any)
        endpoint_type = endpoint.get("type")
        value = endpoint.get("value")
        confidence_calibrated = endpoint.get("confidence_calibrated")
        evidence_level_value = endpoint.get("evidence_level")
        observation = endpoint.get("observation")
        assert isinstance(endpoint_type, str)
        assert isinstance(value, str)
        assert isinstance(confidence_calibrated, (int, float))
        assert 0.0 <= float(confidence_calibrated) <= 1.0
        assert isinstance(evidence_level_value, str)
        assert evidence_level_value in EVIDENCE_LEVELS
        if observation == "static_reference":
            assert float(confidence_calibrated) <= STATIC_ONLY_CAP
        endpoint_tuples.append((endpoint_type, value))
        if endpoint_type == "domain":
            domain_values.append(value)

    assert endpoint_tuples == sorted(
        endpoint_tuples, key=lambda item: (item[0], item[1])
    )
    assert "api.example.org" in domain_values
    assert "foo.ko" not in domain_values
    assert "accountmsg.ko" not in domain_values
    assert "configblob.ko" not in domain_values
    assert "authority.runtime" not in domain_values
