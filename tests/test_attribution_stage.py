from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from aiedge.attribution import AttributionStage
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


def _write_inventory(ctx: StageContext, roots: list[str], extracted_dir: str) -> None:
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


def _write_extraction_manifest(ctx: StageContext) -> None:
    manifest_path = ctx.run_dir / "stages" / "extraction" / "stage.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    _ = manifest_path.write_text("{}\n", encoding="utf-8")


def test_attribution_android_build_prop_claim_contract(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    root_dir = ctx.run_dir / "stages" / "carving" / "roots" / "root0"
    build_prop = root_dir / "system" / "build.prop"
    build_prop.parent.mkdir(parents=True)
    _ = build_prop.write_text(
        "\n".join(
            [
                "ro.product.manufacturer=AcmeDevices",
                "ro.product.model=Rocket-3000",
                "ro.build.version.release=14",
                "ro.build.display.id=UP1A.231005.007",
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
    _write_extraction_manifest(ctx)

    outcome = AttributionStage().run(ctx)
    assert outcome.status == "ok"

    out_path = ctx.run_dir / "stages" / "attribution" / "attribution.json"
    out = _read_json_obj(out_path)
    assert out.get("status") == "ok"

    claims_any = out.get("claims")
    assert isinstance(claims_any, list)
    claims = cast(list[object], claims_any)
    assert claims

    types_seen: set[str] = set()
    for claim_any in claims:
        assert isinstance(claim_any, dict)
        claim = cast(dict[str, object], claim_any)
        claim_type = claim.get("claim_type")
        value = claim.get("value")
        confidence = claim.get("confidence")
        refs = claim.get("evidence_refs")
        assert isinstance(claim_type, str) and claim_type
        assert isinstance(value, str) and value
        assert isinstance(confidence, (int, float))
        assert 0.0 <= float(confidence) <= 1.0
        assert isinstance(refs, list) and refs
        for ref in refs:
            assert isinstance(ref, str) and ref
            assert not ref.startswith("/")
        types_seen.add(claim_type)

    assert {"vendor", "product", "version", "platform"}.issubset(types_seen)


def test_attribution_non_android_is_deterministic(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    root_dir = ctx.run_dir / "stages" / "carving" / "roots" / "root0"
    etc_dir = root_dir / "etc"
    etc_dir.mkdir(parents=True)
    _ = (etc_dir / "os-release").write_text(
        "\n".join(
            [
                "NAME=OpenWrt",
                "ID=openwrt",
                "VERSION_ID=23.05.2",
                "VERSION=23.05.2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _ = (etc_dir / "version").write_text("OpenWrt 23.05.2\n", encoding="utf-8")

    _write_inventory(
        ctx,
        roots=["stages/carving/roots/root0"],
        extracted_dir="stages/extraction/_firmware.bin.extracted",
    )
    _write_extraction_manifest(ctx)

    stage = AttributionStage()
    out1 = stage.run(ctx)
    assert out1.status == "ok"
    json_path = ctx.run_dir / "stages" / "attribution" / "attribution.json"
    text1 = json_path.read_text(encoding="utf-8")

    out2 = stage.run(ctx)
    assert out2.status == "ok"
    text2 = json_path.read_text(encoding="utf-8")

    assert text1 == text2
    payload = _read_json_obj(json_path)
    claims_any = payload.get("claims")
    assert isinstance(claims_any, list)
    claims = cast(list[object], claims_any)
    assert any(
        isinstance(item, dict)
        and cast(dict[str, object], item).get("claim_type") == "platform"
        and cast(dict[str, object], item).get("value") == "linux"
        for item in claims
    )


def test_attribution_partial_when_inventory_and_extraction_missing(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)

    outcome = AttributionStage().run(ctx)
    assert outcome.status == "partial"
    assert any("Inventory output missing" in x for x in outcome.limitations)
    assert any("Extraction manifest missing" in x for x in outcome.limitations)

    out_path = ctx.run_dir / "stages" / "attribution" / "attribution.json"
    payload = _read_json_obj(out_path)
    assert payload.get("status") == "partial"
    claims_any = payload.get("claims")
    assert isinstance(claims_any, list)
    assert not cast(list[object], claims_any)
