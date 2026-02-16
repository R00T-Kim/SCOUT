from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aiedge.attack_surface import AttackSurfaceStage
from aiedge.endpoints import EndpointsStage
from aiedge.graph import GraphStage
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


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _assert_no_absolute_path_fields(value: object) -> None:
    if isinstance(value, dict):
        obj = cast(dict[str, object], value)
        for key, item in sorted(obj.items(), key=lambda kv: kv[0]):
            if key == "path" and isinstance(item, str):
                assert not item.startswith("/")
            _assert_no_absolute_path_fields(item)
        return
    if isinstance(value, list):
        for item in cast(list[object], value):
            _assert_no_absolute_path_fields(item)


def test_downstream_stages_remain_path_safe_when_resolve_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path)

    deny_root = ctx.run_dir / "stages" / "carving" / "roots" / "denyresolve"
    ok_root = ctx.run_dir / "stages" / "carving" / "roots" / "root0"
    deny_root.mkdir(parents=True)
    (ok_root / "etc").mkdir(parents=True)
    _ = (ok_root / "etc" / "config.txt").write_text(
        "https://api.example.test/v1\n",
        encoding="utf-8",
    )

    _write_json(
        ctx.run_dir / "stages" / "inventory" / "inventory.json",
        {
            "status": "ok",
            "roots": [
                "stages/carving/roots/denyresolve",
                "stages/carving/roots/root0",
            ],
            "extracted_dir": "stages/extraction/_firmware.bin.extracted",
            "service_candidates": [
                {
                    "name": "httpd",
                    "kind": "init_script",
                    "confidence": 0.8,
                    "evidence": [{"path": "stages/carving/roots/root0/etc/config.txt"}],
                }
            ],
        },
    )
    _write_json(
        ctx.run_dir / "stages" / "attribution" / "attribution.json",
        {
            "status": "ok",
            "claims": [
                {
                    "claim_type": "vendor",
                    "value": "acme",
                    "confidence": 0.7,
                    "evidence_refs": ["stages/attribution/claims.txt"],
                }
            ],
        },
    )

    original_resolve = Path.resolve

    def _resolve_with_permission_denial(self: Path, strict: bool = False) -> Path:
        if "denyresolve" in str(self):
            raise PermissionError("simulated resolve permission denied")
        return original_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", _resolve_with_permission_denial)

    assert EndpointsStage().run(ctx).status in {"ok", "partial"}
    assert SurfacesStage().run(ctx).status in {"ok", "partial"}
    assert GraphStage().run(ctx).status in {"ok", "partial"}
    assert AttackSurfaceStage().run(ctx).status in {"ok", "partial"}

    artifact_paths = [
        ctx.run_dir / "stages" / "endpoints" / "endpoints.json",
        ctx.run_dir / "stages" / "surfaces" / "surfaces.json",
        ctx.run_dir / "stages" / "graph" / "comm_graph.json",
        ctx.run_dir / "stages" / "graph" / "reference_graph.json",
        ctx.run_dir / "stages" / "graph" / "communication_graph.json",
        ctx.run_dir / "stages" / "attack_surface" / "attack_surface.json",
    ]

    for artifact_path in artifact_paths:
        assert artifact_path.is_file()
        text = artifact_path.read_text(encoding="utf-8")
        assert "/home/" not in text
        parsed = cast(object, json.loads(text))
        _assert_no_absolute_path_fields(parsed)
