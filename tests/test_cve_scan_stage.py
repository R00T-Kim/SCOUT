from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aiedge.cve_scan import CveScanStage
from aiedge.stage import StageContext


def _ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    logs_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


def _read_json(path: Path) -> dict[str, object]:
    raw = cast(object, json.loads(path.read_text(encoding="utf-8")))
    assert isinstance(raw, dict)
    return cast(dict[str, object], raw)


def test_cve_scan_signature_only_still_builds_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path)

    monkeypatch.setattr("aiedge.cve_scan._load_cpe_index", lambda _run_dir: ([], []))
    monkeypatch.setattr(
        CveScanStage,
        "_match_known_cve_signatures",
        lambda self, _run_dir: [
            {
                "cve_id": "CVE-2024-0001",
                "cvss_v3_score": 9.8,
                "confidence": 0.7,
                "description": "known signature match",
                "entry_point": "httpd",
            }
        ],
    )
    monkeypatch.setattr(
        "aiedge.cve_scan._query_epss_with_cache",
        lambda *args, **kwargs: ({}, False),
    )

    stage = CveScanStage(
        run_dir=ctx.run_dir,
        case_id="netgear-r7000",
        remaining_budget_s=lambda: 600.0,
        no_llm=False,
    )
    out = stage.run(ctx)

    assert out.status == "partial"
    payload = _read_json(ctx.run_dir / "stages" / "cve_scan" / "cve_matches.json")
    assert payload["source"] == "known_signature_only"
    candidates = cast(list[object], payload["finding_candidates"])
    assert len(candidates) == 1
    first = cast(dict[str, object], candidates[0])
    assert first["cve_id"] == "CVE-2024-0001"
    assert first["severity"] == "critical"


def test_cve_scan_uses_per_match_component_metadata_for_backport_adjustment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path)
    components = [
        {
            "name": "busybox",
            "version": "1.0",
            "cpe": "cpe:2.3:a:busybox:busybox:1.0:*:*:*:*:*:*:*",
            "patch_revision": "5",
            "detection_method": "opkg",
        },
        {
            "name": "dropbear",
            "version": "2.0",
            "cpe": "cpe:2.3:a:dropbear:dropbear:2.0:*:*:*:*:*:*:*",
        },
    ]
    monkeypatch.setattr(
        "aiedge.cve_scan._load_cpe_index", lambda _run_dir: (components, [])
    )
    monkeypatch.setattr(
        "aiedge.cve_scan._query_nvd_with_cache",
        lambda *args, **kwargs: {"vulnerabilities": [{"dummy": True}]},
    )

    def _fake_extract(
        _cve_item: object,
        *,
        component_name: str,
        component_version: str,
        cpe_name: str,
        component_metadata: dict[str, object] | None = None,
    ) -> list[dict[str, object]]:
        _ = cpe_name
        return [
            {
                "component": component_name,
                "version": component_version,
                "cve_id": f"CVE-{component_name}",
                "cvss_v3_score": 9.0,
                "match_confidence": 0.9,
                "match_type": "exact_version",
                "description": "nvd match",
                "evidence_ref": f"nvd_api:CVE-{component_name}",
                "component_metadata": component_metadata,
                "epss": None,
                "epss_percentile": None,
            }
        ]

    monkeypatch.setattr("aiedge.cve_scan._extract_cve_entry", _fake_extract)
    monkeypatch.setattr(
        CveScanStage,
        "_match_known_cve_signatures",
        lambda self, _run_dir: [],
    )
    monkeypatch.setattr(
        "aiedge.cve_scan._query_epss_with_cache",
        lambda *args, **kwargs: ({}, False),
    )

    stage = CveScanStage(
        run_dir=ctx.run_dir,
        case_id=None,
        remaining_budget_s=lambda: 600.0,
        no_llm=False,
    )
    out = stage.run(ctx)

    assert out.status == "ok"
    payload = _read_json(ctx.run_dir / "stages" / "cve_scan" / "cve_matches.json")
    candidates = {
        cast(dict[str, object], item)["component"]: cast(dict[str, object], item)
        for item in cast(list[object], payload["finding_candidates"])
        if isinstance(item, dict)
    }
    # PR #15: backport detection no longer modifies the strict-static
    # detection_confidence -- it now feeds priority_score instead.
    # Detection confidence must be IDENTICAL for the two findings (same
    # match_confidence, same CVSS, same static cap).
    assert float(candidates["busybox"]["confidence"]) == pytest.approx(
        float(candidates["dropbear"]["confidence"]), abs=1e-9
    )
    # Backport effect must show up on priority_score (-0.20 penalty).
    assert float(candidates["busybox"]["priority_score"]) < float(
        candidates["dropbear"]["priority_score"]
    )
    busybox_inputs = cast(dict[str, object], candidates["busybox"]["priority_inputs"])
    dropbear_inputs = cast(dict[str, object], candidates["dropbear"]["priority_inputs"])
    assert busybox_inputs["backport_present"] is True
    assert dropbear_inputs["backport_present"] is False


def test_cve_scan_applies_epss_enrichment_and_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path)
    components = [
        {
            "name": "dnsmasq",
            "version": "2.0",
            "cpe": "cpe:2.3:a:dnsmasq:dnsmasq:2.0:*:*:*:*:*:*:*",
        }
    ]
    monkeypatch.setattr(
        "aiedge.cve_scan._load_cpe_index", lambda _run_dir: (components, [])
    )
    monkeypatch.setattr(
        "aiedge.cve_scan._query_nvd_with_cache",
        lambda *args, **kwargs: {"vulnerabilities": [{"dummy": True}]},
    )
    monkeypatch.setattr(
        "aiedge.cve_scan._extract_cve_entry",
        lambda *args, **kwargs: [
            {
                "component": "dnsmasq",
                "version": "2.0",
                "cve_id": "CVE-2024-9999",
                "cvss_v3_score": 8.0,
                "match_confidence": 0.9,
                "match_type": "exact_version",
                "description": "nvd match",
                "evidence_ref": "nvd_api:CVE-2024-9999",
                "component_metadata": None,
                "epss": None,
                "epss_percentile": None,
            }
        ],
    )
    monkeypatch.setattr(
        CveScanStage,
        "_match_known_cve_signatures",
        lambda self, _run_dir: [],
    )

    def _fake_query_epss(
        cve_ids: list[str],
        *,
        per_run_cache_dir: Path,
        cross_run_cache_dir: Path | None,
        run_dir: Path,
        stats: dict[str, int],
    ) -> tuple[dict[str, dict[str, object]], bool]:
        _ = (per_run_cache_dir, cross_run_cache_dir, run_dir)
        stats["epss_api_calls"] += 1
        return (
            {
                cve_ids[0]: {
                    "cve": cve_ids[0],
                    "epss": 0.2,
                    "percentile": 0.95,
                    "source": "first_epss_api",
                }
            },
            False,
        )

    monkeypatch.setattr("aiedge.cve_scan._query_epss_with_cache", _fake_query_epss)

    stage = CveScanStage(
        run_dir=ctx.run_dir,
        case_id=None,
        remaining_budget_s=lambda: 600.0,
        no_llm=False,
    )
    out = stage.run(ctx)

    assert out.status == "ok"
    payload = _read_json(ctx.run_dir / "stages" / "cve_scan" / "cve_matches.json")
    summary = cast(dict[str, object], payload["summary"])
    assert summary["epss_api_calls"] == 1
    assert summary["epss_enriched"] == 1
    match = cast(dict[str, object], cast(list[object], payload["matches"])[0])
    assert match["epss"] == 0.2
    candidate = cast(
        dict[str, object], cast(list[object], payload["finding_candidates"])[0]
    )
    assert float(candidate["epss"]) == 0.2
    assert float(candidate["confidence"]) > 0.4
