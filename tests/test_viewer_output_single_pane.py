from __future__ import annotations

from pathlib import Path
from typing import cast

import aiedge.reporting as reporting
from aiedge.schema import JsonValue


def _report_with_claims(claims: list[dict[str, object]]) -> dict[str, object]:
    return {
        "limitations": [],
        "claims": claims,
        "attribution": {},
        "endpoints": {},
        "surfaces": {},
        "graph": {},
        "attack_surface": {},
        "threat_model": {},
        "functional_spec": {},
        "poc_validation": {},
        "llm_synthesis": {},
    }


def _build_viewer_html(tmp_path: Path) -> str:
    report = _report_with_claims(
        [
            {
                "claim_type": "test-claim",
                "value": "test-claim",
                "severity": "high",
                "confidence": 0.9,
                "evidence_refs": ["stages/findings/pattern_scan.json"],
            }
        ]
    )
    viewer_path = reporting.write_analyst_report_v2_viewer(
        tmp_path, cast(dict[str, JsonValue], report)
    )
    return viewer_path.read_text(encoding="utf-8")


def test_viewer_html_contains_required_single_pane_section_anchors(
    tmp_path: Path,
) -> None:
    html = _build_viewer_html(tmp_path)

    required_pane_ids = (
        f'id="pane-{reporting.ANALYST_OVERVIEW_PANE_ANCHOR_OVERVIEW_GATES}"',
        f'id="pane-{reporting.ANALYST_OVERVIEW_PANE_ANCHOR_VULNERABILITIES_VERDICTS}"',
        f'id="pane-{reporting.ANALYST_OVERVIEW_PANE_ANCHOR_STRUCTURE_BINARIES}"',
        f'id="pane-{reporting.ANALYST_OVERVIEW_PANE_ANCHOR_PROTOCOLS_ATTACK_SURFACE}"',
        f'id="pane-{reporting.ANALYST_OVERVIEW_PANE_ANCHOR_EVIDENCE_NEXT_ACTIONS}"',
        'id="pane-executive-verdict"',
        'id="pane-attack-surface-scale"',
        'id="pane-verification-status"',
        'id="pane-evidence-navigator"',
    )

    for pane_id in required_pane_ids:
        assert pane_id in html

    required_mount_ids = (
        f'id="{reporting.ANALYST_OVERVIEW_PANE_ANCHOR_OVERVIEW_GATES}"',
        f'id="{reporting.ANALYST_OVERVIEW_PANE_ANCHOR_VULNERABILITIES_VERDICTS}"',
        f'id="{reporting.ANALYST_OVERVIEW_PANE_ANCHOR_STRUCTURE_BINARIES}"',
        f'id="{reporting.ANALYST_OVERVIEW_PANE_ANCHOR_PROTOCOLS_ATTACK_SURFACE}"',
        f'id="{reporting.ANALYST_OVERVIEW_PANE_ANCHOR_EVIDENCE_NEXT_ACTIONS}"',
        'id="executive-verdict"',
        'id="attack-surface-scale"',
        'id="verification-status"',
        'id="evidence-navigator"',
    )

    for mount_id in required_mount_ids:
        assert mount_id in html


def test_viewer_html_contains_no_remote_http_or_https_urls(tmp_path: Path) -> None:
    html = _build_viewer_html(tmp_path)

    assert "http://" not in html
    assert "https://" not in html


def test_viewer_html_has_offline_warning_and_bootstrap_fallback_hooks(
    tmp_path: Path,
) -> None:
    html = _build_viewer_html(tmp_path)

    assert 'id="file-warning"' in html
    assert "if (warn) warn.hidden = false;" in html
    assert 'id="bootstrap-data"' in html
    assert 'id="bootstrap-overview-data"' in html
    assert 'id="bootstrap-digest-data"' in html

    assert "fetch('./analyst_report_v2.json'" in html
    assert "fetch('./analyst_overview.json'" in html
    assert "fetch('./analyst_digest.json'" in html

    assert "document.getElementById('bootstrap-data')" in html
    assert "document.getElementById('bootstrap-overview-data')" in html
    assert "document.getElementById('bootstrap-digest-data')" in html

    assert ").catch(() => {" in html
    assert "renderOverview(window.__aiedge_overview);" in html
    assert "renderVulnerabilities(window.__aiedge_digest);" in html
    assert "render({});" in html


def test_viewer_html_contains_evidence_navigator_safety_helpers(
    tmp_path: Path,
) -> None:
    html = _build_viewer_html(tmp_path)

    assert "function isSafeRunRelativeRef" in html
    assert "function hrefForEvidenceRef" in html
    assert "function copyText" in html

    assert "evidence-link" in html
    assert "unsafe-ref" in html
    assert "copy-ref" in html
