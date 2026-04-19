"""Phase 3'.1 step B-4 — compliance_report stage tests.

Validates that ComplianceReportStage:
  - emits exactly four per-standard reports;
  - aggregates evidence counts from sbom / cve_scan / findings / cert /
    init / fs_permissions stages;
  - degrades to status=partial (without crashing) when no upstream
    artefacts are present;
  - keeps the canonical 'compatible with' wording in every report;
  - registers cleanly in the stage_registry _STAGE_FACTORIES dict.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from aiedge.compliance_report import (
    _STANDARDS,
    ComplianceReportStage,
)
from aiedge.stage import StageContext
from aiedge.stage_registry import _STAGE_FACTORIES

# ---------------------------------------------------------------------------
# Fixtures (hand-rolled)
# ---------------------------------------------------------------------------


def _make_ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    logs_dir.mkdir(exist_ok=True)
    report_dir.mkdir(exist_ok=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


def _seed_artifact(run_dir: Path, stage: str, filename: str, payload: object) -> None:
    target = run_dir / "stages" / stage
    target.mkdir(parents=True, exist_ok=True)
    (target / filename).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _seed_full_run(run_dir: Path) -> None:
    _seed_artifact(
        run_dir,
        "sbom",
        "sbom.json",
        {
            "schema_version": "sbom-v1",
            "components": [
                {"name": "openssl", "version": "1.0.0"},
                {"name": "curl", "version": "7.36.0"},
                {"name": "libz", "version": "1.2.8"},
            ],
        },
    )
    _seed_artifact(
        run_dir,
        "cve_scan",
        "cve_matches.json",
        {
            "matches": [
                {"cve_id": "CVE-2014-0160", "severity": "Critical"},
                {"cve_id": "CVE-2018-0735", "severity": "High"},
                {"cve_id": "CVE-2018-1000122", "severity": "Medium"},
            ],
        },
    )
    _seed_artifact(
        run_dir,
        "findings",
        "findings.json",
        {
            "findings": [
                {
                    "id": "f1",
                    "severity": "high",
                    "category": "vulnerability",
                    "evidence_tier": "symbol_only",
                },
                {
                    "id": "f2",
                    "severity": "medium",
                    "category": "vulnerability",
                    "evidence_tier": "static_colocated",
                },
                {
                    "id": "f3",
                    "severity": "low",
                    "category": "configuration",
                    "evidence_tier": "symbol_only",
                },
            ]
        },
    )
    _seed_artifact(
        run_dir,
        "cert_analysis",
        "certificate_analysis.json",
        {"findings": [{"id": "c1"}, {"id": "c2"}]},
    )
    _seed_artifact(
        run_dir,
        "init_analysis",
        "init_analysis.json",
        {
            "services": [
                {"name": "telnetd", "risk": "high"},
                {"name": "tftpd", "risk": "medium"},
            ]
        },
    )
    _seed_artifact(
        run_dir,
        "fs_permissions",
        "fs_permissions.json",
        {"findings": [{"id": "p1"}]},
    )


# ---------------------------------------------------------------------------
# Stage outcome shape
# ---------------------------------------------------------------------------


def test_stage_emits_four_reports_when_evidence_present(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    _seed_full_run(ctx.run_dir)

    outcome = ComplianceReportStage().run(ctx)

    assert outcome.status == "ok"
    assert outcome.details["standards_emitted"] == 4
    stage_dir = ctx.run_dir / "stages" / "compliance_report"
    assert (stage_dir / "stage.json").is_file()
    for standard_id, _, _ in _STANDARDS:
        report_path = stage_dir / f"{standard_id}_report.md"
        assert report_path.is_file(), f"missing report for {standard_id}"


def test_stage_degrades_to_partial_when_no_evidence(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    # No upstream artefacts seeded.
    outcome = ComplianceReportStage().run(ctx)

    assert outcome.status == "partial"
    assert outcome.details["evidence_sources"] == 0
    # All four reports still emitted (zero counts inside).
    assert outcome.details["standards_emitted"] == 4
    stage_dir = ctx.run_dir / "stages" / "compliance_report"
    for standard_id, _, _ in _STANDARDS:
        assert (stage_dir / f"{standard_id}_report.md").is_file()
    # Limitation explicitly recorded.
    assert any("no upstream evidence" in lim.lower() for lim in outcome.limitations)


# ---------------------------------------------------------------------------
# Evidence aggregation
# ---------------------------------------------------------------------------


def test_evidence_counts_match_seeded_inputs(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    _seed_full_run(ctx.run_dir)
    ComplianceReportStage().run(ctx)

    stage_json = ctx.run_dir / "stages" / "compliance_report" / "stage.json"
    payload = cast(
        dict[str, object], json.loads(stage_json.read_text(encoding="utf-8"))
    )
    counts = cast(dict[str, object], payload["evidence_counts"])
    assert counts["sbom_component_count"] == 3
    assert counts["cve_match_count"] == 3
    assert counts["cve_critical_high_count"] == 2
    assert counts["finding_total"] == 3
    assert counts["cert_finding_count"] == 2
    assert counts["init_high_risk_service_count"] == 1
    assert counts["fs_perm_finding_count"] == 1
    severity = cast(dict[str, int], counts["finding_by_severity"])
    assert severity["high"] == 1
    assert severity["medium"] == 1
    assert severity["low"] == 1
    tier = cast(dict[str, int], counts["finding_by_evidence_tier"])
    assert tier["symbol_only"] == 2
    assert tier["static_colocated"] == 1


def test_evidence_sources_only_lists_present_artefacts(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    # Seed only sbom and cve_scan; the rest stay absent.
    _seed_artifact(ctx.run_dir, "sbom", "sbom.json", {"components": [{"name": "x"}]})
    _seed_artifact(
        ctx.run_dir,
        "cve_scan",
        "cve_matches.json",
        {"matches": [{"cve_id": "CVE-1", "severity": "low"}]},
    )

    ComplianceReportStage().run(ctx)
    stage_json = ctx.run_dir / "stages" / "compliance_report" / "stage.json"
    payload = cast(
        dict[str, object], json.loads(stage_json.read_text(encoding="utf-8"))
    )
    sources = cast(dict[str, str], payload["evidence_sources"])
    assert set(sources.keys()) == {"sbom", "cve_scan"}


# ---------------------------------------------------------------------------
# Report content invariants
# ---------------------------------------------------------------------------


def test_every_report_carries_compatible_with_disclaimer(tmp_path: Path) -> None:
    """Phase 3'.1 mandates the 'compatible with' wording across the suite."""
    ctx = _make_ctx(tmp_path)
    _seed_full_run(ctx.run_dir)
    ComplianceReportStage().run(ctx)

    stage_dir = ctx.run_dir / "stages" / "compliance_report"
    for standard_id, _, _ in _STANDARDS:
        text = (stage_dir / f"{standard_id}_report.md").read_text(encoding="utf-8")
        assert (
            "compatible with" in text.lower()
        ), f"{standard_id} report missing 'compatible with' disclaimer"
        # And does not contain the forbidden overclaim wording.
        for forbidden in ("compliant with", "fully compliant"):
            assert (
                forbidden not in text.lower()
            ), f"{standard_id} report uses forbidden phrase '{forbidden}'"


def test_every_report_links_back_to_canonical_mapping(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    _seed_full_run(ctx.run_dir)
    ComplianceReportStage().run(ctx)

    stage_dir = ctx.run_dir / "stages" / "compliance_report"
    for standard_id, _, mapping_path in _STANDARDS:
        text = (stage_dir / f"{standard_id}_report.md").read_text(encoding="utf-8")
        assert (
            mapping_path in text
        ), f"{standard_id} report does not reference canonical mapping path"


# ---------------------------------------------------------------------------
# Stage registry integration
# ---------------------------------------------------------------------------


def test_stage_registry_exposes_compliance_report() -> None:
    assert "compliance_report" in _STAGE_FACTORIES


def test_stage_registry_factory_returns_compliance_report_stage(
    tmp_path: Path,
) -> None:
    @dataclass(frozen=True)
    class _DummyRunInfo:
        run_dir: Path
        case_id: str | None = None

        @property
        def firmware_dest(self) -> Path:  # _RunInfoLike protocol member
            return self.run_dir / "firmware.bin"

    info = _DummyRunInfo(run_dir=tmp_path)
    factory = _STAGE_FACTORIES["compliance_report"]
    stage = factory(info, None, lambda: 0.0, True)
    assert stage.name == "compliance_report"
