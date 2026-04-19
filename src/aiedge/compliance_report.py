from __future__ import annotations

"""compliance_report.py — Phase 3'.1 step B-4.

Per-run generator for the four compatibility reports defined in
``docs/compliance_mapping/``: CRA Annex I, FDA Section 524B, ISO/SAE 21434,
and UN R155. Each report is a self-contained Markdown document that
populates the per-requirement coverage tables in the mapping documents
with run-specific evidence (SBOM component count, CVE matches, finding
disposition counts, etc.).

This is a first-cut implementation: it produces narrative reports keyed
to the documented mappings rather than per-clause traceability matrices.
A future revision will widen the per-row evidence (cross-link
finding_id, cve_id, sbom component_id) once the analyst-facing layout
is validated.
"""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from .path_safety import assert_under_dir
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus

_SCHEMA_VERSION = "compliance-report-v1"

# Standards covered. Order matches docs/compliance_mapping/ filename order.
_STANDARDS: tuple[tuple[str, str, str], ...] = (
    (
        "cra_annex_i",
        "EU CRA Annex I",
        "docs/compliance_mapping/cra_annex_i.md",
    ),
    (
        "fda_524b",
        "FDA Section 524B",
        "docs/compliance_mapping/fda_section_524b.md",
    ),
    (
        "iso_21434",
        "ISO/SAE 21434",
        "docs/compliance_mapping/iso_21434.md",
    ),
    (
        "un_r155",
        "UN R155",
        "docs/compliance_mapping/un_r155.md",
    ),
)


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_json_load(path: Path) -> object | None:
    """Return parsed JSON from *path*, or None on any failure."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


def _count_findings_by(findings: list[dict[str, object]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        value_any = f.get(key)
        value = str(value_any) if value_any is not None else "unknown"
        counts[value] = counts.get(value, 0) + 1
    return counts


@dataclass(frozen=True)
class ComplianceEvidence:
    """Per-run evidence inputs the report templates consume."""

    sbom_component_count: int
    cve_match_count: int
    cve_critical_high_count: int
    finding_total: int
    finding_by_severity: dict[str, int]
    finding_by_category: dict[str, int]
    finding_by_evidence_tier: dict[str, int]
    cert_finding_count: int
    init_high_risk_service_count: int
    fs_perm_finding_count: int
    sources: dict[str, str]


def _gather_evidence(run_dir: Path) -> ComplianceEvidence:
    """Collect per-stage evidence counts. All inputs are optional; missing
    artefacts produce zero counts so the report is always emittable."""
    sources: dict[str, str] = {}

    sbom_path = run_dir / "stages" / "sbom" / "sbom.json"
    sbom_data = _safe_json_load(sbom_path)
    sbom_component_count = 0
    if isinstance(sbom_data, dict):
        components_any = cast(dict[str, object], sbom_data).get("components")
        if isinstance(components_any, list):
            sbom_component_count = len(cast(list[object], components_any))
        sources["sbom"] = str(sbom_path)

    cve_path = run_dir / "stages" / "cve_scan" / "cve_matches.json"
    cve_data = _safe_json_load(cve_path)
    cve_match_count = 0
    cve_critical_high = 0
    if isinstance(cve_data, dict):
        matches_any = cast(dict[str, object], cve_data).get("matches")
        if isinstance(matches_any, list):
            matches = cast(list[object], matches_any)
            cve_match_count = len(matches)
            for m_any in matches:
                if isinstance(m_any, dict):
                    sev_any = cast(dict[str, object], m_any).get("severity")
                    if isinstance(sev_any, str) and sev_any.lower() in {
                        "critical",
                        "high",
                    }:
                        cve_critical_high += 1
        sources["cve_scan"] = str(cve_path)

    findings_path = run_dir / "stages" / "findings" / "findings.json"
    findings_data = _safe_json_load(findings_path)
    finding_total = 0
    finding_by_severity: dict[str, int] = {}
    finding_by_category: dict[str, int] = {}
    finding_by_evidence_tier: dict[str, int] = {}
    if isinstance(findings_data, dict):
        findings_any = cast(dict[str, object], findings_data).get("findings")
        if isinstance(findings_any, list):
            findings_list_raw = cast(list[object], findings_any)
            findings_list: list[dict[str, object]] = [
                cast(dict[str, object], f)
                for f in findings_list_raw
                if isinstance(f, dict)
            ]
            finding_total = len(findings_list)
            finding_by_severity = _count_findings_by(findings_list, "severity")
            finding_by_category = _count_findings_by(findings_list, "category")
            finding_by_evidence_tier = _count_findings_by(
                findings_list, "evidence_tier"
            )
        sources["findings"] = str(findings_path)

    cert_path = run_dir / "stages" / "cert_analysis" / "certificate_analysis.json"
    cert_data = _safe_json_load(cert_path)
    cert_finding_count = 0
    if isinstance(cert_data, dict):
        cert_findings_any = cast(dict[str, object], cert_data).get("findings")
        if isinstance(cert_findings_any, list):
            cert_finding_count = len(cast(list[object], cert_findings_any))
        sources["cert_analysis"] = str(cert_path)

    init_path = run_dir / "stages" / "init_analysis" / "init_analysis.json"
    init_data = _safe_json_load(init_path)
    init_high_risk_service_count = 0
    if isinstance(init_data, dict):
        services_any = cast(dict[str, object], init_data).get("services")
        if isinstance(services_any, list):
            for s_any in cast(list[object], services_any):
                if isinstance(s_any, dict):
                    risk_any = cast(dict[str, object], s_any).get("risk")
                    if isinstance(risk_any, str) and risk_any.lower() == "high":
                        init_high_risk_service_count += 1
        sources["init_analysis"] = str(init_path)

    fs_path = run_dir / "stages" / "fs_permissions" / "fs_permissions.json"
    fs_data = _safe_json_load(fs_path)
    fs_perm_finding_count = 0
    if isinstance(fs_data, dict):
        fs_findings_any = cast(dict[str, object], fs_data).get("findings")
        if isinstance(fs_findings_any, list):
            fs_perm_finding_count = len(cast(list[object], fs_findings_any))
        sources["fs_permissions"] = str(fs_path)

    return ComplianceEvidence(
        sbom_component_count=sbom_component_count,
        cve_match_count=cve_match_count,
        cve_critical_high_count=cve_critical_high,
        finding_total=finding_total,
        finding_by_severity=finding_by_severity,
        finding_by_category=finding_by_category,
        finding_by_evidence_tier=finding_by_evidence_tier,
        cert_finding_count=cert_finding_count,
        init_high_risk_service_count=init_high_risk_service_count,
        fs_perm_finding_count=fs_perm_finding_count,
        sources=sources,
    )


def _format_count_table(title: str, counts: dict[str, int]) -> str:
    if not counts:
        return f"### {title}\n\nNo data captured for this run.\n"
    rows = ["| Bucket | Count |", "|---|---|"]
    for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        rows.append(f"| `{k}` | {v} |")
    return f"### {title}\n\n" + "\n".join(rows) + "\n"


def _common_evidence_section(ev: ComplianceEvidence) -> str:
    parts = [
        "## Per-run evidence summary",
        "",
        f"- SBOM components inventoried: **{ev.sbom_component_count}**",
        f"- CVE matches: **{ev.cve_match_count}** (Critical/High: **{ev.cve_critical_high_count}**)",
        f"- Findings (all categories): **{ev.finding_total}**",
        f"- X.509 cert findings: **{ev.cert_finding_count}**",
        f"- Init services flagged HIGH risk: **{ev.init_high_risk_service_count}**",
        f"- File-permission findings: **{ev.fs_perm_finding_count}**",
        "",
        _format_count_table("Findings by severity", ev.finding_by_severity),
        _format_count_table("Findings by category", ev.finding_by_category),
        _format_count_table("Findings by evidence tier", ev.finding_by_evidence_tier),
    ]
    return "\n".join(parts)


def _render_report(
    standard_id: str,
    standard_name: str,
    mapping_doc_path: str,
    ev: ComplianceEvidence,
    run_dir: Path,
    generated_at: str,
) -> str:
    """Render one standard's compliance-evidence report.

    The report is intentionally short: a header + provenance + per-run
    evidence summary + pointer back to the canonical mapping document.
    The canonical mapping owns the per-requirement coverage table.
    """
    return (
        f"# SCOUT {standard_name} Per-Run Compatibility Report\n\n"
        f"**Standard:** {standard_name}\n"
        f"**Mapping doc:** `{mapping_doc_path}`\n"
        f"**Generated at:** {generated_at}\n"
        f"**Run directory:** `{run_dir.name}`\n\n"
        "---\n\n"
        "> **Disclaimer**: SCOUT outputs are *compatible with* the technical "
        "evidence requirements documented in the canonical mapping document "
        "referenced above. This per-run report aggregates the run's evidence "
        "counts; it does not constitute a compliance certification, regulatory "
        "submission, or independent assessment. Final responsibility for any "
        "regulatory submission rests with the operator's complete quality "
        "system, risk management, and (where applicable) certification body.\n\n"
        "---\n\n"
        f"{_common_evidence_section(ev)}\n"
        "## Where to read more\n\n"
        f"- Per-requirement coverage table: `{mapping_doc_path}`\n"
        "- Companion compatibility mappings: see the same directory "
        "(`docs/compliance_mapping/`).\n"
        "- Phase 3'.1 plan: gnosis SSOT "
        "`wiki/projects/scout-phase-2c-2d-plan.md`.\n"
    )


@dataclass(frozen=True)
class ComplianceReportStage:
    """Emit per-standard compatibility reports for the run.

    For every standard listed in ``_STANDARDS``, write
    ``stages/compliance_report/<standard_id>_report.md`` containing the
    per-run evidence summary and a pointer back to the canonical mapping
    document. The companion ``stage.json`` records the standards covered
    and the evidence sources consulted.
    """

    no_llm: bool = False  # Accepted but unused -- stage is always static

    @property
    def name(self) -> str:
        return "compliance_report"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "compliance_report"
        out_json = stage_dir / "stage.json"

        assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        assert_under_dir(run_dir, out_json)

        limitations: list[str] = []
        ev = _gather_evidence(run_dir)
        generated_at = _iso_utc_now()

        if not ev.sources:
            limitations.append(
                "No upstream evidence artefacts were available; reports "
                "were emitted with zero counts."
            )

        emitted: list[dict[str, JsonValue]] = []
        for standard_id, standard_name, mapping_doc_path in _STANDARDS:
            report_md = _render_report(
                standard_id=standard_id,
                standard_name=standard_name,
                mapping_doc_path=mapping_doc_path,
                ev=ev,
                run_dir=run_dir,
                generated_at=generated_at,
            )
            report_path = stage_dir / f"{standard_id}_report.md"
            assert_under_dir(run_dir, report_path)
            report_path.write_text(report_md, encoding="utf-8")
            emitted.append(
                {
                    "standard_id": standard_id,
                    "standard_name": standard_name,
                    "mapping_doc_path": mapping_doc_path,
                    "report_path": str(report_path.relative_to(run_dir)),
                    "report_byte_size": len(report_md.encode("utf-8")),
                }
            )

        status: StageStatus = "ok"
        if not ev.sources:
            # Still produced reports, but mark partial so analyst notices.
            status = "partial"

        evidence_sources_payload: dict[str, JsonValue] = {
            k: v for k, v in ev.sources.items()
        }
        evidence_counts_payload: dict[str, JsonValue] = {
            "sbom_component_count": ev.sbom_component_count,
            "cve_match_count": ev.cve_match_count,
            "cve_critical_high_count": ev.cve_critical_high_count,
            "finding_total": ev.finding_total,
            "finding_by_severity": cast(
                dict[str, JsonValue],
                {k: v for k, v in ev.finding_by_severity.items()},
            ),
            "finding_by_category": cast(
                dict[str, JsonValue],
                {k: v for k, v in ev.finding_by_category.items()},
            ),
            "finding_by_evidence_tier": cast(
                dict[str, JsonValue],
                {k: v for k, v in ev.finding_by_evidence_tier.items()},
            ),
            "cert_finding_count": ev.cert_finding_count,
            "init_high_risk_service_count": ev.init_high_risk_service_count,
            "fs_perm_finding_count": ev.fs_perm_finding_count,
        }
        payload: dict[str, JsonValue] = {
            "schema_version": _SCHEMA_VERSION,
            "status": status,
            "generated_at": generated_at,
            "standards_emitted": cast(list[JsonValue], cast(list[object], emitted)),
            "evidence_sources": evidence_sources_payload,
            "evidence_counts": evidence_counts_payload,
            "limitations": cast(
                list[JsonValue],
                cast(list[object], sorted(set(limitations))),
            ),
        }
        out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        details: dict[str, JsonValue] = {
            "standards_emitted": len(emitted),
            "evidence_sources": len(ev.sources),
            "sbom_component_count": ev.sbom_component_count,
            "cve_match_count": ev.cve_match_count,
            "finding_total": ev.finding_total,
        }
        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
