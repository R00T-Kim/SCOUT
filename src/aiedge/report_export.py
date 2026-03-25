from __future__ import annotations

"""report_export.py — Markdown executive report generator for SCOUT analysis runs.

Reads run artifacts and produces a human-readable Markdown report written to
``report/executive_report.md``.  Every section degrades gracefully: if the
backing artifact is absent or malformed the section is omitted entirely.

Usage::

    from .report_export import generate_executive_report
    md = generate_executive_report(Path("aiedge-runs/run-abc123"))
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .path_safety import assert_under_dir, sha256_file

# ---------------------------------------------------------------------------
# Version tag (mirrors schema constant pattern used elsewhere)
# ---------------------------------------------------------------------------

_SCOUT_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_json_load(path: Path) -> Any | None:
    """Return parsed JSON from *path*, or ``None`` on any failure."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


def _stage_dir(run_dir: Path, stage: str) -> Path:
    return run_dir / "stages" / stage


def _stage_json(run_dir: Path, stage: str) -> Path:
    return _stage_dir(run_dir, stage) / "stage.json"


def _fmt_float(v: object, decimals: int = 2) -> str:
    try:
        return f"{float(v):.{decimals}f}"  # type: ignore[arg-type]
    except Exception:
        return str(v)


def _truncate_lines(text: str, max_lines: int) -> str:
    """Return *text* with at most *max_lines* lines; appends a notice if cut."""
    lines = text.splitlines(keepends=True)
    if len(lines) <= max_lines:
        return text
    kept = lines[:max_lines]
    kept.append(f"\n> *[{len(lines) - max_lines} lines truncated]*\n")
    return "".join(kept)


# ---------------------------------------------------------------------------
# Section generators  (each returns "" when data is unavailable)
# ---------------------------------------------------------------------------


def _section_header(run_dir: Path) -> str:
    """Section 1 — header with run metadata."""
    lines: list[str] = ["# SCOUT Firmware Analysis Report\n"]

    run_id = run_dir.name

    # Prefer manifest.json for timestamp; fall back to earliest stage.json
    ts: str | None = None
    manifest_path = run_dir / "manifest.json"
    manifest = _safe_json_load(manifest_path)
    if isinstance(manifest, dict):
        ts = manifest.get("timestamp") or manifest.get("started_at")  # type: ignore[assignment]
        run_id = manifest.get("run_id", run_id)  # type: ignore[assignment]

    if ts is None:
        # Grab timestamp from any stage.json
        for sj in sorted(run_dir.glob("stages/*/stage.json")):
            data = _safe_json_load(sj)
            if isinstance(data, dict) and data.get("started_at"):
                ts = str(data["started_at"])
                break

    lines.append(f"**Run ID:** `{run_id}`  ")
    lines.append(f"**Analysis timestamp:** {ts or 'unknown'}  ")

    # Firmware file
    fw_path = run_dir / "input" / "firmware.bin"
    if not fw_path.exists():
        # Probe manifest for original filename
        fw_name = None
        if isinstance(manifest, dict):
            fw_name = manifest.get("firmware_path") or manifest.get("input_path")
        if fw_name:
            lines.append(f"**Firmware:** `{fw_name}`  ")
    else:
        try:
            digest = sha256_file(fw_path)
            lines.append(f"**Firmware:** `{fw_path.name}`  ")
            lines.append(f"**SHA-256:** `{digest}`  ")
        except Exception:
            lines.append(f"**Firmware:** `{fw_path.name}`  ")

    lines.append("")
    return "\n".join(lines)


def _section_pipeline(run_dir: Path) -> str:
    """Section 2 — pipeline stage summary table."""
    stage_dirs = sorted((run_dir / "stages").glob("*/stage.json")) if (run_dir / "stages").is_dir() else []
    if not stage_dirs:
        return ""

    rows: list[tuple[str, str, str, str]] = []
    overall_failed = False
    overall_partial = False

    for sj in stage_dirs:
        data = _safe_json_load(sj)
        if not isinstance(data, dict):
            continue
        stage_name = sj.parent.name
        status = str(data.get("status", "unknown"))
        if status == "failed":
            overall_failed = True
        elif status == "partial":
            overall_partial = True

        # Duration
        started = data.get("started_at")
        finished = data.get("finished_at")
        duration = "-"
        if started and finished:
            try:
                s = datetime.fromisoformat(str(started).replace("Z", "+00:00"))
                f = datetime.fromisoformat(str(finished).replace("Z", "+00:00"))
                secs = (f - s).total_seconds()
                duration = f"{secs:.1f}s"
            except Exception:
                duration = str(data.get("duration_s", "-"))
        elif data.get("duration_s") is not None:
            duration = f"{data['duration_s']:.1f}s"

        lims = data.get("limitations", [])
        lim_count = str(len(lims)) if isinstance(lims, list) else "0"

        rows.append((stage_name, status, duration, lim_count))

    if not rows:
        return ""

    overall = "failed" if overall_failed else ("partial" if overall_partial else "ok")

    out: list[str] = [
        "## Pipeline Summary\n",
        f"**Overall status:** {overall}\n",
        "| Stage | Status | Duration | Limitations |",
        "|-------|--------|----------|-------------|",
    ]
    for stage_name, status, duration, lim_count in rows:
        out.append(f"| {stage_name} | {status} | {duration} | {lim_count} |")
    out.append("")
    return "\n".join(out)


def _section_top_risks(run_dir: Path) -> str:
    """Section 3 — top 10 findings by severity then confidence."""
    findings_path = _stage_dir(run_dir, "findings") / "findings.json"
    if not findings_path.exists():
        # Try alternate names
        for alt in ("findings_candidates.json", "all_findings.json"):
            p = _stage_dir(run_dir, "findings") / alt
            if p.exists():
                findings_path = p
                break

    data = _safe_json_load(findings_path)
    if not isinstance(data, (list, dict)):
        return ""

    findings: list[dict[str, Any]] = []
    if isinstance(data, list):
        findings = [f for f in data if isinstance(f, dict)]
    elif isinstance(data, dict):
        raw = data.get("findings") or data.get("items") or []
        if isinstance(raw, list):
            findings = [f for f in raw if isinstance(f, dict)]

    if not findings:
        return ""

    def _sort_key(f: dict[str, Any]) -> tuple[int, float]:
        sev = str(f.get("severity", "info")).lower()
        rank = _SEVERITY_RANK.get(sev, 99)
        conf = -float(f.get("confidence", 0.0))
        return (rank, conf)

    findings.sort(key=_sort_key)
    top = findings[:10]

    out: list[str] = [
        "## Top Risks\n",
        "| Severity | Title | Confidence | Exploitability | Families |",
        "|----------|-------|------------|---------------|---------|",
    ]
    for f in top:
        sev = str(f.get("severity", "-"))
        title = str(f.get("title", f.get("name", "-")))[:60]
        conf = _fmt_float(f.get("confidence", "-"))
        tier = str(f.get("exploitability_tier", f.get("tier", "-")))
        families_raw = f.get("families", f.get("family", []))
        if isinstance(families_raw, list):
            families = ", ".join(str(x) for x in families_raw[:3])
        else:
            families = str(families_raw)
        out.append(f"| {sev} | {title} | {conf} | {tier} | {families} |")
    out.append("")
    return "\n".join(out)


def _section_sbom(run_dir: Path) -> str:
    """Section 4 — SBOM summary."""
    sbom_path = _stage_dir(run_dir, "sbom") / "sbom.json"
    if not sbom_path.exists():
        return ""

    data = _safe_json_load(sbom_path)
    if not isinstance(data, dict):
        return ""

    components: list[dict[str, Any]] = []
    raw_components = data.get("components", [])
    if isinstance(raw_components, list):
        components = [c for c in raw_components if isinstance(c, dict)]

    if not components:
        return ""

    total = len(components)
    type_counts: dict[str, int] = {}
    for c in components:
        t = str(c.get("type", "unknown"))
        type_counts[t] = type_counts.get(t, 0) + 1

    top5 = [str(c.get("name", "?")) for c in components[:5]]

    out: list[str] = [
        "## SBOM Summary\n",
        f"**Total components:** {total}\n",
        "**Component types:**\n",
    ]
    for t, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        out.append(f"- {t}: {count}")
    out.append("\n**Top 5 components:**\n")
    for name in top5:
        out.append(f"- {name}")
    out.append("")
    return "\n".join(out)


def _section_cve(run_dir: Path) -> str:
    """Section 5 — CVE matches table."""
    cve_path = _stage_dir(run_dir, "cve_scan") / "cve_matches.json"
    if not cve_path.exists():
        return ""

    data = _safe_json_load(cve_path)
    matches: list[dict[str, Any]] = []
    if isinstance(data, list):
        matches = [m for m in data if isinstance(m, dict)]
    elif isinstance(data, dict):
        raw = data.get("matches") or data.get("cve_matches") or []
        if isinstance(raw, list):
            matches = [m for m in raw if isinstance(m, dict)]

    if not matches:
        return ""

    # Optional reachability enrichment
    reach_path = _stage_dir(run_dir, "reachability") / "reachability.json"
    reach_data = _safe_json_load(reach_path)
    reach_map: dict[str, str] = {}
    if isinstance(reach_data, dict):
        for cve_id, info in reach_data.items():
            if isinstance(info, dict):
                reach_map[cve_id] = str(info.get("reachability", "-"))
            else:
                reach_map[cve_id] = str(info)

    # Sort by CVSS descending
    def _cvss_key(m: dict[str, Any]) -> float:
        try:
            return -float(m.get("cvss_score", m.get("cvss", 0.0)))
        except Exception:
            return 0.0

    matches.sort(key=_cvss_key)

    out: list[str] = [
        "## CVE Matches\n",
        "| CVE ID | Component | Version | CVSS | Severity | Reachability |",
        "|--------|-----------|---------|------|----------|-------------|",
    ]
    for m in matches[:20]:
        cve_id = str(m.get("cve_id", m.get("id", "-")))
        component = str(m.get("component", m.get("product", "-")))
        version = str(m.get("version", "-"))
        cvss = _fmt_float(m.get("cvss_score", m.get("cvss", "-")))
        sev = str(m.get("severity", "-"))
        reach = reach_map.get(cve_id, str(m.get("reachability", "-")))
        out.append(f"| {cve_id} | {component} | {version} | {cvss} | {sev} | {reach} |")
    out.append("")
    return "\n".join(out)


def _section_attack_surface(run_dir: Path) -> str:
    """Section 6 — attack surface summary."""
    as_dir = _stage_dir(run_dir, "attack_surface")
    if not as_dir.is_dir():
        return ""

    # Gather endpoint and service counts
    ep_count = 0
    svc_count = 0
    top_endpoints: list[dict[str, Any]] = []

    for candidate in ("attack_surface.json", "endpoints.json", "surfaces.json"):
        p = as_dir / candidate
        if not p.exists():
            p = _stage_dir(run_dir, "endpoints") / candidate
        d = _safe_json_load(p) if p.exists() else None
        if isinstance(d, dict):
            if "endpoints" in d and isinstance(d["endpoints"], list):
                eps = [e for e in d["endpoints"] if isinstance(e, dict)]
                ep_count = max(ep_count, len(eps))
                top_endpoints = sorted(eps, key=lambda e: -float(e.get("risk_score", 0.0) if e.get("risk_score") is not None else 0.0))[:5]
            if "services" in d and isinstance(d["services"], list):
                svc_count = max(svc_count, len(d["services"]))
        elif isinstance(d, list):
            ep_count = max(ep_count, len(d))

    # IPC channels from graph stage
    ipc_count = 0
    graph_path = _stage_dir(run_dir, "graph") / "communication_graph.json"
    graph = _safe_json_load(graph_path)
    if isinstance(graph, dict):
        nodes = graph.get("nodes", [])
        if isinstance(nodes, list):
            ipc_count = sum(1 for n in nodes if isinstance(n, dict) and n.get("type") == "ipc_channel")

    if ep_count == 0 and svc_count == 0 and ipc_count == 0:
        return ""

    out: list[str] = [
        "## Attack Surface Summary\n",
        f"- Endpoints detected: {ep_count}",
        f"- Services detected: {svc_count}",
        f"- IPC channels: {ipc_count}",
    ]

    if top_endpoints:
        out.append("\n**Top endpoints by risk score:**\n")
        out.append("| Endpoint | Protocol | Risk Score |")
        out.append("|----------|----------|------------|")
        for ep in top_endpoints:
            ep_name = str(ep.get("path", ep.get("url", ep.get("name", "-"))))[:50]
            proto = str(ep.get("protocol", ep.get("type", "-")))
            risk = _fmt_float(ep.get("risk_score", "-"))
            out.append(f"| {ep_name} | {proto} | {risk} |")

    out.append("")
    return "\n".join(out)


def _section_security_assessment(run_dir: Path) -> str:
    """Section 7 — certificate / init / permission issues."""
    parts: list[str] = []

    # Certificates — probe multiple candidate paths
    for cert_name in ("cert_analysis.json", "certificates.json"):
        cert_path = _stage_dir(run_dir, "inventory") / cert_name
        if not cert_path.exists():
            cert_path = run_dir / "stages" / "cert_analysis" / cert_name
        if cert_path.exists():
            d = _safe_json_load(cert_path)
            if isinstance(d, dict):
                issues = d.get("issues", d.get("findings", []))
                if isinstance(issues, list):
                    parts.append(f"- Certificate issues: {len(issues)}")
            break

    # Init services
    for init_name in ("init_analysis.json", "init_services.json"):
        init_path = _stage_dir(run_dir, "inventory") / init_name
        if not init_path.exists():
            init_path = run_dir / "stages" / "init_analysis" / init_name
        if init_path.exists():
            d = _safe_json_load(init_path)
            if isinstance(d, dict):
                risks = d.get("risks", d.get("services", d.get("findings", [])))
                if isinstance(risks, list):
                    parts.append(f"- Init service risks: {len(risks)}")
            break

    # Filesystem permissions
    for perm_name in ("fs_permissions.json", "permissions.json"):
        perm_path = _stage_dir(run_dir, "inventory") / perm_name
        if not perm_path.exists():
            perm_path = run_dir / "stages" / "fs_permissions" / perm_name
        if perm_path.exists():
            d = _safe_json_load(perm_path)
            if isinstance(d, dict):
                issues = d.get("issues", d.get("findings", d.get("world_writable", [])))
                total = 0
                if isinstance(issues, list):
                    total = len(issues)
                else:
                    # May be broken into sub-keys
                    for key in ("world_writable", "suid_sgid", "sensitive"):
                        sub = d.get(key, [])
                        if isinstance(sub, list):
                            total += len(sub)
                parts.append(f"- Filesystem permission issues: {total}")
            break

    if not parts:
        return ""

    out: list[str] = ["## Security Assessment\n"]
    out.extend(parts)
    out.append("")
    return "\n".join(out)


def _section_credentials(run_dir: Path) -> str:
    """Section 8 — credential findings summary."""
    cred_path = _stage_dir(run_dir, "findings") / "credential_mapping.json"
    if not cred_path.exists():
        cred_path = _stage_dir(run_dir, "surfaces") / "credential_mapping.json"
    if not cred_path.exists():
        return ""

    data = _safe_json_load(cred_path)
    if not isinstance(data, dict):
        return ""

    credentials: list[dict[str, Any]] = []
    raw = data.get("credentials", data.get("items", []))
    if isinstance(raw, list):
        credentials = [c for c in raw if isinstance(c, dict)]

    if not credentials:
        return ""

    risk_counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    type_counts: dict[str, int] = {}
    for c in credentials:
        risk = str(c.get("risk", c.get("severity", "low"))).lower()
        if risk in risk_counts:
            risk_counts[risk] += 1
        ctype = str(c.get("type", c.get("credential_type", "unknown")))
        type_counts[ctype] = type_counts.get(ctype, 0) + 1

    out: list[str] = [
        "## Credential Findings\n",
        f"- High risk: {risk_counts['high']}",
        f"- Medium risk: {risk_counts['medium']}",
        f"- Low risk: {risk_counts['low']}",
        "\n**Types:**\n",
    ]
    for t, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        out.append(f"- {t}: {count}")
    out.append("")
    return "\n".join(out)


def _section_limitations(run_dir: Path) -> str:
    """Section 9 — deduplicated aggregate limitations."""
    seen: set[str] = set()
    limitations: list[str] = []

    for sj in sorted((run_dir / "stages").glob("*/stage.json")):
        data = _safe_json_load(sj)
        if not isinstance(data, dict):
            continue
        lims = data.get("limitations", [])
        if not isinstance(lims, list):
            continue
        for lim in lims:
            text = str(lim).strip()
            if text and text not in seen:
                seen.add(text)
                limitations.append(text)

    if not limitations:
        return ""

    out: list[str] = ["## Limitations\n"]
    for lim in limitations[:30]:
        out.append(f"- {lim}")
    if len(limitations) > 30:
        out.append(f"- *[{len(limitations) - 30} additional limitations omitted]*")
    out.append("")
    return "\n".join(out)


def _section_footer() -> str:
    """Section 10 — footer."""
    ts = _iso_utc_now()
    return f"\n---\n\n*Generated by SCOUT (AIEdge) v{_SCOUT_VERSION} at {ts}*\n"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_executive_report(run_dir: Path) -> str:
    """Generate a Markdown executive report from a SCOUT analysis run.

    Reads artifacts under *run_dir* and assembles a human-readable Markdown
    document.  Each section degrades gracefully when its backing artifact is
    absent or malformed.

    The report is written to ``report/executive_report.md`` inside *run_dir*
    and also returned as a string.

    Args:
        run_dir: Root directory of the SCOUT analysis run
            (e.g. ``aiedge-runs/run-abc123``).

    Returns:
        The complete Markdown report as a string.
    """
    run_dir = run_dir.resolve()

    sections = [
        _section_header(run_dir),
        _section_pipeline(run_dir),
        _section_top_risks(run_dir),
        _section_sbom(run_dir),
        _section_cve(run_dir),
        _section_attack_surface(run_dir),
        _section_security_assessment(run_dir),
        _section_credentials(run_dir),
        _section_limitations(run_dir),
        _section_footer(),
    ]

    report = "\n".join(s for s in sections if s)

    # Enforce 200-line soft cap (footer always preserved)
    report_lines = report.splitlines(keepends=True)
    if len(report_lines) > 200:
        footer_lines = _section_footer().splitlines(keepends=True)
        body = report_lines[: 200 - len(footer_lines)]
        body.append("\n> *[Report truncated at 200 lines]*\n")
        body.extend(footer_lines)
        report = "".join(body)

    # Write to report/executive_report.md
    report_dir = run_dir / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    out_path = report_dir / "executive_report.md"
    assert_under_dir(run_dir, out_path)
    out_path.write_text(report, encoding="utf-8")

    return report
