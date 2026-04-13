"""Finding category taxonomy and classification rules.

Phase 2A.4 (PR #7a) -- additive only. The 'category' field is optional
and downstream consumers may ignore it. PR #7b will promote to required
after consumer migration is verified.

Categories:
- vulnerability: confirmed/suspected security vulnerabilities (taint TPs,
  CVE matches, exploit chains, command execution, injection)
- misconfiguration: insecure defaults / posture issues (telnet enabled,
  debuggable, root login, weak crypto config, SSH misconfig)
- pipeline_artifact: pipeline observations that are NOT vulnerabilities
  (private key file presence, OTA metadata, inventory string-hits,
  exploit_candidate plans, analysis status findings)
"""

from __future__ import annotations

from enum import Enum
from typing import Any


class FindingCategory(str, Enum):
    """Three-category taxonomy for SCOUT findings."""

    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    PIPELINE_ARTIFACT = "pipeline_artifact"


# ---------------------------------------------------------------------------
# Explicit finding id -> category map (highest priority, exact match on "id")
# These are the top-level finding "id" values produced by findings.py
# ---------------------------------------------------------------------------

_FINDING_ID_CATEGORY_MAP: dict[str, FindingCategory] = {
    # --- vulnerability ---
    "aiedge.findings.web.exec_sink_overlap": FindingCategory.VULNERABILITY,
    # --- misconfiguration ---
    "aiedge.findings.debug.telnet_enablement": FindingCategory.MISCONFIGURATION,
    "aiedge.findings.debug.adb_enablement": FindingCategory.MISCONFIGURATION,
    "aiedge.findings.debug.android_manifest_debuggable": FindingCategory.MISCONFIGURATION,
    "aiedge.findings.config.ssh_permit_root_login": FindingCategory.MISCONFIGURATION,
    "aiedge.findings.config.ssh_password_authentication": FindingCategory.MISCONFIGURATION,
    "aiedge.findings.config.ssh_permit_empty_passwords": FindingCategory.MISCONFIGURATION,
    "aiedge.findings.hardening.telnet_disabled": FindingCategory.MISCONFIGURATION,
    # --- pipeline_artifact ---
    "aiedge.findings.secrets.private_key_pem": FindingCategory.PIPELINE_ARTIFACT,
    "aiedge.findings.update.metadata_present": FindingCategory.PIPELINE_ARTIFACT,
    "aiedge.findings.inventory.string_hits_present": FindingCategory.PIPELINE_ARTIFACT,
    "aiedge.findings.exploit.candidate_plan": FindingCategory.PIPELINE_ARTIFACT,
    "aiedge.findings.analysis_incomplete": FindingCategory.PIPELINE_ARTIFACT,
}

# ---------------------------------------------------------------------------
# Explicit rule_id -> category map (used for pattern-scan sub-findings)
# These are the rule_id values from the text/binary rule_specs in findings.py
# ---------------------------------------------------------------------------

_RULE_ID_CATEGORY_MAP: dict[str, FindingCategory] = {
    # command execution / injection -> vulnerability
    "python_exec_sink": FindingCategory.VULNERABILITY,
    "shell_eval_injection": FindingCategory.VULNERABILITY,
    "php_exec_sink": FindingCategory.VULNERABILITY,
    "cpp_strings_risk_link": FindingCategory.VULNERABILITY,
    # format string -> vulnerability
    "c_format_string_vuln": FindingCategory.VULNERABILITY,
    # sql injection -> vulnerability
    "php_sql_concat": FindingCategory.VULNERABILITY,
    # path traversal -> vulnerability
    "php_path_traversal": FindingCategory.VULNERABILITY,
    # ssrf -> vulnerability
    "python_ssrf_sink": FindingCategory.VULNERABILITY,
    "shell_ssrf_sink": FindingCategory.VULNERABILITY,
    "php_ssrf_sink": FindingCategory.VULNERABILITY,
    # upload/exec chain -> vulnerability
    "upload_source_signal": FindingCategory.VULNERABILITY,
    "php_upload_source": FindingCategory.VULNERABILITY,
    # auth gaps -> misconfiguration
    "python_route_without_auth": FindingCategory.MISCONFIGURATION,
    "python_csrf_exempt": FindingCategory.MISCONFIGURATION,
    "php_csrf_bypass": FindingCategory.MISCONFIGURATION,
    # archive extraction -> pipeline_artifact (observation, not confirmed vuln)
    "py_tar_extractall": FindingCategory.PIPELINE_ARTIFACT,
    "shell_archive_extract": FindingCategory.PIPELINE_ARTIFACT,
}


# ---------------------------------------------------------------------------
# ID-prefix heuristics (fallback when exact map has no entry)
# ---------------------------------------------------------------------------

_ID_PREFIX_RULES: list[tuple[str, FindingCategory]] = [
    # aiedge.findings.config.* -> misconfiguration
    ("aiedge.findings.config.", FindingCategory.MISCONFIGURATION),
    # aiedge.findings.debug.* -> misconfiguration
    ("aiedge.findings.debug.", FindingCategory.MISCONFIGURATION),
    # aiedge.findings.hardening.* -> misconfiguration
    ("aiedge.findings.hardening.", FindingCategory.MISCONFIGURATION),
    # aiedge.findings.web.* -> vulnerability (web exposure with exec)
    ("aiedge.findings.web.", FindingCategory.VULNERABILITY),
    # aiedge.findings.secrets.* -> pipeline_artifact (presence, not exploit)
    ("aiedge.findings.secrets.", FindingCategory.PIPELINE_ARTIFACT),
    # aiedge.findings.update.* -> pipeline_artifact
    ("aiedge.findings.update.", FindingCategory.PIPELINE_ARTIFACT),
    # aiedge.findings.inventory.* -> pipeline_artifact
    ("aiedge.findings.inventory.", FindingCategory.PIPELINE_ARTIFACT),
    # aiedge.findings.exploit.* -> pipeline_artifact (plan, not confirmed chain)
    ("aiedge.findings.exploit.", FindingCategory.PIPELINE_ARTIFACT),
    # aiedge.findings.analysis_* -> pipeline_artifact
    ("aiedge.findings.analysis_", FindingCategory.PIPELINE_ARTIFACT),
]


def classify_finding(finding: dict[str, Any]) -> FindingCategory | None:
    """Classify a finding into one of three categories.

    Returns None if classification is uncertain (caller may treat as
    'unclassified' for tracking).

    Algorithm (in priority order):
    1. Check "id" field against _FINDING_ID_CATEGORY_MAP (exact match)
    2. Check "rule_id" field against _RULE_ID_CATEGORY_MAP (exact match)
    3. Heuristic: cve_id present -> vulnerability
    4. Heuristic: "id" field prefix rules (_ID_PREFIX_RULES)
    5. Heuristic: rule_id prefix patterns
    6. Return None if still ambiguous
    """
    if not isinstance(finding, dict):
        return None

    # Stage 1: Exact match on "id" (top-level findings from findings.py)
    finding_id = finding.get("id")
    if isinstance(finding_id, str) and finding_id in _FINDING_ID_CATEGORY_MAP:
        return _FINDING_ID_CATEGORY_MAP[finding_id]

    # Stage 2: Exact match on "rule_id" (pattern-scan sub-findings)
    rule_id = finding.get("rule_id") or finding.get("ruleId") or ""
    if isinstance(rule_id, str) and rule_id in _RULE_ID_CATEGORY_MAP:
        return _RULE_ID_CATEGORY_MAP[rule_id]

    # Stage 3: CVE ID present -> vulnerability
    if finding.get("cve_id") or finding.get("cveId"):
        return FindingCategory.VULNERABILITY

    # Stage 4: "id" prefix heuristic
    if isinstance(finding_id, str):
        for prefix, category in _ID_PREFIX_RULES:
            if finding_id.startswith(prefix):
                return category

    # Stage 5: rule_id prefix heuristic
    rule_lower = (rule_id or "").lower() if isinstance(rule_id, str) else ""
    if rule_lower.startswith(("taint", "exploit_chain", "buffer", "format_str")):
        return FindingCategory.VULNERABILITY
    if rule_lower.startswith(
        ("misconfig", "posture", "telnet", "ssh", "weak", "default_cred")
    ):
        return FindingCategory.MISCONFIGURATION
    if rule_lower.startswith(("ipc", "ota", "inventory", "private_key", "candidate")):
        return FindingCategory.PIPELINE_ARTIFACT

    # Stage 6: Unclassified
    return None


def annotate_findings_with_categories(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Add 'category' field to each finding in-place.

    Only operates on dict findings; non-dict items are skipped.
    Does NOT overwrite an existing non-empty 'category' field.

    Returns counts dict:
        {category_name: count, ..., 'unclassified': count}
    """
    counts: dict[str, int] = {
        FindingCategory.VULNERABILITY.value: 0,
        FindingCategory.MISCONFIGURATION.value: 0,
        FindingCategory.PIPELINE_ARTIFACT.value: 0,
        "unclassified": 0,
    }
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        # Don't overwrite if already set to a non-empty value
        existing = finding.get("category")
        if existing and isinstance(existing, str):
            counts[existing] = counts.get(existing, 0) + 1
            continue
        cat = classify_finding(finding)
        if cat is None:
            finding["category"] = "unclassified"
            counts["unclassified"] += 1
        else:
            finding["category"] = cat.value
            counts[cat.value] += 1
    return counts
