"""Unit tests for finding_categories taxonomy (PR #7a).

Tests cover:
- classify_finding() exact-map, CVE heuristic, prefix heuristic, unclassified
- annotate_findings_with_categories() additive, no-overwrite, counts
- Schema-compatibility: additive only, consumers can ignore the field
"""

from __future__ import annotations

from aiedge.finding_categories import (
    FindingCategory,
    annotate_findings_with_categories,
    classify_finding,
)


class TestClassifyFindingByFindingId:
    """Exact match on the 'id' field (top-level findings from findings.py)."""

    def test_vulnerability_web_exec_overlap(self) -> None:
        f = {"id": "aiedge.findings.web.exec_sink_overlap"}
        assert classify_finding(f) == FindingCategory.VULNERABILITY

    def test_misconfiguration_telnet(self) -> None:
        f = {"id": "aiedge.findings.debug.telnet_enablement"}
        assert classify_finding(f) == FindingCategory.MISCONFIGURATION

    def test_misconfiguration_adb(self) -> None:
        f = {"id": "aiedge.findings.debug.adb_enablement"}
        assert classify_finding(f) == FindingCategory.MISCONFIGURATION

    def test_misconfiguration_android_debuggable(self) -> None:
        f = {"id": "aiedge.findings.debug.android_manifest_debuggable"}
        assert classify_finding(f) == FindingCategory.MISCONFIGURATION

    def test_misconfiguration_ssh_root(self) -> None:
        f = {"id": "aiedge.findings.config.ssh_permit_root_login"}
        assert classify_finding(f) == FindingCategory.MISCONFIGURATION

    def test_misconfiguration_ssh_password_auth(self) -> None:
        f = {"id": "aiedge.findings.config.ssh_password_authentication"}
        assert classify_finding(f) == FindingCategory.MISCONFIGURATION

    def test_misconfiguration_ssh_empty_passwords(self) -> None:
        f = {"id": "aiedge.findings.config.ssh_permit_empty_passwords"}
        assert classify_finding(f) == FindingCategory.MISCONFIGURATION

    def test_misconfiguration_telnet_disabled(self) -> None:
        f = {"id": "aiedge.findings.hardening.telnet_disabled"}
        assert classify_finding(f) == FindingCategory.MISCONFIGURATION

    def test_pipeline_artifact_private_key(self) -> None:
        f = {"id": "aiedge.findings.secrets.private_key_pem"}
        assert classify_finding(f) == FindingCategory.PIPELINE_ARTIFACT

    def test_pipeline_artifact_ota_metadata(self) -> None:
        f = {"id": "aiedge.findings.update.metadata_present"}
        assert classify_finding(f) == FindingCategory.PIPELINE_ARTIFACT

    def test_pipeline_artifact_string_hits(self) -> None:
        f = {"id": "aiedge.findings.inventory.string_hits_present"}
        assert classify_finding(f) == FindingCategory.PIPELINE_ARTIFACT

    def test_pipeline_artifact_exploit_plan(self) -> None:
        f = {"id": "aiedge.findings.exploit.candidate_plan"}
        assert classify_finding(f) == FindingCategory.PIPELINE_ARTIFACT

    def test_pipeline_artifact_analysis_incomplete(self) -> None:
        f = {"id": "aiedge.findings.analysis_incomplete"}
        assert classify_finding(f) == FindingCategory.PIPELINE_ARTIFACT


class TestClassifyFindingByRuleId:
    """Exact match on the 'rule_id' field (pattern-scan sub-findings)."""

    def test_python_exec_sink_is_vulnerability(self) -> None:
        f = {"rule_id": "python_exec_sink"}
        assert classify_finding(f) == FindingCategory.VULNERABILITY

    def test_shell_eval_injection_is_vulnerability(self) -> None:
        f = {"rule_id": "shell_eval_injection"}
        assert classify_finding(f) == FindingCategory.VULNERABILITY

    def test_php_exec_sink_is_vulnerability(self) -> None:
        f = {"rule_id": "php_exec_sink"}
        assert classify_finding(f) == FindingCategory.VULNERABILITY

    def test_cpp_strings_risk_link_is_vulnerability(self) -> None:
        f = {"rule_id": "cpp_strings_risk_link"}
        assert classify_finding(f) == FindingCategory.VULNERABILITY

    def test_c_format_string_vuln_is_vulnerability(self) -> None:
        f = {"rule_id": "c_format_string_vuln"}
        assert classify_finding(f) == FindingCategory.VULNERABILITY

    def test_php_sql_concat_is_vulnerability(self) -> None:
        f = {"rule_id": "php_sql_concat"}
        assert classify_finding(f) == FindingCategory.VULNERABILITY

    def test_php_path_traversal_is_vulnerability(self) -> None:
        f = {"rule_id": "php_path_traversal"}
        assert classify_finding(f) == FindingCategory.VULNERABILITY

    def test_python_ssrf_sink_is_vulnerability(self) -> None:
        f = {"rule_id": "python_ssrf_sink"}
        assert classify_finding(f) == FindingCategory.VULNERABILITY

    def test_shell_ssrf_sink_is_vulnerability(self) -> None:
        f = {"rule_id": "shell_ssrf_sink"}
        assert classify_finding(f) == FindingCategory.VULNERABILITY

    def test_php_ssrf_sink_is_vulnerability(self) -> None:
        f = {"rule_id": "php_ssrf_sink"}
        assert classify_finding(f) == FindingCategory.VULNERABILITY

    def test_upload_source_signal_is_vulnerability(self) -> None:
        f = {"rule_id": "upload_source_signal"}
        assert classify_finding(f) == FindingCategory.VULNERABILITY

    def test_php_upload_source_is_vulnerability(self) -> None:
        f = {"rule_id": "php_upload_source"}
        assert classify_finding(f) == FindingCategory.VULNERABILITY

    def test_python_route_without_auth_is_misconfiguration(self) -> None:
        f = {"rule_id": "python_route_without_auth"}
        assert classify_finding(f) == FindingCategory.MISCONFIGURATION

    def test_python_csrf_exempt_is_misconfiguration(self) -> None:
        f = {"rule_id": "python_csrf_exempt"}
        assert classify_finding(f) == FindingCategory.MISCONFIGURATION

    def test_php_csrf_bypass_is_misconfiguration(self) -> None:
        f = {"rule_id": "php_csrf_bypass"}
        assert classify_finding(f) == FindingCategory.MISCONFIGURATION

    def test_py_tar_extractall_is_pipeline_artifact(self) -> None:
        f = {"rule_id": "py_tar_extractall"}
        assert classify_finding(f) == FindingCategory.PIPELINE_ARTIFACT

    def test_shell_archive_extract_is_pipeline_artifact(self) -> None:
        f = {"rule_id": "shell_archive_extract"}
        assert classify_finding(f) == FindingCategory.PIPELINE_ARTIFACT


class TestClassifyFindingHeuristics:
    """Fallback heuristic rules when no exact map entry exists."""

    def test_vulnerability_by_cve_id(self) -> None:
        f = {"id": "aiedge.findings.unknown.new_rule", "cve_id": "CVE-2024-1234"}
        assert classify_finding(f) == FindingCategory.VULNERABILITY

    def test_vulnerability_by_cveId_camel(self) -> None:
        f = {"cveId": "CVE-2025-9999"}
        assert classify_finding(f) == FindingCategory.VULNERABILITY

    def test_id_prefix_config_fallback(self) -> None:
        # Unknown config finding should still be MISCONFIGURATION via prefix
        f = {"id": "aiedge.findings.config.new_future_rule"}
        assert classify_finding(f) == FindingCategory.MISCONFIGURATION

    def test_id_prefix_debug_fallback(self) -> None:
        f = {"id": "aiedge.findings.debug.some_future_rule"}
        assert classify_finding(f) == FindingCategory.MISCONFIGURATION

    def test_id_prefix_hardening_fallback(self) -> None:
        f = {"id": "aiedge.findings.hardening.some_new_check"}
        assert classify_finding(f) == FindingCategory.MISCONFIGURATION

    def test_id_prefix_web_fallback(self) -> None:
        f = {"id": "aiedge.findings.web.new_web_vuln"}
        assert classify_finding(f) == FindingCategory.VULNERABILITY

    def test_id_prefix_secrets_fallback(self) -> None:
        f = {"id": "aiedge.findings.secrets.certificate_key"}
        assert classify_finding(f) == FindingCategory.PIPELINE_ARTIFACT

    def test_id_prefix_update_fallback(self) -> None:
        f = {"id": "aiedge.findings.update.new_ota_field"}
        assert classify_finding(f) == FindingCategory.PIPELINE_ARTIFACT

    def test_id_prefix_inventory_fallback(self) -> None:
        f = {"id": "aiedge.findings.inventory.new_signal"}
        assert classify_finding(f) == FindingCategory.PIPELINE_ARTIFACT

    def test_id_prefix_exploit_fallback(self) -> None:
        f = {"id": "aiedge.findings.exploit.new_plan"}
        assert classify_finding(f) == FindingCategory.PIPELINE_ARTIFACT

    def test_rule_id_taint_prefix_heuristic(self) -> None:
        f = {"rule_id": "taint-buffer-overflow"}
        assert classify_finding(f) == FindingCategory.VULNERABILITY

    def test_unclassified_unknown_id(self) -> None:
        f = {"id": "aiedge.findings.completely.unknown"}
        assert classify_finding(f) is None

    def test_unclassified_unknown_rule_id(self) -> None:
        f = {"rule_id": "completely-unknown-id-xyz"}
        assert classify_finding(f) is None

    def test_unclassified_empty_finding(self) -> None:
        f: dict[str, object] = {}
        assert classify_finding(f) is None

    def test_non_dict_returns_none(self) -> None:
        assert classify_finding("not a dict") is None  # type: ignore[arg-type]


class TestAnnotateFindings:
    """annotate_findings_with_categories() behaviour."""

    def test_additive_does_not_remove_fields(self) -> None:
        findings = [
            {"id": "aiedge.findings.debug.telnet_enablement", "severity": "medium"}
        ]
        annotate_findings_with_categories(findings)
        assert findings[0]["severity"] == "medium"
        assert findings[0]["category"] == "misconfiguration"

    def test_category_set_correctly_vulnerability(self) -> None:
        findings = [{"id": "aiedge.findings.web.exec_sink_overlap"}]
        annotate_findings_with_categories(findings)
        assert findings[0]["category"] == "vulnerability"

    def test_category_set_correctly_pipeline_artifact(self) -> None:
        findings = [{"id": "aiedge.findings.exploit.candidate_plan"}]
        annotate_findings_with_categories(findings)
        assert findings[0]["category"] == "pipeline_artifact"

    def test_unclassified_unknown_finding(self) -> None:
        findings = [{"id": "aiedge.findings.completely.unknown.xyz"}]
        annotate_findings_with_categories(findings)
        assert findings[0]["category"] == "unclassified"

    def test_does_not_overwrite_existing_non_empty_category(self) -> None:
        findings = [
            {
                "id": "aiedge.findings.debug.telnet_enablement",
                "category": "vulnerability",
            }
        ]
        annotate_findings_with_categories(findings)
        # must NOT overwrite the existing "vulnerability" value
        assert findings[0]["category"] == "vulnerability"

    def test_overwrites_empty_string_category(self) -> None:
        findings = [{"id": "aiedge.findings.debug.telnet_enablement", "category": ""}]
        annotate_findings_with_categories(findings)
        # empty string is treated as absent -> should be classified
        assert findings[0]["category"] == "misconfiguration"

    def test_counts_all_categories(self) -> None:
        findings = [
            {"id": "aiedge.findings.web.exec_sink_overlap"},
            {"id": "aiedge.findings.debug.telnet_enablement"},
            {"id": "aiedge.findings.exploit.candidate_plan"},
            {"id": "aiedge.findings.completely.unknown.xyz"},
        ]
        counts = annotate_findings_with_categories(findings)
        assert counts["vulnerability"] == 1
        assert counts["misconfiguration"] == 1
        assert counts["pipeline_artifact"] == 1
        assert counts["unclassified"] == 1

    def test_counts_skips_non_dict(self) -> None:
        findings = [
            {"id": "aiedge.findings.web.exec_sink_overlap"},
            "not a dict",  # type: ignore[list-item]
            None,  # type: ignore[list-item]
        ]
        counts = annotate_findings_with_categories(findings)
        assert counts["vulnerability"] == 1

    def test_empty_findings_list_returns_zero_counts(self) -> None:
        counts = annotate_findings_with_categories([])
        assert counts["vulnerability"] == 0
        assert counts["misconfiguration"] == 0
        assert counts["pipeline_artifact"] == 0
        assert counts["unclassified"] == 0

    def test_multiple_findings_same_category(self) -> None:
        findings = [
            {"id": "aiedge.findings.config.ssh_permit_root_login"},
            {"id": "aiedge.findings.config.ssh_password_authentication"},
            {"id": "aiedge.findings.debug.adb_enablement"},
        ]
        counts = annotate_findings_with_categories(findings)
        assert counts["misconfiguration"] == 3

    def test_rule_id_finding_classified(self) -> None:
        findings = [{"rule_id": "python_exec_sink", "severity": "high"}]
        annotate_findings_with_categories(findings)
        assert findings[0]["category"] == "vulnerability"
        assert findings[0]["severity"] == "high"


class TestSchemaCompatibility:
    """PR #7a is additive -- must not break consumers that don't know about category."""

    def test_finding_remains_dict(self) -> None:
        findings = [{"id": "aiedge.findings.web.exec_sink_overlap", "path": "/foo"}]
        annotate_findings_with_categories(findings)
        assert isinstance(findings[0], dict)

    def test_consumer_can_ignore_category_field(self) -> None:
        findings = [{"id": "aiedge.findings.web.exec_sink_overlap"}]
        annotate_findings_with_categories(findings)
        # Simulate a consumer that only reads the fields it knows about
        consumer_view = {k: v for k, v in findings[0].items() if k != "category"}
        assert consumer_view == {"id": "aiedge.findings.web.exec_sink_overlap"}

    def test_no_existing_fields_removed(self) -> None:
        original_keys = {
            "id",
            "title",
            "severity",
            "confidence",
            "disposition",
            "evidence",
        }
        finding: dict[str, object] = {
            "id": "aiedge.findings.debug.telnet_enablement",
            "title": "Telnet service enablement signal",
            "severity": "medium",
            "confidence": 0.75,
            "disposition": "confirmed",
            "evidence": [],
        }
        findings = [finding]
        annotate_findings_with_categories(findings)
        assert original_keys.issubset(set(findings[0].keys()))

    def test_only_category_key_is_added(self) -> None:
        finding: dict[str, object] = {
            "id": "aiedge.findings.debug.adb_enablement",
            "severity": "medium",
        }
        before_keys = set(finding.keys())
        findings = [finding]
        annotate_findings_with_categories(findings)
        after_keys = set(findings[0].keys())
        assert after_keys - before_keys == {"category"}

    def test_category_value_is_string(self) -> None:
        findings = [{"id": "aiedge.findings.web.exec_sink_overlap"}]
        annotate_findings_with_categories(findings)
        assert isinstance(findings[0]["category"], str)

    def test_all_known_finding_ids_classified(self) -> None:
        """Ensure none of the 13 known SCOUT finding IDs end up as unclassified."""
        known_ids = [
            "aiedge.findings.secrets.private_key_pem",
            "aiedge.findings.debug.telnet_enablement",
            "aiedge.findings.debug.adb_enablement",
            "aiedge.findings.config.ssh_permit_root_login",
            "aiedge.findings.config.ssh_password_authentication",
            "aiedge.findings.config.ssh_permit_empty_passwords",
            "aiedge.findings.debug.android_manifest_debuggable",
            "aiedge.findings.hardening.telnet_disabled",
            "aiedge.findings.update.metadata_present",
            "aiedge.findings.web.exec_sink_overlap",
            "aiedge.findings.inventory.string_hits_present",
            "aiedge.findings.exploit.candidate_plan",
            "aiedge.findings.analysis_incomplete",
        ]
        findings = [{"id": fid} for fid in known_ids]
        counts = annotate_findings_with_categories(findings)
        assert counts.get("unclassified", 0) == 0, (
            f"Some known finding IDs were unclassified: "
            f"{[f for f in findings if f.get('category') == 'unclassified']}"
        )

    def test_all_known_rule_ids_classified(self) -> None:
        """Ensure none of the 17 SCOUT pattern-scan rule_ids end up as unclassified."""
        known_rule_ids = [
            "py_tar_extractall",
            "shell_archive_extract",
            "python_route_without_auth",
            "python_csrf_exempt",
            "upload_source_signal",
            "python_exec_sink",
            "shell_eval_injection",
            "c_format_string_vuln",
            "python_ssrf_sink",
            "shell_ssrf_sink",
            "php_exec_sink",
            "php_csrf_bypass",
            "php_upload_source",
            "php_sql_concat",
            "php_path_traversal",
            "php_ssrf_sink",
            "cpp_strings_risk_link",
        ]
        findings = [{"rule_id": rid} for rid in known_rule_ids]
        counts = annotate_findings_with_categories(findings)
        assert counts.get("unclassified", 0) == 0, (
            f"Some known rule_ids were unclassified: "
            f"{[f for f in findings if f.get('category') == 'unclassified']}"
        )
