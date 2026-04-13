"""sarif_export.py — Export SCOUT findings to SARIF 2.1.0 format.

Converts findings JSON to the OASIS SARIF 2.1.0 schema for integration
with GitHub Code Scanning, VS Code SARIF Viewer, and other standard tools.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .path_safety import assert_under_dir

# ---------------------------------------------------------------------------
# Severity → SARIF level mapping
# ---------------------------------------------------------------------------

_SEVERITY_TO_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# ---------------------------------------------------------------------------
# Severity → security-severity score (GitHub Code Scanning convention)
# ---------------------------------------------------------------------------

_SEVERITY_TO_SCORE: dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 1.0,
}

# ---------------------------------------------------------------------------
# Confidence → SARIF precision mapping
# ---------------------------------------------------------------------------

_CONFIDENCE_THRESHOLDS: list[tuple[float, str]] = [
    (0.8, "very-high"),
    (0.6, "high"),
    (0.4, "medium"),
]
_CONFIDENCE_DEFAULT_PRECISION = "low"


def _confidence_to_precision(confidence: float) -> str:
    """Map a 0.0–1.0 confidence score to a SARIF precision string."""
    for threshold, precision in _CONFIDENCE_THRESHOLDS:
        if confidence > threshold:
            return precision
    return _CONFIDENCE_DEFAULT_PRECISION


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_str(value: Any, fallback: str = "") -> str:
    """Coerce *value* to str, returning *fallback* when None or non-string."""
    if isinstance(value, str):
        return value
    return fallback


def _safe_float(value: Any, fallback: float = 0.0) -> float:
    """Coerce *value* to float, returning *fallback* on failure."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return fallback


# ---------------------------------------------------------------------------
# Rule conversion
# ---------------------------------------------------------------------------


def _finding_to_rule(finding: dict[str, Any]) -> dict[str, Any]:
    """Convert a SCOUT finding to a SARIF rule definition.

    Args:
        finding: A finding dict as produced by the SCOUT findings stage.

    Returns:
        A SARIF ``reportingDescriptor`` dict suitable for inclusion in
        ``tool.driver.rules``.
    """
    finding_id = _safe_str(finding.get("id"), "unknown-rule")
    title = _safe_str(finding.get("title"), finding_id)
    severity = _safe_str(finding.get("severity"), "info").lower()
    confidence = _safe_float(finding.get("confidence"), 0.5)
    description = _safe_str(finding.get("description"), "")

    rule: dict[str, Any] = {
        "id": finding_id,
        "shortDescription": {"text": title},
        "properties": {
            "security-severity": str(_SEVERITY_TO_SCORE.get(severity, 1.0)),
            "precision": _confidence_to_precision(confidence),
        },
    }

    if description:
        rule["fullDescription"] = {"text": description}

    return rule


# ---------------------------------------------------------------------------
# Result conversion
# ---------------------------------------------------------------------------


def _evidence_to_location(evidence_item: dict[str, Any]) -> dict[str, Any] | None:
    """Convert a single evidence item to a SARIF location, or None if no path."""
    path = _safe_str(evidence_item.get("path"))
    if not path:
        return None

    artifact_location: dict[str, Any] = {
        "uri": path,
        "uriBaseId": "%SRCROOT%",
    }

    region: dict[str, Any] = {}

    offset = evidence_item.get("offset")
    if isinstance(offset, int) and offset >= 0:
        region["byteOffset"] = offset

    line = evidence_item.get("line")
    if isinstance(line, int) and line >= 1:
        region["startLine"] = line

    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": artifact_location,
        }
    }

    if region:
        location["physicalLocation"]["region"] = region

    return location


def _finding_to_result(finding: dict[str, Any]) -> dict[str, Any]:
    """Convert a SCOUT finding to a SARIF result.

    Args:
        finding: A finding dict as produced by the SCOUT findings stage.

    Returns:
        A SARIF ``result`` dict suitable for inclusion in ``run.results``.
    """
    finding_id = _safe_str(finding.get("id"), "unknown-rule")
    severity = _safe_str(finding.get("severity"), "info").lower()
    title = _safe_str(finding.get("title"), finding_id)

    # Build message text: title + rationale if present
    message_parts = [title]
    rationale = finding.get("rationale")
    if isinstance(rationale, list):
        for item in rationale:
            if isinstance(item, str) and item:
                message_parts.append(item)
    elif isinstance(rationale, str) and rationale:
        message_parts.append(rationale)

    result: dict[str, Any] = {
        "ruleId": finding_id,
        "level": _SEVERITY_TO_LEVEL.get(severity, "note"),
        "message": {"text": " — ".join(message_parts)},
    }

    # Locations from evidence items
    evidence_list = finding.get("evidence")
    if isinstance(evidence_list, list):
        locations: list[dict[str, Any]] = []
        for ev_item in evidence_list:
            if not isinstance(ev_item, dict):
                continue
            loc = _evidence_to_location(ev_item)
            if loc is not None:
                locations.append(loc)
        if locations:
            result["locations"] = locations

        # Partial fingerprint from first evidence item with snippet_sha256
        for ev_item in evidence_list:
            if not isinstance(ev_item, dict):
                continue
            snippet_hash = ev_item.get("snippet_sha256")
            if isinstance(snippet_hash, str) and snippet_hash:
                result["partialFingerprints"] = {
                    "primaryLocationLineHash": snippet_hash,
                }
                break

    # Custom properties
    properties: dict[str, Any] = {}

    confidence = finding.get("confidence")
    if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
        properties["confidence"] = float(confidence)

    disposition = finding.get("disposition")
    if isinstance(disposition, str) and disposition:
        properties["disposition"] = disposition

    tier = finding.get("exploitability_tier")
    if isinstance(tier, str) and tier:
        properties["exploitability_tier"] = tier

    # PR #7a: category field is optional; expose when present
    category = finding.get("category")
    if isinstance(category, str) and category:
        properties["scout_category"] = category

    if properties:
        result["properties"] = properties

    return result


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def findings_to_sarif(
    findings: list[dict[str, Any]],
    run_dir: Path,
    tool_version: str = "1.0.0",
) -> dict[str, Any]:
    """Convert a list of SCOUT findings to a complete SARIF 2.1.0 document.

    Args:
        findings: List of finding dicts as produced by the SCOUT findings
            stage (``stages/findings/findings.json`` → ``findings`` key).
        run_dir: Root of the current analysis run (used for context only;
            no files are read or written).
        tool_version: SCOUT version string to embed in the SARIF tool
            metadata.

    Returns:
        A dict representing a valid SARIF 2.1.0 JSON document.
    """
    # Deduplicate rules by finding id
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        finding_id = _safe_str(finding.get("id"), "unknown-rule")

        # Collect unique rules
        if finding_id not in rules_by_id:
            rules_by_id[finding_id] = _finding_to_rule(finding)

        results.append(_finding_to_result(finding))

    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SCOUT",
                        "semanticVersion": tool_version,
                        "informationUri": "https://github.com/R00T-Kim/SCOUT",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    return sarif


# ---------------------------------------------------------------------------
# Convenience file I/O wrapper
# ---------------------------------------------------------------------------


def export_sarif(
    findings_path: Path,
    output_path: Path,
    run_dir: Path,
    *,
    tool_version: str = "1.0.0",
) -> Path:
    """Read findings JSON, convert to SARIF, and write to *output_path*.

    Args:
        findings_path: Path to a SCOUT ``findings.json`` file.  The file
            must contain a JSON object with a ``findings`` key holding a
            list of finding dicts.
        output_path: Destination path for the SARIF JSON output.
        run_dir: Root of the analysis run directory.  Used for path safety
            validation on *output_path*.
        tool_version: SCOUT version string to embed in SARIF metadata.

    Returns:
        *output_path* after the file has been written.

    Raises:
        aiedge.policy.AIEdgePolicyViolation: When *output_path* is outside
            *run_dir*.
        FileNotFoundError: When *findings_path* does not exist.
        json.JSONDecodeError: When *findings_path* is not valid JSON.
    """
    assert_under_dir(run_dir, output_path)

    raw = json.loads(findings_path.read_text(encoding="utf-8"))

    if isinstance(raw, dict):
        findings = raw.get("findings", [])
        if not isinstance(findings, list):
            findings = []
    elif isinstance(raw, list):
        findings = raw
    else:
        findings = []

    sarif = findings_to_sarif(findings, run_dir, tool_version=tool_version)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(sarif, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )

    return output_path
