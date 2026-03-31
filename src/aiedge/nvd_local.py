"""Local NVD CVE database matching for offline firmware CVE detection.

Loads NVD JSON files from a local cache directory and matches firmware
attributes (vendor, model, binaries) against CPE entries.

Usage::

    from aiedge.nvd_local import load_nvd_db, match_nvd_local

    cves = load_nvd_db(Path("data/nvd-cache"))
    matches = match_nvd_local(cves, "netgear", ["r7000"], {"httpd"})
"""

from __future__ import annotations

import json
from pathlib import Path

# ---------------------------------------------------------------------------
# Vendor alias map for cross-referencing CPE vendor fields
# ---------------------------------------------------------------------------

_VENDOR_MAP: dict[str, set[str]] = {
    "dlink": {"d-link", "dlink", "d_link"},
    "tplink": {"tp-link", "tplink", "tp_link"},
    "netgear": {"netgear"},
    "asus": {"asus", "asustek"},
    "linksys": {"linksys"},
    "trendnet": {"trendnet"},
    "zyxel": {"zyxel"},
    "belkin": {"belkin"},
    "tenda": {"tenda"},
    "qnap": {"qnap"},
    "synology": {"synology"},
    "ubiquiti": {"ubiquiti", "ui"},
    "mikrotik": {"mikrotik"},
    "hikvision": {"hikvision", "hikvision_digital_technology"},
}


# ---------------------------------------------------------------------------
# NVD DB loader
# ---------------------------------------------------------------------------


def load_nvd_db(nvd_dir: Path) -> list[dict[str, object]]:
    """Load all NVD JSON files from a directory into a flat CVE list."""
    all_cves: list[dict[str, object]] = []
    if not nvd_dir.is_dir():
        return all_cves
    for f in sorted(nvd_dir.glob("nvd-*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                if cve.get("id"):
                    all_cves.append(cve)
        except (json.JSONDecodeError, OSError):
            pass
    return all_cves


# ---------------------------------------------------------------------------
# CPE / CVSS helpers
# ---------------------------------------------------------------------------


def extract_cpe_products(cve: dict[str, object]) -> list[dict[str, str]]:
    """Extract (vendor, product, version, version_end) from CPE match criteria."""
    products: list[dict[str, str]] = []
    for config in cve.get("configurations", []):
        if not isinstance(config, dict):
            continue
        for node in config.get("nodes", []):
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch", []):
                if not isinstance(match, dict) or not match.get("vulnerable"):
                    continue
                cpe = str(match.get("criteria", ""))
                parts = cpe.split(":")
                if len(parts) >= 6:
                    products.append({
                        "vendor": parts[3].lower(),
                        "product": parts[4].lower(),
                        "version": parts[5] if len(parts) > 5 else "*",
                        "version_end": str(
                            match.get("versionEndExcluding",
                                      match.get("versionEndIncluding", ""))
                        ),
                    })
    return products


def get_cvss_score(cve: dict[str, object]) -> float:
    """Extract CVSS v3.1/v3.0/v2 base score."""
    metrics = cve.get("metrics", {})
    if not isinstance(metrics, dict):
        return 0.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if isinstance(entries, list) and entries:
            data = entries[0].get("cvssData", {})
            if isinstance(data, dict):
                score = data.get("baseScore", 0)
                if isinstance(score, (int, float)):
                    return float(score)
    return 0.0


def _classify_vuln_type(cve: dict[str, object]) -> str:
    """Determine vulnerability type from CWE weaknesses."""
    weaknesses = cve.get("weaknesses", [])
    if not isinstance(weaknesses, list):
        return "unknown"
    for w in weaknesses:
        if not isinstance(w, dict):
            continue
        for wd in w.get("description", []):
            if isinstance(wd, dict):
                cwe = str(wd.get("value", ""))
                if cwe in ("CWE-78", "CWE-77"):
                    return "cmd_injection"
                if cwe in ("CWE-120", "CWE-121", "CWE-122", "CWE-787"):
                    return "buffer_overflow"
                if cwe in ("CWE-287", "CWE-306"):
                    return "auth_bypass"
                if cwe == "CWE-798":
                    return "hardcoded_cred"
                if cwe == "CWE-79":
                    return "xss"
    return "unknown"


# ---------------------------------------------------------------------------
# Main matching function
# ---------------------------------------------------------------------------


def match_nvd_local(
    nvd_cves: list[dict[str, object]],
    vendor: str,
    models: list[str],
    binary_names: set[str],
) -> list[dict[str, object]]:
    """Match firmware against local NVD CVE database.

    Matches by: vendor in CPE + product matches model or binary name.

    Parameters
    ----------
    nvd_cves:
        Flat list of CVE dicts loaded by :func:`load_nvd_db`.
    vendor:
        Primary vendor name (e.g. ``"netgear"``).
    models:
        Model name candidates (e.g. ``["r7000", "r6400"]``).
    binary_names:
        Binary basenames found in firmware (e.g. ``{"httpd", "busybox"}``).

    Returns
    -------
    list[dict]:
        Matched CVE records with confidence, CVSS, type, description.
    """
    matches: list[dict[str, object]] = []
    vendor_lower = vendor.lower().replace("-", "").replace("_", "")
    model_set = {m.lower().replace("-", "").replace("_", "") for m in models}
    binary_lower = {b.lower().replace("-", "").replace("_", "") for b in binary_names}

    # Build vendor alias set
    vendor_aliases: set[str] = {vendor_lower}
    for key, aliases in _VENDOR_MAP.items():
        if vendor_lower in aliases or key == vendor_lower:
            vendor_aliases |= aliases

    for cve in nvd_cves:
        cve_id = str(cve.get("id", ""))
        products = extract_cpe_products(cve)
        if not products:
            continue

        vendor_match = False
        product_match = False
        for prod in products:
            cpe_vendor = prod["vendor"].replace("-", "").replace("_", "")
            if cpe_vendor not in vendor_aliases:
                continue
            vendor_match = True
            cpe_product = prod["product"].replace("-", "").replace("_", "")
            if cpe_product in model_set or cpe_product in binary_lower:
                product_match = True
                break
            for m in model_set:
                if cpe_product in m or m in cpe_product:
                    product_match = True
                    break
            if product_match:
                break

        if not vendor_match or not product_match:
            continue

        score = get_cvss_score(cve)
        desc = ""
        desc_list = cve.get("descriptions", [])
        if isinstance(desc_list, list):
            for d in desc_list:
                if isinstance(d, dict) and d.get("lang") == "en":
                    desc = str(d.get("value", ""))[:200]
                    break

        matches.append({
            "cve_id": cve_id,
            "confidence": 0.70 if product_match else 0.40,
            "cvss_v3_score": score,
            "vuln_type": _classify_vuln_type(cve),
            "description": desc,
            "entry_point": "",
            "match_type": "nvd_local",
            "vendor_match": True,
            "model_match": product_match,
            "binary_match": False,
            "sink_match": False,
        })

    return matches
