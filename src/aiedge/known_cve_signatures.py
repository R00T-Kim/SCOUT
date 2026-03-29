"""Known CVE signature matching for firmware ground-truth validation.

This module encodes patterns from ``docs/known_cve_ground_truth.md`` into
structured data and provides a matching function that compares firmware
analysis results (vendor, model, binaries, symbols) against known CVE
signatures.

Typical usage::

    from aiedge.known_cve_signatures import match_known_signatures

    matches = match_known_signatures(
        vendor_claims=["netgear"],
        model_claims=["r7000"],
        binary_names={"httpd", "busybox"},
        binary_symbols={"httpd": {"system", "popen", "getenv"}},
    )
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CveSignature:
    """Describes a known CVE pattern matchable against inventory data."""

    cve_id: str
    vendor_patterns: frozenset[str]
    model_patterns: frozenset[str]
    binary_indicators: frozenset[str]
    sink_symbols: frozenset[str]
    vuln_type: str  # cmd_injection, buffer_overflow, auth_bypass, hardcoded_cred
    cvss_v3_score: float
    description: str
    entry_point: str  # cgi-bin, soap.cgi, tmUnblock.cgi, etc.


KNOWN_CVE_SIGNATURES: list[CveSignature] = [
    # --- Priority 1: Command Injection ---
    CveSignature(
        cve_id="CVE-2016-6277",
        vendor_patterns=frozenset({"netgear"}),
        model_patterns=frozenset({"r7000", "r6250", "r6400", "r6700", "r6900", "r7300", "r7900", "r8000", "d6220", "d6400"}),
        binary_indicators=frozenset({"httpd"}),
        sink_symbols=frozenset({"system", "popen"}),
        vuln_type="cmd_injection",
        cvss_v3_score=8.8,
        description="NETGEAR cgi-bin command injection via HTTP request URI path",
        entry_point="cgi-bin",
    ),
    CveSignature(
        cve_id="CVE-2018-6530",
        vendor_patterns=frozenset({"d-link", "dlink"}),
        model_patterns=frozenset({"dir-880l", "dir-868l", "dir-865l", "dir-860l"}),
        binary_indicators=frozenset({"cgibin", "soap.cgi", "soapcgi"}),
        sink_symbols=frozenset({"system"}),
        vuln_type="cmd_injection",
        cvss_v3_score=9.8,
        description="D-Link soap.cgi OS command injection via service parameter",
        entry_point="soap.cgi",
    ),
    CveSignature(
        cve_id="CVE-2019-16920",
        vendor_patterns=frozenset({"d-link", "dlink"}),
        model_patterns=frozenset({"dir-655", "dir-866l", "dir-652", "dhp-1565"}),
        binary_indicators=frozenset({"ssi", "cgibin"}),
        sink_symbols=frozenset({"system", "popen"}),
        vuln_type="cmd_injection",
        cvss_v3_score=9.8,
        description="D-Link apply_sec.cgi unauthenticated command injection",
        entry_point="apply_sec.cgi",
    ),
    CveSignature(
        cve_id="CVE-2025-34037",
        vendor_patterns=frozenset({"linksys"}),
        model_patterns=frozenset({"e4200", "e3200", "e3000", "e2500", "e2100l", "e1550", "e1500", "e1200", "e1000", "e900"}),
        binary_indicators=frozenset({"httpd"}),
        sink_symbols=frozenset({"system", "popen"}),
        vuln_type="cmd_injection",
        cvss_v3_score=9.8,
        description="Linksys E-series tmUnblock.cgi command injection (TheMoon worm)",
        entry_point="tmUnblock.cgi",
    ),
    CveSignature(
        cve_id="CVE-2020-10882",
        vendor_patterns=frozenset({"tp-link", "tplink"}),
        model_patterns=frozenset({"archer_a7", "archer-a7"}),
        binary_indicators=frozenset({"tdpserver", "tdpServer"}),
        sink_symbols=frozenset({"system"}),
        vuln_type="cmd_injection",
        cvss_v3_score=8.8,
        description="TP-Link Archer A7 tdpServer command injection via slave_mac",
        entry_point="tdpServer",
    ),
    CveSignature(
        cve_id="CVE-2018-14714",
        vendor_patterns=frozenset({"asus"}),
        model_patterns=frozenset({"rt-ac3200"}),
        binary_indicators=frozenset({"httpd"}),
        sink_symbols=frozenset({"system"}),
        vuln_type="cmd_injection",
        cvss_v3_score=9.8,
        description="ASUS RT-AC3200 appGet.cgi command injection via load_script",
        entry_point="appGet.cgi",
    ),
    CveSignature(
        cve_id="CVE-2014-8888",
        vendor_patterns=frozenset({"d-link", "dlink"}),
        model_patterns=frozenset({"dir-815"}),
        binary_indicators=frozenset({"cgibin", "httpd"}),
        sink_symbols=frozenset({"system", "popen"}),
        vuln_type="cmd_injection",
        cvss_v3_score=9.8,
        description="D-Link DIR-815 remote admin RCE via hedwig.cgi",
        entry_point="hedwig.cgi",
    ),
    CveSignature(
        cve_id="CVE-2014-0356",
        vendor_patterns=frozenset({"zyxel"}),
        model_patterns=frozenset({"nbg-419n"}),
        binary_indicators=frozenset({"httpd"}),
        sink_symbols=frozenset({"system"}),
        vuln_type="cmd_injection",
        cvss_v3_score=8.8,
        description="Zyxel NBG-419N management.c command injection",
        entry_point="management.c",
    ),
    # --- Priority 2: Buffer Overflow ---
    CveSignature(
        cve_id="CVE-2017-6548",
        vendor_patterns=frozenset({"asus"}),
        model_patterns=frozenset({"rt-n56u", "rt-n66u", "rt-ac66u", "rt-ac68u", "rt-ac87u"}),
        binary_indicators=frozenset({"networkmap"}),
        sink_symbols=frozenset({"strcpy", "sprintf", "strcat"}),
        vuln_type="buffer_overflow",
        cvss_v3_score=9.8,
        description="ASUS networkmap multicast buffer overflow RCE",
        entry_point="networkmap",
    ),
    CveSignature(
        cve_id="CVE-2020-15636",
        vendor_patterns=frozenset({"netgear"}),
        model_patterns=frozenset({"r6400", "r6700", "r7000", "r7850", "r7900", "r8000"}),
        binary_indicators=frozenset({"check_ra"}),
        sink_symbols=frozenset({"strcpy", "sprintf"}),
        vuln_type="buffer_overflow",
        cvss_v3_score=8.8,
        description="NETGEAR check_ra stack buffer overflow via raePolicyVersion",
        entry_point="check_ra",
    ),
    CveSignature(
        cve_id="CVE-2017-13772",
        vendor_patterns=frozenset({"tp-link", "tplink"}),
        model_patterns=frozenset({"tl-wr940n", "wr940n"}),
        binary_indicators=frozenset({"httpd"}),
        sink_symbols=frozenset({"strcpy", "sprintf"}),
        vuln_type="buffer_overflow",
        cvss_v3_score=8.8,
        description="TP-Link WR940N PingIframeRpm.htm stack buffer overflow",
        entry_point="PingIframeRpm.htm",
    ),
    # --- Priority 3: Auth Bypass / Hardcoded Credentials ---
    CveSignature(
        cve_id="CVE-2017-5521",
        vendor_patterns=frozenset({"netgear"}),
        model_patterns=frozenset({"r8500", "r8300", "r7000", "r6400", "r7300", "wndr3400"}),
        binary_indicators=frozenset({"httpd"}),
        sink_symbols=frozenset({"system"}),  # less relevant for auth bypass
        vuln_type="auth_bypass",
        cvss_v3_score=8.1,
        description="NETGEAR passwordrecovered.cgi authentication bypass",
        entry_point="passwordrecovered.cgi",
    ),
    CveSignature(
        cve_id="CVE-2014-0354",
        vendor_patterns=frozenset({"zyxel"}),
        model_patterns=frozenset({"nbg-419n"}),
        binary_indicators=frozenset({"httpd"}),
        sink_symbols=frozenset(),
        vuln_type="hardcoded_cred",
        cvss_v3_score=7.8,
        description="Zyxel NBG-419N hardcoded credential qweasdzxc",
        entry_point="admin",
    ),
]


def match_known_signatures(
    *,
    vendor_claims: list[str],
    model_claims: list[str],
    binary_names: set[str],
    binary_symbols: dict[str, set[str]],
) -> list[dict[str, object]]:
    """Match firmware attributes against known CVE signatures.

    Parameters
    ----------
    vendor_claims:
        Lowercase vendor names from attribution (e.g. ["netgear"]).
    model_claims:
        Lowercase model names from attribution/filename (e.g. ["r7000"]).
    binary_names:
        Set of binary basenames found in the firmware (e.g. {"httpd", "busybox"}).
    binary_symbols:
        Mapping of binary basename -> set of imported symbols.

    Returns
    -------
    list[dict]:
        Matched CVE records with confidence scores.
    """
    vendor_set = {v.lower().strip() for v in vendor_claims}
    model_set = {m.lower().strip().replace("_", "-") for m in model_claims}
    binary_lower = {b.lower() for b in binary_names}

    matches: list[dict[str, object]] = []

    for sig in KNOWN_CVE_SIGNATURES:
        # 1. Vendor match
        vendor_match = bool(vendor_set & sig.vendor_patterns)
        if not vendor_match:
            continue

        # 2. Model match
        model_match = bool(model_set & sig.model_patterns)

        # 3. Binary indicators present
        sig_bins_lower = {b.lower() for b in sig.binary_indicators}
        binary_match = bool(binary_lower & sig_bins_lower)

        # 4. Sink symbols present in any matching binary
        sink_match = False
        if sig.sink_symbols:
            all_syms: set[str] = set()
            for bname, syms in binary_symbols.items():
                if bname.lower() in sig_bins_lower or not sig_bins_lower:
                    all_syms |= {s.lower() for s in syms}
            sig_sinks_lower = {s.lower() for s in sig.sink_symbols}
            sink_match = bool(all_syms & sig_sinks_lower)
        else:
            # No sink requirement (e.g., hardcoded_cred)
            sink_match = True

        # Calculate confidence
        score_parts = [
            0.30 if vendor_match else 0.0,
            0.25 if model_match else 0.0,
            0.25 if binary_match else 0.0,
            0.20 if sink_match else 0.0,
        ]
        confidence = sum(score_parts)

        # Minimum threshold: vendor + at least one other factor
        if confidence < 0.50:
            continue

        matches.append({
            "cve_id": sig.cve_id,
            "vendor_match": vendor_match,
            "model_match": model_match,
            "binary_match": binary_match,
            "sink_match": sink_match,
            "confidence": round(confidence, 2),
            "cvss_v3_score": sig.cvss_v3_score,
            "vuln_type": sig.vuln_type,
            "description": sig.description,
            "entry_point": sig.entry_point,
            "match_type": "known_signature",
        })

    # Sort by confidence descending
    matches.sort(key=lambda m: (-float(m.get("confidence", 0)), str(m.get("cve_id", ""))))
    return matches
