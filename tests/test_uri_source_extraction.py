"""Phase 2C+.2 — LARA-style URI / CGI / config-key source identification.

Locks the new pattern catalogues (URI prefixes, CGI environment variables,
NVRAM/sysconf config keys) and the ``_extract_uri_key_sources`` helper that
EnhancedSourceStage now consults per-binary. The helper produces
``(pattern, kind)`` tuples; the stage wraps each tuple into a source dict
with ``confidence=0.40`` and ``method="lara_pattern"``.
"""

from __future__ import annotations

from aiedge.enhanced_source import (
    _CGI_VAR_PATTERNS,
    _CONFIG_KEY_PATTERNS,
    _URI_SOURCE_PATTERNS,
    _extract_uri_key_sources,
)

# ---------------------------------------------------------------------------
# Pattern catalogue size
# ---------------------------------------------------------------------------


def test_pattern_catalogue_total_meets_phase_2c_plus_target() -> None:
    """Phase 2C+.2 ships ≥30 patterns combined across the three categories."""
    total = (
        len(_URI_SOURCE_PATTERNS) + len(_CGI_VAR_PATTERNS) + len(_CONFIG_KEY_PATTERNS)
    )
    assert total >= 30


def test_uri_patterns_cover_cgi_and_rest_and_upnp() -> None:
    must_have = {"/cgi-bin/", "/api/", "/upnp/", "/admin/", "/goform/"}
    assert must_have <= _URI_SOURCE_PATTERNS


def test_cgi_var_patterns_cover_rfc3875_essentials() -> None:
    must_have = {"QUERY_STRING", "REQUEST_METHOD", "HTTP_USER_AGENT", "HTTP_COOKIE"}
    assert must_have <= _CGI_VAR_PATTERNS


def test_config_key_patterns_cover_router_credentials_and_cloud_tokens() -> None:
    must_have = {"http_passwd", "wpa_psk", "cloud_token", "firmware_url"}
    assert must_have <= _CONFIG_KEY_PATTERNS


# ---------------------------------------------------------------------------
# _extract_uri_key_sources behaviour
# ---------------------------------------------------------------------------


def test_extract_returns_empty_for_empty_symbols() -> None:
    assert _extract_uri_key_sources("/usr/sbin/httpd", set()) == []


def test_extract_matches_uri_in_bin_path() -> None:
    matches = _extract_uri_key_sources("/www/cgi-bin/apply.cgi", {"strcpy", "system"})
    kinds = {kind for _, kind in matches}
    assert "uri_endpoint" in kinds
    # Both /cgi-bin/ and /apply.cgi should match
    patterns = {pat for pat, kind in matches if kind == "uri_endpoint"}
    assert "/cgi-bin/" in patterns
    assert "/apply.cgi" in patterns


def test_extract_matches_uri_in_ascii_strings() -> None:
    """Extracted ASCII string literals (e.g. via SBOM `_extract_ascii_runs`)
    routinely contain URL prefixes hard-coded as `.rodata` strings. The
    helper accepts them via the optional ``ascii_strings`` parameter."""
    matches = _extract_uri_key_sources(
        "/usr/sbin/uhttpd",
        {"system"},
        ascii_strings={"GET /cgi-bin/admin?token=", "/upgrade.cgi"},
    )
    patterns = {pat for pat, kind in matches if kind == "uri_endpoint"}
    assert "/cgi-bin/" in patterns
    assert "/upgrade.cgi" in patterns


def test_extract_does_not_match_uri_substring_in_symbol_name() -> None:
    """Symbols are intentionally NOT searched for URI substrings (slashes are
    not valid identifier characters, so any substring overlap would be
    noise). This test pins that policy."""
    matches = _extract_uri_key_sources(
        "/usr/sbin/uhttpd", {"system", "handle_cgi_bin_request"}
    )
    assert all(kind != "uri_endpoint" for _, kind in matches)


def test_extract_matches_cgi_variable_exact_case_insensitive() -> None:
    matches = _extract_uri_key_sources(
        "/usr/sbin/httpd",
        {"strcpy", "query_string", "REQUEST_METHOD"},
    )
    kinds_by_pattern = {pat: kind for pat, kind in matches}
    assert kinds_by_pattern.get("QUERY_STRING") == "cgi_variable"
    assert kinds_by_pattern.get("REQUEST_METHOD") == "cgi_variable"


def test_extract_matches_config_key_in_symbols() -> None:
    matches = _extract_uri_key_sources(
        "/usr/sbin/httpd", {"nvram_get", "get_http_passwd_value"}
    )
    cfg_matches = [pat for pat, kind in matches if kind == "config_key"]
    assert "http_passwd" in cfg_matches


def test_extract_matches_config_key_in_bin_path() -> None:
    matches = _extract_uri_key_sources("/etc/config/wifi_psk_loader", {"strcpy"})
    cfg_matches = [pat for pat, kind in matches if kind == "config_key"]
    assert "wifi_psk" in cfg_matches


def test_extract_returns_multiple_kinds_in_one_call() -> None:
    matches = _extract_uri_key_sources(
        "/www/cgi-bin/auth.cgi",
        {"QUERY_STRING", "get_admin_passwd"},
    )
    kinds = {kind for _, kind in matches}
    assert {"uri_endpoint", "cgi_variable", "config_key"} <= kinds


def test_extract_does_not_double_count_same_pattern() -> None:
    """If a URI pattern matches both bin_path and a symbol, the helper should
    not emit two duplicate tuples for the same pattern."""
    matches = _extract_uri_key_sources(
        "/www/cgi-bin/handler",
        {"cgi_bin_dispatch"},
    )
    cgi_bin_hits = [
        pat for pat, kind in matches if kind == "uri_endpoint" and pat == "/cgi-bin/"
    ]
    assert len(cgi_bin_hits) == 1
