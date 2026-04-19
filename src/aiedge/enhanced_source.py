from __future__ import annotations

"""Enhanced source identification stage.

Identifies external input sources by scanning .dynstr imports in binary
inventory data for known input-receiving API functions.  Purely static
analysis -- always runs even under ``--no-llm``.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .path_safety import assert_under_dir
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus

_SCHEMA_VERSION = "enhanced-source-v1"

INPUT_APIS: frozenset[str] = frozenset(
    {
        "recv",
        "recvfrom",
        "recvmsg",
        "read",
        "fread",
        "fgets",
        "gets",
        "getenv",
        "scanf",
        "sscanf",
        "fscanf",
        "websGetVar",
        "httpGetEnv",
        "nvram_get",
        "acosNvramConfig_get",
        "json_object_get_string",
        "cJSON_GetObjectItem",
        "cJSON_Parse",
        "json_tokener_parse",
        "xmlParseMemory",
        "getParameter",
        "wp_getVar",
    }
)

SINK_APIS: frozenset[str] = frozenset(
    {
        "system",
        "popen",
        "execve",
        "execv",
        "execl",
        "execlp",
        "strcpy",
        "strcat",
        "sprintf",
        "vsprintf",
        "gets",
        "doSystemCmd",
        "twsystem",
        "doSystem",
    }
)

# Lowercase lookup set for case-insensitive matching
_INPUT_APIS_LOWER: frozenset[str] = frozenset(api.lower() for api in INPUT_APIS)
_SINK_APIS_LOWER: frozenset[str] = frozenset(api.lower() for api in SINK_APIS)

# Mapping from lowercase back to canonical name
_API_CANONICAL: dict[str, str] = {api.lower(): api for api in INPUT_APIS | SINK_APIS}

# --- Web server auto-detection ---
_WEB_SERVER_NAMES: frozenset[str] = frozenset(
    {
        "httpd",
        "lighttpd",
        "uhttpd",
        "mini_httpd",
        "boa",
        "goahead",
        "thttpd",
        "nginx",
        "busybox_httpd",
        "micro_httpd",
        "cgibin",
        "prog.cgi",
        "soapcgi",
    }
)


# --- Phase 2C+.2 (LARA-inspired URI / CGI / config-key semantic sources) ---
#
# LARA (USENIX Security 2024) widens source identification beyond C-level
# input APIs by recognising URI / HTTP-variable / config-key strings as
# attacker-influenced data origins. We carry the same idea into SCOUT but
# stay conservative: confidence is capped below the dynstr API path
# (0.40 vs 0.60) because string presence alone does not prove reachability.
#
# These are matched case-insensitively as substrings or against full tokens.

_URI_SOURCE_PATTERNS: frozenset[str] = frozenset(
    {
        # CGI gateway prefixes (router admin UIs)
        "/cgi-bin/",
        "/cgi/",
        "/goform/",
        "/apply.cgi",
        "/upgrade.cgi",
        "/system.cgi",
        "/ipformget.cgi",
        "/ipformset.cgi",
        # REST / SOAP / JSON-RPC API prefixes
        "/api/",
        "/webapi/",
        "/json-rpc/",
        "/jsonrpc/",
        "/rest/",
        "/soap/",
        # Common UPnP / TR-069 / device-management endpoints
        "/upnp/",
        "/control/",
        "/tr069/",
        "/cwmp/",
        # OEM web UI roots
        "/web/",
        "/admin/",
        "/setup.cgi",
    }
)

_CGI_VAR_PATTERNS: frozenset[str] = frozenset(
    {
        # Standard CGI environment variables (RFC 3875)
        "HTTP_USER_AGENT",
        "HTTP_REFERER",
        "HTTP_COOKIE",
        "HTTP_HOST",
        "HTTP_AUTHORIZATION",
        "QUERY_STRING",
        "REQUEST_METHOD",
        "REQUEST_URI",
        "PATH_INFO",
        "PATH_TRANSLATED",
        "REMOTE_ADDR",
        "REMOTE_USER",
        "CONTENT_LENGTH",
        "CONTENT_TYPE",
        # Vendor / OEM extensions seen in router CGIs
        "HTTP_X_FORWARDED_FOR",
        "SCRIPT_NAME",
        "SERVER_NAME",
    }
)

_CONFIG_KEY_PATTERNS: frozenset[str] = frozenset(
    {
        # Authentication / credential keys (router NVRAM + sysconf conventions)
        "http_passwd",
        "http_username",
        "admin_passwd",
        "admin_password",
        "web_admin_token",
        "web_passwd",
        "auth_token",
        "session_id",
        "session_key",
        # Device / connectivity keys frequently controlled remotely
        "wan_ipaddr",
        "lan_ipaddr",
        "wifi_psk",
        "wifi_password",
        "wpa_psk",
        "ssid",
        "ddns_username",
        "ddns_password",
        # Cloud / OTA / pairing keys (modern IoT vendors)
        "cloud_token",
        "device_token",
        "registration_code",
        "pairing_key",
        "firmware_url",
    }
)


def _extract_uri_key_sources(
    bin_path: str,
    symbols: set[str],
    ascii_strings: set[str] | None = None,
) -> list[tuple[str, str]]:
    """Return ``(pattern, kind)`` tuples for any LARA-style URI / CGI / config
    matches surfaced by the binary's symbol table or extracted ASCII strings.

    *kind* is one of ``"uri_endpoint"``, ``"cgi_variable"``, ``"config_key"``.

    Matching policy:
      - URI prefixes (`/cgi-bin/`, `/api/`, ...): case-insensitive substring
        against ``bin_path`` *and* against any provided ``ascii_strings``.
        Symbol names are not searched because dynamic-linker symbols rarely
        embed a literal URI; substring matches there are noisy.
      - CGI environment names (`QUERY_STRING`, ...): exact lower-case match
        against either ``symbols`` or ``ascii_strings``.
      - NVRAM / sysconf config keys (`http_passwd`, ...): case-insensitive
        substring match against ``bin_path``, ``symbols``, and
        ``ascii_strings`` (these short identifiers often appear inside
        wrapper symbol names like ``get_http_passwd_value``).

    ``ascii_strings`` is optional and defaults to an empty set so the helper
    stays cheap when no extracted-string data is available.
    """
    sym_lower_set = {s.lower() for s in symbols} if symbols else set()
    bin_lower = bin_path.lower() if bin_path else ""
    str_lower_set = {s.lower() for s in ascii_strings} if ascii_strings else set()
    if not sym_lower_set and not bin_lower and not str_lower_set:
        return []

    matches: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _record(pattern: str, kind: str) -> None:
        key = (pattern, kind)
        if key in seen:
            return
        seen.add(key)
        matches.append(key)

    for pattern in _URI_SOURCE_PATTERNS:
        needle = pattern.lower()
        if needle in bin_lower:
            _record(pattern, "uri_endpoint")
            continue
        for s_lower in str_lower_set:
            if needle in s_lower:
                _record(pattern, "uri_endpoint")
                break

    for var in _CGI_VAR_PATTERNS:
        var_lower = var.lower()
        if var_lower in sym_lower_set or var_lower in str_lower_set:
            _record(var, "cgi_variable")

    for key in _CONFIG_KEY_PATTERNS:
        needle = key.lower()
        if needle in bin_lower:
            _record(key, "config_key")
            continue
        matched = False
        for sym_lower in sym_lower_set:
            if needle in sym_lower:
                _record(key, "config_key")
                matched = True
                break
        if matched:
            continue
        for s_lower in str_lower_set:
            if needle in s_lower:
                _record(key, "config_key")
                break

    return matches


_WEB_LISTENER_SYMS: frozenset[str] = frozenset(
    {
        "listen",
        "accept",
        "bind",
        "socket",
    }
)

_EXEC_SINK_SYMS: frozenset[str] = frozenset(
    {
        "system",
        "popen",
        "execve",
        "execv",
        "execl",
    }
)


def _classify_web_server(
    path: str,
    symbols: set[str],
    ipc_indicators: dict[str, object] | None,
) -> tuple[bool, float]:
    """Classify binary as web server and return (is_web, confidence_boost)."""
    basename = path.rsplit("/", 1)[-1].lower() if "/" in path else path.lower()
    base_no_ext = basename.rsplit(".", 1)[0] if "." in basename else basename

    has_sink = bool(symbols & _EXEC_SINK_SYMS)
    has_listener = bool(symbols & _WEB_LISTENER_SYMS)
    has_getenv = "getenv" in {s.lower() for s in symbols}

    if ipc_indicators and isinstance(ipc_indicators, dict):
        for key in ("network_symbols", "ipc_symbols"):
            syms_any = ipc_indicators.get(key)
            if isinstance(syms_any, (list, set)):
                net_set = {str(s).lower() for s in syms_any if isinstance(s, str)}
                has_listener = has_listener or bool(net_set & _WEB_LISTENER_SYMS)

    if base_no_ext in _WEB_SERVER_NAMES and has_sink:
        return True, 0.20
    if has_listener and has_getenv and has_sink:
        return True, 0.15
    if ".cgi" in basename and has_sink:
        return True, 0.10
    return False, 0.0


def _load_json_file(path: Path) -> object | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _clamp01(v: float) -> float:
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return float(v)


@dataclass(frozen=True)
class EnhancedSourceStage:
    """Identify external input sources via .dynstr analysis."""

    no_llm: bool = False  # Accepted but unused -- stage is always static

    @property
    def name(self) -> str:
        return "enhanced_source"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "enhanced_source"
        out_json = stage_dir / "sources.json"

        assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        assert_under_dir(run_dir, out_json)

        limitations: list[str] = []
        sources: list[dict[str, JsonValue]] = []

        # --- Load inventory data ---
        inventory_path = run_dir / "stages" / "inventory" / "inventory.json"
        inv_data = _load_json_file(inventory_path)
        if inv_data is None or not isinstance(inv_data, dict):
            limitations.append(
                "inventory.json missing or unreadable; source detection limited"
            )
            inv_obj: dict[str, object] = {}
        else:
            inv_obj = cast(dict[str, object], inv_data)

        # --- Load binary_analysis.json for .dynstr data ---
        binary_analysis_path = run_dir / "stages" / "inventory" / "binary_analysis.json"
        ba_data = _load_json_file(binary_analysis_path)
        ba_hits: list[object] = []
        if isinstance(ba_data, dict):
            hits_any = cast(dict[str, object], ba_data).get("hits")
            if isinstance(hits_any, list):
                ba_hits = cast(list[object], hits_any)
        elif ba_data is None:
            limitations.append("binary_analysis.json missing; .dynstr scan unavailable")

        # --- Scan binary analysis hits for INPUT and SINK APIs ---
        for bin_any in ba_hits:
            if not isinstance(bin_any, dict):
                continue
            bin_obj = cast(dict[str, object], bin_any)
            bin_name_any = (
                bin_obj.get("path") or bin_obj.get("name") or bin_obj.get("binary")
            )
            if not isinstance(bin_name_any, str) or not bin_name_any:
                continue
            bin_path = str(bin_name_any)

            # Collect ALL symbols from matched_symbols + symbol_details
            symbols: set[str] = set()
            for key in (
                "matched_symbols",
                "dynstr_imports",
                "risky_symbols",
                "imports",
            ):
                syms_any = bin_obj.get(key)
                if isinstance(syms_any, list):
                    for sym_any in cast(list[object], syms_any):
                        if isinstance(sym_any, str):
                            symbols.add(sym_any)

            # symbol_details contains per-symbol records
            sd_any = bin_obj.get("symbol_details")
            if isinstance(sd_any, list):
                for sd_item in cast(list[object], sd_any):
                    if isinstance(sd_item, dict):
                        sym_name = cast(dict[str, object], sd_item).get("symbol")
                        if isinstance(sym_name, str):
                            symbols.add(sym_name)

            # Classify symbols
            matched_input: list[str] = []
            matched_sink: list[str] = []
            for sym in symbols:
                sym_lower = sym.lower().strip()
                if sym_lower in _INPUT_APIS_LOWER:
                    matched_input.append(_API_CANONICAL.get(sym_lower, sym))
                if sym_lower in _SINK_APIS_LOWER:
                    matched_sink.append(_API_CANONICAL.get(sym_lower, sym))

            if not matched_input and not matched_sink:
                continue

            # Extract hardening and arch info
            arch_any = bin_obj.get("arch")
            arch = str(arch_any) if isinstance(arch_any, str) else "unknown"
            hardening_any = bin_obj.get("hardening")
            hardening: dict[str, object] = (
                cast(dict[str, object], hardening_any)
                if isinstance(hardening_any, dict)
                else {}
            )

            # Determine confidence based on API presence
            if matched_input and matched_sink:
                # Both input and sink APIs -> high priority source
                confidence = 0.70
            elif matched_input:
                # Input API only -> moderate
                confidence = 0.60
            else:
                # Sink APIs only -> still a source at lower confidence
                confidence = 0.50

            # Web server classification — boost confidence for HTTP binaries
            ipc_any = bin_obj.get("ipc_indicators")
            ipc_dict = (
                cast(dict[str, object], ipc_any) if isinstance(ipc_any, dict) else None
            )
            is_web, conf_boost = _classify_web_server(bin_path, symbols, ipc_dict)
            if is_web:
                confidence = min(0.90, confidence + conf_boost)

            has_recv = bool(symbols & {"recv", "recvfrom", "recvmsg"})
            source_type: str
            if is_web:
                source_type = "http_input"
            elif has_recv:
                source_type = "network_input"
            else:
                source_type = "generic"

            # Record each input API as a source; if none, use sink APIs
            api_list = matched_input if matched_input else matched_sink
            for api in api_list:
                sources.append(
                    {
                        "address": "0x0",
                        "api": api,
                        "binary": bin_path,
                        "confidence": _clamp01(confidence),
                        "method": "enhanced_static",
                        "matched_input_apis": cast(
                            list[JsonValue],
                            cast(list[object], sorted(set(matched_input))),
                        ),
                        "matched_sink_apis": cast(
                            list[JsonValue],
                            cast(list[object], sorted(set(matched_sink))),
                        ),
                        "arch": arch,
                        "hardening": cast(dict[str, JsonValue], hardening),
                        "source_type": source_type,
                        "web_server": is_web,
                    }
                )

            # --- Phase 2C+.2: LARA-style URI / CGI / config-key sources ---
            # Confidence stays at the SYMBOL_COOCCURRENCE cap (0.40) because
            # string presence alone does not prove reachability; downstream
            # taint propagation can promote individual matches.
            for pattern, kind in _extract_uri_key_sources(bin_path, symbols):
                sources.append(
                    {
                        "address": "0x0",
                        "api": pattern,
                        "binary": bin_path,
                        "confidence": _clamp01(0.40),
                        "method": "lara_pattern",
                        "matched_input_apis": cast(list[JsonValue], []),
                        "matched_sink_apis": cast(list[JsonValue], []),
                        "arch": arch,
                        "hardening": cast(dict[str, JsonValue], hardening),
                        "source_type": kind,
                        "web_server": is_web,
                    }
                )

        # --- Fallback: read source_sink_graph.json for additional sources ---
        ssg_path = run_dir / "stages" / "surfaces" / "source_sink_graph.json"
        ssg_data = _load_json_file(ssg_path)
        if isinstance(ssg_data, dict):
            ssg_paths_any = cast(dict[str, object], ssg_data).get("paths")
            if isinstance(ssg_paths_any, list):
                for p_any in cast(list[object], ssg_paths_any):
                    if not isinstance(p_any, dict):
                        continue
                    p_obj = cast(dict[str, object], p_any)
                    sink_any = p_obj.get("sink")
                    source_any = p_obj.get("source")
                    if not isinstance(sink_any, dict):
                        continue
                    sink_obj = cast(dict[str, object], sink_any)
                    sink_bin = str(sink_obj.get("binary", ""))
                    sink_syms_any = sink_obj.get("symbols")
                    sink_syms: list[str] = []
                    if isinstance(sink_syms_any, list):
                        for ss in cast(list[object], sink_syms_any):
                            if isinstance(ss, str):
                                sink_syms.append(ss)
                    if not sink_bin or not sink_syms:
                        continue

                    src_type = ""
                    if isinstance(source_any, dict):
                        src_type = str(
                            cast(dict[str, object], source_any).get("type", "")
                        )
                    conf_any = p_obj.get("confidence")
                    ssg_conf = (
                        _clamp01(float(conf_any))
                        if isinstance(conf_any, (int, float))
                        else 0.45
                    )

                    for sym in sink_syms:
                        sources.append(
                            {
                                "address": "0x0",
                                "api": sym,
                                "binary": sink_bin,
                                "confidence": _clamp01(min(ssg_conf, 0.55)),
                                "method": "source_sink_graph",
                                "source_type": src_type,
                                "matched_input_apis": cast(list[JsonValue], []),
                                "matched_sink_apis": cast(
                                    list[JsonValue], cast(list[object], sink_syms)
                                ),
                            }
                        )

        # --- Also scan inventory service_candidates for input API references ---
        candidates_any = inv_obj.get("service_candidates")
        if isinstance(candidates_any, list):
            for cand_any in cast(list[object], candidates_any):
                if not isinstance(cand_any, dict):
                    continue
                cand = cast(dict[str, object], cand_any)
                cand_name = str(cand.get("name", ""))
                evidence_any = cand.get("evidence")
                if not isinstance(evidence_any, list):
                    continue
                for ev_any in cast(list[object], evidence_any):
                    if not isinstance(ev_any, dict):
                        continue
                    ev = cast(dict[str, object], ev_any)
                    matched_any = ev.get("matched_symbols") or ev.get("symbols")
                    if not isinstance(matched_any, list):
                        continue
                    for sym_any in cast(list[object], matched_any):
                        if not isinstance(sym_any, str):
                            continue
                        sym_lower = sym_any.lower().strip()
                        if (
                            sym_lower in _INPUT_APIS_LOWER
                            or sym_lower in _SINK_APIS_LOWER
                        ):
                            canonical = _API_CANONICAL.get(sym_lower, sym_any)
                            path_any = ev.get("path")
                            bin_path_str = (
                                str(path_any)
                                if isinstance(path_any, str)
                                else cand_name
                            )
                            sources.append(
                                {
                                    "address": "0x0",
                                    "api": canonical,
                                    "binary": bin_path_str,
                                    "confidence": _clamp01(0.50),
                                    "method": "service_candidate",
                                }
                            )

        # --- Deduplicate sources ---
        seen: set[tuple[str, str, str]] = set()
        unique_sources: list[dict[str, JsonValue]] = []
        for src in sources:
            key = (
                cast(str, src["api"]),
                cast(str, src["binary"]),
                cast(str, src["address"]),
            )
            if key not in seen:
                seen.add(key)
                unique_sources.append(src)

        status: StageStatus = "ok"
        if not unique_sources:
            status = "partial"
            if not limitations:
                limitations.append("No input API references found in binaries")

        payload: dict[str, JsonValue] = {
            "schema_version": _SCHEMA_VERSION,
            "status": status,
            "total_sources": len(unique_sources),
            "sources": cast(list[JsonValue], cast(list[object], unique_sources)),
            "limitations": cast(
                list[JsonValue], cast(list[object], sorted(set(limitations)))
            ),
        }
        out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        details: dict[str, JsonValue] = {
            "total_sources": len(unique_sources),
            "unique_apis": len({cast(str, s["api"]) for s in unique_sources}),
            "unique_binaries": len({cast(str, s["binary"]) for s in unique_sources}),
        }
        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
