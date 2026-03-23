from __future__ import annotations

"""cve_scan.py — NVD CVE scanning stage for SCOUT firmware analysis engine.

Queries the NVD API 2.0 to find known CVEs matching SBOM components.
Pure stdlib only; no pip dependencies.

Rate limits:
  Without API key: 6 s between requests  (10 req/min)
  With API key:    1.2 s between requests (50 req/min)

Caching:
  Per-run:    stages/cve_scan/nvd_cache/<sha256_of_cpe>.json
  Cross-run:  AIEDGE_NVD_CACHE_DIR env var (24 h TTL)
"""

import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from .path_safety import assert_under_dir, rel_to_run_dir, sha256_text
from .stage import StageContext, StageOutcome

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_USER_AGENT = "SCOUT-AIEdge/1.0"
_CACHE_TTL_S = 86_400  # 24 hours

_RATE_NO_KEY = 6.0   # seconds between requests without API key
_RATE_WITH_KEY = 1.2  # seconds between requests with API key

_DEFAULT_MAX_COMPONENTS = 50
_DEFAULT_TIMEOUT_S = 30

_CONFIDENCE_EXACT = 0.90
_CONFIDENCE_RANGE = 0.75
_CONFIDENCE_PRODUCT = 0.40

_STATIC_CONFIDENCE_CAP = 0.60  # findings stage governance cap

_CVSS_HIGH_THRESHOLD = 7.0
_CVSS_CRITICAL_THRESHOLD = 9.0
_CVSS_MEDIUM_THRESHOLD = 4.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(ts: str) -> float:
    """Parse an ISO-8601 UTC timestamp string to a POSIX float."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        return 0.0


def _env_int(name: str, *, default: int, min_value: int, max_value: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        v = int(raw)
    except Exception:
        return default
    return max(min_value, min(max_value, v))


def _severity_label(score: float) -> str:
    if score >= _CVSS_CRITICAL_THRESHOLD:
        return "critical"
    if score >= _CVSS_HIGH_THRESHOLD:
        return "high"
    if score >= _CVSS_MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def _finding_confidence(match_confidence: float, cvss_score: float) -> float:
    raw = match_confidence * cvss_score / 10.0 * 0.6
    return min(_STATIC_CONFIDENCE_CAP, raw)


# ---------------------------------------------------------------------------
# CPE / version matching
# ---------------------------------------------------------------------------

def _parse_cpe23(cpe: str) -> dict[str, str]:
    """Parse a CPE 2.3 URI into its component parts."""
    # cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    parts = cpe.split(":")
    keys = ["prefix", "version_id", "part", "vendor", "product",
            "version", "update", "edition", "language",
            "sw_edition", "target_sw", "target_hw", "other"]
    result: dict[str, str] = {}
    for i, key in enumerate(keys):
        result[key] = parts[i] if i < len(parts) else "*"
    return result


def _version_tuple(version_str: str) -> tuple[int, ...]:
    """Convert a dot-separated version string into a sortable integer tuple."""
    parts = []
    for seg in version_str.split("."):
        numeric = ""
        for ch in seg:
            if ch.isdigit():
                numeric += ch
            else:
                break
        try:
            parts.append(int(numeric)) if numeric else parts.append(0)
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _version_in_range(
    version: str,
    *,
    version_start_including: str | None,
    version_start_excluding: str | None,
    version_end_including: str | None,
    version_end_excluding: str | None,
) -> bool:
    """Return True if *version* falls within the NVD version range bounds."""
    if not version or version in ("*", "-"):
        return False
    try:
        v = _version_tuple(version)
    except Exception:
        return False

    if version_start_including:
        try:
            if v < _version_tuple(version_start_including):
                return False
        except Exception:
            pass

    if version_start_excluding:
        try:
            if v <= _version_tuple(version_start_excluding):
                return False
        except Exception:
            pass

    if version_end_including:
        try:
            if v > _version_tuple(version_end_including):
                return False
        except Exception:
            pass

    if version_end_excluding:
        try:
            if v >= _version_tuple(version_end_excluding):
                return False
        except Exception:
            pass

    return True


def _determine_match_type(
    component_version: str,
    cpe_match: dict[str, object],
) -> tuple[str, float] | None:
    """Return (match_type, confidence) or None if no match."""
    criteria_any = cpe_match.get("criteria")
    if not isinstance(criteria_any, str):
        return None

    criteria: str = criteria_any
    parsed = _parse_cpe23(criteria)
    cpe_version = parsed.get("version", "*")

    # Exact version match
    if cpe_version not in ("*", "-") and component_version:
        if cpe_version.lower() == component_version.lower():
            return ("exact_version", _CONFIDENCE_EXACT)

    # Version range match
    vsi = cpe_match.get("versionStartIncluding")
    vse = cpe_match.get("versionStartExcluding")
    vei = cpe_match.get("versionEndIncluding")
    vee = cpe_match.get("versionEndExcluding")

    has_range = any(x is not None for x in (vsi, vse, vei, vee))
    if has_range and component_version:
        in_range = _version_in_range(
            component_version,
            version_start_including=str(vsi) if vsi is not None else None,
            version_start_excluding=str(vse) if vse is not None else None,
            version_end_including=str(vei) if vei is not None else None,
            version_end_excluding=str(vee) if vee is not None else None,
        )
        if in_range:
            return ("version_range", _CONFIDENCE_RANGE)

    # Product-only match (CPE version is wildcard)
    if cpe_version in ("*", "-"):
        return ("product_match", _CONFIDENCE_PRODUCT)

    return None


# ---------------------------------------------------------------------------
# NVD API cache
# ---------------------------------------------------------------------------

def _cache_key(cpe_query: str) -> str:
    return sha256_text(cpe_query)


def _load_cached_response(
    cache_path: Path,
    *,
    max_age_s: float = _CACHE_TTL_S,
) -> dict[str, object] | None:
    """Load a cached NVD response if it exists and is not expired."""
    if not cache_path.is_file():
        return None
    try:
        raw = cast(object, json.loads(cache_path.read_text(encoding="utf-8")))
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None
    cached = cast(dict[str, object], raw)
    cached_at = cached.get("cached_at")
    if isinstance(cached_at, str):
        age = time.time() - _parse_timestamp(cached_at)
        if age > max_age_s:
            return None
    return cached


def _save_cached_response(cache_path: Path, data: dict[str, object]) -> None:
    """Write NVD response data to cache file."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(data)
    payload["cached_at"] = _iso_utc_now()
    cache_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# NVD HTTP client
# ---------------------------------------------------------------------------

def _build_ssl_context(*, verify: bool = True) -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch_nvd(
    cpe_name: str,
    *,
    api_key: str | None,
    timeout_s: int,
    verify_ssl: bool = True,
) -> dict[str, object] | None:
    """Perform a single NVD API request. Returns parsed JSON or None on error."""
    params = urllib.parse.urlencode({"cpeName": cpe_name})  # type: ignore[attr-defined]
    url = f"{_NVD_BASE_URL}?{params}"

    headers: dict[str, str] = {"User-Agent": _USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key

    ctx = _build_ssl_context(verify=verify_ssl)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=ctx) as resp:  # type: ignore[call-arg]
            body = resp.read()
    except urllib.error.HTTPError as exc:
        raise
    except urllib.error.URLError:
        raise
    except OSError:
        raise

    try:
        parsed = cast(object, json.loads(body))
    except Exception:
        return None

    if not isinstance(parsed, dict):
        return None
    return cast(dict[str, object], parsed)


def _query_nvd_with_cache(
    cpe_name: str,
    *,
    api_key: str | None,
    timeout_s: int,
    per_run_cache_dir: Path,
    cross_run_cache_dir: Path | None,
    run_dir: Path,
    stats: dict[str, int],
) -> dict[str, object] | None:
    """Query NVD for *cpe_name*, using caches. Updates *stats* in-place."""
    key = _cache_key(cpe_name)
    per_run_path = per_run_cache_dir / f"{key}.json"
    cross_run_path = (cross_run_cache_dir / f"{key}.json") if cross_run_cache_dir else None

    # 1. Per-run cache (always valid within a run, no TTL check needed for age)
    hit = _load_cached_response(per_run_path, max_age_s=float("inf"))
    if hit is not None:
        stats["cache_hits"] += 1
        return hit

    # 2. Cross-run cache within TTL
    if cross_run_path is not None:
        hit = _load_cached_response(cross_run_path, max_age_s=_CACHE_TTL_S)
        if hit is not None:
            stats["cache_hits"] += 1
            # Populate per-run cache too
            assert_under_dir(run_dir, per_run_path)
            _save_cached_response(per_run_path, hit)
            return hit

    # 3. Live API call
    data: dict[str, object] | None = None
    for verify in (True, False):  # retry without SSL verification on SSL error
        try:
            data = _fetch_nvd(
                cpe_name,
                api_key=api_key,
                timeout_s=timeout_s,
                verify_ssl=verify,
            )
            stats["api_calls"] += 1
            break
        except ssl.SSLError:
            if not verify:
                stats["api_errors"] += 1
                return None
            # retry without SSL
            continue
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                stats["api_errors"] += 1
                return None
            stats["api_errors"] += 1
            # Try cross-run cache regardless of age
            if cross_run_path is not None:
                stale = _load_cached_response(cross_run_path, max_age_s=float("inf"))
                if stale is not None:
                    return stale
            return None
        except (urllib.error.URLError, OSError, TimeoutError):
            stats["api_errors"] += 1
            # Try cross-run cache regardless of age
            if cross_run_path is not None:
                stale = _load_cached_response(cross_run_path, max_age_s=float("inf"))
                if stale is not None:
                    return stale
            return None

    if data is None:
        return None

    # Cache the result
    assert_under_dir(run_dir, per_run_path)
    _save_cached_response(per_run_path, data)
    if cross_run_path is not None:
        _save_cached_response(cross_run_path, data)

    return data


# ---------------------------------------------------------------------------
# CVE extraction from NVD response
# ---------------------------------------------------------------------------

def _extract_cve_entry(
    cve_item: object,
    *,
    component_name: str,
    component_version: str,
    cpe_name: str,
) -> list[dict[str, object]]:
    """Extract CVE match records from a single NVD CVE item."""
    if not isinstance(cve_item, dict):
        return []

    item = cast(dict[str, object], cve_item)
    cve_obj_any = item.get("cve")
    if not isinstance(cve_obj_any, dict):
        return []
    cve_obj = cast(dict[str, object], cve_obj_any)

    cve_id_any = cve_obj.get("id")
    if not isinstance(cve_id_any, str) or not cve_id_any:
        return []
    cve_id: str = cve_id_any

    # Description (English preferred)
    description = ""
    descs_any = cve_obj.get("descriptions")
    if isinstance(descs_any, list):
        for d_any in cast(list[object], descs_any):
            if not isinstance(d_any, dict):
                continue
            d = cast(dict[str, object], d_any)
            if d.get("lang") == "en" and isinstance(d.get("value"), str):
                description = cast(str, d["value"])[:200]
                break

    # CVSS v3.1
    cvss_score = 0.0
    cvss_severity = "UNKNOWN"
    metrics_any = cve_obj.get("metrics")
    if isinstance(metrics_any, dict):
        metrics = cast(dict[str, object], metrics_any)
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries_any = metrics.get(key)
            if not isinstance(entries_any, list) or not entries_any:
                continue
            first_any = cast(list[object], entries_any)[0]
            if not isinstance(first_any, dict):
                continue
            first = cast(dict[str, object], first_any)
            cvss_data_any = first.get("cvssData")
            if not isinstance(cvss_data_any, dict):
                continue
            cvss_data = cast(dict[str, object], cvss_data_any)
            score_any = cvss_data.get("baseScore")
            if isinstance(score_any, (int, float)):
                cvss_score = float(score_any)
            sev_any = cvss_data.get("baseSeverity")
            if isinstance(sev_any, str):
                cvss_severity = sev_any.upper()
            break

    # Configuration nodes — find best match type
    best_match_type: str | None = None
    best_confidence: float = 0.0

    configurations_any = cve_obj.get("configurations")
    if isinstance(configurations_any, list):
        for cfg_any in cast(list[object], configurations_any):
            if not isinstance(cfg_any, dict):
                continue
            cfg = cast(dict[str, object], cfg_any)
            nodes_any = cfg.get("nodes")
            if not isinstance(nodes_any, list):
                continue
            for node_any in cast(list[object], nodes_any):
                if not isinstance(node_any, dict):
                    continue
                node = cast(dict[str, object], node_any)
                cpe_matches_any = node.get("cpeMatch")
                if not isinstance(cpe_matches_any, list):
                    continue
                for cpe_match_any in cast(list[object], cpe_matches_any):
                    if not isinstance(cpe_match_any, dict):
                        continue
                    cpe_match = cast(dict[str, object], cpe_match_any)
                    result = _determine_match_type(component_version, cpe_match)
                    if result is not None:
                        mt, conf = result
                        if conf > best_confidence:
                            best_confidence = conf
                            best_match_type = mt

    if best_match_type is None:
        # Fall back to product match if we got a response at all
        best_match_type = "product_match"
        best_confidence = _CONFIDENCE_PRODUCT

    return [
        {
            "component": component_name,
            "version": component_version,
            "cpe": cpe_name,
            "cve_id": cve_id,
            "cvss_v3_score": cvss_score,
            "cvss_v3_severity": cvss_severity,
            "description": description,
            "match_confidence": best_confidence,
            "match_type": best_match_type,
            "evidence_ref": f"nvd_api:{cve_id}",
        }
    ]


# ---------------------------------------------------------------------------
# SBOM loader
# ---------------------------------------------------------------------------

def _load_cpe_index(run_dir: Path) -> tuple[list[dict[str, object]], list[str]]:
    """Load CPE index from the sbom stage output."""
    limitations: list[str] = []
    cpe_path = run_dir / "stages" / "sbom" / "cpe_index.json"
    if not cpe_path.is_file():
        limitations.append(
            "SBOM CPE index not found at stages/sbom/cpe_index.json; cve_scan skipped"
        )
        return [], limitations

    try:
        raw = cast(object, json.loads(cpe_path.read_text(encoding="utf-8")))
    except Exception as exc:
        limitations.append(f"SBOM CPE index unreadable: {type(exc).__name__}: {exc}")
        return [], limitations

    if not isinstance(raw, dict):
        limitations.append("SBOM CPE index invalid: expected JSON object")
        return [], limitations

    data = cast(dict[str, object], raw)
    components_any = data.get("components")
    if not isinstance(components_any, list):
        # Try flat list directly
        if isinstance(raw, list):
            components_any = raw
        else:
            limitations.append("SBOM CPE index: 'components' field missing or not a list")
            return [], limitations

    components: list[dict[str, object]] = []
    for item_any in cast(list[object], components_any):
        if isinstance(item_any, dict):
            components.append(cast(dict[str, object], item_any))

    return components, limitations


# ---------------------------------------------------------------------------
# Stage
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CveScanStage:
    run_dir: Path
    case_id: str | None
    remaining_budget_s: Callable[[], float]
    no_llm: bool

    @property
    def name(self) -> str:
        return "cve_scan"

    def run(self, ctx: StageContext) -> StageOutcome:  # noqa: C901 – long but linear
        run_dir = ctx.run_dir
        t_start = time.monotonic()

        # ------------------------------------------------------------------ #
        # Configuration from environment
        # ------------------------------------------------------------------ #
        api_key: str | None = os.environ.get("AIEDGE_NVD_API_KEY") or None
        cross_run_cache_str = os.environ.get("AIEDGE_NVD_CACHE_DIR")
        cross_run_cache_dir: Path | None = Path(cross_run_cache_str) if cross_run_cache_str else None

        max_components = _env_int(
            "AIEDGE_CVE_SCAN_MAX_COMPONENTS",
            default=_DEFAULT_MAX_COMPONENTS,
            min_value=1,
            max_value=500,
        )
        timeout_s = _env_int(
            "AIEDGE_CVE_SCAN_TIMEOUT_S",
            default=_DEFAULT_TIMEOUT_S,
            min_value=5,
            max_value=120,
        )

        rate_limit_s = _RATE_WITH_KEY if api_key else _RATE_NO_KEY

        # ------------------------------------------------------------------ #
        # Output directory setup
        # ------------------------------------------------------------------ #
        stage_dir = run_dir / "stages" / "cve_scan"
        stage_dir.mkdir(parents=True, exist_ok=True)
        assert_under_dir(run_dir, stage_dir)

        per_run_cache_dir = stage_dir / "nvd_cache"
        per_run_cache_dir.mkdir(parents=True, exist_ok=True)
        assert_under_dir(run_dir, per_run_cache_dir)

        # ------------------------------------------------------------------ #
        # Load SBOM / CPE index
        # ------------------------------------------------------------------ #
        components, limitations = _load_cpe_index(run_dir)

        if not components:
            outcome = StageOutcome(
                status="skipped",
                details={"reason": "no_sbom_components"},
                limitations=limitations,
            )
            self._write_stage_json(
                stage_dir=stage_dir,
                run_dir=run_dir,
                outcome=outcome,
                started_at=_iso_utc_now(),
                duration_s=time.monotonic() - t_start,
                artifacts=[],
            )
            return outcome

        # Truncate to max_components
        if len(components) > max_components:
            limitations.append(
                f"cve_scan limited to {max_components} components "
                f"(AIEDGE_CVE_SCAN_MAX_COMPONENTS); {len(components) - max_components} skipped"
            )
            components = components[:max_components]

        # ------------------------------------------------------------------ #
        # Main scan loop
        # ------------------------------------------------------------------ #
        stats: dict[str, int] = {
            "cache_hits": 0,
            "api_calls": 0,
            "api_errors": 0,
            "components_skipped": 0,
        }

        scan_timestamp = _iso_utc_now()
        matches: list[dict[str, object]] = []
        last_request_t = 0.0
        network_unavailable = False

        for comp in components:
            # Budget check
            if self.remaining_budget_s() < 30.0:
                limitations.append(
                    "cve_scan halted early: time budget exhausted"
                )
                break

            cpe_any = comp.get("cpe") or comp.get("cpe23") or comp.get("cpe_name")
            if not isinstance(cpe_any, str) or not cpe_any:
                stats["components_skipped"] += 1
                continue

            cpe_name: str = cpe_any
            comp_name_any = comp.get("name") or comp.get("component") or comp.get("product")
            comp_name = str(comp_name_any) if comp_name_any else cpe_name
            comp_version_any = comp.get("version")
            comp_version = str(comp_version_any) if comp_version_any else ""

            # Rate limiting (only for live API calls)
            now = time.monotonic()
            elapsed_since_last = now - last_request_t
            if elapsed_since_last < rate_limit_s:
                needed = rate_limit_s - elapsed_since_last
                # Only sleep if budget allows
                if self.remaining_budget_s() > needed + 30.0:
                    time.sleep(needed)

            nvd_data = _query_nvd_with_cache(
                cpe_name,
                api_key=api_key,
                timeout_s=timeout_s,
                per_run_cache_dir=per_run_cache_dir,
                cross_run_cache_dir=cross_run_cache_dir,
                run_dir=run_dir,
                stats=stats,
            )

            # Track time of last request (even if cached, keep cadence for live calls)
            last_request_t = time.monotonic()

            if nvd_data is None:
                stats["components_skipped"] += 1
                if stats["api_errors"] == 1 and stats["api_calls"] == 0:
                    # First failure with no successful call → network likely unavailable
                    network_unavailable = True
                continue

            # Detect network unavailability pattern
            if stats["api_errors"] > 0 and stats["api_calls"] == 0:
                network_unavailable = True

            # Extract CVE entries
            vulns_any = nvd_data.get("vulnerabilities")
            if not isinstance(vulns_any, list):
                continue

            for vuln_any in cast(list[object], vulns_any):
                extracted = _extract_cve_entry(
                    vuln_any,
                    component_name=comp_name,
                    component_version=comp_version,
                    cpe_name=cpe_name,
                )
                matches.extend(extracted)

        if network_unavailable and not matches:
            limitations.append("nvd_api_unavailable")

        # ------------------------------------------------------------------ #
        # Build finding candidates (CVSS >= 7.0)
        # ------------------------------------------------------------------ #
        finding_candidates: list[dict[str, object]] = []
        for m in matches:
            score_any = m.get("cvss_v3_score")
            score = float(score_any) if isinstance(score_any, (int, float)) else 0.0
            if score < _CVSS_HIGH_THRESHOLD:
                continue

            match_conf_any = m.get("match_confidence")
            match_conf = float(match_conf_any) if isinstance(match_conf_any, (int, float)) else _CONFIDENCE_PRODUCT

            confidence = _finding_confidence(match_conf, score)
            severity = _severity_label(score)
            cve_id = str(m.get("cve_id", ""))
            comp_name_f = str(m.get("component", ""))
            comp_ver_f = str(m.get("version", ""))

            # Stable SBOM reference key
            sbom_ref_part = f"sbom:comp-{comp_name_f}"
            if comp_ver_f:
                sbom_ref_part += f"-{comp_ver_f}"

            finding_candidates.append(
                {
                    "title": f"{cve_id} in {comp_name_f} {comp_ver_f}".strip(),
                    "severity": severity,
                    "confidence": round(confidence, 6),
                    "families": ["known_vulnerability", "cve_match"],
                    "disposition": "suspected",
                    "exploitability_tier": "suspected",
                    "component": comp_name_f,
                    "version": comp_ver_f,
                    "cve_id": cve_id,
                    "cvss_v3_score": score,
                    "evidence_refs": [f"nvd_api:{cve_id}", sbom_ref_part],
                }
            )

        # ------------------------------------------------------------------ #
        # Summary counts
        # ------------------------------------------------------------------ #
        severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for m in matches:
            score_any = m.get("cvss_v3_score")
            score = float(score_any) if isinstance(score_any, (int, float)) else 0.0
            label = _severity_label(score)
            severity_counts[label] = severity_counts.get(label, 0) + 1

        components_with_cves: set[str] = set()
        for m in matches:
            comp_key = f"{m.get('component','')}/{m.get('version','')}"
            components_with_cves.add(comp_key)

        summary: dict[str, object] = {
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "components_skipped": stats["components_skipped"],
            "cache_hits": stats["cache_hits"],
            "api_calls": stats["api_calls"],
            "api_errors": stats["api_errors"],
        }

        # ------------------------------------------------------------------ #
        # Write cve_matches.json
        # ------------------------------------------------------------------ #
        output_data: dict[str, object] = {
            "schema_version": "cve-scan-v1",
            "scan_timestamp": scan_timestamp,
            "api_key_used": api_key is not None,
            "components_scanned": len(components),
            "components_with_cves": len(components_with_cves),
            "total_cve_matches": len(matches),
            "matches": matches,
            "finding_candidates": finding_candidates,
            "limitations": limitations,
            "summary": summary,
        }

        cve_matches_path = stage_dir / "cve_matches.json"
        assert_under_dir(run_dir, cve_matches_path)
        cve_matches_path.write_text(
            json.dumps(output_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        # ------------------------------------------------------------------ #
        # Determine status
        # ------------------------------------------------------------------ #
        if network_unavailable and not matches:
            status: str = "partial"
        elif stats["api_errors"] > 0 and matches:
            status = "partial"
        else:
            status = "ok"

        duration_s = time.monotonic() - t_start

        artifacts = [rel_to_run_dir(run_dir, cve_matches_path)]

        outcome = StageOutcome(
            status=status,  # type: ignore[arg-type]
            details={
                "cve_matches_path": rel_to_run_dir(run_dir, cve_matches_path),
                "components_scanned": len(components),
                "components_with_cves": len(components_with_cves),
                "total_cve_matches": len(matches),
                "finding_candidates_count": len(finding_candidates),
                "api_key_used": api_key is not None,
                "cache_hits": stats["cache_hits"],
                "api_calls": stats["api_calls"],
                "api_errors": stats["api_errors"],
            },
            limitations=limitations,
        )

        self._write_stage_json(
            stage_dir=stage_dir,
            run_dir=run_dir,
            outcome=outcome,
            started_at=scan_timestamp,
            duration_s=duration_s,
            artifacts=artifacts,
        )

        return outcome

    # ---------------------------------------------------------------------- #
    # Internal helpers
    # ---------------------------------------------------------------------- #

    def _write_stage_json(
        self,
        *,
        stage_dir: Path,
        run_dir: Path,
        outcome: StageOutcome,
        started_at: str,
        duration_s: float,
        artifacts: list[str],
    ) -> None:
        """Write the canonical stage.json for this stage."""
        stage_json_path = stage_dir / "stage.json"
        assert_under_dir(run_dir, stage_json_path)

        record: dict[str, object] = {
            "stage": self.name,
            "status": outcome.status,
            "started_at": started_at,
            "finished_at": _iso_utc_now(),
            "duration_s": round(duration_s, 3),
            "details": outcome.details,
            "limitations": outcome.limitations,
            "artifacts": artifacts,
        }
        stage_json_path.write_text(
            json.dumps(record, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

