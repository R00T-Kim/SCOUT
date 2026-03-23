from __future__ import annotations

"""sbom.py — CycloneDX 1.6 SBOM generation stage.

Reads inventory and firmware_profile artifacts to identify software components,
constructs CPE 2.3 strings, and emits a CycloneDX 1.6 BOM plus a flat CPE
index for downstream consumers (e.g. NVD lookups).

Environment variables:
    AIEDGE_SBOM_MAX_COMPONENTS  — cap on component count (default 500)
"""

import hashlib
import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from .path_safety import assert_under_dir, rel_to_run_dir, sha256_file, sha256_text
from .policy import AIEdgePolicyViolation
from .schema import JsonValue
from .stage import StageContext, StageOutcome


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_MAX_COMPONENTS = 500
_STAGE_NAME = "sbom"

# CPE vendor mapping: product-key → (vendor, canonical_product_name)
_CPE_VENDOR: dict[str, tuple[str, str]] = {
    "busybox":  ("busybox", "busybox"),
    "dropbear": ("matt_johnston", "dropbear"),
    "dnsmasq":  ("thekelleys", "dnsmasq"),
    "openssl":  ("openssl", "openssl"),
    "linux":    ("linux", "linux_kernel"),
    "nginx":    ("nginx", "nginx"),
    "curl":     ("haxx", "curl"),
    "openssh":  ("openbsd", "openssh"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "glibc":    ("gnu", "glibc"),
    "musl":     ("musl_libc", "musl"),
}

# Binary version patterns: (canonical_name, regex, confidence)
_BINARY_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    ("busybox",  re.compile(r"BusyBox\s+v(\d+\.\d+[\.\d]*)"),          0.85),
    ("dropbear", re.compile(r"Dropbear\s+(?:sshd\s+)?v?(\d+\.\d+\S*)"), 0.85),
    ("dnsmasq",  re.compile(r"dnsmasq-(\d+\.\d+\S*)"),                   0.85),
    ("lighttpd", re.compile(r"lighttpd/(\d+\.\d+\.\d+\S*)"),             0.85),
    ("nginx",    re.compile(r"nginx/(\d+\.\d+\.\d+\S*)"),                0.85),
    ("openssl",  re.compile(r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)"),         0.85),
    ("curl",     re.compile(r"curl/(\d+\.\d+\.\d+\S*)"),                 0.85),
    ("openssh",  re.compile(r"OpenSSH_(\d+\.\d+[p\d]*)"),                0.85),
]

# SO library version patterns: filename → (canonical_name, version_regex)
_SO_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("openssl",  "libssl",    re.compile(r"libssl\.so\.(\d+[\.\d]*)")),
    ("openssl",  "libcrypto", re.compile(r"libcrypto\.so\.(\d+[\.\d]*)")),
    ("glibc",    "libc",      re.compile(r"libc\.so\.(\d+\.\d[\.\d]*)")),
    ("libpthread","libpthread",re.compile(r"libpthread\.so\.(\d+[\.\d]*)")),
    ("libz",     "libz",      re.compile(r"libz\.so\.(\d+[\.\d]*)")),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _env_max_components() -> int:
    raw = os.environ.get("AIEDGE_SBOM_MAX_COMPONENTS", "")
    try:
        v = int(raw)
        if v > 0:
            return v
    except Exception:
        pass
    return _DEFAULT_MAX_COMPONENTS


def _safe_json_load(path: Path) -> dict[str, object] | None:
    """Return parsed JSON dict from *path*, or None on any error."""
    try:
        text = path.read_text(encoding="utf-8")
        obj = cast(object, json.loads(text))
        if isinstance(obj, dict):
            return cast(dict[str, object], obj)
    except Exception:
        pass
    return None


def _write_json(run_dir: Path, path: Path, payload: object) -> None:
    assert_under_dir(run_dir, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256_of_json(payload: object) -> str:
    text = json.dumps(payload, sort_keys=True)
    return sha256_text(text)


def _bom_ref(name: str, version: str) -> str:
    safe_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", name)
    safe_ver = re.sub(r"[^a-zA-Z0-9_\.\-]", "_", version)
    return f"comp-{safe_name}-{safe_ver}"


def _cpe(name: str, version: str) -> str:
    mapping = _CPE_VENDOR.get(name)
    if mapping:
        vendor, product = mapping
    else:
        vendor = re.sub(r"[^a-z0-9_]", "_", name.lower())
        product = vendor
    safe_version = re.sub(r"[^a-zA-Z0-9_\.\-]", "_", version) if version else "*"
    return f"cpe:2.3:a:{vendor}:{product}:{safe_version}:*:*:*:*:*:*:*"


# ---------------------------------------------------------------------------
# Component model
# ---------------------------------------------------------------------------

@dataclass
class _Component:
    comp_type: str        # "application" | "library" | "operating-system"
    name: str
    version: str
    detection_method: str  # "opkg" | "dpkg" | "binary_string" | "so_filename" | "kernel"
    confidence: float
    source_file: str       # run-dir-relative path or "" if unknown
    evidence_ref: str      # sha256: of source evidence or ""

    def to_cyclonedx(self) -> dict[str, JsonValue]:
        ref = _bom_ref(self.name, self.version)
        obj: dict[str, JsonValue] = {
            "bom-ref": ref,
            "cpe": _cpe(self.name, self.version),
            "name": self.name,
            "properties": [
                {"name": "scout:confidence",       "value": f"{self.confidence:.2f}"},
                {"name": "scout:detection_method", "value": self.detection_method},
            ],
            "type": self.comp_type,
            "version": self.version,
        }
        return obj

    def to_cpe_entry(self) -> dict[str, JsonValue]:
        return {
            "confidence": self.confidence,
            "cpe": _cpe(self.name, self.version),
            "detection_method": self.detection_method,
            "evidence_ref": self.evidence_ref,
            "name": self.name,
            "source_file": self.source_file,
            "version": self.version,
        }


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class _ComponentRegistry:
    """Tracks unique (name, version) pairs; first detection wins."""

    def __init__(self) -> None:
        self._seen: dict[tuple[str, str], _Component] = {}

    def add(self, comp: _Component) -> bool:
        key = (comp.name, comp.version)
        if key in self._seen:
            return False
        self._seen[key] = comp
        return True

    def components(self) -> list[_Component]:
        # Deterministic order: name asc, then version asc
        return sorted(self._seen.values(), key=lambda c: (c.name, c.version))


# ---------------------------------------------------------------------------
# Source parsers
# ---------------------------------------------------------------------------

def _is_pkg_installed(status_line: str) -> bool:
    """Return True only when the dpkg/opkg status field indicates installed state.

    The Status field is three space-separated tokens:
        <want> <error-flag> <inst-state>
    We require the third token to be exactly "installed".
    An empty status line is treated as installed (conservative default).
    """
    if not status_line:
        return True
    tokens = status_line.split()
    if len(tokens) >= 3:
        return tokens[2].lower() == "installed"
    # Fallback: field present but malformed — accept if "installed" appears
    # and "not-installed" / "deinstall" do not dominate.
    lower = status_line.lower()
    if "not-installed" in lower or "deinstall" in lower or "purge" in lower:
        return False
    return "installed" in lower


def _parse_opkg_status(
    text: str,
    source_rel: str,
    registry: _ComponentRegistry,
) -> int:
    """Parse opkg status file (RFC-822 stanza format). Returns components added."""
    added = 0
    for stanza in re.split(r"\n\n+", text):
        name_m = re.search(r"^Package:\s*(.+)$", stanza, re.MULTILINE)
        ver_m = re.search(r"^Version:\s*(.+)$", stanza, re.MULTILINE)
        status_m = re.search(r"^Status:\s*(.+)$", stanza, re.MULTILINE)
        if not name_m or not ver_m:
            continue
        status_line = status_m.group(1).strip() if status_m else ""
        if not _is_pkg_installed(status_line):
            continue
        name = name_m.group(1).strip()
        version = ver_m.group(1).strip()
        if not name or not version:
            continue
        comp = _Component(
            comp_type="library",
            name=name,
            version=version,
            detection_method="opkg",
            confidence=0.90,
            source_file=source_rel,
            evidence_ref=f"sha256:{sha256_text(stanza)}",
        )
        if registry.add(comp):
            added += 1
    return added


def _parse_dpkg_status(
    text: str,
    source_rel: str,
    registry: _ComponentRegistry,
) -> int:
    """Parse dpkg status file (Debian RFC-822 format). Returns components added."""
    added = 0
    for stanza in re.split(r"\n\n+", text):
        name_m = re.search(r"^Package:\s*(.+)$", stanza, re.MULTILINE)
        ver_m = re.search(r"^Version:\s*(.+)$", stanza, re.MULTILINE)
        status_m = re.search(r"^Status:\s*(.+)$", stanza, re.MULTILINE)
        if not name_m or not ver_m:
            continue
        status_line = status_m.group(1).strip() if status_m else ""
        if not _is_pkg_installed(status_line):
            continue
        name = name_m.group(1).strip()
        version = ver_m.group(1).strip()
        if not name or not version:
            continue
        comp = _Component(
            comp_type="library",
            name=name,
            version=version,
            detection_method="dpkg",
            confidence=0.90,
            source_file=source_rel,
            evidence_ref=f"sha256:{sha256_text(stanza)}",
        )
        if registry.add(comp):
            added += 1
    return added


def _detect_from_binary_analysis(
    binary_analysis: list[object],
    registry: _ComponentRegistry,
) -> int:
    """Scan binary_analysis string_hits for known version patterns."""
    added = 0
    for entry in binary_analysis:
        if not isinstance(entry, dict):
            continue
        entry_d = cast(dict[str, object], entry)
        path_any = entry_d.get("path", "")
        source_rel = str(path_any) if isinstance(path_any, str) else ""
        string_hits_any = entry_d.get("string_hits", [])
        if not isinstance(string_hits_any, list):
            continue
        hits_text = " ".join(
            str(h) for h in cast(list[object], string_hits_any) if isinstance(h, str)
        )
        for canon_name, pattern, confidence in _BINARY_PATTERNS:
            m = pattern.search(hits_text)
            if not m:
                continue
            version = m.group(1).strip()
            if not version:
                continue
            comp = _Component(
                comp_type="application",
                name=canon_name,
                version=version,
                detection_method="binary_string",
                confidence=confidence,
                source_file=source_rel,
                evidence_ref=f"sha256:{sha256_text(hits_text)}",
            )
            if registry.add(comp):
                added += 1
    return added


def _detect_so_libraries(
    file_list: list[str],
    registry: _ComponentRegistry,
) -> int:
    """Parse .so.X.Y filenames from a list of run-relative paths."""
    added = 0
    for rel_path in file_list:
        filename = Path(rel_path).name
        for canon_name, lib_prefix, pattern in _SO_PATTERNS:
            m = pattern.search(filename)
            if not m:
                continue
            version = m.group(1).strip()
            if not version:
                continue
            # Distinguish glibc vs musl: musl libc.so has "musl" in path
            effective_name = canon_name
            if canon_name == "glibc" and "musl" in rel_path.lower():
                effective_name = "musl"
            comp = _Component(
                comp_type="library",
                name=effective_name,
                version=version,
                detection_method="so_filename",
                confidence=0.70,
                source_file=rel_path,
                evidence_ref=f"sha256:{sha256_text(rel_path)}",
            )
            if registry.add(comp):
                added += 1
    return added


def _detect_kernel(
    firmware_profile: dict[str, object],
    registry: _ComponentRegistry,
) -> int:
    """Extract kernel version from firmware_profile."""
    # Try direct kernel_version field first
    kv_any = firmware_profile.get("kernel_version")
    if isinstance(kv_any, str) and kv_any.strip():
        version = kv_any.strip()
        comp = _Component(
            comp_type="operating-system",
            name="linux",
            version=version,
            detection_method="kernel",
            confidence=0.80,
            source_file="",
            evidence_ref=f"sha256:{sha256_text(version)}",
        )
        return 1 if registry.add(comp) else 0

    # Fall back to os_hints list
    hints_any = firmware_profile.get("os_hints", [])
    if not isinstance(hints_any, list):
        return 0
    for hint in cast(list[object], hints_any):
        if not isinstance(hint, str):
            continue
        m = re.search(r"Linux\s+(?:kernel\s+)?v?(\d+\.\d+[\.\d\-\w]*)", hint, re.IGNORECASE)
        if m:
            version = m.group(1).strip()
            comp = _Component(
                comp_type="operating-system",
                name="linux",
                version=version,
                detection_method="kernel",
                confidence=0.70,
                source_file="",
                evidence_ref=f"sha256:{sha256_text(hint)}",
            )
            return 1 if registry.add(comp) else 0
    return 0


def _scan_rootfs_for_pkg_dbs(
    run_dir: Path,
    inventory: dict[str, object],
    registry: _ComponentRegistry,
) -> list[str]:
    """Walk inventory roots looking for opkg/dpkg status files."""
    limitations: list[str] = []
    roots_any = inventory.get("roots", [])
    if not isinstance(roots_any, list):
        return limitations

    for root_str in cast(list[object], roots_any):
        if not isinstance(root_str, str) or not root_str or root_str.startswith("/"):
            continue
        root_path = (run_dir / root_str).resolve()
        if not root_path.is_relative_to(run_dir.resolve()):
            continue
        if not root_path.is_dir():
            continue

        # opkg: /usr/lib/opkg/status
        opkg_status = root_path / "usr" / "lib" / "opkg" / "status"
        if opkg_status.is_file():
            try:
                text = opkg_status.read_text(encoding="utf-8", errors="replace")
                source_rel = rel_to_run_dir(run_dir, opkg_status)
                _parse_opkg_status(text, source_rel, registry)
            except OSError as exc:
                limitations.append(f"opkg status read error: {exc}")

        # dpkg: /var/lib/dpkg/status
        dpkg_status = root_path / "var" / "lib" / "dpkg" / "status"
        if dpkg_status.is_file():
            try:
                text = dpkg_status.read_text(encoding="utf-8", errors="replace")
                source_rel = rel_to_run_dir(run_dir, dpkg_status)
                _parse_dpkg_status(text, source_rel, registry)
            except OSError as exc:
                limitations.append(f"dpkg status read error: {exc}")

    return limitations


def _collect_so_files_from_inventory(inventory: dict[str, object]) -> list[str]:
    """Return all run-relative file paths ending in .so* from inventory file_list."""
    file_list_any = inventory.get("file_list", [])
    if not isinstance(file_list_any, list):
        return []
    result: list[str] = []
    for item in cast(list[object], file_list_any):
        if not isinstance(item, str):
            continue
        if ".so" in item:
            result.append(item)
    return result


# ---------------------------------------------------------------------------
# Stage
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SbomStage:
    run_dir: Path
    case_id: str | None
    remaining_budget_s: Callable[[], float]
    no_llm: bool  # unused but required by factory signature

    @property
    def name(self) -> str:
        return _STAGE_NAME

    def run(self, ctx: StageContext) -> StageOutcome:  # noqa: C901
        t0 = time.monotonic()
        run_dir = ctx.run_dir
        limitations: list[str] = []

        # ------------------------------------------------------------------ #
        # Load prerequisite artifacts
        # ------------------------------------------------------------------ #
        inv_path = run_dir / "stages" / "inventory" / "inventory.json"
        if not inv_path.is_file():
            return StageOutcome(
                status="skipped",
                details={"reason": "stages/inventory/inventory.json not found"},
                limitations=["SBOM skipped: inventory artifact missing"],
            )

        inventory = _safe_json_load(inv_path)
        if inventory is None:
            return StageOutcome(
                status="skipped",
                details={"reason": "inventory.json unreadable or not a JSON object"},
                limitations=["SBOM skipped: inventory.json parse failure"],
            )

        # firmware_profile is optional
        fp_path = run_dir / "stages" / "firmware_profile" / "firmware_profile.json"
        firmware_profile: dict[str, object] = {}
        if fp_path.is_file():
            fp = _safe_json_load(fp_path)
            if fp is not None:
                firmware_profile = fp
            else:
                limitations.append("firmware_profile.json unreadable; kernel detection skipped")
        else:
            limitations.append("firmware_profile.json missing; kernel detection skipped")

        # binary_analysis is optional
        ba_path = run_dir / "stages" / "inventory" / "binary_analysis.json"
        binary_analysis: list[object] = []
        if ba_path.is_file():
            ba_raw = _safe_json_load(ba_path)
            if isinstance(ba_raw, dict):
                entries_any = ba_raw.get("binaries", ba_raw.get("entries", []))
                if isinstance(entries_any, list):
                    binary_analysis = cast(list[object], entries_any)
            # Also accept a plain top-level list wrapped in {"items": [...]}
            # Fallback: try reading raw list via a different key or direct list
        elif not ba_path.is_file():
            limitations.append("binary_analysis.json missing; binary version detection skipped")

        max_components = _env_max_components()
        registry = _ComponentRegistry()

        # ------------------------------------------------------------------ #
        # Detection passes (order: pkg dbs → binary strings → SO libs → kernel)
        # ------------------------------------------------------------------ #

        # 1. Package manager databases (opkg / dpkg)
        pkg_limits = _scan_rootfs_for_pkg_dbs(run_dir, inventory, registry)
        limitations.extend(pkg_limits)

        # 2. Binary string version detection
        if binary_analysis:
            _detect_from_binary_analysis(binary_analysis, registry)

        # 3. SO library filenames from inventory file list
        so_files = _collect_so_files_from_inventory(inventory)
        if so_files:
            _detect_so_libraries(so_files, registry)

        # 4. Kernel version from firmware_profile
        if firmware_profile:
            _detect_kernel(firmware_profile, registry)

        # ------------------------------------------------------------------ #
        # Apply component cap
        # ------------------------------------------------------------------ #
        all_components = registry.components()
        capped = False
        if len(all_components) > max_components:
            limitations.append(
                f"Component list capped at {max_components} "
                f"(detected {len(all_components)} total); "
                f"set AIEDGE_SBOM_MAX_COMPONENTS to raise limit"
            )
            all_components = all_components[:max_components]
            capped = True

        # ------------------------------------------------------------------ #
        # Build firmware metadata from inventory / profile
        # ------------------------------------------------------------------ #
        firmware_name_any = (
            firmware_profile.get("firmware_name")
            or inventory.get("firmware_name")
            or inventory.get("label")
        )
        firmware_name = str(firmware_name_any).strip() if firmware_name_any else "unknown"

        # ------------------------------------------------------------------ #
        # Emit CycloneDX 1.6 BOM
        # ------------------------------------------------------------------ #
        timestamp = _iso_utc_now()
        bom: dict[str, JsonValue] = {
            "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "components": [c.to_cyclonedx() for c in all_components],
            "metadata": {
                "component": {
                    "bom-ref": "firmware-root",
                    "name": firmware_name,
                    "type": "firmware",
                },
                "timestamp": timestamp,
                "tools": [
                    {"name": "aiedge-sbom", "vendor": "SCOUT", "version": "1.0"}
                ],
            },
            "specVersion": "1.6",
            "version": 1,
        }

        # ------------------------------------------------------------------ #
        # Emit CPE index
        # ------------------------------------------------------------------ #
        cpe_index: dict[str, JsonValue] = {
            "components": [c.to_cpe_entry() for c in all_components],
            "schema_version": "cpe-index-v1",
        }

        # ------------------------------------------------------------------ #
        # Write artifacts
        # ------------------------------------------------------------------ #
        stage_dir = run_dir / "stages" / _STAGE_NAME
        stage_dir.mkdir(parents=True, exist_ok=True)

        sbom_path = stage_dir / "sbom.json"
        cpe_path = stage_dir / "cpe_index.json"

        write_errors: list[str] = []
        try:
            _write_json(run_dir, sbom_path, bom)
        except (OSError, AIEdgePolicyViolation) as exc:
            write_errors.append(f"sbom.json write failed: {exc}")

        try:
            _write_json(run_dir, cpe_path, cpe_index)
        except (OSError, AIEdgePolicyViolation) as exc:
            write_errors.append(f"cpe_index.json write failed: {exc}")

        limitations.extend(write_errors)

        # ------------------------------------------------------------------ #
        # Compute artifact hashes
        # ------------------------------------------------------------------ #
        artifacts: list[dict[str, JsonValue]] = []
        for art_path in (sbom_path, cpe_path):
            if art_path.is_file():
                try:
                    digest = sha256_file(art_path)
                except OSError:
                    digest = ""
                artifacts.append(
                    {
                        "path": rel_to_run_dir(run_dir, art_path),
                        "sha256": digest,
                    }
                )

        # ------------------------------------------------------------------ #
        # Determine status
        # ------------------------------------------------------------------ #
        if write_errors:
            status: str = "partial"
        elif not all_components:
            status = "partial"
            limitations.append("No software components detected")
        else:
            status = "ok"

        duration_s = max(0.0, time.monotonic() - t0)

        details: dict[str, JsonValue] = {
            "artifacts": cast(JsonValue, artifacts),
            "capped": capped,
            "component_count": len(all_components),
            "duration_s": round(duration_s, 3),
            "firmware_name": firmware_name,
            "max_components": max_components,
        }

        # ------------------------------------------------------------------ #
        # Write stage.json
        # ------------------------------------------------------------------ #
        stage_json: dict[str, JsonValue] = {
            "details": cast(JsonValue, details),
            "limitations": cast(JsonValue, limitations),
            "stage": _STAGE_NAME,
            "status": status,
        }
        stage_json_path = stage_dir / "stage.json"
        try:
            _write_json(run_dir, stage_json_path, stage_json)
        except (OSError, AIEdgePolicyViolation) as exc:
            limitations.append(f"stage.json write failed: {exc}")

        return StageOutcome(
            status=cast(  # type: ignore[arg-type]
                "StageStatus", status  # noqa: F821
            ),
            details=details,
            limitations=limitations,
        )


# ---------------------------------------------------------------------------
# Factory (matches StageFactory signature in stage_registry.py)
# ---------------------------------------------------------------------------

def make_sbom_stage(
    info: object,
    case_id: str | None,
    remaining_budget_s: Callable[[], float],
    no_llm: bool,
) -> SbomStage:
    """Factory function for registration in _STAGE_FACTORIES."""
    firmware_dest_any = getattr(info, "firmware_dest", None)
    run_dir = (
        firmware_dest_any.parent
        if isinstance(firmware_dest_any, Path)
        else Path(".")
    )
    return SbomStage(
        run_dir=run_dir,
        case_id=case_id,
        remaining_budget_s=remaining_budget_s,
        no_llm=no_llm,
    )
