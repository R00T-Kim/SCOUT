from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from .path_safety import assert_under_dir


def _rel_to_run_dir(run_dir: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(run_dir.resolve()))
    except Exception:
        return str(path)


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
    except OSError:
        pass
    return h.hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


# ---------------------------------------------------------------------------
# Service classification tables
# ---------------------------------------------------------------------------

# Maps lowercase binary/service name substring → (classification, risk_level, risk_reason)
_SERVICE_CLASSIFIER: list[tuple[str, str, str, str]] = [
    # (pattern, classification, risk_level, risk_reason)
    ("telnetd",    "telnet",   "high",   "plaintext_credentials"),
    ("in.telnetd", "telnet",   "high",   "plaintext_credentials"),
    ("telnet",     "telnet",   "high",   "plaintext_credentials"),
    ("tftpd",      "tftp",     "medium", "unauthenticated_file_transfer"),
    ("in.tftpd",   "tftp",     "medium", "unauthenticated_file_transfer"),
    ("ftpd",       "ftp",      "medium", "plaintext_data_transfer"),
    ("in.ftpd",    "ftp",      "medium", "plaintext_data_transfer"),
    ("vsftpd",     "ftp",      "medium", "plaintext_data_transfer"),
    ("proftpd",    "ftp",      "medium", "plaintext_data_transfer"),
    ("miniupnpd",  "upnp",     "medium", "attack_surface_expansion"),
    ("upnpd",      "upnp",     "medium", "attack_surface_expansion"),
    ("snmpd",      "snmp",     "medium", "potential_info_disclosure"),
    ("uhttpd",     "web",      "info",   "web_server"),
    ("httpd",      "web",      "info",   "web_server"),
    ("nginx",      "web",      "info",   "web_server"),
    ("lighttpd",   "web",      "info",   "web_server"),
    ("boa",        "web",      "info",   "web_server"),
    ("mini_httpd", "web",      "info",   "web_server"),
    ("dropbear",   "ssh",      "info",   "encrypted_remote_shell"),
    ("sshd",       "ssh",      "info",   "encrypted_remote_shell"),
    ("dnsmasq",    "dns_dhcp", "info",   "dns_dhcp_server"),
    ("named",      "dns",      "info",   "dns_server"),
    ("udhcpd",     "dhcp",     "info",   "dhcp_server"),
    ("dhcpd",      "dhcp",     "info",   "dhcp_server"),
    ("ntpd",       "ntp",      "info",   "time_sync"),
]

# Debug/development service patterns
_DEBUG_SERVICE_RE = re.compile(
    r"\b(gdbserver|gdb|strace|ltrace|tcpdump|wireshark|netcat|nc\b|socat"
    r"|busybox telnet|rsh|rlogin|rexec|tnftp|wget|curl)\b",
    re.IGNORECASE,
)


def _classify_service(binary_or_name: str) -> tuple[str, str, str]:
    """Return (classification, risk_level, risk_reason) for a binary name."""
    name_lower = binary_or_name.lower()
    # Exact and substring match against classifier table (order matters)
    for pattern, classification, risk_level, risk_reason in _SERVICE_CLASSIFIER:
        if pattern in name_lower:
            return classification, risk_level, risk_reason
    # Debug/dev services
    if _DEBUG_SERVICE_RE.search(name_lower):
        return "debug", "medium", "debug_service_at_boot"
    return "unknown", "info", "unclassified_daemon"


# ---------------------------------------------------------------------------
# Text reading with graceful fallback
# ---------------------------------------------------------------------------

_MAX_SCRIPT_BYTES = 256 * 1024  # 256 KB per script


def _read_text_safe(path: Path) -> str | None:
    """Read a text file, returning None on binary/unreadable content."""
    try:
        raw = path.read_bytes()
        if len(raw) > _MAX_SCRIPT_BYTES:
            raw = raw[:_MAX_SCRIPT_BYTES]
        # Heuristic: if >20% non-printable bytes (excluding whitespace), treat as binary
        non_printable = sum(
            1 for b in raw if b < 0x09 or (0x0E <= b < 0x20) or b == 0x7F
        )
        if len(raw) > 0 and (non_printable / len(raw)) > 0.20:
            return None
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Rootfs-relative path helper
# ---------------------------------------------------------------------------

def _rootfs_rel(rootfs: Path, path: Path) -> str:
    try:
        return str(path.relative_to(rootfs))
    except Exception:
        return str(path)


# ---------------------------------------------------------------------------
# SysV / OpenWrt procd init.d parser
# ---------------------------------------------------------------------------

# Matches daemon invocation lines: start-stop-daemon, daemon binary, exec binary
_DAEMON_CMD_RE = re.compile(
    r"""(?:start[-_]stop[-_]daemon\s+[^&\n]*?--exec\s+(\S+))"""
    r"""|(?:start[-_]stop[-_]daemon\s+[^&\n]*?--name\s+(\S+))"""
    r"""|(?:^[ \t]*exec\s+(\S+))"""
    r"""|(?:\bdaemon\s+(\S+))"""
    r"""|(?:\brun_daemon\s+(\S+))"""
    r"""|(?:\bprocd_open_instance\b)""",  # procd marker (no binary extracted here)
    re.MULTILINE | re.IGNORECASE,
)

# Matches direct command execution patterns (fallback)
_CMD_LINE_RE = re.compile(
    r"""^[ \t]*(?:\/usr\/s?bin\/|\/s?bin\/|\.\/)?(\w[\w.\-]+(?:d|server|srv))\s""",
    re.MULTILINE,
)

# procd start_service() and USE_PROCD marker
_PROCD_MARKER_RE = re.compile(
    r"""\bstart_service\s*\(\s*\)|USE_PROCD\s*=\s*1|procd_set_param\s+command\s+(\S+)""",
    re.MULTILINE,
)
_PROCD_CMD_RE = re.compile(
    r"""procd_set_param\s+command\s+(\S+)""",
    re.MULTILINE,
)


def _parse_sysv_script(
    script_path: Path,
    rootfs: Path,
) -> list[dict[str, object]]:
    """Parse a single SysV or procd init.d script, returning service dicts."""
    text = _read_text_safe(script_path)
    if text is None:
        return []

    is_procd = bool(_PROCD_MARKER_RE.search(text))
    init_type = "procd" if is_procd else "sysv"

    # Collect candidate binary names from the script
    candidates: list[str] = []

    if is_procd:
        for m in _PROCD_CMD_RE.finditer(text):
            candidates.append(m.group(1))

    # Generic daemon command patterns
    for m in _DAEMON_CMD_RE.finditer(text):
        for g in m.groups():
            if g and not g.startswith("procd_"):
                candidates.append(g)

    # Fallback: look for obvious daemon executables on command lines
    if not candidates:
        for m in _CMD_LINE_RE.finditer(text):
            candidates.append(m.group(1))

    # Deduplicate preserving first-seen order
    seen: set[str] = set()
    unique_candidates: list[str] = []
    for c in candidates:
        key = c.strip().strip("\"';,")
        if key and key not in seen:
            seen.add(key)
            unique_candidates.append(key)

    if not unique_candidates:
        # Use script filename as service name fallback
        unique_candidates = [script_path.name]

    services: list[dict[str, object]] = []
    for binary in unique_candidates:
        binary = binary.strip("\"';,")
        name = Path(binary).name
        classification, risk_level, risk_reason = _classify_service(name)
        services.append(
            {
                "name": name,
                "binary": binary,
                "init_source": _rootfs_rel(rootfs, script_path),
                "init_type": init_type,
                "run_as": "root",  # SysV scripts typically run as root
                "auto_restart": False,
                "classification": classification,
                "risk_level": risk_level,
                "risk_reason": risk_reason,
            }
        )
    return services


# ---------------------------------------------------------------------------
# BusyBox inittab parser
# ---------------------------------------------------------------------------

# /etc/inittab line format: id:runlevel:action:process
_INITTAB_LINE_RE = re.compile(
    r"""^([^:#]*):([^:]*):(\w+):(.+)$""",
    re.MULTILINE,
)

_INITTAB_BOOT_ACTIONS = frozenset(
    ["sysinit", "wait", "once", "respawn", "askfirst", "boot", "bootwait"]
)

_INITTAB_RESPAWN_ACTIONS = frozenset(["respawn", "askfirst"])


def _parse_inittab(inittab_path: Path, rootfs: Path) -> list[dict[str, object]]:
    text = _read_text_safe(inittab_path)
    if text is None:
        return []

    services: list[dict[str, object]] = []
    for m in _INITTAB_LINE_RE.finditer(text):
        action = m.group(3).lower()
        process = m.group(4).strip()
        if action not in _INITTAB_BOOT_ACTIONS:
            continue
        # Skip shell/console entries
        if process in ("/bin/sh", "/bin/ash", "/sbin/getty", "getty"):
            continue
        if process.startswith("tty") or "/getty" in process:
            continue

        # Extract binary (first token, strip leading -)
        tokens = process.split()
        binary = tokens[0].lstrip("-") if tokens else process
        name = Path(binary).name

        auto_restart = action in _INITTAB_RESPAWN_ACTIONS
        classification, risk_level, risk_reason = _classify_service(name)

        services.append(
            {
                "name": name,
                "binary": binary,
                "init_source": _rootfs_rel(rootfs, inittab_path),
                "init_type": "inittab_respawn" if auto_restart else "inittab_once",
                "run_as": "root",
                "auto_restart": auto_restart,
                "classification": classification,
                "risk_level": risk_level,
                "risk_reason": risk_reason,
            }
        )
    return services


# ---------------------------------------------------------------------------
# systemd unit file parser
# ---------------------------------------------------------------------------

_SYSTEMD_KEY_RE = re.compile(r"""^([A-Za-z]+)\s*=\s*(.*)$""", re.MULTILINE)


def _parse_systemd_unit(unit_path: Path, rootfs: Path) -> list[dict[str, object]]:
    text = _read_text_safe(unit_path)
    if text is None:
        return []

    # Only process [Service] units (not .target, .mount, .timer without ExecStart)
    if "[Service]" not in text and unit_path.suffix not in (".service", ".socket"):
        return []

    props: dict[str, str] = {}
    for m in _SYSTEMD_KEY_RE.finditer(text):
        key = m.group(1)
        val = m.group(2).strip()
        if key not in props:
            props[key] = val

    exec_start = props.get("ExecStart", "").strip()
    if not exec_start:
        return []

    # ExecStart may have leading modifiers: -, @, +, !, !!
    exec_start = exec_start.lstrip("-@+!")
    tokens = exec_start.split()
    binary = tokens[0] if tokens else exec_start
    name = Path(binary).name

    service_type = props.get("Type", "simple")
    user = props.get("User", "root")
    restart = props.get("Restart", "no").lower()
    auto_restart = restart not in ("no", "on-failure")

    classification, risk_level, risk_reason = _classify_service(name)

    # Escalate risk: service running as root
    if user == "root" and risk_level == "info":
        risk_level = "low"
        risk_reason = "runs_as_root"

    return [
        {
            "name": name,
            "binary": binary,
            "init_source": _rootfs_rel(rootfs, unit_path),
            "init_type": f"systemd_{service_type}",
            "run_as": user,
            "auto_restart": auto_restart,
            "classification": classification,
            "risk_level": risk_level,
            "risk_reason": risk_reason,
        }
    ]


# ---------------------------------------------------------------------------
# xinetd / inetd parser
# ---------------------------------------------------------------------------

# inetd.conf: service stream tcp nowait root /usr/sbin/binary binary [args]
_INETD_LINE_RE = re.compile(
    r"""^(\S+)\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+)""",
    re.MULTILINE,
)

# xinetd service block: service <name> { ... server = /path ... }
_XINETD_SERVER_RE = re.compile(
    r"""server\s*=\s*(\S+)""",
    re.MULTILINE,
)
_XINETD_USER_RE = re.compile(
    r"""user\s*=\s*(\S+)""",
    re.MULTILINE,
)
_XINETD_DISABLED_RE = re.compile(
    r"""disable\s*=\s*yes""",
    re.IGNORECASE | re.MULTILINE,
)


def _parse_inetd_conf(inetd_path: Path, rootfs: Path) -> list[dict[str, object]]:
    text = _read_text_safe(inetd_path)
    if text is None:
        return []

    services: list[dict[str, object]] = []
    for m in _INETD_LINE_RE.finditer(text):
        svc_name = m.group(1)
        if svc_name.startswith("#"):
            continue
        user = m.group(2)
        server = m.group(3)
        name = Path(server).name
        classification, risk_level, risk_reason = _classify_service(name)
        services.append(
            {
                "name": name,
                "binary": server,
                "init_source": _rootfs_rel(rootfs, inetd_path),
                "init_type": "inetd",
                "run_as": user,
                "auto_restart": False,
                "classification": classification,
                "risk_level": risk_level,
                "risk_reason": risk_reason,
            }
        )
    return services


def _parse_xinetd_file(xinetd_path: Path, rootfs: Path) -> list[dict[str, object]]:
    text = _read_text_safe(xinetd_path)
    if text is None:
        return []

    services: list[dict[str, object]] = []
    # Split on service blocks
    for block in re.split(r"\bservice\b", text)[1:]:
        if _XINETD_DISABLED_RE.search(block):
            continue
        server_m = _XINETD_SERVER_RE.search(block)
        if not server_m:
            continue
        server = server_m.group(1)
        name = Path(server).name
        user_m = _XINETD_USER_RE.search(block)
        user = user_m.group(1) if user_m else "root"
        classification, risk_level, risk_reason = _classify_service(name)
        services.append(
            {
                "name": name,
                "binary": server,
                "init_source": _rootfs_rel(rootfs, xinetd_path),
                "init_type": "xinetd",
                "run_as": user,
                "auto_restart": False,
                "classification": classification,
                "risk_level": risk_level,
                "risk_reason": risk_reason,
            }
        )
    return services


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _dedup_services(
    services: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Remove duplicate services by (name, init_source) preserving highest-risk entry."""
    _RISK_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}
    best: dict[tuple[str, str], dict[str, object]] = {}
    for svc in services:
        key = (str(svc["name"]), str(svc["init_source"]))
        current_best = best.get(key)
        if current_best is None:
            best[key] = svc
        else:
            cur_rank = _RISK_ORDER.get(str(svc.get("risk_level", "info")), 0)
            prev_rank = _RISK_ORDER.get(str(current_best.get("risk_level", "info")), 0)
            if cur_rank > prev_rank:
                best[key] = svc
    return sorted(best.values(), key=lambda s: (str(s["name"]), str(s["init_source"])))


# ---------------------------------------------------------------------------
# Issue builder
# ---------------------------------------------------------------------------

def _build_issues(
    services: list[dict[str, object]],
    rootfs: Path,
) -> list[dict[str, object]]:
    """Generate security issues from boot services."""
    issues: list[dict[str, object]] = []

    _SEVERITY_MAP = {
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }

    for svc in services:
        risk_level = str(svc.get("risk_level", "info"))
        if risk_level == "info":
            # Only emit info-level issues for auto-restart and debug services
            str(svc.get("classification", ""))
            risk_reason = str(svc.get("risk_reason", ""))
            if risk_reason == "debug_service_at_boot":
                issue_type = "debug_service_at_boot"
                severity = "medium"
            elif svc.get("auto_restart"):
                issue_type = "service_auto_restart"
                severity = "info"
            else:
                continue
        else:
            issue_type = "insecure_service_at_boot"
            severity = _SEVERITY_MAP.get(risk_level, "info")

        # Build evidence ref from init_source content
        init_source_str = str(svc.get("init_source", ""))
        evidence_text = f"{svc['name']}:{init_source_str}:{svc.get('risk_reason', '')}"
        evidence_ref = f"sha256:{_sha256_text(evidence_text)}"

        issues.append(
            {
                "type": issue_type,
                "severity": severity,
                "service": str(svc["name"]),
                "file_path": init_source_str,
                "details": {
                    "classification": str(svc.get("classification", "unknown")),
                    "risk_reason": str(svc.get("risk_reason", "")),
                    "init_type": str(svc.get("init_type", "")),
                    "binary": str(svc.get("binary", "")),
                    "run_as": str(svc.get("run_as", "root")),
                    "auto_restart": bool(svc.get("auto_restart", False)),
                },
                "evidence_ref": evidence_ref,
            }
        )

    # Sort for determinism
    return sorted(
        issues,
        key=lambda i: (
            {"high": 0, "medium": 1, "low": 2, "info": 3}.get(str(i["severity"]), 4),
            str(i["service"]),
            str(i["file_path"]),
        ),
    )


# ---------------------------------------------------------------------------
# Init system detection
# ---------------------------------------------------------------------------

def _detect_init_systems(rootfs: Path) -> list[str]:
    """Return sorted list of detected init system names."""
    systems: list[str] = []
    if (rootfs / "etc" / "inittab").is_file():
        systems.append("inittab")
    if (rootfs / "etc" / "init.d").is_dir():
        systems.append("sysv")
    if (rootfs / "etc" / "inetd.conf").is_file():
        systems.append("inetd")
    if (rootfs / "etc" / "xinetd.conf").is_file() or (rootfs / "etc" / "xinetd.d").is_dir():
        systems.append("xinetd")
    # systemd: look for lib/systemd or usr/lib/systemd
    for candidate in [
        rootfs / "lib" / "systemd",
        rootfs / "usr" / "lib" / "systemd",
        rootfs / "etc" / "systemd",
    ]:
        if candidate.is_dir():
            systems.append("systemd")
            break
    return sorted(set(systems))


# ---------------------------------------------------------------------------
# File collection helpers
# ---------------------------------------------------------------------------

_MAX_INIT_SCRIPTS = 200


def _collect_initd_scripts(rootfs: Path) -> list[Path]:
    initd = rootfs / "etc" / "init.d"
    if not initd.is_dir():
        return []
    scripts: list[Path] = []
    try:
        with os.scandir(initd) as it:
            entries = sorted(it, key=lambda e: e.name)
    except OSError:
        return []
    for entry in entries:
        p = Path(entry.path)
        try:
            if entry.is_file(follow_symlinks=True) and not entry.name.startswith("."):
                scripts.append(p)
        except OSError:
            continue
        if len(scripts) >= _MAX_INIT_SCRIPTS:
            break
    return scripts


def _collect_systemd_units(rootfs: Path) -> list[Path]:
    units: list[Path] = []
    search_roots = [
        rootfs / "lib" / "systemd" / "system",
        rootfs / "usr" / "lib" / "systemd" / "system",
        rootfs / "etc" / "systemd" / "system",
    ]
    for base in search_roots:
        if not base.is_dir():
            continue
        try:
            with os.scandir(base) as it:
                for entry in sorted(it, key=lambda e: e.name):
                    p = Path(entry.path)
                    try:
                        if entry.is_file(follow_symlinks=True) and p.suffix in (
                            ".service",
                            ".socket",
                        ):
                            units.append(p)
                    except OSError:
                        continue
                    if len(units) >= _MAX_INIT_SCRIPTS:
                        return units
        except OSError:
            continue
    return units


def _collect_xinetd_files(rootfs: Path) -> list[Path]:
    files: list[Path] = []
    xinetd_conf = rootfs / "etc" / "xinetd.conf"
    if xinetd_conf.is_file():
        files.append(xinetd_conf)
    xinetd_d = rootfs / "etc" / "xinetd.d"
    if xinetd_d.is_dir():
        try:
            with os.scandir(xinetd_d) as it:
                for entry in sorted(it, key=lambda e: e.name):
                    p = Path(entry.path)
                    try:
                        if entry.is_file(follow_symlinks=True):
                            files.append(p)
                    except OSError:
                        continue
        except OSError:
            pass
    return files


# ---------------------------------------------------------------------------
# Summary builder
# ---------------------------------------------------------------------------

def _build_summary(services: list[dict[str, object]]) -> dict[str, int]:
    counts: dict[str, int] = {"total_services": len(services), "high_risk": 0, "medium_risk": 0, "low_risk": 0, "info": 0}
    for svc in services:
        rl = str(svc.get("risk_level", "info"))
        if rl == "high":
            counts["high_risk"] += 1
        elif rl == "medium":
            counts["medium_risk"] += 1
        elif rl == "low":
            counts["low_risk"] += 1
        else:
            counts["info"] += 1
    return counts


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_init_services(
    rootfs_dirs: list[Path],
    run_dir: Path,
    stage_dir: Path,
) -> dict[str, object]:
    """Analyze init scripts and boot services in firmware rootfs.

    Args:
        rootfs_dirs: List of candidate rootfs root directories to scan.
        run_dir:     The pipeline run directory (used for path safety checks).
        stage_dir:   Directory where output artifacts are written.

    Returns:
        The parsed init_services dict (also written to stage_dir/init_services.json).
    """
    all_services: list[dict[str, object]] = []
    detected_systems_all: set[str] = set()
    limitations: list[str] = []

    for rootfs in rootfs_dirs:
        if not rootfs.is_dir():
            limitations.append(f"rootfs not a directory: {rootfs}")
            continue

        detected_systems = _detect_init_systems(rootfs)
        detected_systems_all.update(detected_systems)

        # --- inittab ---
        inittab_path = rootfs / "etc" / "inittab"
        if inittab_path.is_file():
            try:
                all_services.extend(_parse_inittab(inittab_path, rootfs))
            except Exception as exc:
                limitations.append(f"inittab parse error ({inittab_path}): {exc}")

        # --- SysV / procd init.d ---
        scripts = _collect_initd_scripts(rootfs)
        if len(scripts) >= _MAX_INIT_SCRIPTS:
            limitations.append(
                f"init.d script limit reached ({_MAX_INIT_SCRIPTS}); some scripts skipped"
            )
        for script in scripts:
            try:
                all_services.extend(_parse_sysv_script(script, rootfs))
            except Exception as exc:
                limitations.append(f"init.d parse error ({script.name}): {exc}")

        # --- inetd.conf ---
        inetd_conf = rootfs / "etc" / "inetd.conf"
        if inetd_conf.is_file():
            try:
                all_services.extend(_parse_inetd_conf(inetd_conf, rootfs))
            except Exception as exc:
                limitations.append(f"inetd.conf parse error: {exc}")

        # --- xinetd ---
        for xfile in _collect_xinetd_files(rootfs):
            try:
                all_services.extend(_parse_xinetd_file(xfile, rootfs))
            except Exception as exc:
                limitations.append(f"xinetd parse error ({xfile.name}): {exc}")

        # --- systemd ---
        units = _collect_systemd_units(rootfs)
        if len(units) >= _MAX_INIT_SCRIPTS:
            limitations.append(
                f"systemd unit limit reached ({_MAX_INIT_SCRIPTS}); some units skipped"
            )
        for unit in units:
            try:
                all_services.extend(_parse_systemd_unit(unit, rootfs))
            except Exception as exc:
                limitations.append(f"systemd unit parse error ({unit.name}): {exc}")

    # Deduplicate
    boot_services = _dedup_services(all_services)
    issues = _build_issues(boot_services, rootfs_dirs[0] if rootfs_dirs else run_dir)

    init_system_str = "+".join(sorted(detected_systems_all)) if detected_systems_all else "unknown"

    result: dict[str, object] = {
        "schema_version": "init-services-v1",
        "init_system": init_system_str,
        "services_found": len(boot_services),
        "boot_services": [
            {k: v for k, v in sorted(svc.items())} for svc in boot_services
        ],
        "issues": issues,
        "summary": _build_summary(boot_services),
        "limitations": sorted(set(limitations)),
    }

    # Write output artifact
    out_path = stage_dir / "init_services.json"
    assert_under_dir(run_dir, out_path)
    out_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return result
