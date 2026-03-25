"""fuzz_harness.py — AFL++ harness generation for SCOUT.

Produces the three artefacts AFL++ needs before a campaign can start:

1. **Dictionary** — keyword tokens extracted from binary string hits plus
   common HTTP / CGI / NVRAM protocol tokens.
2. **Seed corpus** — minimal valid inputs that give AFL++ a meaningful
   starting point for each input mode.
3. **Harness config** — a JSON document describing how to invoke the target
   binary (stdin / CGI env / network desock / file).
"""

from __future__ import annotations

import json
from pathlib import Path

from .path_safety import assert_under_dir

# ---------------------------------------------------------------------------
# Protocol keyword constants
# ---------------------------------------------------------------------------

_HTTP_KEYWORDS: tuple[str, ...] = (
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS",
    "HTTP/1.0", "HTTP/1.1",
    "Content-Type:", "Content-Length:", "Transfer-Encoding:",
    "Host:", "User-Agent:", "Cookie:", "Authorization:",
    "Accept:", "Accept-Encoding:", "Connection:",
)

_WEB_APP_KEYWORDS: tuple[str, ...] = (
    "admin", "root", "password", "passwd", "login", "logout",
    "action=", "cmd=", "command=", "exec=", "ping=",
    "ip=", "host=", "url=", "redirect=", "next=",
    "/cgi-bin/", "/goform/", "/apply.cgi", "/setup.cgi",
    "/admin/", "/management/", "/api/v1/",
)

_NVRAM_KEYWORDS: tuple[str, ...] = (
    "nvram", "nvram_get", "nvram_set",
    "lan_ipaddr", "wan_ipaddr", "http_passwd", "http_username",
    "wl_ssid", "pppoe_username", "pppoe_passwd",
)

_ALL_PROTOCOL_KEYWORDS: tuple[str, ...] = (
    _HTTP_KEYWORDS + _WEB_APP_KEYWORDS + _NVRAM_KEYWORDS
)


# ---------------------------------------------------------------------------
# Dictionary generation
# ---------------------------------------------------------------------------

def generate_dictionary(run_dir: Path, target: dict, output_path: Path) -> int:
    """Generate an AFL++ dictionary file from binary strings and protocol tokens.

    Reads up to 500 entries from ``stages/inventory/string_hits.json``,
    filters to strings of 3–64 characters, escapes them in AFL++ ``"…"``
    format, then appends the static protocol keyword list.  Duplicates are
    removed and the result is capped at 1 000 entries.

    Args:
        run_dir: Root of the current analysis run (used for path safety).
        target: Target descriptor dict (used for future per-target tuning).
        output_path: Destination ``.dict`` file path (must be inside
            *run_dir*).

    Returns:
        Number of dictionary entries written.
    """
    assert_under_dir(run_dir, output_path)
    entries: list[str] = []

    # --- string_hits from inventory stage --------------------------------
    sh_path = run_dir / "stages" / "inventory" / "string_hits.json"
    if sh_path.is_file():
        try:
            data = json.loads(sh_path.read_text(encoding="utf-8"))
            samples = data.get("samples", [])
            for sample in samples[:500]:
                match = str(sample.get("match", ""))
                if 3 <= len(match) <= 64:
                    escaped = match.replace("\\", "\\\\").replace('"', '\\"')
                    entries.append(f'"{escaped}"')
        except Exception:
            pass

    # --- static protocol keywords ----------------------------------------
    for kw in _ALL_PROTOCOL_KEYWORDS:
        entries.append(f'"{kw}"')

    # --- deduplicate while preserving insertion order --------------------
    seen: set[str] = set()
    unique: list[str] = []
    for entry in entries:
        if entry not in seen:
            seen.add(entry)
            unique.append(entry)

    output_path.write_text("\n".join(unique[:1000]) + "\n", encoding="utf-8")
    return len(unique[:1000])


# ---------------------------------------------------------------------------
# Seed corpus generation
# ---------------------------------------------------------------------------

def generate_seed_corpus(target: dict, output_dir: Path, run_dir: Path) -> int:
    """Generate minimal seed inputs for AFL++.

    Creates a set of binary seed files appropriate for the target's detected
    input mode.  Seeds are always small and syntactically valid for the
    expected protocol so AFL++ can start exploring from a useful baseline.

    Args:
        target: Target descriptor dict (``path``, ``arch``, etc.).
        output_dir: Directory in which seed files are written (must be
            inside *run_dir*).
        run_dir: Root of the current analysis run (used for path safety).

    Returns:
        Number of seed files written.
    """
    assert_under_dir(run_dir, output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    path: str = target.get("path", "")
    basename = Path(path).name.lower() if path else ""

    seeds: list[tuple[str, bytes]] = []

    # Always include generic stdin seeds
    seeds.append(("seed_empty", b""))
    seeds.append(("seed_newline", b"\n"))
    seeds.append(("seed_a64", b"A" * 64))
    seeds.append(("seed_null", b"\x00"))
    seeds.append(("seed_fmt", b"%s%s%s%s"))

    # CGI / web application seeds
    if ".cgi" in basename or any(
        s in basename for s in ("httpd", "lighttpd", "nginx", "uhttpd")
    ):
        seeds.append(("seed_get_root", b"GET / HTTP/1.0\r\n\r\n"))
        seeds.append((
            "seed_post_apply",
            b"POST /apply.cgi HTTP/1.0\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 12\r\n\r\n"
            b"cmd=id&a=b\r\n",
        ))
        seeds.append(("seed_query_login", b"action=login&user=admin&pass=admin"))
        seeds.append(("seed_query_cmd",   b"cmd=ping+-c+1+127.0.0.1"))
        seeds.append(("seed_get_goform",  b"GET /goform/formLogin HTTP/1.0\r\n\r\n"))

    # Network daemon seeds (non-HTTP)
    elif any(s in basename for s in ("sshd", "dropbear", "telnetd", "ftpd")):
        seeds.append(("seed_crlf",       b"\r\n"))
        seeds.append(("seed_user_root",  b"USER root\r\n"))
        seeds.append(("seed_pass_admin", b"PASS admin\r\n"))

    # UPNP / SOAP seeds
    elif "upnp" in basename or "miniupnp" in basename:
        seeds.append((
            "seed_soap_action",
            b'M-SEARCH * HTTP/1.1\r\n'
            b'HOST: 239.255.255.250:1900\r\n'
            b'MAN: "ssdp:discover"\r\n'
            b'MX: 1\r\n'
            b'ST: ssdp:all\r\n\r\n',
        ))

    # File-based / parser seeds
    elif any(kw in basename for kw in ("parser", "decode", "convert", "extract", "unpack")):
        seeds.append(("seed_elf_magic",  b"\x7fELF"))
        seeds.append(("seed_gz_magic",   b"\x1f\x8b\x08"))
        seeds.append(("seed_zip_magic",  b"PK\x03\x04"))
        seeds.append(("seed_xml_root",   b"<?xml version=\"1.0\"?><r/>"))

    # Write all seeds
    written = 0
    for name, data in seeds:
        seed_path = output_dir / name
        assert_under_dir(run_dir, seed_path)
        seed_path.write_bytes(data)
        written += 1

    return written


# ---------------------------------------------------------------------------
# Harness configuration
# ---------------------------------------------------------------------------

def generate_harness_config(target: dict) -> dict:
    """Generate an AFL++ harness configuration document for *target*.

    The returned dict describes the binary invocation mode, QEMU flag,
    resource limits, and any environment variables required.  It is written
    to ``campaign_results.json`` by :mod:`fuzz_campaign` and is not written
    to disk here.

    Input modes:

    * ``stdin``           — binary reads from ``stdin`` (default)
    * ``cgi``             — CGI environment variables set; input via ``stdin``
    * ``network_desock``  — desocketing shim pre-loaded via ``LD_PRELOAD``
    * ``file``            — input provided as a file path argument (``@@``)

    Args:
        target: Target descriptor dict (``path``, ``arch``, ``hardening``,
            etc.).

    Returns:
        Dict suitable for JSON serialisation.
    """
    path: str = target.get("path", "")
    basename = Path(path).name.lower() if path else ""

    config: dict = {
        "binary": path,
        "mode": "stdin",
        "qemu_mode": True,
        "arch": target.get("arch", "unknown"),
        "timeout_ms": 1000,
        "memory_limit_mb": 256,
        "env": {},
        "extra_args": [],
    }

    # CGI mode — web CGI scripts / small embedded HTTP daemons
    if ".cgi" in basename:
        config["mode"] = "cgi"
        config["env"] = {
            "REQUEST_METHOD": "GET",
            "QUERY_STRING": "@@",
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "CONTENT_LENGTH": "0",
            "SCRIPT_NAME": f"/{basename}",
            "SERVER_NAME": "127.0.0.1",
            "SERVER_PORT": "80",
            "GATEWAY_INTERFACE": "CGI/1.1",
        }

    # Network desock — long-running daemon processes
    elif any(
        d in basename
        for d in ("httpd", "lighttpd", "nginx", "sshd", "dropbear",
                  "telnetd", "ftpd", "uhttpd", "dnsmasq", "miniupnpd")
    ):
        config["mode"] = "network_desock"
        config["env"]["AFL_PRELOAD"] = "/usr/lib/afl/libdesock.so"
        config["timeout_ms"] = 5000  # daemons need more startup time

    # File mode — file-format parsers
    elif any(
        kw in basename
        for kw in ("parser", "decode", "convert", "extract", "unpack")
    ):
        config["mode"] = "file"
        config["extra_args"] = ["@@"]

    # Harden resource limits for PIE / canary-less targets
    hardening = target.get("hardening", {})
    if not hardening.get("nx", True):
        # Increase memory limit for shellcode-heavy targets
        config["memory_limit_mb"] = 512

    return config


# ---------------------------------------------------------------------------
# NVRAM faker stub generation
# ---------------------------------------------------------------------------

_NVRAM_FAKER_C = """\
/*
 * nvram_faker.c -- LD_PRELOAD stub for firmware NVRAM functions.
 *
 * Many embedded firmware binaries call nvram_get() at startup which blocks
 * or crashes without real NVRAM hardware.  This stub satisfies those calls
 * with safe defaults so fuzzing can proceed past initialisation.
 *
 * Compile inside the AFL++ container:
 *   ${CROSS_CC:-gcc} -shared -fPIC -o nvram_faker.so nvram_faker.c
 *
 * Usage:
 *   export AFL_PRELOAD="/path/to/nvram_faker.so"
 */
#include <string.h>

/* Return empty string for any NVRAM key lookup. */
char *nvram_get(const char *key) {
    (void)key;
    return "";
}

/* Accept but ignore NVRAM writes. */
int nvram_set(const char *key, const char *value) {
    (void)key;
    (void)value;
    return 0;
}

/* Commit is a no-op. */
int nvram_commit(void) {
    return 0;
}

/* Return empty buffer for bulk reads. */
int nvram_getall(char *buf, int count) {
    if (buf && count > 0)
        buf[0] = '\\0';
    return 0;
}
"""


def generate_nvram_faker_stub(harness_dir: Path) -> Path | None:
    """Generate a minimal NVRAM faker C source for ``LD_PRELOAD``.

    Many firmware binaries call ``nvram_get()`` at startup which blocks
    without real NVRAM hardware.  This stub returns safe defaults for all
    NVRAM functions, allowing the target to reach its main input-processing
    loop.

    The generated file is a **C source** (``nvram_faker.c``), *not* a
    compiled shared object.  Compilation must happen inside the Docker
    container where the correct cross-compiler is available::

        ${CROSS_CC:-gcc} -shared -fPIC -o nvram_faker.so nvram_faker.c

    Args:
        harness_dir: Directory to write the stub into.

    Returns:
        Path to the generated ``.c`` file, or ``None`` on error.
    """
    try:
        harness_dir.mkdir(parents=True, exist_ok=True)
        stub_path = harness_dir / "nvram_faker.c"
        stub_path.write_text(_NVRAM_FAKER_C, encoding="utf-8")
        return stub_path
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Persistent mode harness wrapper
# ---------------------------------------------------------------------------

_PERSISTENT_WRAPPER_TEMPLATE = """\
#!/bin/sh
# AFL++ persistent mode wrapper for {target_basename}
#
# Persistent mode reuses the target process across multiple inputs,
# avoiding fork() overhead.  Can achieve 10-100x speedup over
# fork-server mode for targets with heavy initialisation.
#
# Generated by SCOUT fuzz_harness.py — do not edit manually.

set -e

TARGET="{target_path}"
HARNESS_DIR="{harness_dir}"

# Desocketing library for network daemons
if [ -f "${{HARNESS_DIR}}/libdesock.so" ]; then
    export AFL_PRELOAD="${{HARNESS_DIR}}/libdesock.so"
fi

# NVRAM faker for firmware binaries that call nvram_get()
if [ -f "${{HARNESS_DIR}}/nvram_faker.so" ]; then
    if [ -n "$AFL_PRELOAD" ]; then
        export AFL_PRELOAD="${{AFL_PRELOAD}}:${{HARNESS_DIR}}/nvram_faker.so"
    else
        export AFL_PRELOAD="${{HARNESS_DIR}}/nvram_faker.so"
    fi
fi

# Firmware library search paths (typical rootfs layout)
ROOTFS_DIR="$(dirname "$(dirname "$TARGET")")"
if [ -d "${{ROOTFS_DIR}}/lib" ]; then
    export LD_LIBRARY_PATH="${{ROOTFS_DIR}}/lib:${{ROOTFS_DIR}}/usr/lib:${{LD_LIBRARY_PATH:-}}"
fi

exec "$TARGET" "$@"
"""


def generate_persistent_harness(
    target_path: str,
    input_mode: str,
    harness_dir: Path,
) -> Path:
    """Generate an AFL++ persistent mode wrapper shell script.

    The wrapper sets up ``LD_PRELOAD`` for desocketing and NVRAM faking,
    configures library search paths for the firmware rootfs, and then
    ``exec``s the target binary.

    For ``network_desock`` mode, the desocketing library (``libdesock.so``)
    is pre-loaded so network ``accept()``/``recv()`` calls are redirected
    to ``stdin``/``stdout``, letting AFL++ fuzz network protocols without
    real sockets.

    Args:
        target_path: Absolute path to the target binary (inside the
            Docker mount).
        input_mode: One of ``stdin``, ``cgi``, ``network_desock``, ``file``.
        harness_dir: Directory to write the wrapper script into.

    Returns:
        Path to the generated wrapper script.
    """
    harness_dir.mkdir(parents=True, exist_ok=True)

    target_basename = Path(target_path).name
    wrapper_content = _PERSISTENT_WRAPPER_TEMPLATE.format(
        target_basename=target_basename,
        target_path=target_path,
        harness_dir=str(harness_dir),
    )

    wrapper_path = harness_dir / "persistent_wrapper.sh"
    wrapper_path.write_text(wrapper_content, encoding="utf-8")
    # Make executable (owner rwx, group/other rx)
    wrapper_path.chmod(0o755)

    return wrapper_path
