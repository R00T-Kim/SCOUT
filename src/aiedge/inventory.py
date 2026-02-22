from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .policy import AIEdgePolicyViolation
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus


def _assert_under_dir(base_dir: Path, target: Path) -> None:
    base = base_dir.resolve()
    resolved = target.resolve()
    if not resolved.is_relative_to(base):
        raise AIEdgePolicyViolation(
            f"Refusing to write outside run dir: target={resolved} base={base}"
        )


def _rel_to_run_dir(run_dir: Path, path: Path) -> str:
    try:
        run_resolved = run_dir.resolve()
    except OSError:
        run_resolved = run_dir
    try:
        return str(path.resolve().relative_to(run_resolved))
    except Exception:
        try:
            return str(path.relative_to(run_resolved))
        except Exception:
            try:
                return os.path.relpath(str(path), start=str(run_resolved))
            except Exception:
                return str(path)


def _append_error(
    errors: list[dict[str, JsonValue]],
    *,
    run_dir: Path,
    path: Path,
    op: str,
    exc: OSError,
) -> None:
    if isinstance(exc.strerror, str) and exc.strerror:
        detail = exc.strerror
    elif isinstance(exc.errno, int):
        detail = os.strerror(exc.errno)
    else:
        detail = "os_error"
    detail = _sanitize_error_message(run_dir, detail)
    errors.append(
        {
            "path": _rel_to_run_dir(run_dir, path),
            "op": op,
            "error": f"{type(exc).__name__}: {detail}",
            "errno": cast(JsonValue, exc.errno if isinstance(exc.errno, int) else None),
        }
    )


_ABS_PATH_RE = re.compile(r"/(?:[^\s'\"]+/)+[^\s'\"]+")


def _sanitize_error_message(run_dir: Path, message: str) -> str:
    try:
        run_dir_s = str(run_dir.resolve())
    except OSError:
        run_dir_s = str(run_dir)
    out = message.replace(run_dir_s, "<run_dir>")
    return _ABS_PATH_RE.sub("<path>", out)


def _resolve_or_record(
    *,
    run_dir: Path,
    path: Path,
    errors: list[dict[str, JsonValue]],
    op: str,
) -> Path | None:
    try:
        return path.resolve()
    except OSError as exc:
        _append_error(errors, run_dir=run_dir, path=path, op=op, exc=exc)
        return None


def _dedupe_key(
    *,
    run_dir: Path,
    path: Path,
    errors: list[dict[str, JsonValue]],
    op: str,
) -> str:
    resolved = _resolve_or_record(run_dir=run_dir, path=path, errors=errors, op=op)
    if isinstance(resolved, Path):
        return str(resolved)
    return str(path)


def _sorted_errors(
    errors: list[dict[str, JsonValue]],
) -> list[dict[str, JsonValue]]:
    return sorted(
        errors,
        key=lambda e: (
            str(e.get("path", "")),
            str(e.get("op", "")),
            str(e.get("error", "")),
            str(e.get("errno", "")),
        ),
    )


def _safe_write_json(
    *,
    run_dir: Path,
    path: Path,
    payload: dict[str, JsonValue],
    errors: list[dict[str, JsonValue]],
    op: str,
) -> bool:
    _assert_under_dir(run_dir, path)
    try:
        _ = path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return True
    except OSError as exc:
        _append_error(errors, run_dir=run_dir, path=path, op=op, exc=exc)
        return False


def _iter_files(
    root: Path,
    *,
    run_dir: Path,
    errors: list[dict[str, JsonValue]],
) -> tuple[int, list[Path], int, int]:
    if not root.exists():
        return 0, [], 0, 0

    skipped_dirs = 0
    skipped_files = 0

    def iter_entries(dir_path: Path) -> list[os.DirEntry[str]]:
        try:
            with os.scandir(dir_path) as it:
                return sorted(list(it), key=lambda e: e.name)
        except OSError as exc:
            nonlocal skipped_dirs
            skipped_dirs += 1
            _append_error(errors, run_dir=run_dir, path=dir_path, op="scandir", exc=exc)
            return []

    files: list[Path] = []
    dirs_to_scan: list[Path] = [root]
    while dirs_to_scan:
        current = dirs_to_scan.pop()
        child_dirs: list[Path] = []
        for entry in iter_entries(current):
            path = Path(entry.path)
            try:
                if entry.is_dir(follow_symlinks=False):
                    child_dirs.append(path)
                    continue
            except OSError as exc:
                skipped_dirs += 1
                _append_error(errors, run_dir=run_dir, path=path, op="is_dir", exc=exc)
                continue

            try:
                if entry.is_file(follow_symlinks=False):
                    files.append(path)
            except OSError as exc:
                skipped_files += 1
                _append_error(errors, run_dir=run_dir, path=path, op="is_file", exc=exc)
                continue

        dirs_to_scan.extend(reversed(child_dirs))

    return len(files), files, skipped_dirs, skipped_files


def _resolve_run_relative_dir(
    run_dir: Path,
    rel_path: str,
    *,
    errors: list[dict[str, JsonValue]],
    op: str,
) -> Path | None:
    run_resolved = _resolve_or_record(
        run_dir=run_dir,
        path=run_dir,
        errors=errors,
        op=f"{op}.run_dir_resolve",
    )
    if not isinstance(run_resolved, Path):
        return None

    candidate = run_dir / rel_path
    p = _resolve_or_record(
        run_dir=run_dir,
        path=candidate,
        errors=errors,
        op=f"{op}.path_resolve",
    )
    if not isinstance(p, Path):
        return None

    if not p.is_relative_to(run_resolved):
        return None
    try:
        is_dir = p.is_dir()
    except OSError as exc:
        _append_error(errors, run_dir=run_dir, path=p, op=f"{op}.is_dir", exc=exc)
        return None
    if not is_dir:
        return None
    return p


def _load_carving_roots(
    run_dir: Path,
    *,
    errors: list[dict[str, JsonValue]],
) -> tuple[list[Path], list[str]]:
    roots_path = run_dir / "stages" / "carving" / "roots.json"
    if not roots_path.is_file():
        return [], []

    try:
        raw = cast(object, json.loads(roots_path.read_text(encoding="utf-8")))
    except Exception as exc:
        return [], [
            f"carving roots.json present but invalid JSON: {type(exc).__name__}: {exc}"
        ]

    roots_any: object
    if isinstance(raw, dict):
        roots_any = cast(dict[str, object], raw).get("roots")
    else:
        roots_any = raw

    if not isinstance(roots_any, list):
        return [], [
            "carving roots.json has unexpected shape; expected list under 'roots'"
        ]

    out: list[Path] = []
    seen: set[str] = set()
    for item in cast(list[object], roots_any):
        if not isinstance(item, str) or not item:
            continue
        if item.startswith("/"):
            continue
        p = _resolve_run_relative_dir(
            run_dir,
            item,
            errors=errors,
            op="carving_root_normalize",
        )
        if not isinstance(p, Path):
            continue
        key = _dedupe_key(
            run_dir=run_dir,
            path=p,
            errors=errors,
            op="carving_root_dedupe_key",
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(p)

    return out, []


def _load_ota_roots(
    run_dir: Path,
    *,
    errors: list[dict[str, JsonValue]],
) -> tuple[list[Path], list[str]]:
    roots_path = run_dir / "stages" / "ota" / "roots.json"
    if not roots_path.is_file():
        return [], []

    try:
        raw = cast(object, json.loads(roots_path.read_text(encoding="utf-8")))
    except Exception as exc:
        return [], [
            f"ota roots.json present but invalid JSON: {type(exc).__name__}: {exc}"
        ]

    roots_any: object
    if isinstance(raw, dict):
        roots_any = cast(dict[str, object], raw).get("roots")
    else:
        roots_any = raw

    if not isinstance(roots_any, list):
        return [], ["ota roots.json has unexpected shape; expected list under 'roots'"]

    out: list[Path] = []
    seen: set[str] = set()
    for item in cast(list[object], roots_any):
        if not isinstance(item, str) or not item:
            continue
        if item.startswith("/"):
            continue
        p = _resolve_run_relative_dir(
            run_dir,
            item,
            errors=errors,
            op="ota_root_normalize",
        )
        if not isinstance(p, Path):
            continue
        key = _dedupe_key(
            run_dir=run_dir,
            path=p,
            errors=errors,
            op="ota_root_dedupe_key",
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(p)

    return out, []


def _service_name_from_path(path: Path) -> str:
    n = path.name
    if n.endswith(".service"):
        return n[: -len(".service")]
    return path.stem or n


def _collect_service_candidates(files: list[Path], *, run_dir: Path) -> list[JsonValue]:
    candidates: list[JsonValue] = []
    seen: set[tuple[str, str, str]] = set()

    def add(
        *,
        name: str,
        kind: str,
        path: Path,
        confidence: float,
        note: str | None = None,
    ) -> None:
        rel = _rel_to_run_dir(run_dir, path)
        key = (kind, name, rel)
        if key in seen:
            return
        seen.add(key)

        ev: dict[str, JsonValue] = {"path": rel}
        if note:
            ev["note"] = note
        candidates.append(
            cast(
                JsonValue,
                {
                    "name": name,
                    "kind": kind,
                    "confidence": float(max(0.0, min(1.0, confidence))),
                    "evidence": [ev],
                },
            )
        )

    for p in files:
        rel = _rel_to_run_dir(run_dir, p)
        rel_l = rel.lower().replace("\\", "/")
        parts = [x for x in rel_l.split("/") if x]
        basename = p.name.lower()
        suffix = p.suffix.lower()

        if len(candidates) >= 120:
            break

        if suffix == ".cgi":
            add(
                name=p.name,
                kind="cgi_script",
                path=p,
                confidence=0.88,
                note="path suffix .cgi",
            )
            continue

        if "cgi-bin" in parts:
            add(
                name=p.name,
                kind="cgi_binary",
                path=p,
                confidence=0.8,
                note="path contains cgi-bin",
            )
            continue

        if basename in _WEB_SERVICE_BINARIES:
            add(
                name=p.name,
                kind="web_server_binary",
                path=p,
                confidence=0.86,
                note="known web service binary name",
            )

        if basename in _NETWORK_SERVICE_BINARIES:
            add(
                name=p.name,
                kind="network_service_binary",
                path=p,
                confidence=0.74,
                note="known network daemon binary name",
            )

        if "etc" in parts and "init.d" in parts:
            add(
                name=_service_name_from_path(p),
                kind="init_script",
                path=p,
                confidence=0.7,
            )
            continue

        if rel_l.endswith(".service") and "systemd" in parts:
            add(
                name=_service_name_from_path(p),
                kind="systemd_unit",
                path=p,
                confidence=0.8,
            )
            continue

        if "supervisor" in parts and rel_l.endswith(".conf"):
            add(
                name=_service_name_from_path(p),
                kind="supervisor_conf",
                path=p,
                confidence=0.6,
            )
            continue

        if "etc" in parts and "xinetd.d" in parts:
            add(
                name=_service_name_from_path(p),
                kind="xinetd_service",
                path=p,
                confidence=0.6,
            )
            continue

        if rel_l.endswith("/etc/inetd.conf") or rel_l.endswith("\\etc\\inetd.conf"):
            add(
                name="inetd",
                kind="inetd_conf",
                path=p,
                confidence=0.5,
            )
            continue

        if rel_l.endswith("/etc/rc.local") or rel_l.endswith("\\etc\\rc.local"):
            add(
                name="rc.local",
                kind="startup_script",
                path=p,
                confidence=0.5,
            )

    config_candidates = _collect_service_candidates_from_configs(
        files,
        run_dir=run_dir,
        max_candidates=120,
    )
    for item_any in config_candidates:
        if len(candidates) >= 120:
            break
        if not isinstance(item_any, dict):
            continue
        item = cast(dict[str, object], item_any)
        name_any = item.get("name")
        kind_any = item.get("kind")
        confidence_any = item.get("confidence")
        evidence_any = item.get("evidence")
        if not (
            isinstance(name_any, str)
            and isinstance(kind_any, str)
            and isinstance(confidence_any, (int, float))
            and isinstance(evidence_any, list)
            and evidence_any
            and isinstance(evidence_any[0], dict)
        ):
            continue
        evidence_obj = cast(dict[str, object], evidence_any[0])
        ev_path_any = evidence_obj.get("path")
        note_any = evidence_obj.get("note")
        if not isinstance(ev_path_any, str) or not ev_path_any:
            continue
        add(
            name=name_any,
            kind=kind_any,
            path=Path(run_dir / ev_path_any),
            confidence=float(confidence_any),
            note=note_any if isinstance(note_any, str) else None,
        )

    return candidates


_CONFIG_EXTS = {
    ".conf",
    ".cfg",
    ".cnf",
    ".ini",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".xml",
    ".properties",
    ".env",
    ".rc",
}

_MIN_INVENTORY_FILE_THRESHOLD = 50
_MIN_INVENTORY_BINARY_THRESHOLD = 5
_RISKY_BINARY_SYMBOLS: dict[str, bytes] = {
    "strcpy": b"strcpy",
    "strcat": b"strcat",
    "sprintf": b"sprintf",
    "vsprintf": b"vsprintf",
    "gets": b"gets",
    "system": b"system",
    "popen": b"popen",
    "execve": b"execve",
}
_ELF_MACHINE_MAP: dict[int, str] = {
    0x03: "x86",
    0x08: "mips",
    0x14: "powerpc",
    0x28: "arm",
    0x3E: "x86_64",
    0xB7: "aarch64",
    0xF3: "riscv",
}
_SERVICES_LINE_RE = re.compile(r"^([a-zA-Z0-9_.+-]+)\s+(\d+)/(tcp|udp)\b")
_WEB_SERVICE_BINARIES: frozenset[str] = frozenset(
    {
        "httpd",
        "nginx",
        "lighttpd",
        "uhttpd",
        "mini_httpd",
        "boa",
        "apache2",
        "synowebapi",
    }
)
_NETWORK_SERVICE_BINARIES: frozenset[str] = frozenset(
    {
        "upnpd",
        "miniupnpd",
        "dnsmasq",
        "dropbear",
        "sshd",
        "telnetd",
    }
)


def _is_config_file(path: Path) -> bool:
    name = path.name.lower()
    if path.suffix.lower() in _CONFIG_EXTS:
        return True

    parts = [p.lower() for p in path.parts]
    if "etc" in parts:
        return True

    return name in {
        "passwd",
        "shadow",
        "group",
        "hosts",
        "resolv.conf",
        "fstab",
        "inittab",
        "rc.local",
        "profile",
    }


def _read_text_sample(
    path: Path,
    *,
    max_bytes: int = 256 * 1024,
    run_dir: Path | None = None,
    errors: list[dict[str, JsonValue]] | None = None,
) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        if isinstance(run_dir, Path) and isinstance(errors, list):
            _append_error(errors, run_dir=run_dir, path=path, op="read_bytes", exc=exc)
        return None
    if not raw:
        return None
    try:
        return raw[:max_bytes].decode("utf-8", errors="ignore")
    except Exception:
        return None


def _collect_service_candidates_from_configs(
    files: list[Path],
    *,
    run_dir: Path,
    max_candidates: int = 120,
) -> list[JsonValue]:
    out: list[JsonValue] = []
    seen: set[tuple[str, str, str]] = set()

    def add(
        *,
        name: str,
        kind: str,
        path: Path,
        confidence: float,
        note: str | None = None,
    ) -> None:
        rel = _rel_to_run_dir(run_dir, path)
        key = (kind, name, rel)
        if key in seen:
            return
        seen.add(key)
        ev: dict[str, JsonValue] = {"path": rel}
        if note:
            ev["note"] = note
        out.append(
            cast(
                JsonValue,
                {
                    "name": name,
                    "kind": kind,
                    "confidence": float(max(0.0, min(1.0, confidence))),
                    "evidence": [ev],
                },
            )
        )

    for path in files:
        if len(out) >= int(max_candidates):
            break
        rel = _rel_to_run_dir(run_dir, path).replace("\\", "/")
        rel_lower = rel.lower()
        basename = path.name.lower()
        is_relevant_config = (
            basename
            in {
                "services",
                "inetd.conf",
                "xinetd.conf",
                "thttpd.conf",
                "httpd.conf",
                "apache2.conf",
                "lighttpd.conf",
                "uhttpd.conf",
                "nginx.conf",
            }
            or "/etc/xinetd.d/" in f"/{rel_lower}"
        )
        if not is_relevant_config:
            continue
        text = _read_text_sample(path, run_dir=run_dir, errors=None)
        if not isinstance(text, str):
            continue
        lines = [ln.strip() for ln in text.splitlines()[:2000]]
        if basename == "services":
            for line in lines:
                if not line or line.startswith("#"):
                    continue
                m = _SERVICES_LINE_RE.match(line)
                if not m:
                    continue
                name = m.group(1)
                port = m.group(2)
                proto = m.group(3)
                add(
                    name=name,
                    kind="services_db",
                    path=path,
                    confidence=0.55,
                    note=f"{port}/{proto}",
                )
                if len(out) >= int(max_candidates):
                    break
            continue
        if basename == "inetd.conf":
            for line in lines:
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if not parts:
                    continue
                service_name = parts[0]
                add(
                    name=service_name,
                    kind="inetd_service_map",
                    path=path,
                    confidence=0.65,
                )
                if len(out) >= int(max_candidates):
                    break
            continue
        if "/etc/xinetd.d/" in f"/{rel_lower}":
            service_name = path.stem
            for line in lines:
                if line.lower().startswith("service "):
                    service_name = line.split(maxsplit=1)[1].strip() or service_name
                    break
            add(
                name=service_name,
                kind="xinetd_service_map",
                path=path,
                confidence=0.65,
            )
            continue

        for line in lines:
            low = line.lower()
            if not low or low.startswith("#"):
                continue
            if "cgipat" in low or "cgi_pattern" in low or "scriptalias" in low:
                add(
                    name=f"{path.stem}-cgi",
                    kind="http_cgi_policy",
                    path=path,
                    confidence=0.75,
                    note=line[:160],
                )
            if low.startswith("listen "):
                add(
                    name=f"{path.stem}-listen",
                    kind="http_listen",
                    path=path,
                    confidence=0.6,
                    note=line[:120],
                )
            if len(out) >= int(max_candidates):
                break

    return out


def _elf_arch_from_file(path: Path) -> str | None:
    try:
        with path.open("rb") as f:
            head = f.read(64)
    except OSError:
        return None
    if len(head) < 20 or not head.startswith(b"\x7fELF"):
        return None
    bits = 64 if head[4] == 2 else 32 if head[4] == 1 else 0
    endian = "little" if head[5] == 1 else "big" if head[5] == 2 else "little"
    machine = int.from_bytes(head[18:20], endian, signed=False)
    arch = _ELF_MACHINE_MAP.get(machine, f"machine_{machine}")
    if bits in {32, 64}:
        return f"{arch}-{bits}"
    return arch


def _scan_binary_analysis(
    files: list[Path],
    *,
    run_dir: Path,
    errors: list[dict[str, JsonValue]],
    max_binaries: int = 400,
    max_bytes_per_file: int = 512 * 1024,
    max_hits: int = 200,
) -> tuple[dict[str, JsonValue], list[dict[str, JsonValue]], int]:
    risky_symbol_counts: dict[str, int] = {k: 0 for k in _RISKY_BINARY_SYMBOLS}
    arch_counts: dict[str, int] = {}
    hits: list[dict[str, JsonValue]] = []
    skipped_files = 0
    binaries_scanned = 0
    elf_binaries = 0
    risky_binaries = 0

    for path in files:
        if binaries_scanned >= int(max_binaries):
            break
        if not _looks_binary(path, run_dir=run_dir, errors=errors):
            continue

        binaries_scanned += 1
        try:
            with path.open("rb") as f:
                sample = f.read(int(max_bytes_per_file))
        except OSError as exc:
            skipped_files += 1
            _append_error(errors, run_dir=run_dir, path=path, op="read_bytes", exc=exc)
            continue
        if not sample:
            continue
        arch = _elf_arch_from_file(path)
        if isinstance(arch, str):
            elf_binaries += 1
            arch_counts[arch] = int(arch_counts.get(arch, 0) + 1)

        matched_symbols = [
            symbol
            for symbol, marker in _RISKY_BINARY_SYMBOLS.items()
            if marker in sample
        ]
        if not matched_symbols:
            continue

        risky_binaries += 1
        for symbol in matched_symbols:
            risky_symbol_counts[symbol] = int(risky_symbol_counts.get(symbol, 0) + 1)

        if len(hits) < int(max_hits):
            rel = _rel_to_run_dir(run_dir, path)
            sha = hashlib.sha256(sample).hexdigest()
            hits.append(
                {
                    "path": rel,
                    "arch": arch or "unknown",
                    "matched_symbols": cast(
                        list[JsonValue], cast(list[object], sorted(set(matched_symbols)))
                    ),
                    "sample_sha256": sha,
                }
            )

    summary: dict[str, JsonValue] = {
        "binaries_scanned": int(binaries_scanned),
        "elf_binaries": int(elf_binaries),
        "risky_binaries": int(risky_binaries),
        "risky_symbol_hits": int(sum(risky_symbol_counts.values())),
        "risky_symbol_counts": cast(
            dict[str, JsonValue],
            {k: int(v) for k, v in sorted(risky_symbol_counts.items()) if v > 0},
        ),
        "arch_counts": cast(
            dict[str, JsonValue],
            {k: int(v) for k, v in sorted(arch_counts.items())},
        ),
    }
    return summary, hits, skipped_files


def _inventory_quality_assessment(
    *,
    files_seen: int,
    binaries_seen: int,
    min_files: int = _MIN_INVENTORY_FILE_THRESHOLD,
    min_binaries: int = _MIN_INVENTORY_BINARY_THRESHOLD,
) -> dict[str, JsonValue]:
    reasons: list[str] = []
    if files_seen < int(min_files):
        reasons.append(
            f"files_seen below threshold ({files_seen} < {int(min_files)})"
        )
    if binaries_seen < int(min_binaries):
        reasons.append(
            f"binaries_seen below threshold ({binaries_seen} < {int(min_binaries)})"
        )
    status = "sufficient" if not reasons else "insufficient"
    return {
        "status": status,
        "min_files": int(min_files),
        "min_binaries": int(min_binaries),
        "files_seen": int(files_seen),
        "binaries_seen": int(binaries_seen),
        "reasons": cast(list[JsonValue], cast(list[object], reasons)),
    }


def _looks_binary(
    path: Path,
    *,
    sniff_bytes: int = 2048,
    run_dir: Path | None = None,
    errors: list[dict[str, JsonValue]] | None = None,
) -> bool:
    try:
        st = path.stat()
    except OSError as exc:
        if isinstance(run_dir, Path) and isinstance(errors, list):
            _append_error(errors, run_dir=run_dir, path=path, op="stat", exc=exc)
        return False

    if stat.S_ISREG(st.st_mode) and (st.st_mode & 0o111):
        return True

    if path.suffix.lower() in {".so", ".a", ".o", ".elf", ".bin", ".exe"}:
        return True

    try:
        with path.open("rb") as f:
            chunk = f.read(sniff_bytes)
    except OSError as exc:
        if isinstance(run_dir, Path) and isinstance(errors, list):
            _append_error(errors, run_dir=run_dir, path=path, op="read", exc=exc)
        return False

    if b"\x00" in chunk:
        return True
    return False


def _find_rootfs_candidates(
    extracted_dir: Path,
    *,
    run_dir: Path,
    errors: list[dict[str, JsonValue]],
) -> tuple[list[Path], int]:
    candidates: list[Path] = []
    skipped_dirs = 0

    def is_dir_safe(path: Path, *, op: str) -> bool:
        try:
            return path.is_dir()
        except OSError as exc:
            _append_error(errors, run_dir=run_dir, path=path, op=op, exc=exc)
            return False

    def is_file_safe(path: Path, *, op: str) -> bool:
        try:
            return path.is_file()
        except OSError as exc:
            _append_error(errors, run_dir=run_dir, path=path, op=op, exc=exc)
            return False

    def looks_like_rootfs(d: Path, *, depth: int) -> bool:
        if not is_dir_safe(d, op="rootfs_probe.is_dir"):
            return False
        # Rootfs probing should focus on top-level candidates only.
        # Deep nested directories frequently contain localized/data "etc"
        # paths (for example vendor text assets) that are not filesystem roots.
        if depth <= 2:
            etc_dir = d / "etc"
            if is_dir_safe(etc_dir, op="rootfs_probe.etc_is_dir") and (
                is_dir_safe(d / "bin", op="rootfs_probe.bin_is_dir")
                or is_dir_safe(d / "usr", op="rootfs_probe.usr_is_dir")
                or is_dir_safe(d / "sbin", op="rootfs_probe.sbin_is_dir")
            ):
                return True
            if is_file_safe(etc_dir / "passwd", op="rootfs_probe.passwd_is_file"):
                return True
        if d.name.endswith("-root") or d.name.endswith("rootfs"):
            return True
        return False

    def iter_dirs(root: Path) -> list[Path]:
        out: list[Path] = []
        dirs_to_scan: list[Path] = [root]
        while dirs_to_scan:
            current = dirs_to_scan.pop()
            try:
                with os.scandir(current) as it:
                    entries = sorted(list(it), key=lambda e: e.name)
            except OSError as exc:
                nonlocal skipped_dirs
                skipped_dirs += 1
                _append_error(
                    errors, run_dir=run_dir, path=current, op="scandir", exc=exc
                )
                continue

            child_dirs: list[Path] = []
            for entry in entries:
                try:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                except OSError as exc:
                    skipped_dirs += 1
                    _append_error(
                        errors,
                        run_dir=run_dir,
                        path=Path(entry.path),
                        op="is_dir",
                        exc=exc,
                    )
                    continue
                child = Path(entry.path)
                out.append(child)
                child_dirs.append(child)

            dirs_to_scan.extend(reversed(child_dirs))

        return out

    for p in iter_dirs(extracted_dir):
        try:
            rel = p.relative_to(extracted_dir)
        except ValueError:
            continue
        if len(rel.parts) > 6:
            continue
        if looks_like_rootfs(p, depth=len(rel.parts)):
            candidates.append(p)

    uniq: list[Path] = []
    seen: set[str] = set()
    for p in sorted(candidates, key=lambda x: (len(x.parts), str(x))):
        key = _dedupe_key(
            run_dir=run_dir,
            path=p,
            errors=errors,
            op="rootfs_candidate_dedupe_key",
        )
        if key in seen:
            continue
        seen.add(key)
        uniq.append(p)

    return uniq, skipped_dirs


_STRING_PATTERNS: dict[str, re.Pattern[str]] = {
    "url": re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "credential_words": re.compile(
        r"\b(password|passwd|secret|apikey|api_key|token|bearer)\b", re.IGNORECASE
    ),
}

DEFAULT_STRING_SCAN_MAX_FILES = 2000
DEFAULT_STRING_SCAN_MAX_TOTAL_MATCHES = 5000
DEFAULT_STRING_SCAN_MAX_BYTES_PER_FILE = 256 * 1024


def _scan_string_hits(
    files: list[Path],
    *,
    run_dir: Path | None = None,
    errors: list[dict[str, JsonValue]] | None = None,
    max_files: int = DEFAULT_STRING_SCAN_MAX_FILES,
    max_bytes_per_file: int = DEFAULT_STRING_SCAN_MAX_BYTES_PER_FILE,
    max_total_matches: int = DEFAULT_STRING_SCAN_MAX_TOTAL_MATCHES,
) -> tuple[dict[str, int], list[dict[str, JsonValue]], int]:
    counts: dict[str, int] = {k: 0 for k in _STRING_PATTERNS}
    samples: list[dict[str, JsonValue]] = []
    skipped_files = 0

    total_matches = 0
    for p in files[:max_files]:
        if _looks_binary(p, run_dir=run_dir, errors=errors):
            continue
        try:
            raw = p.read_bytes()
        except OSError as exc:
            skipped_files += 1
            if isinstance(run_dir, Path) and isinstance(errors, list):
                _append_error(errors, run_dir=run_dir, path=p, op="read_bytes", exc=exc)
            continue
        if not raw:
            continue
        raw = raw[:max_bytes_per_file]

        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            continue

        for key, pat in _STRING_PATTERNS.items():
            for m in pat.finditer(text):
                counts[key] += 1
                total_matches += 1
                if len(samples) < 50:
                    s = m.group(0)
                    s = s[:200]
                    if isinstance(run_dir, Path):
                        file_s = _rel_to_run_dir(run_dir, p)
                    else:
                        file_s = str(p)
                    samples.append({"file": file_s, "pattern": key, "match": s})
                if total_matches >= max_total_matches:
                    return counts, samples, skipped_files

    return counts, samples, skipped_files


def _coverage_metrics(
    *,
    roots_considered: int,
    roots_scanned: int,
    files_seen: int,
    binaries_seen: int,
    configs_seen: int,
    string_hits_seen: int,
    skipped_dirs: int,
    skipped_files: int,
) -> dict[str, JsonValue]:
    return {
        "roots_considered": int(roots_considered),
        "roots_scanned": int(roots_scanned),
        "files_seen": int(files_seen),
        "binaries_seen": int(binaries_seen),
        "configs_seen": int(configs_seen),
        "string_hits_seen": int(string_hits_seen),
        "skipped_dirs": int(skipped_dirs),
        "skipped_files": int(skipped_files),
    }


def _entry_count_from_coverage(coverage_metrics: dict[str, JsonValue]) -> int:
    files_seen_any = coverage_metrics.get("files_seen")
    if isinstance(files_seen_any, int) and not isinstance(files_seen_any, bool):
        return int(max(0, files_seen_any))
    return 0


def _inject_entry_count_aliases(
    payload: dict[str, JsonValue],
    *,
    coverage_metrics: dict[str, JsonValue],
) -> None:
    entry_count = _entry_count_from_coverage(coverage_metrics)
    payload["entry_count"] = int(entry_count)
    # Backward-compatible alias for consumers that historically read `entries`
    # as a scalar count. Prefer summary.files or coverage_metrics.files_seen.
    payload["entries"] = int(entry_count)


def _empty_string_hits_payload() -> dict[str, JsonValue]:
    counts: dict[str, int] = {k: 0 for k in _STRING_PATTERNS}
    return {
        "counts": cast(JsonValue, counts),
        "samples": cast(JsonValue, []),
        "note": "Best-effort string matching; not a findings engine.",
    }


def _write_inventory_payload(
    *,
    run_dir: Path,
    inventory_path: Path,
    payload: dict[str, JsonValue],
    errors: list[dict[str, JsonValue]],
    coverage_metrics: dict[str, JsonValue],
) -> bool:
    payload["errors"] = cast(JsonValue, _sorted_errors(errors))
    payload["coverage_metrics"] = coverage_metrics
    _inject_entry_count_aliases(payload, coverage_metrics=coverage_metrics)
    if _safe_write_json(
        run_dir=run_dir,
        path=inventory_path,
        payload=payload,
        errors=errors,
        op="write_inventory",
    ):
        return True

    minimal_summary = cast(
        dict[str, JsonValue],
        payload.get(
            "summary",
            {
                "roots_scanned": 0,
                "files": 0,
                "binaries": 0,
                "configs": 0,
                "string_hits": 0,
            },
        ),
    )
    minimal_payload: dict[str, JsonValue] = {
        "status": "partial",
        "summary": minimal_summary,
        "service_candidates": cast(
            list[JsonValue], payload.get("service_candidates", cast(JsonValue, []))
        ),
        "services": cast(list[JsonValue], payload.get("services", cast(JsonValue, []))),
        "errors": cast(JsonValue, _sorted_errors(errors)),
        "coverage_metrics": coverage_metrics,
    }
    _inject_entry_count_aliases(minimal_payload, coverage_metrics=coverage_metrics)
    if "reason" in payload:
        minimal_payload["reason"] = payload["reason"]
    if "extracted_dir" in payload:
        minimal_payload["extracted_dir"] = payload["extracted_dir"]

    return _safe_write_json(
        run_dir=run_dir,
        path=inventory_path,
        payload=minimal_payload,
        errors=errors,
        op="write_inventory_minimal",
    )


@dataclass(frozen=True)
class InventoryStage:
    firmware_name: str = "firmware.bin"
    string_scan_max_files: int = DEFAULT_STRING_SCAN_MAX_FILES
    string_scan_max_total_matches: int = DEFAULT_STRING_SCAN_MAX_TOTAL_MATCHES
    string_scan_max_bytes_per_file: int = DEFAULT_STRING_SCAN_MAX_BYTES_PER_FILE

    @property
    def name(self) -> str:
        return "inventory"

    def run(self, ctx: StageContext) -> StageOutcome:
        stage_dir = ctx.run_dir / "stages" / "inventory"
        _assert_under_dir(ctx.run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)

        extracted_dir = (
            ctx.run_dir / "stages" / "extraction" / f"_{self.firmware_name}.extracted"
        )
        extracted_rel = _rel_to_run_dir(ctx.run_dir, extracted_dir)
        inventory_path = stage_dir / "inventory.json"
        _assert_under_dir(ctx.run_dir, inventory_path)
        strings_path = stage_dir / "string_hits.json"
        _assert_under_dir(ctx.run_dir, strings_path)
        binary_analysis_path = stage_dir / "binary_analysis.json"
        _assert_under_dir(ctx.run_dir, binary_analysis_path)

        evidence: list[JsonValue] = []
        errors: list[dict[str, JsonValue]] = []
        limitations: list[str] = []

        skipped_dirs = 0
        skipped_files = 0
        roots_considered = 0
        roots_scanned = 0
        files_seen = 0
        binaries_seen = 0
        configs_seen = 0
        string_hits_seen = 0
        binary_risk_hits_seen = 0

        summary_none: dict[str, JsonValue] = {
            "roots_scanned": 0,
            "files": 0,
            "binaries": 0,
            "configs": 0,
            "string_hits": 0,
            "risky_binary_hits": 0,
        }
        empty_candidates: list[JsonValue] = []
        empty_services: list[JsonValue] = []
        strings_written = _safe_write_json(
            run_dir=ctx.run_dir,
            path=strings_path,
            payload=_empty_string_hits_payload(),
            errors=errors,
            op="write_string_hits_empty",
        )
        if not strings_written:
            limitations.append(
                "Failed to write string_hits.json placeholder; inventory.json still written with error details."
            )
        binary_written = _safe_write_json(
            run_dir=ctx.run_dir,
            path=binary_analysis_path,
            payload={
                "summary": {
                    "binaries_scanned": 0,
                    "elf_binaries": 0,
                    "risky_binaries": 0,
                    "risky_symbol_hits": 0,
                    "risky_symbol_counts": {},
                    "arch_counts": {},
                },
                "hits": [],
                "note": "Best-effort binary risk scan (symbol/string based).",
            },
            errors=errors,
            op="write_binary_analysis_empty",
        )
        if not binary_written:
            limitations.append(
                "Failed to write binary_analysis.json placeholder; inventory.json still written with error details."
            )

        try:
            ota_roots, ota_limits = _load_ota_roots(ctx.run_dir, errors=errors)
            carving_roots, carving_limits = _load_carving_roots(
                ctx.run_dir, errors=errors
            )
            limitations.extend(ota_limits)
            limitations.extend(carving_limits)

            extracted_roots: list[Path] = []
            extracted_state_note: str | None = None
            if extracted_dir.exists():
                extracted_count, _, s_dirs, s_files = _iter_files(
                    extracted_dir,
                    run_dir=ctx.run_dir,
                    errors=errors,
                )
                skipped_dirs += s_dirs
                skipped_files += s_files
                if extracted_count > 0:
                    rootfs, rootfs_skipped_dirs = _find_rootfs_candidates(
                        extracted_dir,
                        run_dir=ctx.run_dir,
                        errors=errors,
                    )
                    skipped_dirs += rootfs_skipped_dirs
                    extracted_roots = rootfs if rootfs else [extracted_dir]
                else:
                    extracted_state_note = "empty"
            else:
                extracted_state_note = "missing"

            roots: list[Path] = []
            seen_roots: set[str] = set()
            for p in list(carving_roots) + list(extracted_roots):
                key = _dedupe_key(
                    run_dir=ctx.run_dir,
                    path=p,
                    errors=errors,
                    op="root_dedupe_key",
                )
                if key in seen_roots:
                    continue
                seen_roots.add(key)
                roots.append(p)

            ota_roots_have_files = False
            if ota_roots:
                for ota_root in ota_roots:
                    ota_file_count, _, s_dirs, s_files = _iter_files(
                        ota_root,
                        run_dir=ctx.run_dir,
                        errors=errors,
                    )
                    skipped_dirs += s_dirs
                    skipped_files += s_files
                    if ota_file_count > 0:
                        ota_roots_have_files = True
                        break

                if ota_roots_have_files:
                    roots = list(ota_roots)
                else:
                    limitations.append(
                        "OTA roots are present but contain no files; falling back to carving/extraction roots."
                    )

            roots_considered = int(len(roots))

            if not ota_roots_have_files and not roots:
                reason = (
                    "extraction produced no extracted directory"
                    if extracted_state_note == "missing"
                    else "extraction produced an empty extracted directory"
                )
                coverage_metrics = _coverage_metrics(
                    roots_considered=roots_considered,
                    roots_scanned=roots_scanned,
                    files_seen=files_seen,
                    binaries_seen=binaries_seen,
                    configs_seen=configs_seen,
                    string_hits_seen=string_hits_seen,
                    skipped_dirs=skipped_dirs,
                    skipped_files=skipped_files,
                )
                quality_none = _inventory_quality_assessment(
                    files_seen=files_seen,
                    binaries_seen=binaries_seen,
                )
                payload_none: dict[str, JsonValue] = {
                    "status": "partial",
                    "reason": reason,
                    "extracted_dir": extracted_rel,
                    "summary": summary_none,
                    "service_candidates": empty_candidates,
                    "services": empty_services,
                    "quality": quality_none,
                }
                _ = _write_inventory_payload(
                    run_dir=ctx.run_dir,
                    inventory_path=inventory_path,
                    payload=payload_none,
                    errors=errors,
                    coverage_metrics=coverage_metrics,
                )

                evidence.append({"path": _rel_to_run_dir(ctx.run_dir, inventory_path)})
                if strings_written:
                    evidence.append(
                        {"path": _rel_to_run_dir(ctx.run_dir, strings_path)}
                    )
                if binary_written:
                    evidence.append(
                        {"path": _rel_to_run_dir(ctx.run_dir, binary_analysis_path)}
                    )
                if extracted_state_note is not None:
                    evidence.append(
                        {"path": extracted_rel, "note": extracted_state_note}
                    )
                carving_roots_path = ctx.run_dir / "stages" / "carving" / "roots.json"
                if carving_roots_path.is_file():
                    evidence.append(
                        {
                            "path": _rel_to_run_dir(ctx.run_dir, carving_roots_path),
                            "note": "present",
                        }
                    )
                ota_roots_path = ctx.run_dir / "stages" / "ota" / "roots.json"
                if ota_roots_path.is_file():
                    evidence.append(
                        {
                            "path": _rel_to_run_dir(ctx.run_dir, ota_roots_path),
                            "note": "present",
                        }
                    )
                limitations.append(
                    "No scan roots available (OTA roots, carving roots, and extraction output unavailable)."
                )
                limitations.append(
                    "Inventory coverage is insufficient; provide a pre-extracted rootfs via --rootfs PATH and rerun."
                )
                if errors:
                    limitations.append(
                        "Inventory encountered recoverable filesystem errors; see inventory.json errors[]."
                    )

                return StageOutcome(
                    status="partial",
                    details=cast(
                        dict[str, JsonValue],
                        {
                            "evidence": evidence,
                            "summary": summary_none,
                            "service_candidates": empty_candidates,
                            "services": empty_services,
                            "extracted_dir": extracted_rel,
                            "reason": reason,
                            "quality": quality_none,
                            "errors": _sorted_errors(errors),
                            "coverage_metrics": coverage_metrics,
                            "entry_count": _entry_count_from_coverage(coverage_metrics),
                            "entries": _entry_count_from_coverage(coverage_metrics),
                            "binary_analysis_summary": {
                                "binaries_scanned": 0,
                                "elf_binaries": 0,
                                "risky_binaries": 0,
                                "risky_symbol_hits": 0,
                                "risky_symbol_counts": {},
                                "arch_counts": {},
                            },
                        },
                    ),
                    limitations=limitations,
                )

            all_files: list[Path] = []
            roots_scanned = int(len(roots))
            for r in roots:
                _, files, s_dirs, s_files = _iter_files(
                    r,
                    run_dir=ctx.run_dir,
                    errors=errors,
                )
                skipped_dirs += s_dirs
                skipped_files += s_files
                all_files.extend(files)

            files_seen = int(len(all_files))
            service_candidates: list[JsonValue] = _collect_service_candidates(
                all_files, run_dir=ctx.run_dir
            )
            services: list[JsonValue] = []

            binaries = 0
            configs = 0
            for p in all_files:
                if _is_config_file(p):
                    configs += 1
                if _looks_binary(p, run_dir=ctx.run_dir, errors=errors):
                    binaries += 1
            binaries_seen = int(binaries)
            configs_seen = int(configs)

            string_counts, string_samples, skipped_string_files = _scan_string_hits(
                all_files,
                run_dir=ctx.run_dir,
                errors=errors,
                max_files=max(1, int(self.string_scan_max_files)),
                max_total_matches=max(1, int(self.string_scan_max_total_matches)),
                max_bytes_per_file=max(256, int(self.string_scan_max_bytes_per_file)),
            )
            skipped_files += skipped_string_files
            string_hits_total = int(sum(string_counts.values()))
            string_hits_seen = int(string_hits_total)

            binary_summary, binary_hits, skipped_binary_files = _scan_binary_analysis(
                all_files,
                run_dir=ctx.run_dir,
                errors=errors,
            )
            skipped_files += skipped_binary_files
            risky_hits_any = binary_summary.get("risky_symbol_hits")
            if isinstance(risky_hits_any, int):
                binary_risk_hits_seen = int(risky_hits_any)

            strings_payload: dict[str, JsonValue] = {
                "counts": cast(JsonValue, string_counts),
                "samples": cast(JsonValue, string_samples),
                "note": "Best-effort string matching; not a findings engine.",
            }
            strings_written = _safe_write_json(
                run_dir=ctx.run_dir,
                path=strings_path,
                payload=strings_payload,
                errors=errors,
                op="write_string_hits",
            )
            if not strings_written:
                limitations.append(
                    "Failed to write string_hits.json; inventory.json still written with error details."
                )
            binary_payload: dict[str, JsonValue] = {
                "summary": binary_summary,
                "hits": cast(
                    list[JsonValue],
                    cast(list[object], binary_hits),
                ),
                "note": "Best-effort binary risk scan (symbol/string based).",
            }
            binary_written = _safe_write_json(
                run_dir=ctx.run_dir,
                path=binary_analysis_path,
                payload=binary_payload,
                errors=errors,
                op="write_binary_analysis",
            )
            if not binary_written:
                limitations.append(
                    "Failed to write binary_analysis.json; inventory.json still written with error details."
                )

            summary: dict[str, JsonValue] = {
                "roots_scanned": int(len(roots)),
                "files": int(len(all_files)),
                "binaries": int(binaries),
                "configs": int(configs),
                "string_hits": int(string_hits_total),
                "risky_binary_hits": int(binary_risk_hits_seen),
            }
            scan_limits: dict[str, JsonValue] = {
                "string_scan_max_files": int(max(1, self.string_scan_max_files)),
                "string_scan_max_total_matches": int(
                    max(1, self.string_scan_max_total_matches)
                ),
                "string_scan_max_bytes_per_file": int(
                    max(256, self.string_scan_max_bytes_per_file)
                ),
            }

            coverage_metrics = _coverage_metrics(
                roots_considered=roots_considered,
                roots_scanned=roots_scanned,
                files_seen=files_seen,
                binaries_seen=binaries_seen,
                configs_seen=configs_seen,
                string_hits_seen=string_hits_seen,
                skipped_dirs=skipped_dirs,
                skipped_files=skipped_files,
            )
            quality = _inventory_quality_assessment(
                files_seen=files_seen,
                binaries_seen=binaries_seen,
            )

            status: str = "partial" if errors else "ok"
            quality_status_any = quality.get("status")
            if quality_status_any == "insufficient":
                extracted_root_only = (
                    len(roots) == 1
                    and roots[0] == extracted_dir
                    and roots_scanned == 1
                )
                if extracted_root_only:
                    status = "partial"
                    limitations.append(
                        "Inventory quality gate flagged insufficient coverage on extraction root; downstream results may be incomplete."
                    )
                else:
                    limitations.append(
                        "Inventory quality heuristics observed sparse coverage, but alternative roots were present."
                    )
            payload: dict[str, JsonValue] = {
                "status": status,
                "extracted_dir": _rel_to_run_dir(ctx.run_dir, extracted_dir),
                "roots": cast(
                    JsonValue, [_rel_to_run_dir(ctx.run_dir, r) for r in roots]
                ),
                "summary": summary,
                "service_candidates": service_candidates,
                "services": services,
                "quality": quality,
                "binary_analysis_summary": binary_summary,
                "scan_limits": scan_limits,
            }
            artifacts_payload: dict[str, JsonValue] = {}
            if strings_written:
                artifacts_payload["string_hits"] = _rel_to_run_dir(
                    ctx.run_dir, strings_path
                )
            if binary_written:
                artifacts_payload["binary_analysis"] = _rel_to_run_dir(
                    ctx.run_dir, binary_analysis_path
                )
            if artifacts_payload:
                payload["artifacts"] = artifacts_payload

            _ = _write_inventory_payload(
                run_dir=ctx.run_dir,
                inventory_path=inventory_path,
                payload=payload,
                errors=errors,
                coverage_metrics=coverage_metrics,
            )

            evidence.append({"path": _rel_to_run_dir(ctx.run_dir, inventory_path)})
            if strings_written:
                evidence.append({"path": _rel_to_run_dir(ctx.run_dir, strings_path)})
            if binary_written:
                evidence.append(
                    {"path": _rel_to_run_dir(ctx.run_dir, binary_analysis_path)}
                )
            evidence.append({"path": _rel_to_run_dir(ctx.run_dir, extracted_dir)})
            carving_roots_path = ctx.run_dir / "stages" / "carving" / "roots.json"
            if carving_roots_path.is_file():
                evidence.append(
                    {"path": _rel_to_run_dir(ctx.run_dir, carving_roots_path)}
                )
            ota_roots_path = ctx.run_dir / "stages" / "ota" / "roots.json"
            if ota_roots_path.is_file():
                evidence.append({"path": _rel_to_run_dir(ctx.run_dir, ota_roots_path)})
            for r in roots[:5]:
                evidence.append(
                    {
                        "path": _rel_to_run_dir(ctx.run_dir, r),
                        "note": "rootfs_candidate",
                    }
                )
            if errors:
                limitations.append(
                    "Inventory encountered recoverable filesystem errors; see inventory.json errors[]."
                )

            return StageOutcome(
                status=cast(StageStatus, status),
                details=cast(
                    dict[str, JsonValue],
                    {
                        "evidence": evidence,
                        "summary": summary,
                        "service_candidates": service_candidates,
                        "services": services,
                        "extracted_dir": _rel_to_run_dir(ctx.run_dir, extracted_dir),
                        "roots": cast(
                            list[JsonValue],
                            [_rel_to_run_dir(ctx.run_dir, r) for r in roots],
                        ),
                        "errors": _sorted_errors(errors),
                        "coverage_metrics": coverage_metrics,
                        "entry_count": _entry_count_from_coverage(coverage_metrics),
                        "entries": _entry_count_from_coverage(coverage_metrics),
                        "quality": quality,
                        "binary_analysis_summary": binary_summary,
                        "scan_limits": scan_limits,
                    },
                ),
                limitations=limitations,
            )
        except Exception as exc:
            if isinstance(exc, OSError):
                _append_error(
                    errors,
                    run_dir=ctx.run_dir,
                    path=ctx.run_dir,
                    op="run",
                    exc=exc,
                )
            else:
                errors.append(
                    {
                        "path": ".",
                        "op": "run",
                        "error": _sanitize_error_message(
                            ctx.run_dir, f"{type(exc).__name__}: {exc}"
                        ),
                        "errno": None,
                    }
                )

            coverage_metrics = _coverage_metrics(
                roots_considered=roots_considered,
                roots_scanned=roots_scanned,
                files_seen=files_seen,
                binaries_seen=binaries_seen,
                configs_seen=configs_seen,
                string_hits_seen=string_hits_seen,
                skipped_dirs=skipped_dirs,
                skipped_files=skipped_files,
            )
            quality_fallback = _inventory_quality_assessment(
                files_seen=files_seen,
                binaries_seen=binaries_seen,
            )
            fallback_payload: dict[str, JsonValue] = {
                "status": "partial",
                "reason": "inventory_recovered_from_exception",
                "extracted_dir": extracted_rel,
                "summary": summary_none,
                "service_candidates": empty_candidates,
                "services": empty_services,
                "quality": quality_fallback,
                "binary_analysis_summary": {
                    "binaries_scanned": 0,
                    "elf_binaries": 0,
                    "risky_binaries": 0,
                    "risky_symbol_hits": 0,
                    "risky_symbol_counts": {},
                    "arch_counts": {},
                },
            }
            if not strings_written:
                strings_written = _safe_write_json(
                    run_dir=ctx.run_dir,
                    path=strings_path,
                    payload=_empty_string_hits_payload(),
                    errors=errors,
                    op="write_string_hits_recovery",
                )
            _ = _write_inventory_payload(
                run_dir=ctx.run_dir,
                inventory_path=inventory_path,
                payload=fallback_payload,
                errors=errors,
                coverage_metrics=coverage_metrics,
            )
            limitations.append(
                "Inventory recovered from an unexpected exception; see inventory.json errors[]."
            )

            return StageOutcome(
                status="partial",
                details=cast(
                    dict[str, JsonValue],
                    {
                        "summary": summary_none,
                        "service_candidates": empty_candidates,
                        "services": empty_services,
                        "extracted_dir": extracted_rel,
                        "errors": _sorted_errors(errors),
                        "coverage_metrics": coverage_metrics,
                        "entry_count": _entry_count_from_coverage(coverage_metrics),
                        "entries": _entry_count_from_coverage(coverage_metrics),
                        "quality": quality_fallback,
                        "binary_analysis_summary": {
                            "binaries_scanned": 0,
                            "elf_binaries": 0,
                            "risky_binaries": 0,
                            "risky_symbol_hits": 0,
                            "risky_symbol_counts": {},
                            "arch_counts": {},
                        },
                    },
                ),
                limitations=limitations,
            )
