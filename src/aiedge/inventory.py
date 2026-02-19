from __future__ import annotations

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

        if len(candidates) >= 50:
            break

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

    def looks_like_rootfs(d: Path) -> bool:
        if not is_dir_safe(d, op="rootfs_probe.is_dir"):
            return False
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
        if looks_like_rootfs(p):
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


def _scan_string_hits(
    files: list[Path],
    *,
    run_dir: Path | None = None,
    errors: list[dict[str, JsonValue]] | None = None,
    max_files: int = 2000,
    max_bytes_per_file: int = 256 * 1024,
    max_total_matches: int = 5000,
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

        summary_none: dict[str, JsonValue] = {
            "roots_scanned": 0,
            "files": 0,
            "binaries": 0,
            "configs": 0,
            "string_hits": 0,
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
                payload_none: dict[str, JsonValue] = {
                    "status": "partial",
                    "reason": reason,
                    "extracted_dir": extracted_rel,
                    "summary": summary_none,
                    "service_candidates": empty_candidates,
                    "services": empty_services,
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
                            "errors": _sorted_errors(errors),
                            "coverage_metrics": coverage_metrics,
                            "entry_count": _entry_count_from_coverage(coverage_metrics),
                            "entries": _entry_count_from_coverage(coverage_metrics),
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
            )
            skipped_files += skipped_string_files
            string_hits_total = int(sum(string_counts.values()))
            string_hits_seen = int(string_hits_total)

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

            summary: dict[str, JsonValue] = {
                "roots_scanned": int(len(roots)),
                "files": int(len(all_files)),
                "binaries": int(binaries),
                "configs": int(configs),
                "string_hits": int(string_hits_total),
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

            status: str = "partial" if errors else "ok"
            payload: dict[str, JsonValue] = {
                "status": status,
                "extracted_dir": _rel_to_run_dir(ctx.run_dir, extracted_dir),
                "roots": cast(
                    JsonValue, [_rel_to_run_dir(ctx.run_dir, r) for r in roots]
                ),
                "summary": summary,
                "service_candidates": service_candidates,
                "services": services,
            }
            if strings_written:
                payload["artifacts"] = {
                    "string_hits": _rel_to_run_dir(ctx.run_dir, strings_path)
                }

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
            fallback_payload: dict[str, JsonValue] = {
                "status": "partial",
                "reason": "inventory_recovered_from_exception",
                "extracted_dir": extracted_rel,
                "summary": summary_none,
                "service_candidates": empty_candidates,
                "services": empty_services,
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
                    },
                ),
                limitations=limitations,
            )
