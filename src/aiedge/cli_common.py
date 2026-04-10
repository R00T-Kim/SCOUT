"""Shared constants, protocols, and utility helpers for CLI modules."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Protocol, cast

# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------


class _RunInfo(Protocol):
    run_dir: Path


class _RunReport(Protocol):
    status: str


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CANONICAL_8MB_SHA256 = (
    "387d97fd925125471691d5c565fcc0ff009e111bdbdfd2ddb057f9212a939c8a"
)
_CANONICAL_8MB_SIZE_BYTES = 8_388_608
_TUI_VERIFIED_CHAIN_REF = "verified_chain/verified_chain.json"
_TUI_DYNAMIC_VALIDATION_REQUIRED_REFS = (
    "stages/dynamic_validation/dynamic_validation.json",
    "stages/dynamic_validation/isolation/firewall_snapshot.txt",
    "stages/dynamic_validation/pcap/dynamic_validation.pcap",
)
_TUI_RUNTIME_COMMUNICATION_NODE_TYPE_ORDER = {
    "service": 0,
    "host": 1,
    "endpoint": 2,
    "component": 3,
    "surface": 4,
    "vendor": 5,
    "unknown": 6,
}

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------

_ANSI_RESET = "\x1b[0m"
_ANSI_BOLD = "\x1b[1m"
_ANSI_DIM = "\x1b[2m"
_ANSI_CYAN = "\x1b[36m"
_ANSI_GREEN = "\x1b[32m"
_ANSI_YELLOW = "\x1b[33m"
_ANSI_RED = "\x1b[31m"
_ANSI_MAGENTA = "\x1b[35m"
_ANSI_BLUE = "\x1b[34m"

# Extended colors (256-color mode) for richer branding
_ANSI_PURPLE_256 = "\x1b[38;5;141m"       # Soft violet (#af87ff) - brand accent
_ANSI_DEEP_PURPLE_256 = "\x1b[38;5;98m"   # Deep purple (#875fd7) - secondary
_ANSI_LIME_256 = "\x1b[38;5;149m"         # Lime green (#afd75f) - highlight


def _tui_ansi_supported() -> bool:
    no_color = os.environ.get("NO_COLOR")
    if no_color:
        return False
    force_color = os.environ.get("FORCE_COLOR") or os.environ.get("CLICOLOR_FORCE")
    if force_color and force_color != "0":
        return True
    if os.environ.get("TERM", "dumb").lower() == "dumb":
        return False
    if os.environ.get("CLICOLOR") == "0":
        return False
    return bool(sys.stdout.isatty())


def _tui_unicode_supported() -> bool:
    if os.environ.get("AIEDGE_TUI_ASCII") == "1":
        return False
    encoding = (sys.stdout.encoding or "").lower()
    if not encoding:
        return False
    return "utf" in encoding


def _ansi(text: str, *codes: str, enabled: bool) -> str:
    if not enabled or not codes:
        return text
    return "".join(codes) + text + _ANSI_RESET


# ---------------------------------------------------------------------------
# Data conversion utilities
# ---------------------------------------------------------------------------


def _safe_load_json_object(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        obj_any = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return {}
    if not isinstance(obj_any, dict):
        return {}
    return cast(dict[str, object], obj_any)


def _as_int(value: object, *, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return int(value)
    return default


def _as_float(value: object, *, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    return default


def _short_text(value: object, *, max_len: int = 96) -> str:
    if not isinstance(value, str):
        return ""
    text = " ".join(value.split())
    if len(text) <= max_len:
        return text
    if max_len <= 3:
        return text[:max_len]
    return text[: max_len - 3] + "..."


def _short_path(value: object, *, max_len: int = 120) -> str:
    if not isinstance(value, str):
        return ""
    text = " ".join(value.split())
    if len(text) <= max_len:
        return text
    if max_len <= 7:
        return text[:max_len]
    keep = max_len - 3
    head = int(keep * 0.55)
    tail = keep - head
    return text[:head] + "..." + text[-tail:]


def _path_tail(value: object, *, max_segments: int = 4, max_len: int = 84) -> str:
    if not isinstance(value, str):
        return ""
    text = " ".join(value.split())
    if not text:
        return ""
    parts = [p for p in text.split("/") if p]
    if not parts:
        return _short_path(text, max_len=max_len)
    tail = "/".join(parts[-max_segments:])
    if len(parts) > max_segments:
        tail = ".../" + tail
    return _short_path(tail, max_len=max_len)


def _safe_node_text(value: object, *, fallback: str = "unknown", max_len: int = 160) -> str:
    if not isinstance(value, str):
        return fallback
    text = " ".join(value.replace("\n", " ").replace("\r", " ").split())
    text = text.encode("ascii", errors="ignore").decode("ascii")
    if not text:
        return fallback
    return text[:max_len]


def _safe_ascii_label_for_comm(value: object, *, max_len: int = 72) -> str:
    return _safe_node_text(value, max_len=max_len)


def _safe_node_value(value: str) -> str:
    return _safe_node_text(value, max_len=220)


def _as_path(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.replace("\\", "/").strip()


def _normalize_ref(value: object) -> str | None:
    text = _as_path(value)
    if not text:
        return None
    if text.startswith("/"):
        return text.lstrip("/")
    return text


def _sorted_count_pairs(
    counts: dict[str, int],
    *,
    limit: int = 6,
) -> list[tuple[str, int]]:
    ordered = sorted(
        ((k, v) for k, v in counts.items() if k and v > 0),
        key=lambda kv: (-int(kv[1]), kv[0]),
    )
    return ordered[: max(0, limit)]


# ---------------------------------------------------------------------------
# Run directory utilities
# ---------------------------------------------------------------------------


def _looks_like_run_dir(path: Path) -> bool:
    if not path.is_dir():
        return False
    manifest_ok = (path / "manifest.json").is_file()
    report_ok = (path / "report" / "report.json").is_file() or (path / "report" / "viewer.html").is_file()
    return bool(manifest_ok and report_ok)


def _run_dir_mtime(path: Path) -> float:
    candidates = [
        path / "report" / "report.json",
        path / "report" / "analyst_digest.json",
        path / "manifest.json",
        path,
    ]
    for candidate in candidates:
        try:
            if candidate.exists():
                return float(candidate.stat().st_mtime)
        except OSError:
            continue
    return 0.0


def _discover_latest_run_dir(*, cwd: Path) -> Path | None:
    env_roots_raw = os.environ.get("AIEDGE_RUNS_DIRS", "").strip()
    env_roots = [x for x in env_roots_raw.split(os.pathsep) if x] if env_roots_raw else []
    roots: list[Path] = [Path(x).expanduser() for x in env_roots]
    roots.extend(
        [
            cwd / "aiedge-runs",
            cwd / "aiedge-8mb-runs",
            cwd,
        ]
    )

    seen_roots: set[str] = set()
    discovered: list[Path] = []
    for root in roots:
        try:
            root_resolved = root.resolve()
        except Exception:
            root_resolved = root
        root_key = str(root_resolved)
        if root_key in seen_roots:
            continue
        seen_roots.add(root_key)

        if not root_resolved.is_dir():
            continue

        if _looks_like_run_dir(root_resolved):
            discovered.append(root_resolved)

        try:
            children = list(root_resolved.iterdir())
        except OSError:
            continue

        for child in children:
            if not child.is_dir():
                continue
            if _looks_like_run_dir(child):
                discovered.append(child)

    if not discovered:
        return None

    discovered.sort(
        key=lambda p: (_run_dir_mtime(p), str(p)),
        reverse=True,
    )
    return discovered[0]


def _resolve_tui_run_dir(raw: str | None) -> Path | None:
    token = (raw or "").strip()
    if token == ".":
        cwd = Path.cwd().resolve()
        if _looks_like_run_dir(cwd):
            return cwd
    latest_tokens = {"", "latest", "@latest"}
    if token not in latest_tokens:
        return Path(token).expanduser().resolve()
    return _discover_latest_run_dir(cwd=Path.cwd())


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_manifest_track_marker(manifest_path: Path) -> None:
    obj_any = cast(object, json.loads(manifest_path.read_text(encoding="utf-8")))
    if not isinstance(obj_any, dict):
        raise ValueError("manifest.json is not an object")
    obj = cast(dict[str, object], obj_any)
    obj["track"] = {
        "track_id": "8mb",
        "canonical_sha256_prefix": _CANONICAL_8MB_SHA256[:12],
        "canonical_size_bytes": _CANONICAL_8MB_SIZE_BYTES,
    }
    _ = manifest_path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _write_manifest_profile_marker(
    manifest_path: Path,
    *,
    profile: str,
    exploit_gate: dict[str, str] | None,
) -> None:
    obj_any = cast(object, json.loads(manifest_path.read_text(encoding="utf-8")))
    if not isinstance(obj_any, dict):
        raise ValueError("manifest.json is not an object")
    obj = cast(dict[str, object], obj_any)
    obj["profile"] = profile
    if exploit_gate is not None:
        obj["exploit_gate"] = dict(exploit_gate)
    _ = manifest_path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _write_manifest_rootfs_marker(
    manifest_path: Path,
    *,
    rootfs_path: Path | None,
) -> None:
    obj_any = cast(object, json.loads(manifest_path.read_text(encoding="utf-8")))
    if not isinstance(obj_any, dict):
        raise ValueError("manifest.json is not an object")
    obj = cast(dict[str, object], obj_any)
    if rootfs_path is None:
        obj.pop("rootfs_input_path", None)
    else:
        obj["rootfs_input_path"] = str(rootfs_path.resolve())
    _ = manifest_path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _write_manifest_scan_limits_marker(
    manifest_path: Path,
    *,
    max_files: int | None,
    max_matches: int | None,
) -> None:
    obj_any = cast(object, json.loads(manifest_path.read_text(encoding="utf-8")))
    if not isinstance(obj_any, dict):
        raise ValueError("manifest.json is not an object")
    obj = cast(dict[str, object], obj_any)

    if max_files is None and max_matches is None:
        obj.pop("scan_limits", None)
    else:
        scan_limits: dict[str, int] = {}
        if isinstance(max_files, int) and max_files > 0:
            scan_limits["max_files"] = int(max_files)
        if isinstance(max_matches, int) and max_matches > 0:
            scan_limits["max_matches"] = int(max_matches)
        if scan_limits:
            obj["scan_limits"] = scan_limits
        else:
            obj.pop("scan_limits", None)

    _ = manifest_path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
