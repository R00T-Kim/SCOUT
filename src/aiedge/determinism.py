from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast


Json = object


_VOLATILE_KEYS = {
    "created_at",
    "run_id",
    "started_at",
    "finished_at",
    "duration_s",
}


_ALLOW_MISMATCH_KEYS = {
    "stages/extraction/stage.json",
    "stages/emulation/stage.json",
}

_ALLOW_MISMATCH_PATHS = {
    "report/report.json/extraction/summary/extraction_timeout_s",
    "stages/extraction/stage.json/params/timeout_s",
    "stages/extraction/stage.json/stage_key",
}

_ALLOW_MISMATCH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^stages/extraction/stage\.json/artifacts/\d+/sha256$"),
    re.compile(r"^stages/emulation/stage\.json/artifacts/\d+/sha256$"),
    re.compile(r"^stages/carving/stage\.json/artifacts/\d+/sha256$"),
)


def _canonical_dumps(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _normalize_json(value: object) -> object:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        return float(round(value, 6))
    if isinstance(value, list):
        return [_normalize_json(v) for v in cast(list[object], value)]
    if isinstance(value, dict):
        obj = cast(dict[object, object], value)
        out: dict[str, object] = {}
        for k_any, v_any in obj.items():
            k = str(k_any)
            if k in _VOLATILE_KEYS:
                continue
            out[k] = _normalize_json(v_any)
        return out
    return str(value)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _path_allowlisted(path: str) -> bool:
    if path in _ALLOW_MISMATCH_PATHS:
        return True
    return any(pat.match(path) for pat in _ALLOW_MISMATCH_PATTERNS)


def _collect_diff_paths(left: object, right: object, prefix: str = "") -> list[str]:
    if type(left) is not type(right):
        return [prefix or "$"]

    if isinstance(left, dict):
        left_obj = cast(dict[object, object], left)
        right_obj = cast(dict[object, object], right)
        left_map = {str(k): v for k, v in left_obj.items()}
        right_map = {str(k): v for k, v in right_obj.items()}
        left_keys = set(left_map.keys())
        right_keys = set(right_map.keys())
        diff_paths: list[str] = []
        for k in sorted(left_keys | right_keys):
            child = f"{prefix}/{k}" if prefix else k
            if k not in left_keys or k not in right_keys:
                diff_paths.append(child)
                continue
            diff_paths.extend(_collect_diff_paths(left_map[k], right_map[k], child))
        return diff_paths

    if isinstance(left, list):
        left_list = cast(list[object], left)
        right_list = cast(list[object], right)
        out: list[str] = []
        if len(left_list) != len(right_list):
            out.append(f"{prefix}/length" if prefix else "length")
        for idx, (l_item, r_item) in enumerate(zip(left_list, right_list)):
            child = f"{prefix}/{idx}" if prefix else str(idx)
            out.extend(_collect_diff_paths(l_item, r_item, child))
        return out

    if left != right:
        return [prefix or "$"]
    return []


@dataclass(frozen=True)
class DeterminismBundle:
    items: dict[str, object]
    digest_sha256: str


def collect_run_bundle(run_dir: Path) -> DeterminismBundle:
    items: dict[str, object] = {}

    manifest_path = run_dir / "manifest.json"
    report_path = run_dir / "report" / "report.json"
    stages_dir = run_dir / "stages"

    for path in (manifest_path, report_path):
        if path.is_file():
            rel = path.relative_to(run_dir).as_posix()
            parsed = cast(object, json.loads(path.read_text(encoding="utf-8")))
            items[rel] = _normalize_json(parsed)

    if stages_dir.is_dir():
        for stage_dir in sorted(p for p in stages_dir.iterdir() if p.is_dir()):
            stage_json = stage_dir / "stage.json"
            if not stage_json.is_file():
                continue
            rel = stage_json.relative_to(run_dir).as_posix()
            parsed = cast(object, json.loads(stage_json.read_text(encoding="utf-8")))
            items[rel] = _normalize_json(parsed)

    canonical = _canonical_dumps(items)
    digest = _sha256_text(canonical)
    return DeterminismBundle(items=items, digest_sha256=digest)


def assert_bundles_equal(left: DeterminismBundle, right: DeterminismBundle) -> None:
    if left.digest_sha256 == right.digest_sha256:
        return

    left_keys = set(left.items.keys())
    right_keys = set(right.items.keys())
    missing_left = sorted(right_keys - left_keys)
    missing_right = sorted(left_keys - right_keys)
    mismatched: list[str] = []
    for k in sorted(left_keys & right_keys):
        if _canonical_dumps(left.items[k]) != _canonical_dumps(right.items[k]):
            mismatched.append(k)

    diff_paths: list[str] = []
    for k in mismatched:
        diff_paths.extend(_collect_diff_paths(left.items[k], right.items[k], k))

    parts: list[str] = [
        "determinism bundle mismatch",
        f"left_digest={left.digest_sha256}",
        f"right_digest={right.digest_sha256}",
    ]
    if missing_left:
        parts.append("missing_in_left=" + ",".join(missing_left))
    if missing_right:
        parts.append("missing_in_right=" + ",".join(missing_right))
    if mismatched:
        parts.append("mismatched=" + ",".join(mismatched[:10]))
    if diff_paths:
        parts.append("diff_paths=" + ",".join(diff_paths[:20]))

    # Allowlist-based relaxation: determinism gate allows known noisy fields.
    if (
        not missing_left
        and not missing_right
        and mismatched
        and all(k in _ALLOW_MISMATCH_KEYS for k in mismatched)
    ):
        return

    if (
        not missing_left
        and not missing_right
        and diff_paths
        and all(_path_allowlisted(path) for path in diff_paths)
    ):
        return

    raise AssertionError("; ".join(parts))
