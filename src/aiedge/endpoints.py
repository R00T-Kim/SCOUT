from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit, urlunsplit

from .confidence_caps import calibrated_confidence, evidence_level
from .policy import AIEdgePolicyViolation
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus


DEFAULT_MAX_FILES = 2000
DEFAULT_MAX_BYTES_PER_FILE = 256 * 1024
DEFAULT_MAX_TOTAL_MATCHES = 5000
MAX_VALUE_CHARS = 200
_DOMAIN_NOISE_TLDS: frozenset[str] = frozenset({"ko", "runtime"})

_ENDPOINT_PATTERN_SPECS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    (
        "url",
        re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE),
        0.85,
    ),
    (
        "domain",
        re.compile(
            r"\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\b",
            re.IGNORECASE,
        ),
        0.65,
    ),
    (
        "ipv4",
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        0.7,
    ),
    (
        "email",
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
        0.6,
    ),
)


def _assert_under_dir(base_dir: Path, target: Path) -> None:
    base = base_dir.resolve()
    resolved = target.resolve()
    if not resolved.is_relative_to(base):
        raise AIEdgePolicyViolation(
            f"Refusing to write outside run dir: target={resolved} base={base}"
        )


def _rel_to_run_dir(run_dir: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(run_dir.resolve()))
    except Exception:
        return str(path)


def _clamp01(v: float) -> float:
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return float(v)


def _load_inventory_roots(
    run_dir: Path,
) -> tuple[list[Path], list[str], bool, Path | None]:
    inv_path = run_dir / "stages" / "inventory" / "inventory.json"
    if not inv_path.is_file():
        return (
            [],
            ["Inventory output missing: stages/inventory/inventory.json"],
            False,
            None,
        )

    try:
        inv_any = cast(object, json.loads(inv_path.read_text(encoding="utf-8")))
    except Exception as exc:
        return (
            [],
            [f"Inventory output unreadable: {type(exc).__name__}: {exc}"],
            True,
            inv_path,
        )
    if not isinstance(inv_any, dict):
        return (
            [],
            ["Inventory output shape invalid; expected JSON object"],
            True,
            inv_path,
        )

    inv = cast(dict[str, object], inv_any)
    roots_any = inv.get("roots")
    roots: list[Path] = []
    limits: list[str] = []
    if isinstance(roots_any, list):
        for item in cast(list[object], roots_any):
            if not isinstance(item, str) or not item or item.startswith("/"):
                continue
            p = (run_dir / item).resolve()
            if not p.is_relative_to(run_dir.resolve()):
                continue
            if p.is_dir():
                roots.append(p)

    extracted_dir: Path | None = None
    ext_any = inv.get("extracted_dir")
    if isinstance(ext_any, str) and ext_any and not ext_any.startswith("/"):
        extracted_dir_candidate = (run_dir / ext_any).resolve()
        if extracted_dir_candidate.is_relative_to(run_dir.resolve()):
            extracted_dir = extracted_dir_candidate

    if not roots:
        if isinstance(extracted_dir, Path) and extracted_dir.is_dir():
            roots.append(extracted_dir)
            limits.append(
                "Inventory roots unavailable; endpoints fell back to inventory extracted_dir"
            )
        else:
            limits.append("Inventory roots unavailable for endpoint extraction")

    unique_roots: list[Path] = []
    seen: set[str] = set()
    for root in sorted(roots, key=lambda p: str(p)):
        key = str(root.resolve())
        if key in seen:
            continue
        seen.add(key)
        unique_roots.append(root)

    return unique_roots, limits, True, inv_path


def _is_forbidden_relative_path(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/")
    parts = [part for part in norm.split("/") if part]
    if "proc" in parts or "sys" in parts:
        return True
    if norm.endswith("/etc/shadow") or norm == "etc/shadow":
        return True
    return False


def _iter_candidate_files(
    roots: list[Path], *, run_dir: Path, max_files: int
) -> tuple[list[Path], bool]:
    out: list[Path] = []
    seen: set[str] = set()
    stack = sorted(roots, key=lambda p: str(p), reverse=True)
    truncated = False

    while stack and len(out) < max_files:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = sorted(list(it), key=lambda e: e.name)
        except OSError:
            continue

        child_dirs: list[Path] = []
        for entry in entries:
            p = Path(entry.path)
            rel = _rel_to_run_dir(run_dir, p)
            if _is_forbidden_relative_path(rel):
                continue

            try:
                if entry.is_dir(follow_symlinks=False):
                    child_dirs.append(p)
                    continue
            except OSError:
                continue

            try:
                if not entry.is_file(follow_symlinks=True):
                    continue
            except OSError:
                continue

            key = str(p.resolve())
            if key in seen:
                continue
            seen.add(key)
            out.append(p)
            if len(out) >= max_files:
                truncated = True
                break

        stack.extend(reversed(child_dirs))

    return out, truncated


def _is_text_candidate(raw: bytes) -> bool:
    return b"\x00" not in raw[:2048]


def _sanitize_url(raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        return ""
    parsed = urlsplit(value)
    netloc = parsed.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    cleaned = urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path, parsed.query, parsed.fragment)
    )
    return cleaned[:MAX_VALUE_CHARS]


def _normalize_endpoint_value(endpoint_type: str, raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        return ""

    if endpoint_type == "url":
        return _sanitize_url(value)

    if endpoint_type == "domain":
        normalized = value.lower().rstrip(".")[:MAX_VALUE_CHARS]
        labels = [label for label in normalized.split(".") if label]
        if len(labels) < 2:
            return ""
        if labels[-1] in _DOMAIN_NOISE_TLDS:
            return ""
        return normalized

    if endpoint_type == "email":
        return value.lower()[:MAX_VALUE_CHARS]

    if endpoint_type == "ipv4":
        parts = value.split(".")
        if len(parts) != 4:
            return ""
        try:
            nums = [int(part) for part in parts]
        except ValueError:
            return ""
        if any(num < 0 or num > 255 for num in nums):
            return ""
        return value[:MAX_VALUE_CHARS]

    return value[:MAX_VALUE_CHARS]


def _empty_summary() -> dict[str, JsonValue]:
    return {
        "roots_scanned": 0,
        "files_scanned": 0,
        "endpoints": 0,
        "matches_seen": 0,
        "classification": "candidate",
        "observation": "static_reference",
    }


@dataclass(frozen=True)
class EndpointsStage:
    max_files: int = DEFAULT_MAX_FILES
    max_bytes_per_file: int = DEFAULT_MAX_BYTES_PER_FILE
    max_total_matches: int = DEFAULT_MAX_TOTAL_MATCHES

    @property
    def name(self) -> str:
        return "endpoints"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "endpoints"
        out_json = stage_dir / "endpoints.json"

        _assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(stage_dir, out_json)

        roots, limits, inventory_present, inventory_path = _load_inventory_roots(
            run_dir
        )

        endpoints_map: dict[tuple[str, str], set[str]] = {}
        total_matches = 0
        files_scanned = 0
        hit_max_total_matches = False
        hit_max_files = False

        if roots:
            files, hit_max_files = _iter_candidate_files(
                roots,
                run_dir=run_dir,
                max_files=int(self.max_files),
            )
            for p in files:
                rel = _rel_to_run_dir(run_dir, p).replace("\\", "/")
                if _is_forbidden_relative_path(rel):
                    continue

                try:
                    raw = p.read_bytes()
                except OSError:
                    continue
                if not raw:
                    continue
                raw = raw[: int(self.max_bytes_per_file)]
                if not _is_text_candidate(raw):
                    continue

                try:
                    text = raw.decode("utf-8", errors="ignore")
                except Exception:
                    continue
                files_scanned += 1

                for endpoint_type, pattern, _confidence in _ENDPOINT_PATTERN_SPECS:
                    for match in pattern.finditer(text):
                        if total_matches >= int(self.max_total_matches):
                            hit_max_total_matches = True
                            break
                        value = _normalize_endpoint_value(endpoint_type, match.group(0))
                        if not value:
                            continue
                        key = (endpoint_type, value)
                        refs = endpoints_map.setdefault(key, set())
                        refs.add(rel)
                        total_matches += 1
                    if hit_max_total_matches:
                        break
                if hit_max_total_matches:
                    break

        endpoints: list[dict[str, JsonValue]] = []
        confidence_map = {k: conf for k, _pat, conf in _ENDPOINT_PATTERN_SPECS}
        for endpoint_type, value in sorted(
            endpoints_map.keys(), key=lambda x: (x[0], x[1])
        ):
            refs = sorted(endpoints_map[(endpoint_type, value)])
            if not refs:
                continue
            confidence = _clamp01(float(confidence_map.get(endpoint_type, 0.5)))
            observation = "static_reference"
            endpoints.append(
                {
                    "type": endpoint_type,
                    "value": value,
                    "confidence": confidence,
                    "confidence_calibrated": calibrated_confidence(
                        confidence=confidence,
                        observation=observation,
                        evidence_refs=refs,
                    ),
                    "classification": "candidate",
                    "observation": observation,
                    "evidence_level": evidence_level(observation, refs),
                    "evidence_refs": cast(list[JsonValue], cast(list[object], refs)),
                }
            )

        summary: dict[str, JsonValue] = {
            "roots_scanned": len(roots),
            "files_scanned": files_scanned,
            "endpoints": len(endpoints),
            "matches_seen": total_matches,
            "classification": "candidate",
            "observation": "static_reference",
        }

        if hit_max_files:
            limits.append(
                f"Endpoint scan reached max_files cap ({int(self.max_files)}); remaining files were skipped"
            )
        if hit_max_total_matches:
            limits.append(
                f"Endpoint scan reached max_total_matches cap ({int(self.max_total_matches)}); additional matches were skipped"
            )
        if not inventory_present:
            limits.append(
                "Endpoints used degraded mode because inventory stage output is missing"
            )

        status: StageStatus = "ok"
        if not roots:
            status = "partial"
            summary = _empty_summary()

        payload: dict[str, JsonValue] = {
            "status": status,
            "summary": summary,
            "endpoints": cast(list[JsonValue], cast(list[object], endpoints)),
            "limitations": cast(
                list[JsonValue], cast(list[object], sorted(set(limits)))
            ),
            "note": "Static candidate endpoint references only; no observed runtime connections.",
        }
        _ = out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        evidence_list: list[dict[str, JsonValue]] = []
        evidence_list.append({"path": _rel_to_run_dir(run_dir, out_json)})
        if inventory_path is not None:
            evidence_list.append({"path": _rel_to_run_dir(run_dir, inventory_path)})

        details: dict[str, JsonValue] = {
            "summary": summary,
            "endpoints": cast(list[JsonValue], cast(list[object], endpoints)),
            "evidence": cast(list[JsonValue], cast(list[object], evidence_list)),
            "endpoints_json": _rel_to_run_dir(run_dir, out_json),
            "classification": "candidate",
            "observation": "static_reference",
        }

        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limits)),
        )
