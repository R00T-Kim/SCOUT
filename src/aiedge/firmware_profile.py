from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from .schema import JsonValue
from .stage import StageContext, StageOutcome

OsTypeGuess = Literal["linux_fs", "rtos_monolithic", "unextractable_or_unknown"]
InventoryMode = Literal["filesystem", "binary_only"]
EmulationFeasibility = Literal["high", "medium", "low", "unknown"]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_relative(path: Path, run_dir: Path) -> str | None:
    try:
        rel = path.resolve().relative_to(run_dir.resolve())
    except ValueError:
        return None
    return rel.as_posix()


def _iter_dirs_sorted(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    out: list[Path] = [root]
    queue: list[Path] = [root]
    while queue:
        current = queue.pop(0)
        try:
            with os.scandir(current) as it:
                entries = sorted(list(it), key=lambda e: e.name)
        except OSError:
            continue

        child_dirs: list[Path] = []
        for entry in entries:
            try:
                if not entry.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            child = Path(entry.path)
            child_dirs.append(child)
            out.append(child)
        queue.extend(child_dirs)
    return out


def _looks_like_rootfs(path: Path) -> bool:
    if not path.is_dir():
        return False
    etc_dir = path / "etc"
    if not etc_dir.is_dir():
        return False
    return (path / "bin").is_dir() or (path / "usr").is_dir()


def _find_rootfs_candidates(extracted_dir: Path, run_dir: Path) -> list[str]:
    candidates: list[str] = []
    for directory in _iter_dirs_sorted(extracted_dir):
        if not _looks_like_rootfs(directory):
            continue
        rel = _run_relative(directory, run_dir)
        if rel is not None and rel not in candidates:
            candidates.append(rel)
    return sorted(candidates)


def _extract_sdk_hints(extracted_dir: Path) -> list[str]:
    hints: list[str] = []
    checks: list[tuple[str, Path]] = [
        ("openwrt", extracted_dir / "etc" / "openwrt_release"),
        ("busybox", extracted_dir / "bin" / "busybox"),
        ("buildroot", extracted_dir / "etc" / "init.d" / "rcS"),
    ]
    for hint, marker in checks:
        if marker.exists() and hint not in hints:
            hints.append(hint)
    return sorted(hints)


@dataclass(frozen=True)
class FirmwareProfileStage:
    @property
    def name(self) -> str:
        return "firmware_profile"

    def run(self, ctx: StageContext) -> StageOutcome:
        stage_dir = ctx.run_dir / "stages" / "firmware_profile"
        stage_dir.mkdir(parents=True, exist_ok=True)
        out_path = stage_dir / "firmware_profile.json"

        firmware_path = ctx.run_dir / "input" / "firmware.bin"
        extraction_dir = (
            ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted"
        )
        binwalk_log = ctx.run_dir / "stages" / "extraction" / "binwalk.log"
        carving_roots = ctx.run_dir / "stages" / "carving" / "roots.json"
        carving_partitions = ctx.run_dir / "stages" / "carving" / "partitions.json"

        evidence_refs: list[str] = []
        for candidate in [
            binwalk_log,
            extraction_dir,
            carving_roots,
            carving_partitions,
        ]:
            if not candidate.exists():
                continue
            rel = _run_relative(candidate, ctx.run_dir)
            if rel is not None and rel not in evidence_refs:
                evidence_refs.append(rel)

        rootfs_candidates = _find_rootfs_candidates(extraction_dir, ctx.run_dir)
        sdk_hints = _extract_sdk_hints(extraction_dir)

        limitations: list[str] = []
        if not extraction_dir.exists():
            limitations.append(
                "Extraction directory is missing; rootfs classification may be incomplete."
            )
        elif not rootfs_candidates:
            limitations.append(
                "No plausible extracted rootfs candidate found (requires etc/ and bin/ or usr/)."
            )

        firmware_id = "firmware:unknown"
        if firmware_path.is_file():
            firmware_id = f"firmware:{_sha256_file(firmware_path)}"
        else:
            limitations.append(
                "input/firmware.bin is missing; profile confidence is reduced."
            )

        os_type_guess: OsTypeGuess
        inventory_mode: InventoryMode
        why: str
        emulation_feasibility: EmulationFeasibility

        if rootfs_candidates:
            os_type_guess = "linux_fs"
            inventory_mode = "filesystem"
            emulation_feasibility = "high"
            why = (
                "Found extracted rootfs candidate(s) containing etc/ and bin/ or usr/."
            )
        elif firmware_path.is_file():
            os_type_guess = "rtos_monolithic"
            inventory_mode = "binary_only"
            emulation_feasibility = "medium"
            why = "No extracted rootfs candidates; firmware blob is present, so treat as monolithic/binary-first."
        else:
            os_type_guess = "unextractable_or_unknown"
            inventory_mode = "binary_only"
            emulation_feasibility = "unknown"
            why = "Insufficient extraction and firmware evidence for confident OS classification."

        profile: dict[str, JsonValue] = {
            "branch_plan": {
                "inventory_mode": inventory_mode,
                "why": why,
            },
            "emulation_feasibility": emulation_feasibility,
            "evidence_refs": cast(
                list[JsonValue], cast(list[object], sorted(evidence_refs))
            ),
            "firmware_id": firmware_id,
            "limitations": cast(
                list[JsonValue], cast(list[object], sorted(set(limitations)))
            ),
            "os_type_guess": os_type_guess,
            "schema_version": 1,
            "sdk_hints": cast(list[JsonValue], cast(list[object], sdk_hints)),
        }
        _ = out_path.write_text(
            json.dumps(profile, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        details: dict[str, JsonValue] = dict(profile)
        out_rel = _run_relative(out_path, ctx.run_dir)
        if out_rel is not None:
            details["profile_path"] = out_rel

        status = "ok" if firmware_path.is_file() else "partial"
        return StageOutcome(
            status=status,
            details=details,
            limitations=cast(list[str], profile["limitations"]),
        )
