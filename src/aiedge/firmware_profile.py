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
        return rel.as_posix()
    except (OSError, RuntimeError, ValueError):
        pass
    try:
        rel = path.relative_to(run_dir)
    except ValueError:
        return None
    return rel.as_posix()


def _sanitize_os_error(exc: OSError) -> str:
    kind = exc.__class__.__name__
    detail = exc.strerror or "OS error"
    return f"{kind}: {detail}"


def _record_probe_error(
    *,
    errors: list[dict[str, JsonValue]],
    limitations: list[str],
    run_dir: Path,
    path: Path,
    op: str,
    exc: OSError,
) -> None:
    rel = _run_relative(path, run_dir) or "<outside_run_dir>"
    err: dict[str, JsonValue] = {
        "error": _sanitize_os_error(exc),
        "op": op,
        "path": rel,
    }
    if exc.errno is not None:
        err["errno"] = exc.errno
    errors.append(err)
    limitations.append(
        f"Probe failed at {rel} ({op}); best-effort classification applied."
    )


def _probe_is_dir(
    path: Path,
    *,
    run_dir: Path,
    errors: list[dict[str, JsonValue]],
    limitations: list[str],
    op: str,
) -> bool:
    try:
        return path.is_dir()
    except OSError as exc:
        _record_probe_error(
            errors=errors,
            limitations=limitations,
            run_dir=run_dir,
            path=path,
            op=op,
            exc=exc,
        )
        return False


def _probe_is_file(
    path: Path,
    *,
    run_dir: Path,
    errors: list[dict[str, JsonValue]],
    limitations: list[str],
    op: str,
) -> bool:
    try:
        return path.is_file()
    except OSError as exc:
        _record_probe_error(
            errors=errors,
            limitations=limitations,
            run_dir=run_dir,
            path=path,
            op=op,
            exc=exc,
        )
        return False


def _probe_exists(
    path: Path,
    *,
    run_dir: Path,
    errors: list[dict[str, JsonValue]],
    limitations: list[str],
    op: str,
) -> bool:
    try:
        return path.exists()
    except OSError as exc:
        _record_probe_error(
            errors=errors,
            limitations=limitations,
            run_dir=run_dir,
            path=path,
            op=op,
            exc=exc,
        )
        return False


def _sorted_unique_errors(
    errors: list[dict[str, JsonValue]],
) -> list[dict[str, JsonValue]]:
    deduped: dict[tuple[str, str, int | None, str], dict[str, JsonValue]] = {}
    for err in errors:
        op = str(err.get("op", ""))
        path = str(err.get("path", ""))
        errno_raw = err.get("errno")
        errno = int(errno_raw) if isinstance(errno_raw, int) else None
        error = str(err.get("error", ""))
        key = (op, path, errno, error)
        if key not in deduped:
            deduped[key] = err
    return [
        deduped[key]
        for key in sorted(
            deduped.keys(), key=lambda item: (item[0], item[1], item[2] or -1, item[3])
        )
    ]


def _iter_dirs_sorted(
    root: Path,
    *,
    run_dir: Path,
    errors: list[dict[str, JsonValue]],
    limitations: list[str],
) -> list[Path]:
    if not _probe_is_dir(
        root,
        run_dir=run_dir,
        errors=errors,
        limitations=limitations,
        op="rootfs_probe.root_is_dir",
    ):
        return []
    out: list[Path] = [root]
    queue: list[Path] = [root]
    while queue:
        current = queue.pop(0)
        try:
            with os.scandir(current) as it:
                entries = sorted(list(it), key=lambda e: e.name)
        except OSError as exc:
            _record_probe_error(
                errors=errors,
                limitations=limitations,
                run_dir=run_dir,
                path=current,
                op="rootfs_probe.listdir",
                exc=exc,
            )
            continue

        child_dirs: list[Path] = []
        for entry in entries:
            try:
                if not entry.is_dir(follow_symlinks=False):
                    continue
            except OSError as exc:
                _record_probe_error(
                    errors=errors,
                    limitations=limitations,
                    run_dir=run_dir,
                    path=current / entry.name,
                    op="rootfs_probe.entry_is_dir",
                    exc=exc,
                )
                continue
            child = Path(entry.path)
            child_dirs.append(child)
            out.append(child)
        queue.extend(child_dirs)
    return out


def _looks_like_rootfs(
    path: Path,
    *,
    run_dir: Path,
    errors: list[dict[str, JsonValue]],
    limitations: list[str],
) -> bool:
    if not _probe_is_dir(
        path,
        run_dir=run_dir,
        errors=errors,
        limitations=limitations,
        op="rootfs_probe.candidate_is_dir",
    ):
        return False
    etc_dir = path / "etc"
    if not _probe_is_dir(
        etc_dir,
        run_dir=run_dir,
        errors=errors,
        limitations=limitations,
        op="rootfs_probe.etc_is_dir",
    ):
        return False
    return _probe_is_dir(
        path / "bin",
        run_dir=run_dir,
        errors=errors,
        limitations=limitations,
        op="rootfs_probe.bin_is_dir",
    ) or _probe_is_dir(
        path / "usr",
        run_dir=run_dir,
        errors=errors,
        limitations=limitations,
        op="rootfs_probe.usr_is_dir",
    )


def _find_rootfs_candidates(
    extracted_dir: Path,
    run_dir: Path,
    *,
    errors: list[dict[str, JsonValue]],
    limitations: list[str],
) -> list[str]:
    candidates: list[str] = []
    for directory in _iter_dirs_sorted(
        extracted_dir,
        run_dir=run_dir,
        errors=errors,
        limitations=limitations,
    ):
        if not _looks_like_rootfs(
            directory,
            run_dir=run_dir,
            errors=errors,
            limitations=limitations,
        ):
            continue
        rel = _run_relative(directory, run_dir)
        if rel is not None and rel not in candidates:
            candidates.append(rel)
    return sorted(candidates)


def _extract_sdk_hints(
    extracted_dir: Path,
    *,
    run_dir: Path,
    errors: list[dict[str, JsonValue]],
    limitations: list[str],
) -> list[str]:
    hints: list[str] = []
    checks: list[tuple[str, Path]] = [
        ("openwrt", extracted_dir / "etc" / "openwrt_release"),
        ("busybox", extracted_dir / "bin" / "busybox"),
        ("buildroot", extracted_dir / "etc" / "init.d" / "rcS"),
    ]
    for hint, marker in checks:
        if (
            _probe_exists(
                marker,
                run_dir=run_dir,
                errors=errors,
                limitations=limitations,
                op="sdk_probe.exists",
            )
            and hint not in hints
        ):
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

        limitations: list[str] = []
        errors: list[dict[str, JsonValue]] = []

        evidence_refs: list[str] = []
        for candidate in [
            binwalk_log,
            extraction_dir,
            carving_roots,
            carving_partitions,
        ]:
            if not _probe_exists(
                candidate,
                run_dir=ctx.run_dir,
                errors=errors,
                limitations=limitations,
                op="evidence_probe.exists",
            ):
                continue
            rel = _run_relative(candidate, ctx.run_dir)
            if rel is not None and rel not in evidence_refs:
                evidence_refs.append(rel)

        rootfs_candidates = _find_rootfs_candidates(
            extraction_dir,
            ctx.run_dir,
            errors=errors,
            limitations=limitations,
        )
        sdk_hints = _extract_sdk_hints(
            extraction_dir,
            run_dir=ctx.run_dir,
            errors=errors,
            limitations=limitations,
        )

        if not _probe_exists(
            extraction_dir,
            run_dir=ctx.run_dir,
            errors=errors,
            limitations=limitations,
            op="extraction_probe.exists",
        ):
            limitations.append(
                "Extraction directory is missing; rootfs classification may be incomplete."
            )
        elif not rootfs_candidates:
            limitations.append(
                "No plausible extracted rootfs candidate found (requires etc/ and bin/ or usr/)."
            )

        firmware_id = "firmware:unknown"
        firmware_is_file = _probe_is_file(
            firmware_path,
            run_dir=ctx.run_dir,
            errors=errors,
            limitations=limitations,
            op="firmware_probe.is_file",
        )
        if firmware_is_file:
            try:
                firmware_id = f"firmware:{_sha256_file(firmware_path)}"
            except OSError as exc:
                _record_probe_error(
                    errors=errors,
                    limitations=limitations,
                    run_dir=ctx.run_dir,
                    path=firmware_path,
                    op="firmware_probe.read",
                    exc=exc,
                )
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
        elif firmware_is_file:
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
            "errors": cast(
                list[JsonValue],
                cast(list[object], _sorted_unique_errors(errors)),
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

        status = "ok" if firmware_is_file else "partial"
        return StageOutcome(
            status=status,
            details=details,
            limitations=cast(list[str], profile["limitations"]),
        )
