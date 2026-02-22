from __future__ import annotations

import bz2
import gzip
import os
import shutil
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .policy import AIEdgePolicyViolation
from .schema import JsonValue
from .stage import StageContext, StageOutcome

_UBI_MAGIC = b"UBI#"
_SQUASHFS_MAGICS = (b"hsqs", b"sqsh")
_CPIO_MAGICS = (b"070701", b"070702", b"070707")
_GZIP_MAGIC = b"\x1f\x8b"
_BZIP_MAGIC = b"BZh"
_ARCHIVE_EXTRACT_MAX_DEPTH = 6


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


def _evidence_path(
    run_dir: Path, path: Path, *, note: str | None = None
) -> dict[str, JsonValue]:
    ev: dict[str, JsonValue] = {"path": _rel_to_run_dir(run_dir, path)}
    if note:
        ev["note"] = note
    return ev


def _count_files(root: Path) -> int:
    if not root.exists():
        return 0
    n = 0
    for p in root.rglob("*"):
        if p.is_file():
            n += 1
    return n


def _append_log(log_path: Path, line: str) -> None:
    try:
        with log_path.open("a", encoding="utf-8") as f:
            _ = f.write(line)
            if not line.endswith("\n"):
                _ = f.write("\n")
    except Exception:
        return


def _read_head(path: Path, size: int = 4) -> bytes:
    try:
        with path.open("rb") as f:
            return f.read(int(max(1, size)))
    except Exception:
        return b""


def _read_at(path: Path, offset: int, size: int) -> bytes:
    if offset < 0 or size <= 0:
        return b""
    try:
        with path.open("rb") as f:
            _ = f.seek(int(offset), os.SEEK_SET)
            return f.read(int(size))
    except Exception:
        return b""


def _looks_like_tar_archive(path: Path) -> bool:
    marker = _read_at(path, 257, 5)
    return marker == b"ustar"


def _looks_like_ext_filesystem(path: Path) -> bool:
    magic = _read_at(path, 1080, 2)
    return magic == b"\x53\xef"


def _archive_kind(path: Path) -> str | None:
    head = _read_head(path, size=6)
    lower_name = path.name.lower()
    lower_suffixes = "".join(s.lower() for s in path.suffixes)

    if head.startswith(_GZIP_MAGIC):
        return "gzip"
    if head.startswith(_BZIP_MAGIC):
        return "bzip2"
    if head.startswith(_CPIO_MAGICS):
        return "cpio"
    if _looks_like_tar_archive(path):
        return "tar"
    if _looks_like_ext_filesystem(path):
        return "extfs"

    if lower_suffixes.endswith(".tar.gz") or lower_suffixes.endswith(".tgz"):
        return "gzip"
    if lower_suffixes.endswith(".tar.bz2") or lower_suffixes.endswith(".tbz2"):
        return "bzip2"
    if lower_name.endswith(".cpio"):
        return "cpio"
    if lower_name.endswith(".tar"):
        return "tar"
    if lower_name.endswith((".img", ".ext2", ".ext3", ".ext4")):
        return "extfs"
    return None


def _iter_archive_candidates(
    root: Path,
    *,
    max_candidates: int,
    max_file_bytes: int,
) -> list[tuple[Path, str]]:
    out: list[tuple[Path, str]] = []
    if not root.is_dir():
        return out

    skip_parts = {"__recursive_squashfs", "__ubi_recursive", "__recursive_layers"}
    for p in sorted(root.rglob("*")):
        if len(out) >= int(max_candidates):
            break
        if any(part in skip_parts for part in p.parts):
            continue
        if not p.is_file():
            continue
        try:
            size = int(p.stat().st_size)
        except OSError:
            continue
        if size <= 0 or size > int(max_file_bytes):
            continue
        kind = _archive_kind(p)
        if kind is None:
            continue
        out.append((p, kind))

    return out


def _safe_extract_tar(archive_path: Path, out_dir: Path) -> tuple[bool, str]:
    try:
        with tarfile.open(archive_path, mode="r:*") as tf:
            members = tf.getmembers()
            out_dir_resolved = out_dir.resolve()
            safe_members: list[tarfile.TarInfo] = []
            skipped = 0
            for member in members:
                member_path = out_dir / member.name
                try:
                    resolved = member_path.resolve()
                except Exception:
                    skipped += 1
                    continue
                if not resolved.is_relative_to(out_dir_resolved):
                    skipped += 1
                    continue
                safe_members.append(member)

            tf.extractall(path=out_dir, members=safe_members)  # noqa: S202
            if skipped > 0:
                return True, f"tar extracted with {skipped} unsafe path(s) skipped"
            return True, "tar extracted"
    except tarfile.ReadError:
        return False, "tar read error"
    except Exception as exc:
        return False, f"tar extraction failed: {type(exc).__name__}: {exc}"


def _decompressed_output_path(path: Path, kind: str) -> Path:
    lower = path.name.lower()
    if kind == "gzip":
        if lower.endswith(".tar.gz"):
            return path.with_name(path.name[: -len(".tar.gz")] + ".tar")
        if lower.endswith(".tgz"):
            return path.with_name(path.name[: -len(".tgz")] + ".tar")
        if path.suffix.lower() == ".gz":
            return path.with_suffix("")
    if kind == "bzip2":
        if lower.endswith(".tar.bz2"):
            return path.with_name(path.name[: -len(".tar.bz2")] + ".tar")
        if lower.endswith(".tbz2"):
            return path.with_name(path.name[: -len(".tbz2")] + ".tar")
        if path.suffix.lower() == ".bz2":
            return path.with_suffix("")
    return path.with_name(path.name + ".decompressed")


def _decompress_archive(path: Path, out_dir: Path, kind: str) -> tuple[bool, str]:
    out_path = out_dir / _decompressed_output_path(path, kind).name
    try:
        if kind == "gzip":
            with gzip.open(path, "rb") as src, out_path.open("wb") as dst:
                shutil.copyfileobj(src, dst)
        elif kind == "bzip2":
            with bz2.open(path, "rb") as src, out_path.open("wb") as dst:
                shutil.copyfileobj(src, dst)
        else:
            return False, f"unsupported decompressor kind={kind}"
    except Exception as exc:
        return False, f"{kind} decompression failed: {type(exc).__name__}: {exc}"

    if out_path.is_file() and out_path.stat().st_size > 0:
        return True, f"{kind} decompressed to {out_path.name}"
    return False, f"{kind} decompressed output is empty"


def _extract_cpio_archive(
    *,
    archive_path: Path,
    out_dir: Path,
    log_path: Path,
    stage_dir: Path,
    timeout_s: float | None,
) -> tuple[bool, str]:
    cpio = shutil.which("cpio")
    if not cpio:
        return False, "cpio command unavailable"

    argv = [cpio, "-idm", "--no-absolute-filenames", "--quiet"]
    _append_log(log_path, f"recursive cpio argv: {argv}")
    try:
        with archive_path.open("rb") as in_f:
            cp = subprocess.run(
                argv,
                cwd=str(out_dir),
                text=False,
                stdin=in_f,
                capture_output=True,
                check=False,
                timeout=max(30.0, min(float(timeout_s or 0.0), 300.0)),
            )
    except subprocess.TimeoutExpired:
        return False, "cpio extraction timed out"
    except Exception as exc:
        return False, f"cpio extraction failed: {type(exc).__name__}: {exc}"

    _append_log(log_path, f"recursive cpio returncode: {cp.returncode}")
    if cp.stdout:
        _append_log(log_path, "--- recursive cpio stdout (trunc) ---")
        _append_log(log_path, cp.stdout.decode("utf-8", errors="ignore")[:4096])
    if cp.stderr:
        _append_log(log_path, "--- recursive cpio stderr (trunc) ---")
        _append_log(log_path, cp.stderr.decode("utf-8", errors="ignore")[:4096])

    if cp.returncode != 0:
        return False, f"cpio extraction failed (rc={cp.returncode})"
    if _count_files(out_dir) <= 0:
        return False, "cpio extraction produced empty output"
    return True, "cpio extracted"


def _extract_ext_filesystem(
    *,
    image_path: Path,
    out_dir: Path,
    log_path: Path,
    stage_dir: Path,
    timeout_s: float | None,
) -> tuple[bool, str]:
    debugfs = shutil.which("debugfs")
    if not debugfs:
        return False, "debugfs unavailable"

    argv = [debugfs, "-R", f"rdump / {out_dir}", str(image_path)]
    _append_log(log_path, f"recursive debugfs argv: {argv}")
    try:
        cp = subprocess.run(
            argv,
            cwd=str(stage_dir),
            text=True,
            capture_output=True,
            check=False,
            timeout=max(30.0, min(float(timeout_s or 0.0), 300.0)),
        )
    except subprocess.TimeoutExpired:
        return False, "debugfs extraction timed out"
    except Exception as exc:
        return False, f"debugfs extraction failed: {type(exc).__name__}: {exc}"

    _append_log(log_path, f"recursive debugfs returncode: {cp.returncode}")
    if cp.stdout:
        _append_log(log_path, "--- recursive debugfs stdout (trunc) ---")
        _append_log(log_path, cp.stdout[:4096])
    if cp.stderr:
        _append_log(log_path, "--- recursive debugfs stderr (trunc) ---")
        _append_log(log_path, cp.stderr[:4096])

    if cp.returncode != 0:
        return False, f"debugfs extraction failed (rc={cp.returncode})"
    if _count_files(out_dir) <= 0:
        return False, "debugfs extraction produced empty output"
    return True, "ext filesystem extracted"


def _extract_archive_candidate(
    *,
    kind: str,
    candidate: Path,
    out_dir: Path,
    log_path: Path,
    stage_dir: Path,
    timeout_s: float | None,
) -> tuple[bool, str]:
    if kind == "tar":
        return _safe_extract_tar(candidate, out_dir)
    if kind in {"gzip", "bzip2"}:
        return _decompress_archive(candidate, out_dir, kind)
    if kind == "cpio":
        return _extract_cpio_archive(
            archive_path=candidate,
            out_dir=out_dir,
            log_path=log_path,
            stage_dir=stage_dir,
            timeout_s=timeout_s,
        )
    if kind == "extfs":
        return _extract_ext_filesystem(
            image_path=candidate,
            out_dir=out_dir,
            log_path=log_path,
            stage_dir=stage_dir,
            timeout_s=timeout_s,
        )
    return False, f"unsupported archive kind={kind}"


def _recursive_archive_extraction(
    *,
    run_dir: Path,
    stage_dir: Path,
    extracted_dir: Path,
    log_path: Path,
    timeout_s: float | None,
    max_depth: int = _ARCHIVE_EXTRACT_MAX_DEPTH,
) -> tuple[dict[str, JsonValue], list[str], list[dict[str, JsonValue]]]:
    details: dict[str, JsonValue] = {
        "attempted": False,
        "max_depth": int(max_depth),
        "archive_candidate_count": 0,
        "archive_candidates": cast(list[JsonValue], cast(list[object], [])),
        "archive_extract_attempted": 0,
        "archive_extract_ok": 0,
        "archive_extract_by_type": cast(dict[str, JsonValue], {}),
        "cpio_available": bool(shutil.which("cpio")),
        "debugfs_available": bool(shutil.which("debugfs")),
    }
    limitations: list[str] = []
    evidence: list[dict[str, JsonValue]] = []

    if not extracted_dir.is_dir():
        details["reason"] = "missing_extracted_dir"
        return details, limitations, evidence

    details["attempted"] = True
    layer_root = extracted_dir / "__recursive_layers"
    _assert_under_dir(run_dir, layer_root)
    if layer_root.exists():
        shutil.rmtree(layer_root, ignore_errors=True)
    layer_root.mkdir(parents=True, exist_ok=True)

    queue: list[tuple[Path, int]] = [(extracted_dir, 0)]
    seen_candidates: set[str] = set()
    candidate_refs: list[str] = []
    by_type: dict[str, int] = {}
    attempted = 0
    ok = 0
    layer_index = 0
    max_depth_seen = 0

    while queue:
        current_root, depth = queue.pop(0)
        max_depth_seen = max(max_depth_seen, depth)
        if depth >= int(max_depth):
            continue

        candidates = _iter_archive_candidates(
            current_root,
            max_candidates=24,
            max_file_bytes=4 * 1024 * 1024 * 1024,
        )
        for candidate, kind in candidates:
            key = str(candidate.resolve())
            if key in seen_candidates:
                continue
            seen_candidates.add(key)
            candidate_refs.append(f"{_rel_to_run_dir(run_dir, candidate)}::{kind}")
            attempted += 1
            by_type[kind] = int(by_type.get(kind, 0) + 1)

            layer_index += 1
            out_dir = layer_root / f"layer_{layer_index:03d}_{kind}"
            _assert_under_dir(run_dir, out_dir)
            out_dir.mkdir(parents=True, exist_ok=True)

            ok_extract, reason = _extract_archive_candidate(
                kind=kind,
                candidate=candidate,
                out_dir=out_dir,
                log_path=log_path,
                stage_dir=stage_dir,
                timeout_s=timeout_s,
            )
            if not ok_extract:
                limitations.append(
                    f"recursive {kind} extraction failed for {_rel_to_run_dir(run_dir, candidate)}: {reason}"
                )
                shutil.rmtree(out_dir, ignore_errors=True)
                continue

            if _count_files(out_dir) <= 0:
                limitations.append(
                    f"recursive {kind} extraction produced empty output for {_rel_to_run_dir(run_dir, candidate)}"
                )
                shutil.rmtree(out_dir, ignore_errors=True)
                continue

            ok += 1
            ev = _evidence_path(
                run_dir,
                out_dir,
                note=f"recursive_{kind}_depth_{depth + 1}",
            )
            evidence.append(ev)
            queue.append((out_dir, depth + 1))

    details["archive_candidates"] = cast(
        list[JsonValue], cast(list[object], sorted(candidate_refs)[:64])
    )
    details["archive_candidate_count"] = int(len(candidate_refs))
    details["archive_extract_attempted"] = int(attempted)
    details["archive_extract_ok"] = int(ok)
    details["archive_depth_reached"] = int(max_depth_seen)
    details["archive_extract_by_type"] = cast(
        dict[str, JsonValue],
        {k: int(v) for k, v in sorted(by_type.items())},
    )
    return details, limitations, evidence


def _has_magic(path: Path, magics: tuple[bytes, ...]) -> bool:
    if not path.is_file():
        return False
    head = _read_head(path, size=max(len(m) for m in magics))
    if not head:
        return False
    return any(head.startswith(m) for m in magics)


def _iter_magic_files(
    root: Path,
    *,
    magics: tuple[bytes, ...],
    max_candidates: int,
    max_file_bytes: int,
    skip_part: str | None = None,
) -> list[Path]:
    out: list[Path] = []
    if not root.is_dir():
        return out
    for p in sorted(root.rglob("*")):
        if len(out) >= int(max_candidates):
            break
        if skip_part and skip_part in p.parts:
            continue
        if not p.is_file():
            continue
        try:
            size = int(p.stat().st_size)
        except OSError:
            continue
        if size <= 0 or size > int(max_file_bytes):
            continue
        if _has_magic(p, magics):
            out.append(p)
    return out


def _recursive_nested_extraction(
    *,
    run_dir: Path,
    stage_dir: Path,
    extracted_dir: Path,
    firmware_path: Path,
    log_path: Path,
    timeout_s: float | None,
) -> tuple[dict[str, JsonValue], list[str], list[dict[str, JsonValue]]]:
    details: dict[str, JsonValue] = {
        "attempted": False,
        "ubi_candidates": cast(list[JsonValue], cast(list[object], [])),
        "squashfs_candidates": cast(list[JsonValue], cast(list[object], [])),
        "ubi_extract_attempted": 0,
        "ubi_extract_ok": 0,
        "squashfs_extract_attempted": 0,
        "squashfs_extract_ok": 0,
        "archive_candidate_count": 0,
        "archive_candidates": cast(list[JsonValue], cast(list[object], [])),
        "archive_extract_attempted": 0,
        "archive_extract_ok": 0,
        "archive_extract_by_type": cast(dict[str, JsonValue], {}),
    }
    limitations: list[str] = []
    evidence: list[dict[str, JsonValue]] = []

    if not extracted_dir.is_dir():
        details["reason"] = "missing_extracted_dir"
        return details, limitations, evidence

    details["attempted"] = True

    ubireader = shutil.which("ubireader_extract_images")
    unsquashfs = shutil.which("unsquashfs")
    details["ubireader_extract_images_available"] = bool(ubireader)
    details["unsquashfs_available"] = bool(unsquashfs)

    ubi_out_root = extracted_dir / "__ubi_recursive"
    squash_out_root = extracted_dir / "__recursive_squashfs"
    _assert_under_dir(run_dir, ubi_out_root)
    _assert_under_dir(run_dir, squash_out_root)
    if ubi_out_root.exists():
        shutil.rmtree(ubi_out_root, ignore_errors=True)
    if squash_out_root.exists():
        shutil.rmtree(squash_out_root, ignore_errors=True)

    ubi_candidates: list[Path] = []
    if _has_magic(firmware_path, (_UBI_MAGIC,)):
        ubi_candidates.append(firmware_path)
    ubi_candidates.extend(
        _iter_magic_files(
            extracted_dir,
            magics=(_UBI_MAGIC,),
            max_candidates=12,
            max_file_bytes=2 * 1024 * 1024 * 1024,
            skip_part="__recursive_squashfs",
        )
    )
    dedup_ubi: list[Path] = []
    seen_ubi: set[str] = set()
    for p in ubi_candidates:
        key = str(p.resolve())
        if key in seen_ubi:
            continue
        seen_ubi.add(key)
        dedup_ubi.append(p)
    ubi_candidates = dedup_ubi[:8]

    details["ubi_candidates"] = cast(
        list[JsonValue],
        cast(list[object], [_rel_to_run_dir(run_dir, p) for p in ubi_candidates]),
    )
    details["ubi_candidate_count"] = int(len(ubi_candidates))

    if ubi_candidates and not ubireader:
        limitations.append(
            "UBI container detected but ubireader_extract_images is unavailable; nested extraction skipped."
        )

    ubi_ok = 0
    for idx, ubi_path in enumerate(ubi_candidates, start=1):
        if not ubireader:
            break
        out_dir = ubi_out_root / f"ubi_{idx:02d}"
        _assert_under_dir(run_dir, out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        evidence.append(_evidence_path(run_dir, out_dir))
        argv = [ubireader, "-o", str(out_dir), str(ubi_path)]
        _append_log(log_path, f"recursive ubireader argv: {argv}")
        try:
            cp = subprocess.run(
                argv,
                cwd=str(stage_dir),
                text=True,
                capture_output=True,
                check=False,
                timeout=max(30.0, min(float(timeout_s or 0.0), 300.0)),
            )
        except subprocess.TimeoutExpired:
            limitations.append(
                f"ubireader_extract_images timed out for {_rel_to_run_dir(run_dir, ubi_path)}"
            )
            continue
        details["ubi_extract_attempted"] = int(
            cast(int, details.get("ubi_extract_attempted", 0)) + 1
        )
        _append_log(log_path, f"recursive ubireader returncode: {cp.returncode}")
        if cp.stdout:
            _append_log(log_path, "--- recursive ubireader stdout (trunc) ---")
            _append_log(log_path, cp.stdout[:4096])
        if cp.stderr:
            _append_log(log_path, "--- recursive ubireader stderr (trunc) ---")
            _append_log(log_path, cp.stderr[:4096])
        if cp.returncode != 0:
            limitations.append(
                f"ubireader_extract_images failed for {_rel_to_run_dir(run_dir, ubi_path)} (rc={cp.returncode})"
            )
            continue
        ubi_ok += 1

    details["ubi_extract_ok"] = int(ubi_ok)

    squashfs_candidates = _iter_magic_files(
        extracted_dir,
        magics=_SQUASHFS_MAGICS,
        max_candidates=24,
        max_file_bytes=1024 * 1024 * 1024,
        skip_part="__recursive_squashfs",
    )
    details["squashfs_candidates"] = cast(
        list[JsonValue],
        cast(
            list[object],
            [_rel_to_run_dir(run_dir, p) for p in squashfs_candidates[:12]],
        ),
    )
    details["squashfs_candidate_count"] = int(len(squashfs_candidates))

    if squashfs_candidates and not unsquashfs:
        limitations.append(
            "SquashFS candidate detected but unsquashfs is unavailable; nested squashfs extraction skipped."
        )

    squash_ok = 0
    for idx, sq_path in enumerate(squashfs_candidates, start=1):
        if not unsquashfs:
            break
        out_dir = squash_out_root / f"root_{idx:02d}"
        _assert_under_dir(run_dir, out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        argv = [unsquashfs, "-d", str(out_dir), str(sq_path)]
        _append_log(log_path, f"recursive unsquashfs argv: {argv}")
        try:
            cp = subprocess.run(
                argv,
                cwd=str(stage_dir),
                text=True,
                capture_output=True,
                check=False,
                timeout=max(30.0, min(float(timeout_s or 0.0) * 2.0, 600.0)),
            )
        except subprocess.TimeoutExpired:
            limitations.append(
                f"unsquashfs timed out for {_rel_to_run_dir(run_dir, sq_path)}"
            )
            continue
        details["squashfs_extract_attempted"] = int(
            cast(int, details.get("squashfs_extract_attempted", 0)) + 1
        )
        _append_log(log_path, f"recursive unsquashfs returncode: {cp.returncode}")
        if cp.stdout:
            _append_log(log_path, "--- recursive unsquashfs stdout (trunc) ---")
            _append_log(log_path, cp.stdout[:4096])
        if cp.stderr:
            _append_log(log_path, "--- recursive unsquashfs stderr (trunc) ---")
            _append_log(log_path, cp.stderr[:4096])
        if cp.returncode != 0:
            limitations.append(
                f"unsquashfs failed for {_rel_to_run_dir(run_dir, sq_path)} (rc={cp.returncode})"
            )
            continue
        if _count_files(out_dir) <= 0:
            limitations.append(
                f"unsquashfs produced empty output for {_rel_to_run_dir(run_dir, sq_path)}"
            )
            continue
        squash_ok += 1
        evidence.append(_evidence_path(run_dir, out_dir))

    details["squashfs_extract_ok"] = int(squash_ok)

    archive_info, archive_limits, archive_evidence = _recursive_archive_extraction(
        run_dir=run_dir,
        stage_dir=stage_dir,
        extracted_dir=extracted_dir,
        log_path=log_path,
        timeout_s=timeout_s,
    )
    details["archive_candidate_count"] = int(
        cast(int, archive_info.get("archive_candidate_count", 0))
    )
    details["archive_candidates"] = cast(
        list[JsonValue],
        cast(list[object], archive_info.get("archive_candidates", [])),
    )
    details["archive_extract_attempted"] = int(
        cast(int, archive_info.get("archive_extract_attempted", 0))
    )
    details["archive_extract_ok"] = int(
        cast(int, archive_info.get("archive_extract_ok", 0))
    )
    details["archive_extract_by_type"] = cast(
        dict[str, JsonValue],
        cast(
            dict[str, object],
            archive_info.get("archive_extract_by_type", cast(object, {})),
        ),
    )
    details["archive_depth_reached"] = int(
        cast(int, archive_info.get("archive_depth_reached", 0))
    )
    details["cpio_available"] = bool(archive_info.get("cpio_available", False))
    details["debugfs_available"] = bool(archive_info.get("debugfs_available", False))
    if archive_limits:
        limitations.extend(archive_limits)
    for ev in archive_evidence:
        evidence.append(ev)

    return details, limitations, evidence


@dataclass(frozen=True)
class ExtractionStage:
    firmware_path: Path
    timeout_s: float | None = 120.0
    matryoshka: bool = True
    matryoshka_depth: int = 8
    provided_rootfs_dir: Path | None = None
    min_extracted_files: int = 50

    @property
    def name(self) -> str:
        return "extraction"

    def run(self, ctx: StageContext) -> StageOutcome:
        fw = self.firmware_path
        if not fw.is_file():
            return StageOutcome(
                status="failed",
                details={
                    "confidence": 0.0,
                    "reasons": [f"firmware not found: {str(fw)}"],
                    "evidence": [
                        _evidence_path(ctx.run_dir, fw, note="missing"),
                    ],
                },
                limitations=["Firmware file missing inside run directory."],
            )

        stage_dir = ctx.run_dir / "stages" / "extraction"
        _assert_under_dir(ctx.run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)

        reasons: list[str] = []
        evidence: list[dict[str, JsonValue]] = [
            _evidence_path(ctx.run_dir, stage_dir),
            _evidence_path(ctx.run_dir, fw),
        ]
        details: dict[str, JsonValue] = {
            "stage_dir": _rel_to_run_dir(ctx.run_dir, stage_dir),
            "tool": "binwalk",
            "firmware": _rel_to_run_dir(ctx.run_dir, fw),
        }

        details["matryoshka"] = bool(self.matryoshka)
        details["matryoshka_depth"] = int(self.matryoshka_depth)
        details["lzop_available"] = bool(shutil.which("lzop"))
        details["minimum_expected_file_count"] = int(max(0, self.min_extracted_files))

        log_path = stage_dir / "binwalk.log"
        _assert_under_dir(stage_dir, log_path)
        extracted_dir = stage_dir / f"_{fw.name}.extracted"
        binwalk = shutil.which("binwalk")
        details["binwalk_available"] = bool(binwalk)
        extraction_mode = "binwalk"
        res: subprocess.CompletedProcess[str] | None = None

        if self.provided_rootfs_dir is not None:
            extraction_mode = "provided_rootfs"
            rootfs_src = self.provided_rootfs_dir.expanduser().resolve()
            details["manual_rootfs_requested"] = True
            try:
                if rootfs_src.is_relative_to(ctx.run_dir.resolve()):
                    rootfs_ref = _rel_to_run_dir(ctx.run_dir, rootfs_src)
                else:
                    rootfs_ref = "<external_rootfs_input>"
            except Exception:
                rootfs_ref = "<external_rootfs_input>"
            details["manual_rootfs_source"] = rootfs_ref

            if not rootfs_src.is_dir():
                reasons.append("provided rootfs directory does not exist or is not a directory")
                details["confidence"] = 0.0
                details["reasons"] = cast(list[JsonValue], list(reasons))
                _ = log_path.write_text(
                    "provided rootfs directory is invalid; extraction skipped\n",
                    encoding="utf-8",
                )
                evidence.append(_evidence_path(ctx.run_dir, log_path))
                evidence.append(_evidence_path(ctx.run_dir, extracted_dir, note="missing"))
                details["evidence"] = cast(list[JsonValue], cast(list[object], evidence))
                return StageOutcome(
                    status="failed",
                    details=details,
                    limitations=[
                        "Manual rootfs input is invalid; pass --rootfs with an extracted filesystem directory."
                    ],
                )

            if extracted_dir.exists():
                shutil.rmtree(extracted_dir, ignore_errors=True)
            shutil.copytree(rootfs_src, extracted_dir, symlinks=True)
            _ = log_path.write_text(
                "\n".join(
                    [
                        "manual rootfs mode enabled",
                        f"source: {rootfs_ref}",
                        f"destination: {extracted_dir}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            reasons.append("used pre-extracted rootfs provided by operator")
            details["tool"] = "provided_rootfs"
            details["manual_rootfs_applied"] = True

        else:
            details["manual_rootfs_requested"] = False
            if not binwalk:
                reasons.append("binwalk not installed")
                details["confidence"] = 0.0
                details["reasons"] = cast(list[JsonValue], list(reasons))
                _ = log_path.write_text(
                    "binwalk not installed; extraction skipped\n", encoding="utf-8"
                )
                evidence.append(_evidence_path(ctx.run_dir, log_path))
                evidence.append(_evidence_path(ctx.run_dir, extracted_dir, note="missing"))
                details["evidence"] = cast(list[JsonValue], cast(list[object], evidence))
                return StageOutcome(
                    status="partial",
                    details=details,
                    limitations=["binwalk not installed; skipping extraction."],
                )

            argv: list[str] = [binwalk]
            if self.matryoshka:
                argv.append("-M")
                argv.extend(["-d", str(int(self.matryoshka_depth))])
            argv.append("-e")
            argv.append(str(fw))
            try:
                res = subprocess.run(
                    argv,
                    cwd=str(stage_dir),
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=self.timeout_s,
                )
            except subprocess.TimeoutExpired:
                reasons.append(f"binwalk timed out after {self.timeout_s}s")
                details["confidence"] = 0.0
                details["reasons"] = cast(list[JsonValue], list(reasons))
                _ = log_path.write_text(
                    "\n".join(
                        [
                            f"argv: {argv}",
                            f"timeout_s: {self.timeout_s}",
                            "binwalk timed out",
                            "",
                        ]
                    ),
                    encoding="utf-8",
                )
                evidence.append(_evidence_path(ctx.run_dir, log_path))
                evidence.append(
                    _evidence_path(ctx.run_dir, extracted_dir, note="unknown")
                )
                details["evidence"] = cast(
                    list[JsonValue], cast(list[object], evidence)
                )
                return StageOutcome(
                    status="failed",
                    details=details,
                    limitations=["Extraction timed out."],
                )

            _ = log_path.write_text(
                "\n".join(
                    [
                        f"argv: {argv}",
                        f"returncode: {res.returncode}",
                        "--- stdout ---",
                        res.stdout or "",
                        "--- stderr ---",
                        res.stderr or "",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

        recursive_info: dict[str, JsonValue] = {"attempted": False}
        recursive_limits: list[str] = []
        if extracted_dir.is_dir():
            recursive_info, recursive_limits, recursive_evidence = (
                _recursive_nested_extraction(
                    run_dir=ctx.run_dir,
                    stage_dir=stage_dir,
                    extracted_dir=extracted_dir,
                    firmware_path=fw,
                    log_path=log_path,
                    timeout_s=self.timeout_s,
                )
            )
            for ev in recursive_evidence:
                if ev not in evidence:
                    evidence.append(ev)
            if recursive_limits:
                reasons.extend(recursive_limits)

        extracted_files = _count_files(extracted_dir)
        min_expected_files = int(max(0, self.min_extracted_files))
        limitations: list[str] = list(recursive_limits)

        if res is not None:
            details["binwalk_returncode"] = int(res.returncode)
        else:
            details["binwalk_returncode"] = None
        details["binwalk_log"] = _rel_to_run_dir(ctx.run_dir, log_path)
        details["extracted_dir"] = _rel_to_run_dir(ctx.run_dir, extracted_dir)
        details["extracted_file_count"] = int(extracted_files)
        details["recursive_extraction"] = recursive_info
        details["extraction_mode"] = extraction_mode

        evidence.append(_evidence_path(ctx.run_dir, log_path))
        if extracted_dir.exists():
            evidence.append(_evidence_path(ctx.run_dir, extracted_dir))
        else:
            evidence.append(_evidence_path(ctx.run_dir, extracted_dir, note="missing"))

        if extraction_mode == "provided_rootfs":
            if extracted_files <= 0:
                reasons.append("provided rootfs directory contains no files")
                confidence = 0.2
                status = "partial"
            else:
                reasons.append(f"ingested {extracted_files} files from provided rootfs")
                confidence = 0.95
                status = "ok"
        elif res is not None and res.returncode != 0:
            reasons.append(f"binwalk failed with return code {res.returncode}")
            confidence = 0.1
            status = "partial"
        elif extracted_files <= 0:
            reasons.append("binwalk succeeded but no extracted files were produced")
            confidence = 0.4
            status = "partial"
        else:
            reasons.append(f"extracted {extracted_files} files via binwalk")
            confidence = 0.85
            status = "ok"

        quality_status = "pass"
        if extracted_files < min_expected_files:
            quality_status = "insufficient"
            reasons.append(
                f"extraction quality gate failed: extracted_file_count={extracted_files} < min_expected={min_expected_files}"
            )
            limitations.append(
                "Extraction quality is insufficient for reliable downstream analysis; provide a pre-extracted rootfs via --rootfs PATH."
            )
            if status == "ok":
                status = "partial"
                confidence = min(confidence, 0.5)
        details["quality_gate"] = {
            "status": quality_status,
            "actual_files": int(extracted_files),
            "min_expected_files": int(min_expected_files),
        }

        details["confidence"] = float(confidence)
        details["reasons"] = cast(list[JsonValue], list(reasons))
        details["evidence"] = cast(list[JsonValue], cast(list[object], evidence))
        return StageOutcome(status=status, details=details, limitations=limitations)
