from __future__ import annotations

import gzip
import io
import json
import os
import re
import struct
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
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


def _read_u32le(buf: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(buf):
        return 0
    return int(cast(tuple[int], struct.unpack_from("<I", buf, offset))[0])


def _read_c_string(buf: bytes, start: int, size: int) -> str:
    if start < 0 or size <= 0 or start >= len(buf):
        return ""
    end = min(len(buf), start + size)
    raw = buf[start:end]
    nul = raw.find(b"\x00")
    if nul >= 0:
        raw = raw[:nul]
    return raw.decode("utf-8", errors="replace").strip()


def _align(n: int, align_to: int) -> int:
    if align_to <= 0:
        return n
    return ((n + align_to - 1) // align_to) * align_to


@dataclass(frozen=True)
class OtaBootTriageCaps:
    max_files: int = 10_000
    max_total_bytes: int = 256 * 1024 * 1024
    max_single_file_bytes: int = 16 * 1024 * 1024
    max_cpio_entries: int = 50_000


@dataclass(frozen=True)
class OtaBootTriageTimeouts:
    ramdisk_parse_s: float = 30.0


@dataclass(frozen=True)
class _BootImageMeta:
    format: str
    header_version: int
    page_size: int
    kernel_size: int
    ramdisk_offset: int
    ramdisk_size: int
    name: str
    cmdline: str
    supported: bool
    reason: str


@dataclass(frozen=True)
class _CpioOutcome:
    extracted_files: int
    extracted_dirs: int
    extracted_symlinks: int
    skipped_special: int
    skipped_unsafe_paths: int
    skipped_caps: int
    skipped_too_large: int
    limitations: list[str]


_WIN_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_CPIO_MAGIC = {b"070701", b"070702"}
_S_IFMT = 0o170000
_S_IFREG = 0o100000
_S_IFDIR = 0o040000
_S_IFLNK = 0o120000


def _normalize_member_name(name: str) -> str:
    s = (name or "").replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    while "//" in s:
        s = s.replace("//", "/")
    return s


def _is_safe_member_path(name: str) -> bool:
    if not name:
        return False
    n = _normalize_member_name(name)
    if not n:
        return False
    if n.startswith("/"):
        return False
    if _WIN_DRIVE_RE.match(n):
        return False
    p = PurePosixPath(n)
    if any(part == ".." for part in p.parts):
        return False
    return True


def _parse_boot_image(img: bytes) -> _BootImageMeta:
    if len(img) < 608:
        return _BootImageMeta(
            format="unknown",
            header_version=0,
            page_size=0,
            kernel_size=0,
            ramdisk_offset=0,
            ramdisk_size=0,
            name="",
            cmdline="",
            supported=False,
            reason="image too small for Android boot header",
        )
    if img[:8] != b"ANDROID!":
        return _BootImageMeta(
            format="unknown",
            header_version=0,
            page_size=0,
            kernel_size=0,
            ramdisk_offset=0,
            ramdisk_size=0,
            name="",
            cmdline="",
            supported=False,
            reason="missing ANDROID! boot magic",
        )

    kernel_size = _read_u32le(img, 8)
    ramdisk_size = _read_u32le(img, 16)
    page_size = _read_u32le(img, 36)
    hv_raw = _read_u32le(img, 40)
    header_version = hv_raw if 0 <= hv_raw <= 4 else 0
    name = _read_c_string(img, 48, 16)
    cmdline = (
        _read_c_string(img, 64, 512) + " " + _read_c_string(img, 608, 1024)
    ).strip()

    if page_size <= 0:
        return _BootImageMeta(
            format="android_boot",
            header_version=header_version,
            page_size=page_size,
            kernel_size=kernel_size,
            ramdisk_offset=0,
            ramdisk_size=ramdisk_size,
            name=name,
            cmdline=cmdline,
            supported=False,
            reason="invalid or missing page_size",
        )

    if header_version >= 3:
        return _BootImageMeta(
            format="android_boot",
            header_version=header_version,
            page_size=page_size,
            kernel_size=kernel_size,
            ramdisk_offset=0,
            ramdisk_size=ramdisk_size,
            name=name,
            cmdline=cmdline,
            supported=False,
            reason=f"unsupported boot image header_version={header_version}",
        )

    kernel_offset = int(page_size)
    ramdisk_offset = kernel_offset + _align(int(kernel_size), int(page_size))
    end = ramdisk_offset + int(ramdisk_size)
    if ramdisk_offset < 0 or end > len(img):
        return _BootImageMeta(
            format="android_boot",
            header_version=header_version,
            page_size=page_size,
            kernel_size=kernel_size,
            ramdisk_offset=max(0, ramdisk_offset),
            ramdisk_size=ramdisk_size,
            name=name,
            cmdline=cmdline,
            supported=False,
            reason="ramdisk offset/size out of bounds",
        )

    return _BootImageMeta(
        format="android_boot",
        header_version=header_version,
        page_size=page_size,
        kernel_size=kernel_size,
        ramdisk_offset=ramdisk_offset,
        ramdisk_size=ramdisk_size,
        name=name,
        cmdline=cmdline,
        supported=True,
        reason="",
    )


def _extract_newc_cpio(
    *,
    payload: bytes,
    out_dir: Path,
    run_dir: Path,
    caps: OtaBootTriageCaps,
    timeout_s: float,
) -> _CpioOutcome:
    out_dir.mkdir(parents=True, exist_ok=True)
    _assert_under_dir(run_dir, out_dir)

    extracted_files = 0
    extracted_dirs = 0
    extracted_symlinks = 0
    skipped_special = 0
    skipped_unsafe_paths = 0
    skipped_caps = 0
    skipped_too_large = 0
    limitations: list[str] = []

    pos = 0
    total_written = 0
    entry_count = 0
    t0 = time.monotonic()

    while pos + 110 <= len(payload):
        if (time.monotonic() - t0) > float(timeout_s):
            limitations.append("CPIO parse timeout reached")
            break
        if entry_count >= int(caps.max_cpio_entries):
            limitations.append("CPIO entry cap reached")
            break

        header = payload[pos : pos + 110]
        magic = header[:6]
        if magic not in _CPIO_MAGIC:
            limitations.append("CPIO payload is not newc/crc at entry boundary")
            break

        try:
            mode = int(header[14:22], 16)
            filesize = int(header[54:62], 16)
            namesize = int(header[94:102], 16)
        except Exception:
            limitations.append("Failed to parse CPIO newc header")
            break

        if namesize <= 0:
            limitations.append("CPIO entry has invalid namesize")
            break

        name_start = pos + 110
        name_end = name_start + namesize
        if name_end > len(payload):
            limitations.append("CPIO name exceeds payload size")
            break

        raw_name = payload[name_start:name_end]
        nul = raw_name.find(b"\x00")
        if nul >= 0:
            raw_name = raw_name[:nul]
        name = raw_name.decode("utf-8", errors="replace")
        name_n = _normalize_member_name(name)

        data_start = _align(name_end, 4)
        data_end = data_start + filesize
        if data_end > len(payload):
            limitations.append("CPIO file data exceeds payload size")
            break

        if name_n == "TRAILER!!!":
            break

        entry_count += 1

        if not _is_safe_member_path(name_n):
            skipped_unsafe_paths += 1
            pos = _align(data_end, 4)
            continue

        kind = mode & _S_IFMT
        rel_path = PurePosixPath(name_n)
        dest = out_dir.joinpath(*rel_path.parts)
        _assert_under_dir(out_dir, dest)

        if kind == _S_IFDIR:
            dest.mkdir(parents=True, exist_ok=True)
            extracted_dirs += 1
            pos = _align(data_end, 4)
            continue

        if kind == _S_IFREG:
            if filesize > int(caps.max_single_file_bytes):
                skipped_too_large += 1
                pos = _align(data_end, 4)
                continue
            if extracted_files >= int(caps.max_files):
                skipped_caps += 1
                pos = _align(data_end, 4)
                continue
            if total_written + filesize > int(caps.max_total_bytes):
                skipped_caps += 1
                pos = _align(data_end, 4)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            _assert_under_dir(out_dir, dest.parent)
            _ = dest.write_bytes(payload[data_start:data_end])
            extracted_files += 1
            total_written += filesize
            pos = _align(data_end, 4)
            continue

        if kind == _S_IFLNK:
            if extracted_files >= int(caps.max_files):
                skipped_caps += 1
                pos = _align(data_end, 4)
                continue
            target = payload[data_start:data_end].decode("utf-8", errors="replace")
            if not target:
                pos = _align(data_end, 4)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            _assert_under_dir(out_dir, dest.parent)
            try:
                if dest.exists() or dest.is_symlink():
                    dest.unlink()
                os.symlink(target, dest)
                extracted_symlinks += 1
            except Exception:
                limitations.append(f"Failed to materialize symlink: {name_n}")
            pos = _align(data_end, 4)
            continue

        skipped_special += 1
        pos = _align(data_end, 4)

    if skipped_special > 0:
        limitations.append(f"Skipped special CPIO entries: {skipped_special}")
    if skipped_unsafe_paths > 0:
        limitations.append(f"Skipped unsafe CPIO paths: {skipped_unsafe_paths}")
    if skipped_too_large > 0:
        limitations.append("Some CPIO files exceeded max_single_file_bytes")
    if skipped_caps > 0:
        limitations.append("CPIO extraction hit configured caps")

    return _CpioOutcome(
        extracted_files=extracted_files,
        extracted_dirs=extracted_dirs,
        extracted_symlinks=extracted_symlinks,
        skipped_special=skipped_special,
        skipped_unsafe_paths=skipped_unsafe_paths,
        skipped_caps=skipped_caps,
        skipped_too_large=skipped_too_large,
        limitations=limitations,
    )


def _extract_ramdisk(
    *,
    ramdisk_bytes: bytes,
    out_dir: Path,
    run_dir: Path,
    caps: OtaBootTriageCaps,
    timeout_s: float,
) -> tuple[str, _CpioOutcome | None, list[str]]:
    limits: list[str] = []
    payload = ramdisk_bytes
    compression = "none"
    if payload.startswith(b"\x1f\x8b"):
        compression = "gzip"
        try:
            payload = gzip.GzipFile(fileobj=io.BytesIO(payload)).read()
        except Exception as exc:
            limits.append(
                f"Failed to decompress gzip ramdisk: {type(exc).__name__}: {exc}"
            )
            return compression, None, limits

    if not payload.startswith((b"070701", b"070702")):
        limits.append("Ramdisk is not CPIO newc/newcrc after optional gzip")
        return compression, None, limits

    res = _extract_newc_cpio(
        payload=payload,
        out_dir=out_dir,
        run_dir=run_dir,
        caps=caps,
        timeout_s=timeout_s,
    )
    return compression, res, limits + list(res.limitations)


def _find_init_scripts(ramdisk_dir: Path, run_dir: Path) -> list[dict[str, JsonValue]]:
    out: list[dict[str, JsonValue]] = []
    if not ramdisk_dir.is_dir():
        return out
    for p in sorted(ramdisk_dir.rglob("*.rc")):
        if not p.is_file() and not p.is_symlink():
            continue
        name = p.name
        if name == "init.rc" or (
            name.startswith("init.recovery.") and name.endswith(".rc")
        ):
            out.append(_evidence_path(run_dir, p))
    return out


def _minimal_doc(*, reason: str, run_dir: Path, img_path: Path) -> dict[str, JsonValue]:
    return {
        "status": "skipped",
        "reason": reason,
        "image": _rel_to_run_dir(run_dir, img_path),
        "evidence": cast(
            list[JsonValue],
            cast(
                list[object],
                [
                    _evidence_path(run_dir, img_path, note="missing"),
                ],
            ),
        ),
    }


def _analyze_image(
    *,
    run_dir: Path,
    img_path: Path,
    json_path: Path,
    ramdisk_out: Path,
    caps: OtaBootTriageCaps,
    timeouts: OtaBootTriageTimeouts,
) -> tuple[StageStatus, dict[str, JsonValue], list[str], list[dict[str, JsonValue]]]:
    limitations: list[str] = []
    evidence: list[dict[str, JsonValue]] = [
        _evidence_path(run_dir, img_path),
        _evidence_path(run_dir, json_path),
        _evidence_path(run_dir, ramdisk_out),
    ]

    img = img_path.read_bytes()
    meta = _parse_boot_image(img)

    status: StageStatus = "ok"
    if not meta.supported:
        limitations.append(meta.reason)
        status = "partial"

    doc: dict[str, JsonValue] = {
        "status": status,
        "image": _rel_to_run_dir(run_dir, img_path),
        "format": meta.format,
        "header_version": int(meta.header_version),
        "name": meta.name,
        "cmdline": meta.cmdline,
        "header": {
            "page_size": int(meta.page_size),
            "kernel_size": int(meta.kernel_size),
            "ramdisk_offset": int(meta.ramdisk_offset),
            "ramdisk_size": int(meta.ramdisk_size),
        },
        "ramdisk": {
            "dir": _rel_to_run_dir(run_dir, ramdisk_out),
            "compression": "unknown",
            "status": "skipped",
        },
        "evidence": cast(list[JsonValue], cast(list[object], evidence)),
        "limitations": cast(list[JsonValue], list(limitations)),
    }

    init_scripts: list[dict[str, JsonValue]] = []
    if meta.supported and meta.ramdisk_size > 0:
        ramdisk = img[meta.ramdisk_offset : meta.ramdisk_offset + meta.ramdisk_size]
        compression, cpio_out, ramdisk_limits = _extract_ramdisk(
            ramdisk_bytes=ramdisk,
            out_dir=ramdisk_out,
            run_dir=run_dir,
            caps=caps,
            timeout_s=timeouts.ramdisk_parse_s,
        )
        limitations.extend(ramdisk_limits)
        ramdisk_obj = cast(dict[str, JsonValue], doc["ramdisk"])
        ramdisk_obj["compression"] = compression
        if cpio_out is None:
            ramdisk_obj["status"] = "partial"
            status = "partial"
        else:
            ramdisk_obj["status"] = "ok"
            ramdisk_obj["summary"] = {
                "extracted_files": int(cpio_out.extracted_files),
                "extracted_dirs": int(cpio_out.extracted_dirs),
                "extracted_symlinks": int(cpio_out.extracted_symlinks),
                "skipped_special": int(cpio_out.skipped_special),
                "skipped_unsafe_paths": int(cpio_out.skipped_unsafe_paths),
                "skipped_caps": int(cpio_out.skipped_caps),
                "skipped_too_large": int(cpio_out.skipped_too_large),
            }
            init_scripts = _find_init_scripts(ramdisk_out, run_dir)
            if init_scripts:
                for ev in init_scripts:
                    evidence.append(ev)
    else:
        if meta.supported and meta.ramdisk_size == 0:
            limitations.append("Ramdisk size is zero")
            status = "partial"

    if limitations:
        status = "partial" if status == "ok" else status

    doc["status"] = status
    doc["evidence"] = cast(list[JsonValue], cast(list[object], evidence))
    doc["limitations"] = cast(list[JsonValue], list(limitations))
    _ = json_path.write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return status, doc, limitations, init_scripts


@dataclass(frozen=True)
class OtaBootTriageStage:
    caps: OtaBootTriageCaps = OtaBootTriageCaps()
    timeouts: OtaBootTriageTimeouts = OtaBootTriageTimeouts()

    @property
    def name(self) -> str:
        return "ota_boottriage"

    def run(self, ctx: StageContext) -> StageOutcome:
        stage_dir = ctx.run_dir / "stages" / "ota" / "boottriage"
        partitions_dir = ctx.run_dir / "stages" / "ota" / "partitions"
        boot_img = partitions_dir / "boot.img"
        recovery_img = partitions_dir / "recovery.img"
        boot_json = stage_dir / "boot.json"
        recovery_json = stage_dir / "recovery.json"
        boot_ramdisk = stage_dir / "boot_ramdisk"
        recovery_ramdisk = stage_dir / "recovery_ramdisk"

        for p in [
            stage_dir,
            partitions_dir,
            boot_img,
            recovery_img,
            boot_json,
            recovery_json,
            boot_ramdisk,
            recovery_ramdisk,
        ]:
            _assert_under_dir(ctx.run_dir, p)

        stage_dir.mkdir(parents=True, exist_ok=True)
        boot_ramdisk.mkdir(parents=True, exist_ok=True)
        recovery_ramdisk.mkdir(parents=True, exist_ok=True)

        missing_boot = not boot_img.is_file()
        missing_recovery = not recovery_img.is_file()

        if missing_boot or missing_recovery:
            boot_doc = (
                _minimal_doc(
                    reason="boot image missing",
                    run_dir=ctx.run_dir,
                    img_path=boot_img,
                )
                if missing_boot
                else {
                    "status": "skipped",
                    "reason": "boot triage skipped because recovery image is missing",
                    "image": _rel_to_run_dir(ctx.run_dir, boot_img),
                    "evidence": cast(
                        list[JsonValue],
                        cast(list[object], [_evidence_path(ctx.run_dir, boot_img)]),
                    ),
                }
            )
            recovery_doc = (
                _minimal_doc(
                    reason="recovery image missing",
                    run_dir=ctx.run_dir,
                    img_path=recovery_img,
                )
                if missing_recovery
                else {
                    "status": "skipped",
                    "reason": "boot triage skipped because boot image is missing",
                    "image": _rel_to_run_dir(ctx.run_dir, recovery_img),
                    "evidence": cast(
                        list[JsonValue],
                        cast(list[object], [_evidence_path(ctx.run_dir, recovery_img)]),
                    ),
                }
            )
            _ = boot_json.write_text(
                json.dumps(boot_doc, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            _ = recovery_json.write_text(
                json.dumps(recovery_doc, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            details: dict[str, JsonValue] = {
                "artifacts": {
                    "boot_json": _rel_to_run_dir(ctx.run_dir, boot_json),
                    "recovery_json": _rel_to_run_dir(ctx.run_dir, recovery_json),
                    "boot_ramdisk": _rel_to_run_dir(ctx.run_dir, boot_ramdisk),
                    "recovery_ramdisk": _rel_to_run_dir(ctx.run_dir, recovery_ramdisk),
                },
                "evidence": cast(
                    list[JsonValue],
                    cast(
                        list[object],
                        [
                            _evidence_path(ctx.run_dir, stage_dir),
                            _evidence_path(
                                ctx.run_dir,
                                boot_img,
                                note="missing" if missing_boot else None,
                            ),
                            _evidence_path(
                                ctx.run_dir,
                                recovery_img,
                                note="missing" if missing_recovery else None,
                            ),
                            _evidence_path(ctx.run_dir, boot_json),
                            _evidence_path(ctx.run_dir, recovery_json),
                            _evidence_path(ctx.run_dir, boot_ramdisk),
                            _evidence_path(ctx.run_dir, recovery_ramdisk),
                        ],
                    ),
                ),
            }
            limitations = [
                "OTA boot triage skipped: boot or recovery partition image missing"
            ]
            return StageOutcome(
                status="skipped", details=details, limitations=limitations
            )

        boot_status, _, boot_limits, boot_init = _analyze_image(
            run_dir=ctx.run_dir,
            img_path=boot_img,
            json_path=boot_json,
            ramdisk_out=boot_ramdisk,
            caps=self.caps,
            timeouts=self.timeouts,
        )
        rec_status, _, rec_limits, rec_init = _analyze_image(
            run_dir=ctx.run_dir,
            img_path=recovery_img,
            json_path=recovery_json,
            ramdisk_out=recovery_ramdisk,
            caps=self.caps,
            timeouts=self.timeouts,
        )

        limitations = [f"boot: {x}" for x in boot_limits] + [
            f"recovery: {x}" for x in rec_limits
        ]

        status: StageStatus = "ok"
        if any(s == "failed" for s in [boot_status, rec_status]):
            status = "failed"
        elif any(s == "partial" for s in [boot_status, rec_status]):
            status = "partial"

        evidence: list[dict[str, JsonValue]] = [
            _evidence_path(ctx.run_dir, stage_dir),
            _evidence_path(ctx.run_dir, boot_img),
            _evidence_path(ctx.run_dir, recovery_img),
            _evidence_path(ctx.run_dir, boot_json),
            _evidence_path(ctx.run_dir, recovery_json),
            _evidence_path(ctx.run_dir, boot_ramdisk),
            _evidence_path(ctx.run_dir, recovery_ramdisk),
        ]
        evidence.extend(boot_init)
        evidence.extend(rec_init)

        details = {
            "artifacts": {
                "boot_json": _rel_to_run_dir(ctx.run_dir, boot_json),
                "recovery_json": _rel_to_run_dir(ctx.run_dir, recovery_json),
                "boot_ramdisk": _rel_to_run_dir(ctx.run_dir, boot_ramdisk),
                "recovery_ramdisk": _rel_to_run_dir(ctx.run_dir, recovery_ramdisk),
            },
            "evidence": cast(list[JsonValue], cast(list[object], evidence)),
        }
        return StageOutcome(status=status, details=details, limitations=limitations)
