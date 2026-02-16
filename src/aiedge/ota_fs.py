from __future__ import annotations

import json
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


SPARSE_MAGIC = b"\x3a\xff\x26\xed"
EXT4_SUPERBLOCK_OFFSET = 1024
EXT4_MAGIC_OFFSET_IN_SUPERBLOCK = 56
EXT4_MAGIC = b"\x53\xef"


def _read_exact(path: Path, *, offset: int, size: int) -> bytes:
    with path.open("rb") as f:
        _ = f.seek(int(offset))
        return f.read(int(size))


def _detect_fs_for_image(run_dir: Path, img_path: Path) -> dict[str, JsonValue]:
    rel = _rel_to_run_dir(run_dir, img_path)
    result: dict[str, JsonValue] = {
        "path": rel,
        "exists": False,
        "size": 0,
        "type": "unknown",
        "evidence": {
            "sparse_magic": "",
            "ext4_magic": "",
        },
    }

    if not img_path.is_file():
        result["evidence"] = {
            "note": "missing image",
            "sparse_magic": "",
            "ext4_magic": "",
        }
        return result

    size = int(img_path.stat().st_size)
    sparse_bytes = _read_exact(img_path, offset=0, size=4)
    ext4_offset = EXT4_SUPERBLOCK_OFFSET + EXT4_MAGIC_OFFSET_IN_SUPERBLOCK
    ext4_bytes = _read_exact(img_path, offset=ext4_offset, size=2)

    fs_type = "unknown"
    if sparse_bytes == SPARSE_MAGIC:
        fs_type = "android_sparse"
    elif ext4_bytes == EXT4_MAGIC:
        fs_type = "ext4_raw"

    result["exists"] = True
    result["size"] = size
    result["type"] = fs_type
    result["evidence"] = {
        "sparse_magic": sparse_bytes.hex(),
        "ext4_magic": ext4_bytes.hex(),
        "ext4_magic_offset": int(ext4_offset),
    }
    return result


@dataclass(frozen=True)
class OtaFsStage:
    @property
    def name(self) -> str:
        return "ota_fs"

    def run(self, ctx: StageContext) -> StageOutcome:
        stage_dir = ctx.run_dir / "stages" / "ota"
        partitions_dir = stage_dir / "partitions"
        fs_json_path = stage_dir / "fs.json"

        for p in [stage_dir, partitions_dir, fs_json_path]:
            _assert_under_dir(ctx.run_dir, p)

        stage_dir.mkdir(parents=True, exist_ok=True)
        partitions_dir.mkdir(parents=True, exist_ok=True)

        partitions = ["system", "vendor", "product"]
        detections: dict[str, JsonValue] = {}
        evidence: list[dict[str, JsonValue]] = [
            _evidence_path(ctx.run_dir, stage_dir),
            _evidence_path(ctx.run_dir, partitions_dir),
        ]
        limitations: list[str] = []

        missing_count = 0
        for part in partitions:
            img_path = partitions_dir / f"{part}.img"
            d = _detect_fs_for_image(ctx.run_dir, img_path)
            detections[part] = cast(JsonValue, d)
            if not bool(d.get("exists")):
                missing_count += 1
                evidence.append(_evidence_path(ctx.run_dir, img_path, note="missing"))
                limitations.append(f"Missing OTA partition image: {part}.img")
            else:
                evidence.append(_evidence_path(ctx.run_dir, img_path))

        status: StageStatus = "ok"
        if missing_count > 0:
            status = "partial"

        doc: dict[str, JsonValue] = {
            "status": status,
            "partitions": detections,
            "evidence": cast(list[JsonValue], cast(list[object], evidence)),
            "limitations": cast(list[JsonValue], list(limitations)),
        }
        _ = fs_json_path.write_text(
            json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        details: dict[str, JsonValue] = {
            "artifacts": {
                "fs_json": _rel_to_run_dir(ctx.run_dir, fs_json_path),
                "partitions_dir": _rel_to_run_dir(ctx.run_dir, partitions_dir),
            },
            "partitions": detections,
            "evidence": cast(list[JsonValue], cast(list[object], evidence)),
        }
        return StageOutcome(status=status, details=details, limitations=limitations)
