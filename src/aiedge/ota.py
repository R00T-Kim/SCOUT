from __future__ import annotations

import json
import re
import tempfile
import zipfile
from collections import deque
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO, cast

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


_WIN_DRIVE_RE = re.compile(r"^[A-Za-z]:")


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


def _is_zip_member(name: str) -> bool:
    return _normalize_member_name(name).lower().endswith(".zip")


def _is_payload_member(name: str) -> bool:
    n = _normalize_member_name(name)
    return n == "payload.bin" or n.endswith("/payload.bin")


def _is_metadata_member(name: str) -> bool:
    n = _normalize_member_name(name)
    return n == "META-INF/com/android/metadata"


def _json_int(v: JsonValue, default: int = 0) -> int:
    if isinstance(v, bool):
        return int(default)
    if isinstance(v, int):
        return int(v)
    return int(default)


@dataclass(frozen=True)
class OtaDiscoveryLimits:
    max_depth: int = 5
    max_archives: int = 200
    max_entries_per_zip: int = 200_000
    max_streamed_member_bytes: int = 8_589_934_592


def _copy_stream_limited(
    src: IO[bytes],
    dst: IO[bytes],
    *,
    max_bytes: int,
    label: str,
) -> int:
    copied = 0
    while True:
        chunk = src.read(1024 * 1024)
        if not chunk:
            return copied
        copied += len(chunk)
        if copied > int(max_bytes):
            raise AIEdgePolicyViolation(
                f"streamed member too large at {label}: bytes={copied} max_streamed_member_bytes={int(max_bytes)}"
            )
        _ = dst.write(chunk)


def discover_ota_candidates(
    zip_path: Path,
    *,
    limits: OtaDiscoveryLimits | None = None,
    scratch_dir: Path | None = None,
) -> dict[str, JsonValue]:
    cfg = limits or OtaDiscoveryLimits()
    refusal_reasons: list[str] = []
    candidates: list[dict[str, JsonValue]] = []

    if not zip_path.is_file():
        refusal_reasons.append(f"input archive missing: {zip_path}")
        return {
            "candidates": cast(list[JsonValue], cast(list[object], candidates)),
            "refusal_reasons": cast(list[JsonValue], list(refusal_reasons)),
        }

    queue: deque[tuple[tuple[str, ...], int, Path | None]] = deque()
    queue.append((tuple(), 0, None))
    archives_seen = 0

    nested_tmp_ctx: tempfile.TemporaryDirectory[str] | None = None
    nested_root: Path
    if scratch_dir is None:
        nested_tmp_ctx = tempfile.TemporaryDirectory(prefix="aiedge-ota-discovery-")
        nested_root = Path(nested_tmp_ctx.name)
    else:
        nested_root = scratch_dir
        _assert_under_dir(scratch_dir, nested_root)
        nested_root.mkdir(parents=True, exist_ok=True)

    nested_seq = 0
    try:
        while queue:
            chain, depth, archive_file = queue.popleft()
            if archives_seen >= int(cfg.max_archives):
                refusal_reasons.append(
                    f"archive limit exceeded: max_archives={int(cfg.max_archives)}"
                )
                break

            archive_path = "<root>" if not chain else "!/".join(chain)
            source = zip_path if archive_file is None else archive_file
            try:
                zf = zipfile.ZipFile(source)
            except Exception as exc:
                refusal_reasons.append(
                    f"invalid zip archive at {archive_path}: {type(exc).__name__}: {exc}"
                )
                continue

            archives_seen += 1
            with zf:
                infos = zf.infolist()
                if len(infos) > int(cfg.max_entries_per_zip):
                    refusal_reasons.append(
                        f"entry limit exceeded at {archive_path}: entries={len(infos)} max_entries_per_zip={int(cfg.max_entries_per_zip)}"
                    )
                    continue

                payload_member: str | None = None
                payload_size = 0
                metadata_member: str | None = None

                for info in infos:
                    raw_name = info.filename
                    if not _is_safe_member_path(raw_name):
                        refusal_reasons.append(
                            f"zip-slip path rejected at {archive_path}: {raw_name!r}"
                        )
                        continue

                    norm_name = _normalize_member_name(raw_name)
                    if _is_payload_member(norm_name):
                        payload_member = norm_name
                        payload_size = int(info.file_size)
                    if _is_metadata_member(norm_name):
                        metadata_member = norm_name

                    if _is_zip_member(norm_name):
                        if depth >= int(cfg.max_depth):
                            refusal_reasons.append(
                                f"max depth reached at {archive_path}: {norm_name}"
                            )
                            continue
                        nested_seq += 1
                        nested_file = (
                            nested_root / f"nested-{depth + 1}-{nested_seq}.zip"
                        )
                        _assert_under_dir(nested_root, nested_file)
                        try:
                            if int(info.file_size) > int(cfg.max_streamed_member_bytes):
                                raise AIEdgePolicyViolation(
                                    f"streamed member too large at {archive_path}: {norm_name}: file_size={int(info.file_size)} max_streamed_member_bytes={int(cfg.max_streamed_member_bytes)}"
                                )
                            with (
                                zf.open(info, "r") as member_src,
                                nested_file.open("wb") as member_dst,
                            ):
                                _ = _copy_stream_limited(
                                    member_src,
                                    member_dst,
                                    max_bytes=int(cfg.max_streamed_member_bytes),
                                    label=f"{archive_path}: {norm_name}",
                                )
                        except Exception as exc:
                            refusal_reasons.append(
                                f"failed to stream nested zip at {archive_path}: {norm_name}: {type(exc).__name__}: {exc}"
                            )
                            if nested_file.exists():
                                nested_file.unlink(missing_ok=True)
                            continue
                        queue.append((chain + (norm_name,), depth + 1, nested_file))

                if payload_member is not None or metadata_member is not None:
                    candidates.append(
                        {
                            "archive_path": archive_path,
                            "archive_chain": cast(list[JsonValue], list(chain)),
                            "depth": int(depth),
                            "has_payload_bin": bool(payload_member is not None),
                            "payload_bin_path": payload_member or "",
                            "payload_bin_size": int(payload_size),
                            "has_metadata": bool(metadata_member is not None),
                            "metadata_path": metadata_member or "",
                        }
                    )
    finally:
        if nested_tmp_ctx is not None:
            nested_tmp_ctx.cleanup()

    sorted_candidates = sorted(
        candidates,
        key=lambda c: (
            -_json_int(c.get("payload_bin_size"), 0),
            str(c.get("archive_path") or ""),
            str(c.get("payload_bin_path") or ""),
            str(c.get("metadata_path") or ""),
        ),
    )

    chosen: dict[str, JsonValue] | None = None
    if sorted_candidates:
        chosen = dict(sorted_candidates[0])

    return {
        "archives_scanned": int(archives_seen),
        "candidates": cast(list[JsonValue], cast(list[object], sorted_candidates)),
        "chosen": cast(JsonValue, chosen),
        "refusal_reasons": cast(list[JsonValue], list(refusal_reasons)),
    }


@dataclass(frozen=True)
class OtaStage:
    input_path: Path
    source_input_path: str | None = None
    limits: OtaDiscoveryLimits = OtaDiscoveryLimits()

    @property
    def name(self) -> str:
        return "ota"

    def run(self, ctx: StageContext) -> StageOutcome:
        stage_dir = ctx.run_dir / "stages" / "ota"
        ota_json_path = stage_dir / "ota.json"
        input_dir = stage_dir / "input"
        nested_dir = input_dir / "_nested"

        _assert_under_dir(ctx.run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(ctx.run_dir, input_dir)
        input_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(ctx.run_dir, nested_dir)
        nested_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(stage_dir, ota_json_path)

        source_name = self.source_input_path or self.input_path.name
        suffix = Path(source_name).suffix.lower()
        is_zip_input = suffix == ".zip"

        obj: dict[str, JsonValue] = {
            "input": _rel_to_run_dir(ctx.run_dir, self.input_path),
            "source_input_path": source_name,
            "is_zip_input": bool(is_zip_input),
            "limits": {
                "max_depth": int(self.limits.max_depth),
                "max_archives": int(self.limits.max_archives),
                "max_entries_per_zip": int(self.limits.max_entries_per_zip),
                "max_streamed_member_bytes": int(self.limits.max_streamed_member_bytes),
            },
            "archives_scanned": 0,
            "candidates": [],
            "chosen": None,
            "refusal_reasons": [],
        }

        status: StageStatus = "skipped"
        limitations: list[str] = []

        if not is_zip_input:
            limitations.append("OTA discovery skipped: input extension is not .zip")
        elif not self.input_path.is_file():
            status = "failed"
            limitations.append(f"OTA discovery input missing: {self.input_path}")
            obj["refusal_reasons"] = cast(list[JsonValue], list(limitations))
        else:
            discovered = discover_ota_candidates(
                self.input_path,
                limits=self.limits,
                scratch_dir=nested_dir,
            )
            obj["archives_scanned"] = discovered.get("archives_scanned", 0)
            obj["candidates"] = discovered.get("candidates", [])
            obj["chosen"] = discovered.get("chosen")
            obj["refusal_reasons"] = discovered.get("refusal_reasons", [])

            chosen_any = discovered.get("chosen")
            if isinstance(chosen_any, dict):
                status = "ok"
            else:
                status = "partial"
                limitations.append("No OTA candidates found in zip input")

        _ = ota_json_path.write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        details: dict[str, JsonValue] = {
            "stage_dir": _rel_to_run_dir(ctx.run_dir, stage_dir),
            "ota_json": _rel_to_run_dir(ctx.run_dir, ota_json_path),
            "input": _rel_to_run_dir(ctx.run_dir, self.input_path),
            "source_input_path": source_name,
            "is_zip_input": bool(is_zip_input),
            "chosen": obj.get("chosen"),
            "candidates": obj.get("candidates", []),
            "limits": obj.get("limits", {}),
            "evidence": cast(
                list[JsonValue],
                cast(
                    list[object],
                    [
                        {"path": _rel_to_run_dir(ctx.run_dir, stage_dir)},
                        {"path": _rel_to_run_dir(ctx.run_dir, ota_json_path)},
                    ],
                ),
            ),
        }
        return StageOutcome(status=status, details=details, limitations=limitations)
