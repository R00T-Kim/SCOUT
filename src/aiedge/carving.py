from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .mtdparts import parse_mtdparts
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


def _append_log(log_path: Path, text: str) -> None:
    try:
        _ = log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as f:
            _ = f.write(text)
            if not text.endswith("\n"):
                _ = f.write("\n")
    except Exception:
        return


_NON_ALNUM_RE = re.compile(r"[^A-Za-z0-9]+")


def _sanitize_name(name: str, *, fallback: str = "part", max_len: int = 80) -> str:
    s = (name or "").strip()
    s = _NON_ALNUM_RE.sub("_", s)
    s = s.strip("_")
    if not s:
        s = fallback
    if len(s) > int(max_len):
        s = s[: int(max_len)].rstrip("_")
    if not s:
        s = fallback
    return s


def _load_json_obj(path: Path) -> dict[str, object] | None:
    try:
        data = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return cast(dict[str, object], data)


def _extract_mtdparts_terms(structure_obj: dict[str, object]) -> list[str]:
    bootargs_any = structure_obj.get("bootargs")
    if not isinstance(bootargs_any, dict):
        return []
    bootargs = cast(dict[str, object], bootargs_any)
    terms_any = bootargs.get("terms")
    if not isinstance(terms_any, dict):
        return []
    terms = cast(dict[str, object], terms_any)
    vals_any = terms.get("mtdparts")
    if not isinstance(vals_any, list):
        return []
    out: list[str] = []
    for x in cast(list[object], vals_any):
        if isinstance(x, str) and x.strip() and x.strip() not in out:
            out.append(x.strip())
    return out


def _detect_blob_magic(path: Path) -> dict[str, bool]:
    out = {
        "squashfs": False,
        "ubi": False,
        "jffs2": False,
        "dtb": False,
    }
    try:
        with path.open("rb") as f:
            head = f.read(64)
    except Exception:
        return out

    if len(head) >= 4 and head[:4] in (b"hsqs", b"sqsh"):
        out["squashfs"] = True
    if len(head) >= 4 and head[:4] == b"UBI#":
        out["ubi"] = True
    if len(head) >= 4 and int.from_bytes(head[:4], "big", signed=False) == 0xD00DFEED:
        out["dtb"] = True
    if len(head) >= 2:
        v_le = int.from_bytes(head[:2], "little", signed=False)
        v_be = int.from_bytes(head[:2], "big", signed=False)
        if v_le == 0x1985 or v_be == 0x1985:
            out["jffs2"] = True

    return out


def _json_int(v: JsonValue, default: int = 0) -> int:
    if isinstance(v, bool):
        return int(default)
    if isinstance(v, int):
        return int(v)
    return int(default)


def _stream_carve(
    *,
    firmware_path: Path,
    out_path: Path,
    offset: int,
    size: int,
    chunk_size: int = 1024 * 1024,
) -> int:
    if offset < 0 or size <= 0:
        return 0

    fw_size = firmware_path.stat().st_size
    if offset >= fw_size:
        return 0

    to_take = min(int(size), int(fw_size - offset))
    if to_take <= 0:
        return 0

    tmp_path = out_path.with_suffix(out_path.suffix + ".tmp")
    wrote = 0
    try:
        with firmware_path.open("rb") as in_f, tmp_path.open("wb") as out_f:
            _ = in_f.seek(int(offset))
            left = int(to_take)
            while left > 0:
                chunk = in_f.read(min(int(chunk_size), left))
                if not chunk:
                    break
                _ = out_f.write(chunk)
                wrote += len(chunk)
                left -= len(chunk)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        return 0

    if wrote <= 0:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        return 0

    try:
        _ = tmp_path.replace(out_path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        return 0

    return int(wrote)


def _bounded_signature_scan(
    firmware_path: Path,
    *,
    max_scan_bytes: int,
    max_hits: int,
    magics: list[tuple[str, bytes]],
) -> list[tuple[str, int]]:
    hits: list[tuple[str, int]] = []
    if not firmware_path.is_file():
        return hits

    fw_size = firmware_path.stat().st_size
    scan_limit = min(int(max_scan_bytes), int(fw_size))
    if scan_limit <= 0:
        return hits

    chunk_size = 1024 * 1024
    overlap = max((len(b) for _, b in magics), default=4) - 1
    prev = b""
    pos = 0
    seen_offs: set[int] = set()

    with firmware_path.open("rb") as f:
        while pos < scan_limit and len(hits) < int(max_hits):
            to_read = min(int(chunk_size), int(scan_limit - pos))
            chunk = f.read(to_read)
            if not chunk:
                break

            hay = prev + chunk
            start_off = pos - len(prev)
            for name, magic in magics:
                i = 0
                while len(hits) < int(max_hits):
                    j = hay.find(magic, i)
                    if j < 0:
                        break
                    off = int(start_off + j)
                    if off >= 0 and off not in seen_offs:
                        hits.append((name, off))
                        seen_offs.add(off)
                    i = j + 1

            if len(chunk) >= overlap:
                prev = chunk[-overlap:]
            else:
                prev = chunk
            pos += to_read

    return hits


@dataclass(frozen=True)
class CarvingStage:
    firmware_path: Path
    max_total_bytes: int = 5 * 1024 * 1024 * 1024
    max_attempts: int = 100
    max_signature_scan_bytes: int = 256 * 1024 * 1024
    evidence_slice_bytes: int = 1024 * 1024
    unsquashfs_timeout_s: float = 60.0
    unsquashfs_extract_timeout_s: float = 300.0
    max_unsquashfs_extract_bytes: int = 512 * 1024 * 1024

    @property
    def name(self) -> str:
        return "carving"

    def run(self, ctx: StageContext) -> StageOutcome:
        fw = self.firmware_path
        stage_dir = ctx.run_dir / "stages" / "carving"
        blobs_dir = stage_dir / "blobs"
        roots_dir = stage_dir / "roots"
        evidence_dir = stage_dir / "evidence"
        log_path = stage_dir / "carving.log"
        partitions_path = stage_dir / "partitions.json"
        roots_path = stage_dir / "roots.json"

        _assert_under_dir(ctx.run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(stage_dir, blobs_dir)
        blobs_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(stage_dir, roots_dir)
        roots_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(stage_dir, evidence_dir)
        evidence_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(stage_dir, partitions_path)
        _assert_under_dir(stage_dir, roots_path)
        _assert_under_dir(stage_dir, log_path)

        evidence: list[str] = [
            _rel_to_run_dir(ctx.run_dir, stage_dir),
            _rel_to_run_dir(ctx.run_dir, partitions_path),
            _rel_to_run_dir(ctx.run_dir, roots_path),
        ]
        limitations: list[str] = []

        unsquashfs_path = shutil.which("unsquashfs")
        tools: dict[str, JsonValue] = {"unsquashfs_available": bool(unsquashfs_path)}

        partitions: list[dict[str, JsonValue]] = []
        roots: list[str] = []
        wrote_any = False
        bytes_written = 0
        attempts = 0
        used_partition_inference = False

        def write_roots_json() -> None:
            payload = {"roots": list(roots)}
            _ = roots_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

        def write_partitions_json(status: StageStatus) -> None:
            payload: dict[str, JsonValue] = {
                "status": status,
                "firmware": _rel_to_run_dir(ctx.run_dir, fw),
                "partitions": cast(list[JsonValue], cast(list[object], partitions)),
                "tools": tools,
                "limitations": cast(list[JsonValue], list(limitations)),
                "evidence": cast(list[JsonValue], list(evidence)),
            }
            _ = partitions_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

        def add_evidence_path(p: Path) -> None:
            rel = _rel_to_run_dir(ctx.run_dir, p)
            if rel and rel not in evidence:
                evidence.append(rel)

        _append_log(log_path, f"firmware: {_rel_to_run_dir(ctx.run_dir, fw)}")
        _append_log(log_path, f"max_total_bytes: {int(self.max_total_bytes)}")
        _append_log(log_path, f"max_attempts: {int(self.max_attempts)}")

        structure_path = ctx.run_dir / "stages" / "structure" / "structure.json"
        mtdparts_terms: list[str] = []
        if structure_path.is_file():
            structure_obj = _load_json_obj(structure_path)
            if structure_obj is None:
                limitations.append(
                    "structure.json present but invalid JSON; cannot infer partitions"
                )
            else:
                mtdparts_terms = _extract_mtdparts_terms(structure_obj)
                if not mtdparts_terms:
                    limitations.append(
                        "No bootargs.terms.mtdparts found in structure.json"
                    )
        else:
            limitations.append("Missing structure.json; cannot infer partitions")

        inferred: list[dict[str, JsonValue]] = []
        if mtdparts_terms:
            used_partition_inference = True
            for term in mtdparts_terms:
                try:
                    rep = cast(dict[str, object], parse_mtdparts(term))
                except Exception as exc:
                    limitations.append(
                        f"mtdparts parse failed for term={term!r}: {type(exc).__name__}: {exc}"
                    )
                    continue

                devs_any = rep.get("devices")
                if not isinstance(devs_any, list):
                    continue
                for dev_any in cast(list[object], devs_any):
                    if not isinstance(dev_any, dict):
                        continue
                    dev = cast(dict[str, object], dev_any)
                    dev_id_any = dev.get("id")
                    dev_id = dev_id_any if isinstance(dev_id_any, str) else ""
                    parts_any = dev.get("parts")
                    if not isinstance(parts_any, list):
                        continue
                    for p_any in cast(list[object], parts_any):
                        if not isinstance(p_any, dict):
                            continue
                        pobj = cast(dict[str, object], p_any)
                        name_any = pobj.get("name")
                        name = name_any if isinstance(name_any, str) else ""
                        off_any = pobj.get("offset_bytes")
                        size_any = pobj.get("size_bytes")

                        if not isinstance(off_any, int):
                            continue
                        off = int(off_any)
                        size: int | None
                        if isinstance(size_any, int):
                            size = int(size_any)
                        elif size_any is None:
                            size = None
                        else:
                            size = None

                        inferred.append(
                            {
                                "device": dev_id,
                                "name": name,
                                "safe_name": _sanitize_name(name, fallback="part"),
                                "offset_bytes": int(off),
                                "size_bytes": size,
                            }
                        )

        seen_keys: set[tuple[int, int | None, str]] = set()
        for p in sorted(
            inferred,
            key=lambda x: (
                _json_int(x.get("offset_bytes", 0)),
                str(x.get("safe_name", "")),
            ),
        ):
            off = _json_int(p.get("offset_bytes", 0))
            size_v = p.get("size_bytes")
            size2: int | None
            if isinstance(size_v, int):
                size2 = int(size_v)
            else:
                size2 = None
            safe = str(p.get("safe_name") or "part")
            key = (off, size2, safe)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            partitions.append(p)

        if not fw.is_file():
            limitations.append("Firmware file missing; carving cannot run")
            write_roots_json()
            write_partitions_json("failed")
            return StageOutcome(
                status="failed",
                details={
                    "stage_dir": _rel_to_run_dir(ctx.run_dir, stage_dir),
                    "firmware": _rel_to_run_dir(ctx.run_dir, fw),
                    "partitions_json": _rel_to_run_dir(ctx.run_dir, partitions_path),
                    "roots_json": _rel_to_run_dir(ctx.run_dir, roots_path),
                    "evidence": cast(list[JsonValue], list(evidence)),
                    "tools": tools,
                },
                limitations=limitations,
            )

        fw_size = fw.stat().st_size
        _append_log(log_path, f"firmware_size_bytes: {int(fw_size)}")

        def remaining_budget() -> int:
            return max(0, int(self.max_total_bytes) - int(bytes_written))

        def carve_blob(
            *,
            offset: int,
            size_bytes: int | None,
            safe_name: str,
            idx: int,
        ) -> tuple[Path | None, int]:
            nonlocal bytes_written
            if attempts >= int(self.max_attempts):
                return None, 0

            if offset < 0 or offset >= fw_size:
                return None, 0

            if size_bytes is None:
                desired = int(fw_size - offset)
            else:
                desired = int(size_bytes)

            desired = max(0, desired)
            desired = min(desired, int(fw_size - offset))
            desired = min(desired, remaining_budget())
            if desired <= 0:
                return None, 0

            name = _sanitize_name(safe_name, fallback=f"part{idx:03d}")
            out_path = (
                blobs_dir / f"{idx:03d}_{name}_off-0x{offset:x}_size-{desired}.bin"
            )
            _assert_under_dir(blobs_dir, out_path)
            wrote = _stream_carve(
                firmware_path=fw,
                out_path=out_path,
                offset=int(offset),
                size=int(desired),
            )
            if wrote > 0:
                bytes_written += int(wrote)
                add_evidence_path(out_path)
                return out_path, int(wrote)
            return None, 0

        def maybe_unsquashfs(*, blob: Path, root_name: str) -> Path | None:
            if not unsquashfs_path:
                return None

            try:
                blob_size = blob.stat().st_size
            except OSError:
                return None

            argv_s = [unsquashfs_path, "-s", str(blob)]
            _append_log(log_path, f"unsquashfs -s argv: {argv_s}")
            try:
                res = subprocess.run(
                    list(argv_s),
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=float(self.unsquashfs_timeout_s),
                )
            except subprocess.TimeoutExpired:
                limitations.append(
                    f"unsquashfs -s timed out after {self.unsquashfs_timeout_s}s for {blob.name}"
                )
                return None
            except Exception as exc:
                limitations.append(
                    f"unsquashfs -s crashed: {type(exc).__name__}: {exc}"
                )
                return None

            _append_log(log_path, f"unsquashfs -s returncode: {res.returncode}")
            if res.stdout:
                _append_log(
                    log_path,
                    "--- unsquashfs -s stdout (trunc) ---\n" + res.stdout[:4096],
                )
            if res.stderr:
                _append_log(
                    log_path,
                    "--- unsquashfs -s stderr (trunc) ---\n" + res.stderr[:4096],
                )

            if res.returncode != 0:
                limitations.append(
                    f"unsquashfs -s failed for {blob.name} (rc={res.returncode})"
                )
                return None

            if blob_size > int(self.max_unsquashfs_extract_bytes):
                limitations.append(
                    f"Skipping unsquashfs extract for {blob.name}: blob too large ({blob_size} bytes)"
                )
                return None
            if remaining_budget() <= 0:
                limitations.append(
                    f"Skipping unsquashfs extract for {blob.name}: stage byte budget exhausted"
                )
                return None

            root_safe = _sanitize_name(root_name, fallback="root")
            root_dir = roots_dir / root_safe
            _assert_under_dir(roots_dir, root_dir)

            if root_dir.exists():
                for i in range(1, 1000):
                    alt = roots_dir / f"{root_safe}_{i}"
                    _assert_under_dir(roots_dir, alt)
                    if not alt.exists():
                        root_dir = alt
                        break

            root_dir.mkdir(parents=True, exist_ok=False)
            add_evidence_path(root_dir)

            argv_x = [unsquashfs_path, "-d", str(root_dir), str(blob)]
            _append_log(log_path, f"unsquashfs -d argv: {argv_x}")
            try:
                res2 = subprocess.run(
                    list(argv_x),
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=float(self.unsquashfs_extract_timeout_s),
                )
            except subprocess.TimeoutExpired:
                limitations.append(
                    f"unsquashfs extract timed out after {self.unsquashfs_extract_timeout_s}s for {blob.name}"
                )
                return None
            except Exception as exc:
                limitations.append(
                    f"unsquashfs extract crashed: {type(exc).__name__}: {exc}"
                )
                return None

            _append_log(log_path, f"unsquashfs extract returncode: {res2.returncode}")
            if res2.stdout:
                _append_log(
                    log_path,
                    "--- unsquashfs extract stdout (trunc) ---\n" + res2.stdout[:4096],
                )
            if res2.stderr:
                _append_log(
                    log_path,
                    "--- unsquashfs extract stderr (trunc) ---\n" + res2.stderr[:4096],
                )
            if res2.returncode != 0:
                limitations.append(
                    f"unsquashfs extract failed for {blob.name} (rc={res2.returncode})"
                )
                return None

            return root_dir

        if partitions:
            used_partition_inference = True
            _append_log(log_path, f"inferred_partitions: {len(partitions)}")
            for idx, p in enumerate(partitions[: int(self.max_attempts)]):
                if attempts >= int(self.max_attempts):
                    break
                attempts += 1
                off = _json_int(p.get("offset_bytes", 0))
                size_any = p.get("size_bytes")
                size = int(size_any) if isinstance(size_any, int) else None
                safe_name = str(p.get("safe_name") or p.get("name") or "part")

                blob, wrote = carve_blob(
                    offset=off,
                    size_bytes=size,
                    safe_name=safe_name,
                    idx=idx,
                )
                if blob is None or wrote <= 0:
                    p["carved"] = False
                    continue

                wrote_any = True
                p["carved"] = True
                p["blob"] = _rel_to_run_dir(ctx.run_dir, blob)
                p["carved_bytes"] = int(wrote)

                det = _detect_blob_magic(blob)
                p["detected"] = cast(dict[str, JsonValue], cast(object, det))
                if det.get("squashfs"):
                    root = maybe_unsquashfs(blob=blob, root_name=safe_name)
                    if root is not None and root.is_dir():
                        rel_root = _rel_to_run_dir(ctx.run_dir, root)
                        if rel_root not in roots:
                            roots.append(rel_root)
                            add_evidence_path(root)
        else:
            _append_log(log_path, "no_partitions_inferred: true")

            magics = [
                ("squashfs_hsqs", b"hsqs"),
                ("squashfs_sqsh", b"sqsh"),
                ("ubi", b"UBI#"),
                ("dtb", (0xD00DFEED).to_bytes(4, "big", signed=False)),
            ]
            hits = _bounded_signature_scan(
                fw,
                max_scan_bytes=int(self.max_signature_scan_bytes),
                max_hits=int(self.max_attempts),
                magics=magics,
            )
            _append_log(log_path, f"signature_hits: {len(hits)}")

            for hit_idx, (kind, off) in enumerate(hits[: int(self.max_attempts)]):
                if attempts >= int(self.max_attempts):
                    break
                if remaining_budget() <= 0:
                    limitations.append(
                        "Stage byte budget exhausted; stopping signature evidence carving"
                    )
                    break
                attempts += 1

                slice_len = min(
                    int(self.evidence_slice_bytes),
                    int(fw_size - off),
                    remaining_budget(),
                )
                if slice_len <= 0:
                    continue

                out_path = (
                    evidence_dir
                    / f"evidence_{hit_idx:03d}_{_sanitize_name(kind)}_off-0x{off:x}_len-{slice_len}.bin"
                )
                _assert_under_dir(evidence_dir, out_path)
                wrote = _stream_carve(
                    firmware_path=fw,
                    out_path=out_path,
                    offset=int(off),
                    size=int(slice_len),
                )
                if wrote > 0:
                    wrote_any = True
                    bytes_written += int(wrote)
                    add_evidence_path(out_path)

        write_roots_json()
        status: StageStatus = "ok" if wrote_any else "partial"
        if not wrote_any:
            limitations.append("No carve attempts produced any output")

        write_partitions_json(status)

        details: dict[str, JsonValue] = {
            "stage_dir": _rel_to_run_dir(ctx.run_dir, stage_dir),
            "firmware": _rel_to_run_dir(ctx.run_dir, fw),
            "structure_json": _rel_to_run_dir(ctx.run_dir, structure_path),
            "partitions_json": _rel_to_run_dir(ctx.run_dir, partitions_path),
            "roots_json": _rel_to_run_dir(ctx.run_dir, roots_path),
            "used_partition_inference": bool(used_partition_inference),
            "mtdparts_terms": cast(list[JsonValue], list(mtdparts_terms)),
            "partition_count": int(len(partitions)),
            "roots_count": int(len(roots)),
            "bytes_written": int(bytes_written),
            "max_total_bytes": int(self.max_total_bytes),
            "attempts": int(attempts),
            "max_attempts": int(self.max_attempts),
            "tools": tools,
            "evidence": cast(list[JsonValue], list(evidence)),
        }
        if log_path.is_file():
            add_evidence_path(log_path)
            details["carving_log"] = _rel_to_run_dir(ctx.run_dir, log_path)

        return StageOutcome(status=status, details=details, limitations=limitations)
