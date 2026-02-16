from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
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


_DTB_MAGIC = 0xD00DFEED
_DTB_HEADER_BYTES = 40


@dataclass(frozen=True)
class _DtbHeader:
    magic: int
    totalsize: int
    off_dt_struct: int
    off_dt_strings: int
    off_mem_rsvmap: int
    version: int
    last_comp_version: int
    boot_cpuid_phys: int
    size_dt_strings: int
    size_dt_struct: int


def _be_u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off : off + 4], "big", signed=False)


def _parse_dtb_header(buf: bytes) -> _DtbHeader | None:
    if len(buf) < _DTB_HEADER_BYTES:
        return None

    magic = _be_u32(buf, 0)
    if magic != _DTB_MAGIC:
        return None

    hdr = _DtbHeader(
        magic=magic,
        totalsize=_be_u32(buf, 4),
        off_dt_struct=_be_u32(buf, 8),
        off_dt_strings=_be_u32(buf, 12),
        off_mem_rsvmap=_be_u32(buf, 16),
        version=_be_u32(buf, 20),
        last_comp_version=_be_u32(buf, 24),
        boot_cpuid_phys=_be_u32(buf, 28),
        size_dt_strings=_be_u32(buf, 32),
        size_dt_struct=_be_u32(buf, 36),
    )

    if hdr.totalsize < _DTB_HEADER_BYTES:
        return None
    if any(
        x >= hdr.totalsize
        for x in (hdr.off_dt_struct, hdr.off_dt_strings, hdr.off_mem_rsvmap)
    ):
        return None

    return hdr


_BINWALK_DTB_RE = re.compile(
    r"Flattened device tree,\s*size:\s*(?P<size>\d+)\s*bytes",
    re.IGNORECASE,
)


def _parse_binwalk_dtb_hits(log_path: Path) -> list[tuple[int, int]]:
    hits: list[tuple[int, int]] = []
    if not log_path.is_file():
        return hits

    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return hits

    for line in text.splitlines():
        if "Flattened device tree" not in line and "flattened device tree" not in line:
            continue

        m = _BINWALK_DTB_RE.search(line)
        if not m:
            continue
        try:
            size = int(m.group("size"))
        except Exception:
            continue
        if size <= 0:
            continue

        tokens = line.strip().split()
        if not tokens:
            continue

        offset: int | None = None
        for tok in tokens[:3]:
            if tok.startswith("0x"):
                try:
                    offset = int(tok, 16)
                    break
                except Exception:
                    continue
            if tok.isdigit():
                try:
                    offset = int(tok)
                    break
                except Exception:
                    continue
        if offset is None or offset < 0:
            continue

        hits.append((offset, size))

    return hits


def _scan_for_dtb_magic(
    firmware_path: Path,
    *,
    max_scan_bytes: int,
    max_hits: int,
    max_totalsize: int,
) -> list[tuple[int, int]]:
    hits: list[tuple[int, int]] = []
    if not firmware_path.is_file():
        return hits

    file_size = firmware_path.stat().st_size
    scan_limit = min(int(max_scan_bytes), int(file_size))
    if scan_limit <= 0:
        return hits

    magic_bytes = _DTB_MAGIC.to_bytes(4, "big", signed=False)
    chunk_size = 1024 * 1024
    overlap = len(magic_bytes) - 1

    with firmware_path.open("rb") as scan_f, firmware_path.open("rb") as hdr_f:
        pos = 0
        prev = b""
        while pos < scan_limit and len(hits) < int(max_hits):
            to_read = min(chunk_size, scan_limit - pos)
            chunk = scan_f.read(to_read)
            if not chunk:
                break

            hay = prev + chunk
            start_off = pos - len(prev)

            i = 0
            while len(hits) < int(max_hits):
                j = hay.find(magic_bytes, i)
                if j < 0:
                    break

                hit_pos = start_off + j
                if 0 <= hit_pos <= file_size - _DTB_HEADER_BYTES:
                    try:
                        _ = hdr_f.seek(hit_pos)
                        hdr_buf = hdr_f.read(_DTB_HEADER_BYTES)
                    except Exception:
                        hdr_buf = b""

                    hdr = _parse_dtb_header(hdr_buf)
                    if hdr is not None and 0 < hdr.totalsize <= int(max_totalsize):
                        hits.append((int(hit_pos), int(hdr.totalsize)))

                i = j + 1

            if len(chunk) >= overlap:
                prev = chunk[-overlap:]
            else:
                prev = chunk

            pos += to_read

    return hits


_BOOTARGS_DTS_RE = re.compile(r"\bbootargs\s*=\s*\"(?P<val>[^\"]*)\"\s*;", re.I)


_BOOTARG_KEYS = [
    "mtdparts",
    "ubi.mtd",
    "root",
    "rootfstype",
    "console",
]


def _extract_cstring(buf: bytes, *, pos: int, max_len: int) -> str:
    if pos < 0 or pos >= len(buf):
        return ""
    s = pos
    while s > 0 and buf[s - 1] != 0:
        s -= 1
    e = pos
    while e < len(buf) and buf[e] != 0 and (e - s) < int(max_len):
        e += 1
    try:
        return buf[s:e].decode("ascii", errors="ignore")
    except Exception:
        return ""


def _bootarg_tokens_from_text(text: str) -> list[str]:
    toks: list[str] = []
    for k in _BOOTARG_KEYS:
        pat = re.compile(r"\b" + re.escape(k) + r"=\S+")
        for m in pat.finditer(text):
            tok = m.group(0)
            if tok and tok not in toks:
                toks.append(tok)
    return toks


def _scan_firmware_for_bootargs(
    fw: Path, *, max_scan_bytes: int, max_hits: int
) -> list[str]:
    try:
        with fw.open("rb") as f:
            data = f.read(int(max_scan_bytes))
    except Exception:
        return []

    needles = [bytes(k + "=", "ascii") for k in _BOOTARG_KEYS]
    hits: list[int] = []
    for needle in needles:
        i = 0
        while len(hits) < int(max_hits):
            j = data.find(needle, i)
            if j < 0:
                break
            hits.append(int(j))
            i = int(j) + 1

    out: list[str] = []
    seen: set[str] = set()
    for off in sorted(set(hits)):
        cstr = _extract_cstring(data, pos=int(off), max_len=4096)
        toks = _bootarg_tokens_from_text(cstr)
        if not toks:
            continue
        line = " ".join(toks)
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
        if len(out) >= int(max_hits):
            break

    return out


def _extract_bootargs_terms(bootargs: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {k: [] for k in _BOOTARG_KEYS}
    for token in bootargs.split():
        for k in _BOOTARG_KEYS:
            prefix = k + "="
            if token.startswith(prefix):
                out[k].append(token[len(prefix) :])
    return out


def _append_log(log_path: Path, text: str) -> None:
    try:
        _ = log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as f:
            _ = f.write(text)
            if not text.endswith("\n"):
                _ = f.write("\n")
    except Exception:
        return


@dataclass(frozen=True)
class StructureStage:
    firmware_path: Path
    max_dtbs: int = 50
    max_dtb_bytes: int = 4 * 1024 * 1024
    max_scan_bytes: int = 256 * 1024 * 1024
    dtc_timeout_s: float = 15.0
    fdtget_timeout_s: float = 3.0

    @property
    def name(self) -> str:
        return "structure"

    def run(self, ctx: StageContext) -> StageOutcome:
        fw = self.firmware_path
        stage_dir = ctx.run_dir / "stages" / "structure"
        dtb_dir = stage_dir / "dtb"
        log_path = stage_dir / "structure.log"
        out_json = stage_dir / "structure.json"

        _assert_under_dir(ctx.run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(stage_dir, dtb_dir)
        dtb_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(stage_dir, log_path)
        _assert_under_dir(stage_dir, out_json)

        evidence: list[str] = [
            _rel_to_run_dir(ctx.run_dir, stage_dir),
            _rel_to_run_dir(ctx.run_dir, dtb_dir),
            _rel_to_run_dir(ctx.run_dir, out_json),
            _rel_to_run_dir(ctx.run_dir, log_path),
        ]

        limitations: list[str] = []
        reasons: list[str] = []
        details: dict[str, JsonValue] = {
            "stage_dir": _rel_to_run_dir(ctx.run_dir, stage_dir),
            "firmware": _rel_to_run_dir(ctx.run_dir, fw),
        }

        _append_log(log_path, f"firmware: {details['firmware']}")

        if not fw.is_file():
            limitations.append("Firmware file missing; structure stage cannot run.")
            details["evidence"] = cast(list[JsonValue], list(evidence))
            _ = out_json.write_text(
                json.dumps(
                    {
                        "status": "failed",
                        "dtbs": [],
                        "bootargs": {"raw": [], "terms": {}},
                        "limitations": limitations,
                        "evidence": evidence,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            return StageOutcome(
                status="failed", details=details, limitations=limitations
            )

        fw_size = fw.stat().st_size
        _append_log(log_path, f"firmware_size_bytes: {fw_size}")
        extraction_log = ctx.run_dir / "stages" / "extraction" / "binwalk.log"
        candidates = _parse_binwalk_dtb_hits(extraction_log)
        used_binwalk = bool(candidates)

        if candidates:
            reasons.append(f"Found {len(candidates)} DTB candidate(s) in binwalk log")
        else:
            reasons.append(
                "No DTB candidates in binwalk log; falling back to magic scan"
            )
            candidates = _scan_for_dtb_magic(
                fw,
                max_scan_bytes=int(self.max_scan_bytes),
                max_hits=int(self.max_dtbs),
                max_totalsize=int(self.max_dtb_bytes),
            )

        used_magic_scan = not used_binwalk
        if used_magic_scan:
            if candidates:
                reasons.append(f"Magic scan found {len(candidates)} DTB candidate(s)")
            else:
                reasons.append("Magic scan found no DTB candidates")

        details["discovery"] = {
            "binwalk_log": _rel_to_run_dir(ctx.run_dir, extraction_log),
            "binwalk_used": bool(used_binwalk),
            "magic_scan_used": bool(used_magic_scan),
            "candidates": int(len(candidates)),
            "max_scan_bytes": int(min(int(self.max_scan_bytes), int(fw_size))),
        }

        dtc_path = shutil.which("dtc")
        fdtget_path = shutil.which("fdtget")
        details["tools"] = {
            "dtc_available": bool(dtc_path),
            "fdtget_available": bool(fdtget_path),
        }

        extracted: list[dict[str, JsonValue]] = []
        bootargs_raw: list[str] = []
        bootargs_terms: dict[str, list[str]] = {
            "mtdparts": [],
            "ubi.mtd": [],
            "root": [],
            "rootfstype": [],
            "console": [],
        }

        seen_sha256: set[str] = set()
        warned_dtc_missing = False
        warned_fdtget_missing = False

        def merge_terms(src: dict[str, list[str]]) -> None:
            for k, vals in src.items():
                if k in bootargs_terms:
                    for v in vals:
                        if v and v not in bootargs_terms[k]:
                            bootargs_terms[k].append(v)

        with fw.open("rb") as f:
            for i, (off, size_hint) in enumerate(candidates[: int(self.max_dtbs)]):
                if off < 0 or off > fw_size - _DTB_HEADER_BYTES:
                    continue
                try:
                    _ = f.seek(int(off))
                    hdr_buf = f.read(_DTB_HEADER_BYTES)
                except Exception:
                    continue

                hdr = _parse_dtb_header(hdr_buf)
                if hdr is None:
                    continue

                totalsize = int(hdr.totalsize)
                extract_size = totalsize
                if extract_size <= 0:
                    continue

                if extract_size > int(self.max_dtb_bytes):
                    limitations.append(
                        f"DTB totalsize capped: offset=0x{off:x} totalsize={extract_size} cap={int(self.max_dtb_bytes)}"
                    )
                    extract_size = int(self.max_dtb_bytes)

                remaining = fw_size - int(off)
                if extract_size > remaining:
                    limitations.append(
                        f"DTB totalsize exceeds EOF: offset=0x{off:x} totalsize={totalsize} remaining={remaining}; extracting remaining bytes"
                    )
                    extract_size = int(max(0, remaining))

                if extract_size < _DTB_HEADER_BYTES:
                    continue

                name = f"dtb_{i:03d}_off-0x{off:x}_size-{extract_size}.dtb"
                dtb_path = dtb_dir / name
                _assert_under_dir(dtb_dir, dtb_path)

                h = hashlib.sha256()
                try:
                    _ = f.seek(int(off))
                except Exception:
                    continue

                tmp_path = dtb_path.with_suffix(dtb_path.suffix + ".tmp")
                _assert_under_dir(dtb_dir, tmp_path)

                wrote = 0
                try:
                    with tmp_path.open("wb") as out_f:
                        left = int(extract_size)
                        while left > 0:
                            chunk = f.read(min(left, 1024 * 1024))
                            if not chunk:
                                break
                            _ = out_f.write(chunk)
                            h.update(chunk)
                            wrote += len(chunk)
                            left -= len(chunk)
                except Exception:
                    try:
                        tmp_path.unlink(missing_ok=True)
                    except Exception:
                        pass
                    continue

                sha = h.hexdigest()
                if sha in seen_sha256:
                    try:
                        tmp_path.unlink(missing_ok=True)
                    except Exception:
                        pass
                    continue
                seen_sha256.add(sha)

                try:
                    _ = tmp_path.replace(dtb_path)
                except Exception:
                    try:
                        tmp_path.unlink(missing_ok=True)
                    except Exception:
                        pass
                    continue

                evidence.append(_rel_to_run_dir(ctx.run_dir, dtb_path))

                dtb_obj: dict[str, JsonValue] = {
                    "path": _rel_to_run_dir(ctx.run_dir, dtb_path),
                    "offset": int(off),
                    "offset_hex": f"0x{off:x}",
                    "totalsize": int(totalsize),
                    "extracted_size": int(wrote),
                    "sha256": sha,
                }
                if int(size_hint) > 0:
                    dtb_obj["binwalk_size_hint"] = int(size_hint)

                dts_path: Path | None = None
                if dtc_path:
                    dts_path = dtb_path.with_suffix(".dts")
                    _assert_under_dir(dtb_dir, dts_path)
                    argv = [
                        dtc_path,
                        "-I",
                        "dtb",
                        "-O",
                        "dts",
                        str(dtb_path),
                        "-o",
                        str(dts_path),
                    ]
                    _append_log(log_path, f"dtc argv: {argv}")
                    try:
                        res = subprocess.run(
                            list(argv),
                            text=True,
                            capture_output=True,
                            check=False,
                            timeout=float(self.dtc_timeout_s),
                        )
                        _append_log(log_path, f"dtc returncode: {res.returncode}")
                        if res.stdout:
                            _append_log(log_path, "--- dtc stdout ---\n" + res.stdout)
                        if res.stderr:
                            _append_log(log_path, "--- dtc stderr ---\n" + res.stderr)
                        if res.returncode != 0 or not dts_path.is_file():
                            limitations.append(
                                f"dtc failed for {dtb_path.name} (rc={res.returncode})"
                            )
                            dts_path = None
                        else:
                            evidence.append(_rel_to_run_dir(ctx.run_dir, dts_path))
                            dtb_obj["dts"] = _rel_to_run_dir(ctx.run_dir, dts_path)
                    except subprocess.TimeoutExpired:
                        limitations.append(
                            f"dtc timed out after {self.dtc_timeout_s}s for {dtb_path.name}"
                        )
                        dts_path = None
                    except Exception as exc:
                        limitations.append(
                            f"dtc invocation crashed: {type(exc).__name__}: {exc}"
                        )
                        dts_path = None
                else:
                    if not warned_dtc_missing:
                        limitations.append("dtc not available; skipping DTB decompile")
                        warned_dtc_missing = True

                dtb_bootargs: list[str] = []
                if fdtget_path:
                    argv2 = [
                        fdtget_path,
                        "-t",
                        "s",
                        str(dtb_path),
                        "/chosen",
                        "bootargs",
                    ]
                    _append_log(log_path, f"fdtget argv: {argv2}")
                    try:
                        res2 = subprocess.run(
                            list(argv2),
                            text=True,
                            capture_output=True,
                            check=False,
                            timeout=float(self.fdtget_timeout_s),
                        )
                        _append_log(log_path, f"fdtget returncode: {res2.returncode}")
                        if res2.stdout:
                            _append_log(
                                log_path, "--- fdtget stdout ---\n" + res2.stdout
                            )
                        if res2.stderr:
                            _append_log(
                                log_path, "--- fdtget stderr ---\n" + res2.stderr
                            )
                        if res2.returncode == 0:
                            out = (res2.stdout or "").strip()
                            if out:
                                dtb_bootargs.append(out)
                    except subprocess.TimeoutExpired:
                        limitations.append(
                            f"fdtget timed out after {self.fdtget_timeout_s}s for {dtb_path.name}"
                        )
                    except Exception as exc:
                        limitations.append(
                            f"fdtget invocation crashed: {type(exc).__name__}: {exc}"
                        )
                else:
                    if not warned_fdtget_missing:
                        limitations.append(
                            "fdtget not available; bootargs extraction may be incomplete"
                        )
                        warned_fdtget_missing = True

                if not dtb_bootargs and dts_path and dts_path.is_file():
                    try:
                        dts_text = dts_path.read_text(
                            encoding="utf-8", errors="replace"
                        )
                    except Exception:
                        dts_text = ""
                    for m in _BOOTARGS_DTS_RE.finditer(dts_text):
                        val = m.group("val")
                        if val:
                            dtb_bootargs.append(val)

                if dtb_bootargs:
                    dtb_obj["bootargs"] = cast(list[JsonValue], list(dtb_bootargs))
                    for ba in dtb_bootargs:
                        if ba not in bootargs_raw:
                            bootargs_raw.append(ba)
                        merge_terms(_extract_bootargs_terms(ba))

                extracted.append(dtb_obj)

        bootargs_from_firmware = _scan_firmware_for_bootargs(
            fw,
            max_scan_bytes=int(min(int(self.max_scan_bytes), int(fw_size))),
            max_hits=50,
        )
        if bootargs_from_firmware:
            details["bootargs_string_scan"] = {
                "used": True,
                "found": int(len(bootargs_from_firmware)),
                "max_scan_bytes": int(min(int(self.max_scan_bytes), int(fw_size))),
            }
            for ba in bootargs_from_firmware:
                if ba not in bootargs_raw:
                    bootargs_raw.append(ba)
                merge_terms(_extract_bootargs_terms(ba))
        else:
            details["bootargs_string_scan"] = {
                "used": True,
                "found": 0,
                "max_scan_bytes": int(min(int(self.max_scan_bytes), int(fw_size))),
            }

        if not extracted:
            limitations.append("No DTBs were extracted.")

        if extracted:
            reasons.append(f"Extracted {len(extracted)} unique DTB(s)")

        status: StageStatus
        if not extracted:
            status = "partial"
        elif limitations:
            status = "partial"
        else:
            status = "ok"

        structure_obj: dict[str, JsonValue] = {
            "status": status,
            "dtbs": cast(list[JsonValue], cast(list[object], extracted)),
            "bootargs": {
                "raw": cast(list[JsonValue], list(bootargs_raw)),
                "terms": cast(dict[str, JsonValue], cast(object, bootargs_terms)),
            },
            "discovery": cast(dict[str, JsonValue], details.get("discovery", {})),
            "tools": cast(dict[str, JsonValue], details.get("tools", {})),
            "limitations": cast(list[JsonValue], list(limitations)),
            "evidence": cast(list[JsonValue], list(evidence)),
        }

        _ = out_json.write_text(
            json.dumps(structure_obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        details["reasons"] = cast(list[JsonValue], list(reasons))
        details["dtb_count"] = int(len(extracted))
        details["structure_json"] = _rel_to_run_dir(ctx.run_dir, out_json)
        details["evidence"] = cast(list[JsonValue], list(evidence))
        return StageOutcome(status=status, details=details, limitations=limitations)
