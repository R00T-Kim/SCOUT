"""Tolerant parser for Linux kernel cmdline `mtdparts=` strings."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import TypeAlias


JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)


_NUM_RE = re.compile(r"^(0[xX][0-9a-fA-F]+|\d+)([kKmMgG])?$")


@dataclass(frozen=True, slots=True)
class Partition:
    raw: str
    name: str
    size_bytes: int | None
    offset_bytes: int
    flags: list[str]

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "raw": self.raw,
            "name": self.name,
            "size_bytes": self.size_bytes,
            "offset_bytes": self.offset_bytes,
            "flags": list(self.flags),
        }


@dataclass(frozen=True, slots=True)
class DevicePartitions:
    id: str
    raw: str
    errors: list[str]
    parts: list[Partition]

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "id": self.id,
            "raw": self.raw,
            "errors": list(self.errors),
            "parts": [p.to_json() for p in self.parts],
        }


def parse_mtdparts(s: str) -> dict[str, JsonValue]:
    """Parse an `mtdparts=`-style string.

    Returns a deterministic structure and accumulates errors per-device.
    Raises ValueError only for an empty/whitespace input.
    """

    raw = s
    stripped = raw.strip()
    if not stripped:
        raise ValueError("empty mtdparts string")

    if stripped.startswith("mtdparts="):
        stripped = stripped[len("mtdparts=") :]

    devices: list[DevicePartitions] = []
    for idx, dev_seg in enumerate(_split_nonempty(stripped, ";")):
        dev = _parse_device(dev_seg, idx)
        devices.append(dev)

    return {
        "raw": raw,
        "devices": [d.to_json() for d in devices],
    }


def _split_nonempty(s: str, sep: str) -> list[str]:
    return [p.strip() for p in s.split(sep) if p.strip()]


def _parse_device(dev_seg: str, idx: int) -> DevicePartitions:
    errors: list[str] = []
    if ":" not in dev_seg:
        dev_id = f"<unknown-{idx}>"
        parts_str = dev_seg
        errors.append("missing ':' between mtd-id and partitions")
    else:
        dev_id_raw, parts_str = dev_seg.split(":", 1)
        dev_id = dev_id_raw.strip() or f"<unknown-{idx}>"
        if not dev_id_raw.strip():
            errors.append("empty mtd-id")

    parts: list[Partition] = []
    next_offset: int = 0
    next_offset_known = True

    part_segs = [p.strip() for p in parts_str.split(",")]
    if not any(p for p in part_segs):
        errors.append("no partition definitions")
        return DevicePartitions(id=dev_id, raw=dev_seg, errors=errors, parts=[])

    for part_idx, part_raw in enumerate(part_segs):
        if not part_raw:
            errors.append(f"part[{part_idx}]: empty segment")
            continue
        part, part_errors, next_offset, next_offset_known = _parse_partition(
            part_raw,
            next_offset=next_offset,
            next_offset_known=next_offset_known,
        )
        for e in part_errors:
            errors.append(f"part[{part_idx}]: {e}")
        parts.append(part)

    return DevicePartitions(id=dev_id, raw=dev_seg, errors=errors, parts=parts)


def _parse_partition(
    part_raw: str, *, next_offset: int, next_offset_known: bool
) -> tuple[Partition, list[str], int, bool]:
    errors: list[str] = []

    pre, name, rest, name_errors = _split_name(part_raw)
    errors.extend(name_errors)

    size_str, offset_str, size_offset_errors = _split_size_offset(pre)
    errors.extend(size_offset_errors)

    size_bytes, is_remaining, size_err = _parse_size_token(size_str)
    if size_err:
        errors.append(size_err)
        size_bytes = 0
        is_remaining = False

    explicit_offset = False
    if offset_str is not None:
        explicit_offset = True
        off, off_err = _parse_int_token(offset_str)
        if off_err:
            errors.append(off_err)
            off = 0
        offset_bytes = off
    else:
        if next_offset_known:
            offset_bytes = next_offset
        else:
            offset_bytes = 0
            errors.append("missing offset after a remaining-size partition")

    flags = _parse_flags(rest)

    if is_remaining:
        next_offset_known = False
        next_offset_out = next_offset
    else:
        next_offset_known = True
        next_offset_out = int(offset_bytes) + int(size_bytes or 0)

    _ = explicit_offset

    return (
        Partition(
            raw=part_raw,
            name=name,
            size_bytes=None if is_remaining else int(size_bytes or 0),
            offset_bytes=int(offset_bytes),
            flags=flags,
        ),
        errors,
        next_offset_out,
        next_offset_known,
    )


def _split_name(part_raw: str) -> tuple[str, str, str, list[str]]:
    errors: list[str] = []
    if "(" not in part_raw:
        return part_raw.strip(), "", "", ["missing (name)"]
    pre, after = part_raw.split("(", 1)
    if ")" not in after:
        name = after.strip()
        return pre.strip(), name, "", ["missing closing ')' in name"]
    name_raw, rest = after.split(")", 1)
    name = name_raw.strip()
    if not name:
        errors.append("empty name")
    return pre.strip(), name, rest.strip(), errors


def _split_size_offset(pre: str) -> tuple[str, str | None, list[str]]:
    errors: list[str] = []
    pre = pre.strip()
    if not pre:
        return "", None, ["missing size"]
    if "@" not in pre:
        return pre, None, []
    left, right = pre.split("@", 1)
    left = left.strip()
    right = right.strip()
    if not left:
        errors.append("missing size before '@'")
    if not right:
        errors.append("missing offset after '@'")
        return left or "", None, errors
    return left or "", right, errors


def _parse_size_token(tok: str) -> tuple[int | None, bool, str | None]:
    tok = tok.strip()
    if tok == "-":
        return None, True, None
    if not tok:
        return 0, False, "missing size"
    m = _NUM_RE.match(tok)
    if not m:
        return 0, False, f"invalid size token: {tok!r}"
    num_s, suffix = m.group(1), m.group(2)
    try:
        base = int(num_s, 16) if num_s.lower().startswith("0x") else int(num_s, 10)
    except ValueError:
        return 0, False, f"invalid size number: {tok!r}"
    mult = _suffix_multiplier(suffix)
    return int(base * mult), False, None


def _parse_int_token(tok: str) -> tuple[int, str | None]:
    tok = tok.strip()
    if not tok:
        return 0, "missing offset"
    m = _NUM_RE.match(tok)
    if not m:
        return 0, f"invalid offset token: {tok!r}"
    num_s, suffix = m.group(1), m.group(2)
    try:
        base = int(num_s, 16) if num_s.lower().startswith("0x") else int(num_s, 10)
    except ValueError:
        return 0, f"invalid offset number: {tok!r}"
    mult = _suffix_multiplier(suffix)
    return int(base * mult), None


def _suffix_multiplier(suffix: str | None) -> int:
    if not suffix:
        return 1
    if suffix in ("k", "K"):
        return 1024
    if suffix in ("m", "M"):
        return 1024 * 1024
    if suffix in ("g", "G"):
        return 1024 * 1024 * 1024
    return 1


def _parse_flags(rest: str) -> list[str]:
    if not rest:
        return []

    flags: list[str] = []
    for m in re.finditer(r"\[([^\]]*)\]", rest):
        val = (m.group(1) or "").strip()
        if val:
            flags.append(val)

    bare = re.sub(r"\[[^\]]*\]", " ", rest)
    for m in re.finditer(r"[A-Za-z0-9_\-]+", bare):
        tok = m.group(0).strip()
        if tok:
            flags.append(tok)

    return flags
