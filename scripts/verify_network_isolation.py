#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import cast

_EXPECTED_FIREWALL_SNAPSHOT = (
    "stages/dynamic_validation/isolation/firewall_snapshot.txt"
)
_EXPECTED_PCAP = "stages/dynamic_validation/pcap/dynamic_validation.pcap"
_EXPECTED_SUMMARY = "stages/dynamic_validation/dynamic_validation.json"

_PCAP_MAGIC_NATIVE = 0xA1B2C3D4
_PCAP_MAGIC_SWAPPED = 0xD4C3B2A1

_ALLOWED_DESTINATION_RANGES: tuple[IPv4Network, ...] = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
    IPv4Network("169.254.0.0/16"),
    IPv4Network("127.0.0.0/8"),
)


class VerificationError(ValueError):
    reason_code: str
    detail: str

    def __init__(self, reason_code: str, detail: str) -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}: {detail}")


def _as_object(value: object, *, path: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise VerificationError("invalid_contract", f"{path} must be object")
    src = cast(dict[object, object], value)
    out: dict[str, object] = {}
    for key, item in src.items():
        out[str(key)] = item
    return out


def _load_json_object(path: Path) -> dict[str, object]:
    try:
        value = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception as exc:
        raise VerificationError(
            "invalid_contract", f"invalid JSON: {path}: {exc}"
        ) from exc
    return _as_object(value, path=str(path))


def _is_run_relative_path(path: str) -> bool:
    if not path:
        return False
    if path.startswith("/"):
        return False
    if re.match(r"^[A-Za-z]:\\", path):
        return False
    return True


def _resolve_run_relative_path(
    run_dir: Path, rel_path: str, *, field_path: str
) -> Path:
    if not _is_run_relative_path(rel_path):
        raise VerificationError(
            "invalid_contract", f"{field_path} must be run-relative path: {rel_path!r}"
        )
    candidate = (run_dir / rel_path).resolve()
    run_root = run_dir.resolve()
    try:
        _ = candidate.relative_to(run_root)
    except ValueError as exc:
        raise VerificationError(
            "invalid_contract", f"{field_path} escapes run_dir: {rel_path!r}"
        ) from exc
    return candidate


def _require_file(path: Path, *, reason_code: str, detail: str) -> None:
    if not path.is_file():
        raise VerificationError(reason_code, detail)


def _validate_dynamic_summary(run_dir: Path) -> None:
    summary_path = run_dir / _EXPECTED_SUMMARY
    _require_file(
        summary_path,
        reason_code="missing_required_artifact",
        detail=f"missing file: {_EXPECTED_SUMMARY}",
    )

    summary = _load_json_object(summary_path)
    isolation_any = summary.get("isolation")
    isolation = _as_object(isolation_any, path="dynamic_validation.isolation")

    firewall_rel_any = isolation.get("firewall_snapshot")
    pcap_rel_any = isolation.get("pcap")
    if not isinstance(firewall_rel_any, str) or not firewall_rel_any:
        raise VerificationError(
            "invalid_contract",
            "dynamic_validation.isolation.firewall_snapshot must be non-empty string",
        )
    if not isinstance(pcap_rel_any, str) or not pcap_rel_any:
        raise VerificationError(
            "invalid_contract",
            "dynamic_validation.isolation.pcap must be non-empty string",
        )

    _ = _resolve_run_relative_path(
        run_dir,
        firewall_rel_any,
        field_path="dynamic_validation.isolation.firewall_snapshot",
    )
    _ = _resolve_run_relative_path(
        run_dir,
        pcap_rel_any,
        field_path="dynamic_validation.isolation.pcap",
    )

    if firewall_rel_any != _EXPECTED_FIREWALL_SNAPSHOT:
        raise VerificationError(
            "invalid_contract",
            "dynamic_validation.isolation.firewall_snapshot has unexpected path",
        )
    if pcap_rel_any != _EXPECTED_PCAP:
        raise VerificationError(
            "invalid_contract",
            "dynamic_validation.isolation.pcap has unexpected path",
        )


def _parse_ipv4_destinations_from_pcap(pcap_path: Path) -> set[IPv4Address]:
    try:
        raw = pcap_path.read_bytes()
    except Exception as exc:
        raise VerificationError(
            "pcap_parse_unavailable", f"cannot read pcap file: {pcap_path}: {exc}"
        ) from exc

    if len(raw) < 24:
        raise VerificationError("pcap_parse_unavailable", "pcap header is truncated")

    magic_tuple = cast(tuple[int], struct.unpack_from("<I", raw, 0))
    magic_le = int(magic_tuple[0])
    if magic_le == _PCAP_MAGIC_NATIVE:
        endian = "<"
    elif magic_le == _PCAP_MAGIC_SWAPPED:
        endian = ">"
    else:
        raise VerificationError(
            "pcap_parse_unavailable", "unsupported pcap format or pcapng"
        )

    try:
        network_tuple = cast(tuple[int], struct.unpack_from(endian + "I", raw, 20))
        network = int(network_tuple[0])
    except struct.error as exc:
        raise VerificationError(
            "pcap_parse_unavailable", "pcap global header parse failed"
        ) from exc

    supported_links = {1, 12, 113}
    if network not in supported_links:
        raise VerificationError(
            "pcap_parse_unavailable", f"unsupported pcap linktype: {network}"
        )

    offset = 24
    observed: set[IPv4Address] = set()

    while offset + 16 <= len(raw):
        try:
            packet_header = cast(
                tuple[int, int, int, int],
                struct.unpack_from(endian + "IIII", raw, offset),
            )
            _ts_sec, _ts_usec, incl_len, _orig_len = packet_header
        except struct.error as exc:
            raise VerificationError(
                "pcap_parse_unavailable", "pcap packet header parse failed"
            ) from exc
        offset += 16

        if incl_len < 0:
            raise VerificationError(
                "pcap_parse_unavailable", "pcap packet length is invalid"
            )
        if offset + incl_len > len(raw):
            raise VerificationError(
                "pcap_parse_unavailable", "pcap packet payload is truncated"
            )

        packet = raw[offset : offset + incl_len]
        offset += incl_len

        ip_offset: int | None = None
        if network == 1:
            if len(packet) < 14:
                continue
            ethertype_tuple = cast(tuple[int], struct.unpack_from("!H", packet, 12))
            ethertype = int(ethertype_tuple[0])
            if ethertype != 0x0800:
                continue
            ip_offset = 14
        elif network == 12:
            ip_offset = 0
        elif network == 113:
            if len(packet) < 16:
                continue
            proto_tuple = cast(tuple[int], struct.unpack_from("!H", packet, 14))
            proto = int(proto_tuple[0])
            if proto != 0x0800:
                continue
            ip_offset = 16

        if ip_offset is None:
            continue
        if len(packet) < ip_offset + 20:
            continue

        version_ihl = packet[ip_offset]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4
        if version != 4 or ihl < 20:
            continue
        if len(packet) < ip_offset + ihl:
            continue

        dst_start = ip_offset + 16
        dst_end = dst_start + 4
        dst_ip_raw = packet[dst_start:dst_end]
        if len(dst_ip_raw) != 4:
            continue
        observed.add(IPv4Address(dst_ip_raw))

    return observed


def _verify_network_isolation(run_dir: Path) -> str:
    dynamic_dir = run_dir / "stages" / "dynamic_validation"
    if not dynamic_dir.is_dir():
        raise VerificationError(
            "missing_dynamic_bundle", "missing directory: stages/dynamic_validation"
        )

    _validate_dynamic_summary(run_dir)

    firewall_snapshot = run_dir / _EXPECTED_FIREWALL_SNAPSHOT
    _require_file(
        firewall_snapshot,
        reason_code="missing_required_artifact",
        detail=f"missing file: {_EXPECTED_FIREWALL_SNAPSHOT}",
    )
    if firewall_snapshot.stat().st_size <= 0:
        raise VerificationError(
            "missing_required_artifact",
            f"artifact must be non-empty: {_EXPECTED_FIREWALL_SNAPSHOT}",
        )

    pcap_path = run_dir / _EXPECTED_PCAP
    _require_file(
        pcap_path,
        reason_code="missing_required_artifact",
        detail=f"missing file: {_EXPECTED_PCAP}",
    )

    observed_destinations = sorted(
        _parse_ipv4_destinations_from_pcap(pcap_path), key=lambda ip: int(ip)
    )
    disallowed = [
        ip
        for ip in observed_destinations
        if not any(ip in net for net in _ALLOWED_DESTINATION_RANGES)
    ]
    if disallowed:
        raise VerificationError(
            "egress_violation",
            "disallowed destination(s): " + ", ".join(str(ip) for ip in disallowed),
        )

    pcap_sha256 = hashlib.sha256(pcap_path.read_bytes()).hexdigest()
    return (
        "network isolation verified: "
        f"{run_dir} (destinations={len(observed_destinations)}, pcap_sha256={pcap_sha256})"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify dynamic validation network isolation evidence and no-egress policy."
    )
    _ = parser.add_argument("--run-dir", required=True, help="Path to run directory")
    args = parser.parse_args(argv)

    run_dir_raw = getattr(args, "run_dir", None)
    if not isinstance(run_dir_raw, str) or not run_dir_raw:
        print("[FAIL] invalid_contract: --run-dir must be a non-empty path")
        return 1

    run_dir = Path(run_dir_raw).resolve()
    if not run_dir.is_dir():
        print(
            f"[FAIL] missing_required_artifact: run_dir is not a directory: {run_dir}"
        )
        return 1

    try:
        detail = _verify_network_isolation(run_dir)
    except VerificationError as exc:
        print(f"[FAIL] {exc.reason_code}: {exc.detail}")
        return 1
    except Exception as exc:
        print(f"[FAIL] invalid_contract: unexpected verifier error: {exc}")
        return 1

    print(f"[OK] {detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
