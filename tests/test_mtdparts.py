from __future__ import annotations

from typing import cast

import pytest

from aiedge.mtdparts import parse_mtdparts


def _devices(rep: dict[str, object]) -> list[dict[str, object]]:
    devs_any = rep.get("devices")
    assert isinstance(devs_any, list)
    devs = cast(list[object], devs_any)
    assert all(isinstance(d, dict) for d in devs)
    return cast(list[dict[str, object]], devs)


def _parts(dev: dict[str, object]) -> list[dict[str, object]]:
    parts_any = dev.get("parts")
    assert isinstance(parts_any, list)
    parts = cast(list[object], parts_any)
    assert all(isinstance(p, dict) for p in parts)
    return cast(list[dict[str, object]], parts)


def test_timesys_nand_example_parses_and_offsets_are_sequential() -> None:
    s = (
        "mtdparts=atmel_nand:0x20000(AT91Bootstrap),0x40000(U-Boot),"
        "0x20000(U-Boot_Env),0x20000(U-Boot_Env_Red),0x260000(Kernel),-(RFS)"
    )
    rep = cast(dict[str, object], parse_mtdparts(s))
    devs = _devices(rep)
    assert len(devs) == 1
    assert devs[0]["id"] == "atmel_nand"
    assert devs[0]["errors"] == []

    parts = _parts(devs[0])
    assert [p["name"] for p in parts] == [
        "AT91Bootstrap",
        "U-Boot",
        "U-Boot_Env",
        "U-Boot_Env_Red",
        "Kernel",
        "RFS",
    ]
    assert [p["offset_bytes"] for p in parts] == [
        0x000000,
        0x020000,
        0x060000,
        0x080000,
        0x0A0000,
        0x300000,
    ]
    assert parts[-1]["size_bytes"] is None


def test_two_devices_separated_by_semicolon() -> None:
    s = "mtdparts=dev0:256k(boot)ro,-(root);dev1:0x1000@0x0(cfg)[ro][lk],-(data)"
    rep = cast(dict[str, object], parse_mtdparts(s))
    devs = _devices(rep)
    assert [d["id"] for d in devs] == ["dev0", "dev1"]

    d0_parts = _parts(devs[0])
    assert d0_parts[0]["size_bytes"] == 256 * 1024
    assert d0_parts[0]["flags"] == ["ro"]
    assert d0_parts[1]["size_bytes"] is None
    assert d0_parts[1]["offset_bytes"] == 256 * 1024

    d1_parts = _parts(devs[1])
    assert d1_parts[0]["offset_bytes"] == 0
    assert d1_parts[0]["size_bytes"] == 0x1000
    assert d1_parts[0]["flags"] == ["ro", "lk"]
    assert d1_parts[1]["offset_bytes"] == 0x1000


def test_missing_offsets_imply_sequential_layout() -> None:
    rep = cast(dict[str, object], parse_mtdparts("flash0:1k(a),2k(b),3k(c)"))
    dev = _devices(rep)[0]
    parts = _parts(dev)
    assert [p["offset_bytes"] for p in parts] == [0, 1024, 1024 + 2048]


def test_remaining_partition_followed_by_missing_offset_records_error_and_continues() -> (
    None
):
    rep = cast(dict[str, object], parse_mtdparts("flash0:-(all),1k(after)"))
    dev = _devices(rep)[0]
    errors = cast(list[object], dev.get("errors"))
    assert any(
        "missing offset after a remaining-size partition" in str(e) for e in errors
    )
    parts = _parts(dev)
    assert parts[0]["size_bytes"] is None
    assert parts[1]["offset_bytes"] == 0


def test_hex_and_suffix_sizes() -> None:
    rep = cast(dict[str, object], parse_mtdparts("d:0x10k(a),1M(b),4096(c)"))
    dev = _devices(rep)[0]
    parts = _parts(dev)
    assert [p["size_bytes"] for p in parts] == [16 * 1024, 1024 * 1024, 4096]
    assert [p["offset_bytes"] for p in parts] == [0, 16 * 1024, 16 * 1024 + 1024 * 1024]


def test_unknown_flags_are_preserved() -> None:
    rep = cast(dict[str, object], parse_mtdparts("d:1k(a)[foo][ro]bar"))
    dev = _devices(rep)[0]
    parts = _parts(dev)
    assert parts[0]["flags"] == ["foo", "ro", "bar"]


def test_empty_input_raises() -> None:
    with pytest.raises(ValueError):
        _ = parse_mtdparts("\n\t")
