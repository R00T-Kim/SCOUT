from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path
from typing import cast

import pytest

from aiedge.ota_roots import OtaRootsCaps, OtaRootsStage
from aiedge.run import analyze_run, create_run
from aiedge.stage import StageContext


def _ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    logs_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


def _seed_fs_json(run_dir: Path) -> None:
    stage_dir = run_dir / "stages" / "ota"
    stage_dir.mkdir(parents=True, exist_ok=True)
    fs_path = stage_dir / "fs.json"
    _ = fs_path.write_text(
        json.dumps(
            {
                "status": "ok",
                "partitions": {
                    "system": {"type": "ext4_raw"},
                    "vendor": {"type": "ext4_raw"},
                    "product": {"type": "ext4_raw"},
                },
                "evidence": [],
                "limitations": [],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _prepare_partition_images(run_dir: Path) -> None:
    parts = run_dir / "stages" / "ota" / "partitions"
    parts.mkdir(parents=True, exist_ok=True)
    for name in ("system", "vendor", "product"):
        _ = (parts / f"{name}.img").write_bytes(b"img")


def _mk_fake_debugfs(monkeypatch: pytest.MonkeyPatch, *, include_special: bool) -> None:
    trees: dict[str, dict[str, tuple[str, int]]] = {
        "system.img": {
            "/": ("dir", 0),
            "/system": ("dir", 0),
            "/system/app": ("dir", 0),
            "/system/app/Maps": ("dir", 0),
            "/system/app/Maps/base.apk": ("file", 10),
            "/system/lib": ("dir", 0),
            "/system/lib/liba.so": ("file", 5),
            "/system/build.prop": ("file", 7),
            "/init.usb.rc": ("file", 8),
            "/etc": ("dir", 0),
            "/etc/fstab.qcom": ("file", 6),
            "/manifest.xml": ("file", 4),
        },
        "vendor.img": {
            "/": ("dir", 0),
            "/app": ("dir", 0),
            "/app/VendorApp": ("dir", 0),
            "/app/VendorApp/v.apk": ("file", 9),
            "/vendor": ("dir", 0),
            "/vendor/lib64": ("dir", 0),
            "/vendor/lib64/libv.so": ("file", 11),
        },
        "product.img": {
            "/": ("dir", 0),
            "/product": ("dir", 0),
            "/product/priv-app": ("dir", 0),
            "/product/priv-app/Prod": ("dir", 0),
            "/product/priv-app/Prod/p.apk": ("file", 12),
            "/lib": ("dir", 0),
            "/lib/libp.so": ("file", 13),
        },
    }
    if include_special:
        trees["system.img"]["/system/app/devnode"] = ("special", 0)

    children: dict[str, dict[str, list[str]]] = {}
    for img, node_map in trees.items():
        c: dict[str, list[str]] = {}
        for p in node_map:
            if p == "/":
                continue
            parent = str(Path(p).parent).replace("\\", "/")
            if not parent.startswith("/"):
                parent = "/" + parent
            c.setdefault(parent, []).append(Path(p).name)
        children[img] = c

    def _fake_run(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        request = argv[2]
        image = Path(argv[3]).name
        nodes = trees.get(image, {})
        kids = children.get(image, {})
        cmd = shlex.split(request)

        if len(cmd) >= 2 and cmd[0] == "stat":
            p = cmd[1]
            kind_size = nodes.get(p)
            if kind_size is None:
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr="ENOENT")
            kind, size = kind_size
            if kind == "dir":
                out = "Inode: 2   Type: directory\n"
                return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")
            if kind == "file":
                out = f"Inode: 3   Type: regular\nSize: {size}\n"
                return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")
            out = "Inode: 4   Type: character device\n"
            return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")

        if len(cmd) >= 3 and cmd[0] == "ls" and cmd[1] == "-p":
            p = cmd[2]
            if nodes.get(p, ("", 0))[0] != "dir":
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr="ENOTDIR")
            names = sorted(set(kids.get(p, [])))
            out = "\n".join(f"/1/040755/0/0/{name}/" for name in names)
            return subprocess.CompletedProcess(
                argv, 0, stdout=out + ("\n" if out else ""), stderr=""
            )

        if len(cmd) >= 4 and cmd[0] == "dump" and cmd[1] == "-p":
            src = cmd[2]
            dst = Path(cmd[3])
            kind, size = nodes.get(src, ("", 0))
            if kind != "file":
                return subprocess.CompletedProcess(
                    argv, 1, stdout="", stderr="bad file"
                )
            dst.parent.mkdir(parents=True, exist_ok=True)
            _ = dst.write_bytes(b"X" * int(size))
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="unsupported")

    monkeypatch.setattr("aiedge.ota_roots.subprocess.run", _fake_run)


def test_ota_roots_extracts_expected_trees_and_artifacts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ctx = _ctx(tmp_path)
    _seed_fs_json(ctx.run_dir)
    _prepare_partition_images(ctx.run_dir)
    _mk_fake_debugfs(monkeypatch, include_special=False)

    out = OtaRootsStage().run(ctx)
    assert out.status == "ok"

    roots_dir = ctx.run_dir / "stages" / "ota" / "roots"
    assert (roots_dir / "system" / "app" / "Maps" / "base.apk").is_file()
    assert (roots_dir / "system" / "etc" / "fstab.qcom").is_file()
    assert (roots_dir / "vendor" / "app" / "VendorApp" / "v.apk").is_file()
    assert (roots_dir / "product" / "priv-app" / "Prod" / "p.apk").is_file()

    roots_json = cast(
        dict[str, object],
        json.loads((ctx.run_dir / "stages" / "ota" / "roots.json").read_text()),
    )
    roots_any = roots_json.get("roots")
    assert isinstance(roots_any, list)
    roots = cast(list[object], roots_any)
    assert roots == [
        "stages/ota/roots/system",
        "stages/ota/roots/vendor",
        "stages/ota/roots/product",
    ]

    stage_doc = cast(
        dict[str, object],
        json.loads((ctx.run_dir / "stages" / "ota" / "roots_stage.json").read_text()),
    )
    assert stage_doc.get("status") == "ok"
    parts = cast(dict[str, object], stage_doc.get("partitions"))
    assert cast(dict[str, object], parts["system"]).get("fs_type") == "ext4_raw"


def test_ota_roots_enforces_caps_and_skips_special(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ctx = _ctx(tmp_path)
    _seed_fs_json(ctx.run_dir)
    _prepare_partition_images(ctx.run_dir)
    _mk_fake_debugfs(monkeypatch, include_special=True)

    stage = OtaRootsStage(
        caps=OtaRootsCaps(max_total_bytes=20, max_files=2, max_single_file_bytes=8)
    )
    out = stage.run(ctx)
    assert out.status == "partial"
    assert any("max_single_file_bytes" in x for x in out.limitations)

    stage_doc = cast(
        dict[str, object],
        json.loads((ctx.run_dir / "stages" / "ota" / "roots_stage.json").read_text()),
    )
    summary = cast(dict[str, object], stage_doc.get("summary"))
    assert int(cast(int, summary.get("skipped_too_large_files"))) >= 1
    assert int(cast(int, summary.get("skipped_special_files"))) >= 1


def test_analyze_run_writes_ota_roots_artifacts(tmp_path: Path) -> None:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"firmware")

    info = create_run(
        str(fw),
        case_id="case-ota-roots",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    _ = analyze_run(info, time_budget_s=0, no_llm=True)

    roots_json_path = info.run_dir / "stages" / "ota" / "roots.json"
    roots_stage_path = info.run_dir / "stages" / "ota" / "roots_stage.json"
    assert roots_json_path.is_file()
    assert roots_stage_path.is_file()

    report_obj = cast(
        dict[str, object],
        json.loads(
            (info.run_dir / "report" / "report.json").read_text(encoding="utf-8")
        ),
    )
    assert "ota_roots" in report_obj
