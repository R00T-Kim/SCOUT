from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from fnmatch import fnmatch
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


def _debugfs_quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


@dataclass(frozen=True)
class OtaRootsCaps:
    max_total_bytes: int = 20 * 1024 * 1024 * 1024
    max_files: int = 200_000
    max_single_file_bytes: int = 1024 * 1024 * 1024


@dataclass(frozen=True)
class OtaRootsTimeouts:
    ls_s: float = 20.0
    stat_s: float = 20.0
    dump_s: float = 120.0


@dataclass(frozen=True)
class _FsNode:
    path: str
    kind: str
    size: int


def _parse_fs_type(fs_json: Path) -> dict[str, str]:
    if not fs_json.is_file():
        return {}
    try:
        raw = cast(object, json.loads(fs_json.read_text(encoding="utf-8")))
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    parts_any = cast(dict[str, object], raw).get("partitions")
    if not isinstance(parts_any, dict):
        return {}
    out: dict[str, str] = {}
    for k in ("system", "vendor", "product"):
        p_any = cast(dict[str, object], parts_any).get(k)
        if not isinstance(p_any, dict):
            continue
        type_any = cast(dict[str, object], p_any).get("type")
        out[k] = type_any if isinstance(type_any, str) else "unknown"
    return out


def _run_debugfs(
    *,
    image_path: Path,
    request: str,
    timeout_s: float,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["debugfs", "-R", request, str(image_path)],
        text=True,
        capture_output=True,
        check=False,
        timeout=float(timeout_s),
    )


def _list_dir(
    image_path: Path, dir_path: str, *, timeout_s: float
) -> tuple[bool, list[str]]:
    req = f"ls -p {_debugfs_quote(dir_path)}"
    proc = _run_debugfs(image_path=image_path, request=req, timeout_s=timeout_s)
    if proc.returncode != 0:
        return False, []
    names: list[str] = []
    for line in (proc.stdout or "").splitlines():
        s = line.strip()
        if not s or s.startswith("debugfs"):
            continue
        parts = [x for x in s.split("/") if x]
        if len(parts) < 5:
            continue
        name = parts[4].strip()
        if not name or name in (".", ".."):
            continue
        names.append(name)
    return True, names


def _stat_path(image_path: Path, fs_path: str, *, timeout_s: float) -> _FsNode | None:
    req = f"stat {_debugfs_quote(fs_path)}"
    proc = _run_debugfs(image_path=image_path, request=req, timeout_s=timeout_s)
    if proc.returncode != 0:
        return None

    mode_s = ""
    size = 0
    for line in (proc.stdout or "").splitlines():
        s = line.strip()
        if "Type:" in s:
            if "directory" in s.lower():
                return _FsNode(path=fs_path, kind="dir", size=0)
            if "regular" in s.lower():
                mode_s = "regular"
            elif (
                "block" in s.lower()
                or "character" in s.lower()
                or "fifo" in s.lower()
                or "socket" in s.lower()
                or "symlink" in s.lower()
            ):
                return _FsNode(path=fs_path, kind="special", size=0)
        if "Size:" in s:
            try:
                part = s.split("Size:", 1)[1].strip().split()[0]
                size = int(part)
            except Exception:
                size = 0

    if mode_s == "regular":
        return _FsNode(path=fs_path, kind="file", size=int(max(0, size)))
    return None


def _join_fs_path(base: str, name: str) -> str:
    b = base.rstrip("/")
    if not b:
        b = "/"
    if b == "/":
        return "/" + name
    return b + "/" + name


def _discover_tree_files(
    *,
    image_path: Path,
    tree_path: str,
    dest_prefix: str,
    timeouts: OtaRootsTimeouts,
    limitations: list[str],
) -> tuple[list[tuple[_FsNode, str]], int]:
    root = _stat_path(image_path, tree_path, timeout_s=timeouts.stat_s)
    if root is None or root.kind != "dir":
        return [], 0

    out: list[tuple[_FsNode, str]] = []
    special_count = 0
    stack: list[tuple[str, str]] = [(tree_path, dest_prefix.strip("/"))]
    while stack:
        fs_dir, rel_dir = stack.pop()
        exists, names = _list_dir(image_path, fs_dir, timeout_s=timeouts.ls_s)
        if not exists:
            limitations.append(f"debugfs ls failed for {fs_dir}")
            continue
        for name in names:
            child_fs = _join_fs_path(fs_dir, name)
            child = _stat_path(image_path, child_fs, timeout_s=timeouts.stat_s)
            if child is None:
                limitations.append(f"debugfs stat failed for {child_fs}")
                continue
            child_rel = f"{rel_dir}/{name}" if rel_dir else name
            if child.kind == "dir":
                stack.append((child_fs, child_rel))
            elif child.kind == "file":
                out.append((child, child_rel))
            else:
                special_count += 1
                limitations.append(f"Skipped special inode: {child_fs}")
    return out, special_count


def _discover_dir_pattern_files(
    *,
    image_path: Path,
    dir_path: str,
    name_pattern: str,
    dest_prefix: str,
    timeouts: OtaRootsTimeouts,
    limitations: list[str],
) -> tuple[list[tuple[_FsNode, str]], int]:
    root = _stat_path(image_path, dir_path, timeout_s=timeouts.stat_s)
    if root is None or root.kind != "dir":
        return [], 0
    exists, names = _list_dir(image_path, dir_path, timeout_s=timeouts.ls_s)
    if not exists:
        limitations.append(f"debugfs ls failed for {dir_path}")
        return [], 0

    out: list[tuple[_FsNode, str]] = []
    special_count = 0
    for name in names:
        if not fnmatch(name, name_pattern):
            continue
        fs_path = _join_fs_path(dir_path, name)
        node = _stat_path(image_path, fs_path, timeout_s=timeouts.stat_s)
        if node is None:
            limitations.append(f"debugfs stat failed for {fs_path}")
            continue
        if node.kind == "file":
            out.append((node, f"{dest_prefix.strip('/')}/{name}".strip("/")))
        elif node.kind != "dir":
            special_count += 1
            limitations.append(f"Skipped special inode: {fs_path}")
    return out, special_count


@dataclass(frozen=True)
class OtaRootsStage:
    caps: OtaRootsCaps = OtaRootsCaps()
    timeouts: OtaRootsTimeouts = OtaRootsTimeouts()

    @property
    def name(self) -> str:
        return "ota_roots"

    def run(self, ctx: StageContext) -> StageOutcome:
        stage_dir = ctx.run_dir / "stages" / "ota"
        partitions_dir = stage_dir / "partitions"
        fs_json_path = stage_dir / "fs.json"
        roots_dir = stage_dir / "roots"
        roots_json_path = stage_dir / "roots.json"
        roots_stage_json_path = stage_dir / "roots_stage.json"

        system_root = roots_dir / "system"
        vendor_root = roots_dir / "vendor"
        product_root = roots_dir / "product"

        for p in [
            stage_dir,
            partitions_dir,
            fs_json_path,
            roots_dir,
            roots_json_path,
            roots_stage_json_path,
            system_root,
            vendor_root,
            product_root,
        ]:
            _assert_under_dir(ctx.run_dir, p)

        roots_dir.mkdir(parents=True, exist_ok=True)
        system_root.mkdir(parents=True, exist_ok=True)
        vendor_root.mkdir(parents=True, exist_ok=True)
        product_root.mkdir(parents=True, exist_ok=True)

        limitations: list[str] = []
        fs_types = _parse_fs_type(fs_json_path)

        extracted_files = 0
        extracted_bytes = 0
        skipped_cap_files = 0
        skipped_cap_bytes = 0
        skipped_too_large_files = 0
        skipped_special_files = 0
        cap_hit = False

        partition_docs: dict[str, JsonValue] = {}
        seen_dest_rel: set[str] = set()

        roots_rel = [
            _rel_to_run_dir(ctx.run_dir, system_root),
            _rel_to_run_dir(ctx.run_dir, vendor_root),
            _rel_to_run_dir(ctx.run_dir, product_root),
        ]

        for part, root_dir, prefixes in [
            ("system", system_root, ["/system", "/"]),
            ("vendor", vendor_root, ["/vendor", "/"]),
            ("product", product_root, ["/product", "/"]),
        ]:
            img_path = partitions_dir / f"{part}.img"
            fs_type = fs_types.get(part, "unknown")
            part_doc: dict[str, JsonValue] = {
                "partition": part,
                "image": _rel_to_run_dir(ctx.run_dir, img_path),
                "fs_type": fs_type,
                "attempted": True,
                "paths_found": cast(list[JsonValue], []),
                "candidate_files": 0,
                "candidate_bytes": 0,
                "extracted_files": 0,
                "extracted_bytes": 0,
                "skipped_cap_files": 0,
                "skipped_cap_bytes": 0,
                "skipped_too_large_files": 0,
                "skipped_special_files": 0,
                "skipped_reasons": cast(list[JsonValue], []),
            }
            skipped_reasons = cast(list[JsonValue], part_doc["skipped_reasons"])

            if not img_path.is_file():
                limitations.append(f"Missing OTA partition image: {part}.img")
                skipped_reasons.append("missing image")
                partition_docs[part] = cast(JsonValue, part_doc)
                continue
            if fs_type != "ext4_raw":
                limitations.append(
                    f"Skipping non-ext4 OTA partition image: {part}.img (type={fs_type})"
                )
                skipped_reasons.append(f"unsupported fs type: {fs_type}")
                partition_docs[part] = cast(JsonValue, part_doc)
                continue

            found_paths: list[str] = []
            candidates: list[tuple[_FsNode, str]] = []
            part_special = 0
            tree_names = ["app", "priv-app", "lib", "lib64"]

            for prefix in prefixes:
                for tree_name in tree_names:
                    source = _join_fs_path(prefix, tree_name)
                    files, special_ct = _discover_tree_files(
                        image_path=img_path,
                        tree_path=source,
                        dest_prefix=tree_name,
                        timeouts=self.timeouts,
                        limitations=limitations,
                    )
                    skipped_special_files += int(special_ct)
                    part_special += int(special_ct)
                    if files:
                        found_paths.append(source)
                        candidates.extend(files)

            for prefix in prefixes:
                for cfg_name in ["build.prop", "manifest.xml"]:
                    source = _join_fs_path(prefix, cfg_name)
                    node = _stat_path(img_path, source, timeout_s=self.timeouts.stat_s)
                    if node is not None and node.kind == "file":
                        found_paths.append(source)
                        candidates.append((node, cfg_name))
                    elif node is not None and node.kind == "special":
                        skipped_special_files += 1
                        part_special += 1
                        limitations.append(f"Skipped special inode: {source}")

            for prefix in prefixes:
                root_source = prefix if prefix != "/" else "/"
                files = _discover_dir_pattern_files(
                    image_path=img_path,
                    dir_path=root_source,
                    name_pattern="init*.rc",
                    dest_prefix="",
                    timeouts=self.timeouts,
                    limitations=limitations,
                )
                pattern_files, special_ct = files
                skipped_special_files += int(special_ct)
                part_special += int(special_ct)
                if pattern_files:
                    found_paths.append(root_source)
                    candidates.extend(pattern_files)

            for prefix in prefixes:
                etc_source = _join_fs_path(prefix, "etc")
                files = _discover_dir_pattern_files(
                    image_path=img_path,
                    dir_path=etc_source,
                    name_pattern="fstab*",
                    dest_prefix="etc",
                    timeouts=self.timeouts,
                    limitations=limitations,
                )
                pattern_files, special_ct = files
                skipped_special_files += int(special_ct)
                part_special += int(special_ct)
                if pattern_files:
                    found_paths.append(etc_source)
                    candidates.extend(pattern_files)

            unique_candidates: list[tuple[_FsNode, str]] = []
            seen_local: set[str] = set()
            for node, rel in candidates:
                rel_n = rel.strip("/")
                if not rel_n:
                    continue
                key = f"{part}:{rel_n}"
                if key in seen_local:
                    continue
                seen_local.add(key)
                unique_candidates.append((node, rel_n))

            candidate_files = len(unique_candidates)
            candidate_bytes = sum(max(0, int(n.size)) for n, _ in unique_candidates)
            part_doc["paths_found"] = cast(
                list[JsonValue], list(dict.fromkeys(found_paths))
            )
            part_doc["candidate_files"] = int(candidate_files)
            part_doc["candidate_bytes"] = int(candidate_bytes)

            part_extracted_files = 0
            part_extracted_bytes = 0
            part_cap_files = 0
            part_cap_bytes = 0
            part_too_large = 0

            for node, rel in unique_candidates:
                dest_path = root_dir / rel
                _assert_under_dir(root_dir, dest_path)

                rel_key = _rel_to_run_dir(ctx.run_dir, dest_path)
                if rel_key in seen_dest_rel:
                    continue

                if node.size > int(self.caps.max_single_file_bytes):
                    skipped_too_large_files += 1
                    part_too_large += 1
                    skipped_reasons.append(
                        f"max_single_file_bytes exceeded for {node.path}"
                    )
                    continue

                if cap_hit or extracted_files >= int(self.caps.max_files):
                    cap_hit = True
                    part_cap_files += 1
                    part_cap_bytes += int(max(0, node.size))
                    skipped_cap_files += 1
                    skipped_cap_bytes += int(max(0, node.size))
                    continue

                if extracted_bytes + int(max(0, node.size)) > int(
                    self.caps.max_total_bytes
                ):
                    cap_hit = True
                    part_cap_files += 1
                    part_cap_bytes += int(max(0, node.size))
                    skipped_cap_files += 1
                    skipped_cap_bytes += int(max(0, node.size))
                    continue

                dest_path.parent.mkdir(parents=True, exist_ok=True)
                _assert_under_dir(root_dir, dest_path.parent)

                req = f"dump -p {_debugfs_quote(node.path)} {_debugfs_quote(str(dest_path))}"
                try:
                    proc = _run_debugfs(
                        image_path=img_path,
                        request=req,
                        timeout_s=self.timeouts.dump_s,
                    )
                except subprocess.TimeoutExpired:
                    limitations.append(f"debugfs dump timed out for {part}:{node.path}")
                    continue
                if proc.returncode != 0:
                    limitations.append(f"debugfs dump failed for {part}:{node.path}")
                    continue

                if not dest_path.is_file():
                    limitations.append(
                        f"debugfs dump produced non-regular output for {part}:{node.path}"
                    )
                    continue

                seen_dest_rel.add(rel_key)
                extracted_files += 1
                extracted_bytes += int(max(0, node.size))
                part_extracted_files += 1
                part_extracted_bytes += int(max(0, node.size))

            part_doc["extracted_files"] = int(part_extracted_files)
            part_doc["extracted_bytes"] = int(part_extracted_bytes)
            part_doc["skipped_cap_files"] = int(part_cap_files)
            part_doc["skipped_cap_bytes"] = int(part_cap_bytes)
            part_doc["skipped_too_large_files"] = int(part_too_large)
            part_doc["skipped_special_files"] = int(part_special)
            partition_docs[part] = cast(JsonValue, part_doc)

        if cap_hit:
            limitations.append(
                "OTA roots extraction hit configured caps; output is partial."
            )
        if skipped_too_large_files > 0:
            limitations.append(
                "Some files were skipped because they exceeded max_single_file_bytes."
            )

        roots_payload: dict[str, JsonValue] = {
            "roots": cast(list[JsonValue], list(roots_rel)),
        }
        _ = roots_json_path.write_text(
            json.dumps(roots_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        status: StageStatus = "ok" if not limitations else "partial"
        roots_stage_payload: dict[str, JsonValue] = {
            "status": status,
            "caps": {
                "max_total_bytes": int(self.caps.max_total_bytes),
                "max_files": int(self.caps.max_files),
                "max_single_file_bytes": int(self.caps.max_single_file_bytes),
            },
            "timeouts": {
                "ls_s": float(self.timeouts.ls_s),
                "stat_s": float(self.timeouts.stat_s),
                "dump_s": float(self.timeouts.dump_s),
            },
            "summary": {
                "extracted_files": int(extracted_files),
                "extracted_bytes": int(extracted_bytes),
                "skipped_cap_files": int(skipped_cap_files),
                "skipped_cap_bytes": int(skipped_cap_bytes),
                "skipped_too_large_files": int(skipped_too_large_files),
                "skipped_special_files": int(skipped_special_files),
            },
            "partitions": partition_docs,
            "roots": cast(list[JsonValue], list(roots_rel)),
            "limitations": cast(list[JsonValue], list(limitations)),
            "evidence": cast(
                list[JsonValue],
                cast(
                    list[object],
                    [
                        _evidence_path(ctx.run_dir, stage_dir),
                        _evidence_path(ctx.run_dir, partitions_dir),
                        _evidence_path(ctx.run_dir, fs_json_path, note=None),
                        _evidence_path(ctx.run_dir, roots_dir),
                        _evidence_path(ctx.run_dir, roots_json_path),
                        _evidence_path(ctx.run_dir, roots_stage_json_path),
                    ],
                ),
            ),
        }
        _ = roots_stage_json_path.write_text(
            json.dumps(roots_stage_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        details: dict[str, JsonValue] = {
            "artifacts": {
                "roots_json": _rel_to_run_dir(ctx.run_dir, roots_json_path),
                "roots_stage_json": _rel_to_run_dir(ctx.run_dir, roots_stage_json_path),
                "roots_dir": _rel_to_run_dir(ctx.run_dir, roots_dir),
            },
            "roots": cast(list[JsonValue], list(roots_rel)),
            "summary": cast(dict[str, JsonValue], roots_stage_payload["summary"]),
            "partitions": partition_docs,
            "caps": cast(dict[str, JsonValue], roots_stage_payload["caps"]),
            "evidence": cast(list[JsonValue], roots_stage_payload["evidence"]),
        }
        return StageOutcome(status=status, details=details, limitations=limitations)
