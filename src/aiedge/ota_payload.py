from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO, cast

from .ota import OtaDiscoveryLimits
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


def _json_int(v: object, default: int = 0) -> int:
    if isinstance(v, bool):
        return int(default)
    if isinstance(v, int):
        return int(v)
    return int(default)


def _read_limits(ota_obj: dict[str, object]) -> OtaDiscoveryLimits:
    limits_any = ota_obj.get("limits")
    if not isinstance(limits_any, dict):
        return OtaDiscoveryLimits()
    limits_obj = cast(dict[str, object], limits_any)
    return OtaDiscoveryLimits(
        max_depth=max(0, _json_int(limits_obj.get("max_depth"), 5)),
        max_archives=max(1, _json_int(limits_obj.get("max_archives"), 200)),
        max_entries_per_zip=max(
            1, _json_int(limits_obj.get("max_entries_per_zip"), 200_000)
        ),
        max_streamed_member_bytes=max(
            1,
            _json_int(
                limits_obj.get("max_streamed_member_bytes"),
                8_589_934_592,
            ),
        ),
    )


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


def _safe_member_map(
    zf: zipfile.ZipFile,
    *,
    archive_label: str,
    limits: OtaDiscoveryLimits,
) -> dict[str, zipfile.ZipInfo]:
    infos = zf.infolist()
    if len(infos) > int(limits.max_entries_per_zip):
        raise AIEdgePolicyViolation(
            f"entry limit exceeded at {archive_label}: entries={len(infos)} max_entries_per_zip={int(limits.max_entries_per_zip)}"
        )
    out: dict[str, zipfile.ZipInfo] = {}
    for info in infos:
        raw_name = info.filename
        if not _is_safe_member_path(raw_name):
            raise AIEdgePolicyViolation(
                f"zip-slip path rejected at {archive_label}: {raw_name!r}"
            )
        n = _normalize_member_name(raw_name)
        if n and n not in out:
            out[n] = info
    return out


def extract_payload_and_properties(
    *,
    firmware_zip_path: Path,
    archive_chain: list[str],
    payload_member_path: str,
    input_dir: Path,
    limits: OtaDiscoveryLimits,
) -> tuple[Path, Path, str | None]:
    _assert_under_dir(input_dir, input_dir / "update.zip")
    _assert_under_dir(input_dir, input_dir / "payload.bin")

    update_zip_path = input_dir / "update.zip"
    payload_path = input_dir / "payload.bin"
    nested_dir = input_dir / "_nested"
    _assert_under_dir(input_dir, nested_dir)
    nested_dir.mkdir(parents=True, exist_ok=True)

    current_archive_path = firmware_zip_path
    nested_paths: list[Path] = []
    archives_seen = 0

    for depth, member in enumerate(archive_chain):
        if depth >= int(limits.max_depth):
            raise AIEdgePolicyViolation(f"max depth reached: {member}")
        if archives_seen >= int(limits.max_archives):
            raise AIEdgePolicyViolation(
                f"archive limit exceeded: max_archives={int(limits.max_archives)}"
            )

        member_n = _normalize_member_name(member)
        if not _is_safe_member_path(member_n):
            raise AIEdgePolicyViolation(f"unsafe archive member in chain: {member!r}")

        zf = zipfile.ZipFile(current_archive_path)
        archive_label = "<root>" if depth == 0 else "!/".join(archive_chain[:depth])

        archives_seen += 1
        with zf:
            member_map = _safe_member_map(
                zf, archive_label=archive_label, limits=limits
            )
            info = member_map.get(member_n)
            if info is None:
                raise FileNotFoundError(
                    f"chosen archive chain member missing: {member_n}"
                )
            if int(info.file_size) > int(limits.max_streamed_member_bytes):
                raise AIEdgePolicyViolation(
                    f"streamed member too large at {archive_label}: {member_n}: file_size={int(info.file_size)} max_streamed_member_bytes={int(limits.max_streamed_member_bytes)}"
                )
            nested_path = nested_dir / f"chain-{depth + 1}.zip"
            _assert_under_dir(input_dir, nested_path)
            with zf.open(info, "r") as src, nested_path.open("wb") as dst:
                _ = _copy_stream_limited(
                    src,
                    dst,
                    max_bytes=int(limits.max_streamed_member_bytes),
                    label=f"{archive_label}: {member_n}",
                )
            nested_paths.append(nested_path)
            current_archive_path = nested_path

    if not archive_chain:
        _ = shutil.copy2(firmware_zip_path, update_zip_path)
        chosen_zf = zipfile.ZipFile(firmware_zip_path)
        archive_label = "<root>"
    else:
        _ = shutil.copy2(current_archive_path, update_zip_path)
        chosen_zf = zipfile.ZipFile(current_archive_path)
        archive_label = "!/".join(archive_chain)

    payload_member_n = _normalize_member_name(payload_member_path)
    if not _is_safe_member_path(payload_member_n):
        raise AIEdgePolicyViolation(
            f"unsafe payload member path: {payload_member_path!r}"
        )

    with chosen_zf:
        member_map = _safe_member_map(
            chosen_zf, archive_label=archive_label, limits=limits
        )
        payload_info = member_map.get(payload_member_n)
        if payload_info is None:
            raise FileNotFoundError(
                f"payload member not found in chosen archive: {payload_member_n}"
            )
        with (
            chosen_zf.open(payload_info, "r") as payload_src,
            payload_path.open("wb") as payload_dst,
        ):
            _ = _copy_stream_limited(
                payload_src,
                payload_dst,
                max_bytes=int(limits.max_streamed_member_bytes),
                label=f"{archive_label}: {payload_member_n}",
            )

        preferred_props = ""
        parent = str(PurePosixPath(payload_member_n).parent)
        if parent and parent != ".":
            preferred_props = f"{parent}/payload_properties.txt"

        props_candidates = [
            preferred_props,
            "payload_properties.txt",
        ]
        props_path: str | None = None
        for candidate in props_candidates:
            if candidate and candidate in member_map:
                props_path = candidate
                break
        if props_path is None:
            for name in member_map:
                if name == "payload_properties.txt" or name.endswith(
                    "/payload_properties.txt"
                ):
                    props_path = name
                    break

        props_text: str | None = None
        if props_path is not None:
            with chosen_zf.open(member_map[props_path], "r") as props_src:
                raw = props_src.read(int(limits.max_streamed_member_bytes))
                if props_src.read(1):
                    raise AIEdgePolicyViolation(
                        "payload_properties.txt exceeds max_streamed_member_bytes"
                    )
            props_text = raw.decode("utf-8", errors="replace")

    for nested_path in nested_paths:
        nested_path.unlink(missing_ok=True)

    return update_zip_path, payload_path, props_text


def _parse_file_hash(props_text: str | None) -> str | None:
    if not props_text:
        return None
    for line in props_text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("FILE_HASH="):
            return s.split("=", 1)[1].strip()
    return None


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_payload_file_hash(
    payload_path: Path, payload_properties_text: str | None
) -> dict[str, JsonValue]:
    actual_hex = _sha256_file(payload_path)
    file_hash_b64 = _parse_file_hash(payload_properties_text)
    result: dict[str, JsonValue] = {
        "payload_sha256": actual_hex,
        "file_hash_present": bool(file_hash_b64),
        "file_hash_b64": file_hash_b64 or "",
        "file_hash_expected_sha256": "",
        "file_hash_matches": None,
        "file_hash_error": "",
    }

    if not file_hash_b64:
        return result

    try:
        expected_digest = base64.b64decode(file_hash_b64, validate=True)
    except Exception as exc:
        result["file_hash_error"] = (
            f"invalid FILE_HASH base64: {type(exc).__name__}: {exc}"
        )
        return result

    expected_hex = expected_digest.hex()
    result["file_hash_expected_sha256"] = expected_hex
    result["file_hash_matches"] = bool(expected_hex == actual_hex)
    return result


def _build_partitions_manifest(
    run_dir: Path, partitions_dir: Path
) -> list[dict[str, JsonValue]]:
    items: list[dict[str, JsonValue]] = []
    for img in sorted(partitions_dir.glob("*.img")):
        if not img.is_file():
            continue
        sha256 = _sha256_file(img)
        rel = _rel_to_run_dir(run_dir, img)
        items.append(
            {
                "name": img.stem,
                "path": rel,
                "size": int(img.stat().st_size),
                "sha256": sha256,
            }
        )
    return items


@dataclass(frozen=True)
class OtaPayloadStage:
    input_path: Path
    module_version: str = "v0.0.0-20241120142751-a51234eaead2"

    @property
    def name(self) -> str:
        return "ota_payload"

    def run(self, ctx: StageContext) -> StageOutcome:
        stage_dir = ctx.run_dir / "stages" / "ota"
        ota_json_path = stage_dir / "ota.json"
        payload_json_path = stage_dir / "payload.json"
        input_dir = stage_dir / "input"
        partitions_dir = stage_dir / "partitions"
        tools_dir = stage_dir / "tools"

        for p in [
            stage_dir,
            ota_json_path,
            payload_json_path,
            input_dir,
            partitions_dir,
            tools_dir,
        ]:
            _assert_under_dir(ctx.run_dir, p)

        stage_dir.mkdir(parents=True, exist_ok=True)
        input_dir.mkdir(parents=True, exist_ok=True)
        partitions_dir.mkdir(parents=True, exist_ok=True)
        tools_dir.mkdir(parents=True, exist_ok=True)

        limitations: list[str] = []
        status: StageStatus = "failed"
        details: dict[str, JsonValue] = {}

        if not ota_json_path.is_file():
            details = {
                "evidence": cast(
                    list[JsonValue],
                    cast(
                        list[object],
                        [
                            _evidence_path(ctx.run_dir, stage_dir),
                            _evidence_path(ctx.run_dir, ota_json_path, note="missing"),
                        ],
                    ),
                ),
                "artifacts": {
                    "payload_json": _rel_to_run_dir(ctx.run_dir, payload_json_path)
                },
            }
            limitations.append("OTA payload stage skipped: stages/ota/ota.json missing")
            _ = payload_json_path.write_text(
                json.dumps(
                    {
                        "status": "skipped",
                        "reason": "missing ota.json",
                        "evidence": details["evidence"],
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            return StageOutcome(
                status="skipped", details=details, limitations=limitations
            )

        ota_raw = cast(object, json.loads(ota_json_path.read_text(encoding="utf-8")))
        ota_obj = cast(dict[str, object], ota_raw if isinstance(ota_raw, dict) else {})
        chosen_any = ota_obj.get("chosen")
        if not isinstance(chosen_any, dict):
            details = {
                "evidence": cast(
                    list[JsonValue],
                    cast(
                        list[object],
                        [
                            _evidence_path(ctx.run_dir, stage_dir),
                            _evidence_path(ctx.run_dir, ota_json_path),
                        ],
                    ),
                ),
                "artifacts": {
                    "payload_json": _rel_to_run_dir(ctx.run_dir, payload_json_path)
                },
            }
            limitations.append(
                "OTA payload stage skipped: no chosen OTA candidate in ota.json"
            )
            _ = payload_json_path.write_text(
                json.dumps(
                    {
                        "status": "skipped",
                        "reason": "no chosen candidate",
                        "evidence": details["evidence"],
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            return StageOutcome(
                status="skipped", details=details, limitations=limitations
            )

        chosen = cast(dict[str, object], chosen_any)
        chosen_json = cast(dict[str, JsonValue], cast(object, chosen))
        archive_chain_any = chosen.get("archive_chain")
        archive_chain: list[str] = []
        if isinstance(archive_chain_any, list):
            for item in cast(list[object], archive_chain_any):
                if isinstance(item, str) and item:
                    archive_chain.append(_normalize_member_name(item))

        payload_member_any = chosen.get("payload_bin_path")
        payload_member = (
            payload_member_any if isinstance(payload_member_any, str) else ""
        )
        if not payload_member:
            limitations.append("Chosen OTA candidate has no payload_bin_path")
            status = "failed"
            payload_doc_missing_member: dict[str, JsonValue] = {
                "status": status,
                "limitations": cast(list[JsonValue], list(limitations)),
            }
            _ = payload_json_path.write_text(
                json.dumps(payload_doc_missing_member, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            details = {
                "evidence": cast(
                    list[JsonValue],
                    cast(
                        list[object],
                        [
                            _evidence_path(ctx.run_dir, stage_dir),
                            _evidence_path(ctx.run_dir, ota_json_path),
                            _evidence_path(ctx.run_dir, payload_json_path),
                        ],
                    ),
                ),
                "artifacts": {
                    "payload_json": _rel_to_run_dir(ctx.run_dir, payload_json_path)
                },
            }
            return StageOutcome(status=status, details=details, limitations=limitations)

        limits = _read_limits(ota_obj)

        update_zip_path: Path
        payload_path: Path
        payload_props_text: str | None
        try:
            update_zip_path, payload_path, payload_props_text = (
                extract_payload_and_properties(
                    firmware_zip_path=self.input_path,
                    archive_chain=archive_chain,
                    payload_member_path=payload_member,
                    input_dir=input_dir,
                    limits=limits,
                )
            )
        except Exception as exc:
            limitations.append(
                f"Failed to materialize OTA payload input: {type(exc).__name__}: {exc}"
            )
            status = "failed"
            payload_doc_extract_failure: dict[str, JsonValue] = {
                "status": status,
                "limits": {
                    "max_depth": int(limits.max_depth),
                    "max_archives": int(limits.max_archives),
                    "max_entries_per_zip": int(limits.max_entries_per_zip),
                    "max_streamed_member_bytes": int(limits.max_streamed_member_bytes),
                },
                "limitations": cast(list[JsonValue], list(limitations)),
            }
            _ = payload_json_path.write_text(
                json.dumps(payload_doc_extract_failure, indent=2, sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            details = {
                "evidence": cast(
                    list[JsonValue],
                    cast(
                        list[object],
                        [
                            _evidence_path(ctx.run_dir, stage_dir),
                            _evidence_path(ctx.run_dir, ota_json_path),
                            _evidence_path(ctx.run_dir, payload_json_path),
                            _evidence_path(ctx.run_dir, input_dir),
                        ],
                    ),
                ),
                "artifacts": {
                    "ota_json": _rel_to_run_dir(ctx.run_dir, ota_json_path),
                    "payload_json": _rel_to_run_dir(ctx.run_dir, payload_json_path),
                },
            }
            return StageOutcome(status=status, details=details, limitations=limitations)

        hash_result = verify_payload_file_hash(payload_path, payload_props_text)
        hash_match_any = hash_result.get("file_hash_matches")
        if isinstance(hash_match_any, bool) and not hash_match_any:
            limitations.append(
                "payload_properties FILE_HASH does not match payload.bin sha256"
            )

        go_bin = shutil.which("go")
        tool_module = f"github.com/ssut/payload-dumper-go@{self.module_version}"
        install_argv = ["go", "install", tool_module]
        tool_home = tools_dir / "home"
        tool_go = tools_dir / "go"
        tool_bin_dir = tools_dir / "bin"
        tool_cache = tool_go / "cache"
        tool_modcache = tool_go / "pkg" / "mod"

        for p in [tool_home, tool_go, tool_bin_dir, tool_cache, tool_modcache]:
            _assert_under_dir(tools_dir, p)
            p.mkdir(parents=True, exist_ok=True)

        env = os.environ.copy()
        env["HOME"] = str(tool_home)
        env["GOPATH"] = str(tool_go)
        env["GOBIN"] = str(tool_bin_dir)
        env["GOCACHE"] = str(tool_cache)
        env["GOMODCACHE"] = str(tool_modcache)

        install_exit: int | None = None
        install_stdout = ""
        install_stderr = ""
        payload_dumper_bin = tool_bin_dir / "payload-dumper-go"

        if go_bin is None:
            limitations.append("payload-dumper-go unavailable: go toolchain not found")
        else:
            try:
                proc = subprocess.run(
                    [go_bin, "install", tool_module],
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=180.0,
                    env=env,
                )
                install_exit = int(proc.returncode)
                install_stdout = proc.stdout or ""
                install_stderr = proc.stderr or ""
                if proc.returncode != 0:
                    limitations.append(
                        "payload-dumper-go install failed: "
                        + (proc.stderr.strip() or f"exit_code={proc.returncode}")
                    )
            except subprocess.TimeoutExpired:
                limitations.append("payload-dumper-go install timed out")

        dump_argv = [
            str(payload_dumper_bin),
            "-o",
            str(partitions_dir),
            str(payload_path),
        ]
        dump_exit: int | None = None
        dump_stdout = ""
        dump_stderr = ""

        if not payload_dumper_bin.is_file():
            limitations.append(
                "payload-dumper-go binary missing after install; partition dump skipped"
            )
            status = "partial"
        else:
            try:
                dump = subprocess.run(
                    dump_argv,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=1800.0,
                    env=env,
                )
                dump_exit = int(dump.returncode)
                dump_stdout = dump.stdout or ""
                dump_stderr = dump.stderr or ""
                if dump.returncode != 0:
                    limitations.append(
                        "payload-dumper-go extraction failed: "
                        + (dump.stderr.strip() or f"exit_code={dump.returncode}")
                    )
                    status = "partial"
            except subprocess.TimeoutExpired:
                limitations.append("payload-dumper-go extraction timed out")
                status = "partial"

        partitions = _build_partitions_manifest(ctx.run_dir, partitions_dir)
        if status != "partial":
            if partitions:
                status = "ok" if not limitations else "partial"
            else:
                limitations.append(
                    "No partition images were produced by payload-dumper-go"
                )
                status = "partial"

        evidence = [
            _evidence_path(ctx.run_dir, stage_dir),
            _evidence_path(ctx.run_dir, ota_json_path),
            _evidence_path(ctx.run_dir, payload_json_path),
            _evidence_path(ctx.run_dir, input_dir),
            _evidence_path(ctx.run_dir, update_zip_path),
            _evidence_path(ctx.run_dir, payload_path),
            _evidence_path(ctx.run_dir, partitions_dir),
            _evidence_path(ctx.run_dir, tools_dir),
            _evidence_path(
                ctx.run_dir,
                payload_dumper_bin,
                note="missing" if not payload_dumper_bin.is_file() else None,
            ),
        ]

        payload_doc: dict[str, JsonValue] = {
            "status": status,
            "chosen": cast(JsonValue, chosen_json),
            "limits": {
                "max_depth": int(limits.max_depth),
                "max_archives": int(limits.max_archives),
                "max_entries_per_zip": int(limits.max_entries_per_zip),
                "max_streamed_member_bytes": int(limits.max_streamed_member_bytes),
            },
            "input": {
                "ota_json": _rel_to_run_dir(ctx.run_dir, ota_json_path),
                "update_zip": _rel_to_run_dir(ctx.run_dir, update_zip_path),
                "payload_bin": _rel_to_run_dir(ctx.run_dir, payload_path),
            },
            "file_hash": hash_result,
            "payload_dumper_go": {
                "module": tool_module,
                "version": self.module_version,
                "install": {
                    "argv": cast(JsonValue, list(install_argv)),
                    "exit_code": install_exit,
                    "stdout": install_stdout,
                    "stderr": install_stderr,
                },
                "extract": {
                    "argv": cast(JsonValue, list(dump_argv)),
                    "exit_code": dump_exit,
                    "stdout": dump_stdout,
                    "stderr": dump_stderr,
                },
            },
            "partitions": cast(list[JsonValue], cast(list[object], partitions)),
            "evidence": cast(list[JsonValue], cast(list[object], evidence)),
            "limitations": cast(list[JsonValue], list(limitations)),
        }
        _ = payload_json_path.write_text(
            json.dumps(payload_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        details = {
            "artifacts": {
                "ota_json": _rel_to_run_dir(ctx.run_dir, ota_json_path),
                "payload_json": _rel_to_run_dir(ctx.run_dir, payload_json_path),
                "update_zip": _rel_to_run_dir(ctx.run_dir, update_zip_path),
                "payload_bin": _rel_to_run_dir(ctx.run_dir, payload_path),
                "partitions_dir": _rel_to_run_dir(ctx.run_dir, partitions_dir),
            },
            "partitions": cast(list[JsonValue], cast(list[object], partitions)),
            "file_hash": hash_result,
            "evidence": cast(list[JsonValue], cast(list[object], evidence)),
        }
        return StageOutcome(status=status, details=details, limitations=limitations)
