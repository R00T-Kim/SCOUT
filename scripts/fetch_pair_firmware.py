#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

_CHUNK = 1024 * 1024


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != "pair-eval-v1":
        raise ValueError("unsupported pair manifest schema_version")
    if not isinstance(payload.get("pairs"), list):
        raise ValueError("pairs must be a list")
    return payload


def _select_pairs(payload: dict[str, Any], pair_ids: set[str] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in payload["pairs"]:
        if not isinstance(item, dict):
            continue
        pair_id = str(item.get("pair_id") or "")
        if pair_ids is None or pair_id in pair_ids:
            out.append(item)
    missing = sorted(pair_ids - {str(p.get("pair_id") or "") for p in out}) if pair_ids else []
    if missing:
        raise ValueError("pair_id not found: " + ", ".join(missing))
    return out


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=dest.name + ".", suffix=".tmp", dir=dest.parent, delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        with urllib.request.urlopen(url, timeout=60) as response, tmp_path.open("wb") as handle:  # noqa: S310 - operator-provided firmware URL from manifest
            shutil.copyfileobj(response, handle, length=_CHUNK)
        tmp_path.replace(dest)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def _process_side(pair: dict[str, Any], side: str, *, dest_root: Path, force: bool, dry_run: bool) -> dict[str, Any]:
    raw_side = pair.get(side)
    if not isinstance(raw_side, dict):
        raise ValueError(f"{pair.get('pair_id')} {side} side must be an object")
    firmware_path = str(raw_side.get("firmware_path") or "")
    expected_sha = str(raw_side.get("sha256") or "")
    source_url = str(raw_side.get("source_url") or "")
    if not firmware_path or not expected_sha:
        raise ValueError(f"{pair.get('pair_id')} {side} side is missing firmware_path/sha256")
    if not source_url:
        raise ValueError(f"{pair.get('pair_id')} {side} side is missing source_url")

    dest = (dest_root / firmware_path).resolve()
    before_exists = dest.is_file()
    action = "verify_existing" if before_exists and not force else "download"
    actual_sha = ""
    if dry_run:
        status = "planned"
    else:
        if action == "download":
            _download(source_url, dest)
        actual_sha = _sha256_file(dest)
        status = "ok" if actual_sha == expected_sha else "sha256_mismatch"
    return {
        "side": side,
        "firmware_path": firmware_path,
        "destination": str(dest),
        "source_url": source_url,
        "expected_sha256": expected_sha,
        "actual_sha256": actual_sha,
        "preexisting": before_exists,
        "action": action,
        "status": status,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch official firmware files for pair-eval entries and verify SHA-256."
    )
    parser.add_argument("--pairs", default="benchmarks/pair-eval/pairs.json")
    parser.add_argument("--pair-id", action="append", default=[], help="Pair id to fetch; repeatable. Defaults to all entries with source_url.")
    parser.add_argument("--dest-root", type=Path, default=Path("."))
    parser.add_argument("--force", action="store_true", help="Re-download even when the destination exists.")
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        payload = _load_manifest(Path(args.pairs))
        pair_ids = set(args.pair_id) if args.pair_id else None
        pairs = _select_pairs(payload, pair_ids)
        if pair_ids is None:
            pairs = [
                pair for pair in pairs
                if all(isinstance(pair.get(side), dict) and pair[side].get("source_url") for side in ("vulnerable", "patched"))
            ]
        rows: list[dict[str, Any]] = []
        for pair in pairs:
            pair_rows = [
                _process_side(pair, "vulnerable", dest_root=args.dest_root, force=args.force, dry_run=args.dry_run),
                _process_side(pair, "patched", dest_root=args.dest_root, force=args.force, dry_run=args.dry_run),
            ]
            rows.append({
                "pair_id": pair.get("pair_id"),
                "vendor": pair.get("vendor"),
                "model": pair.get("model"),
                "cve_id": pair.get("cve_id"),
                "sides": pair_rows,
                "status": "ok" if all(row["status"] in {"ok", "planned"} for row in pair_rows) else "failed",
            })
        result = {"schema_version": "pair-firmware-fetch-v1", "pairs": rows}
        print(json.dumps(result, indent=2, sort_keys=True) + "\n", end="")
        return 0 if all(row["status"] == "ok" or args.dry_run for row in rows) else 47
    except Exception as exc:
        print(json.dumps({"schema_version": "pair-firmware-fetch-v1", "error": str(exc)}, indent=2, sort_keys=True) + "\n", end="")
        return 48


if __name__ == "__main__":
    raise SystemExit(main())
