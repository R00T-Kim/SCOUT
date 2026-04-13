#!/usr/bin/env python3
"""Build a SCOUT benchmark baseline from analysis runs.

Enforces benchmark governance rules from docs/benchmark_governance.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REQUIRED_TIER_FIELDS = {"driver", "firmware_count", "validation_date"}
REQUIRED_MANIFEST_FIELDS = {"version", "release_date", "tier1", "tier2"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def validate_manifest(manifest: dict[str, Any]) -> list[str]:
    errors = []
    for field in REQUIRED_MANIFEST_FIELDS:
        if field not in manifest:
            errors.append(f"Missing required field: {field}")
    for tier in ("tier1", "tier2"):
        if tier in manifest:
            tier_data = manifest[tier]
            for field in REQUIRED_TIER_FIELDS:
                if field not in tier_data:
                    errors.append(f"Missing {tier}.{field}")
    return errors


def write_hashes(baseline_dir: Path, hashes_file: Path) -> None:
    lines = ["# SHA-256 hashes for baseline artifacts"]
    for path in sorted(baseline_dir.rglob("*.json")):
        if path == hashes_file:
            continue
        rel = path.relative_to(baseline_dir)
        lines.append(f"{sha256_file(path)}  {rel}")
    hashes_file.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build SCOUT benchmark baseline")
    parser.add_argument(
        "--version", required=True, help="Baseline version (e.g., v2.5.1)"
    )
    parser.add_argument(
        "--manifest", type=Path, help="Pre-built manifest.json to validate"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmarks/baselines"),
        help="Output directory",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate existing baseline without building",
    )
    args = parser.parse_args()

    baseline_dir = args.output / args.version

    if args.validate_only:
        manifest_path = baseline_dir / "manifest.json"
        if not manifest_path.exists():
            print(f"ERROR: {manifest_path} does not exist", file=sys.stderr)
            return 1
        manifest = json.loads(manifest_path.read_text())
        errors = validate_manifest(manifest)
        if errors:
            print("Validation errors:", file=sys.stderr)
            for e in errors:
                print(f"  - {e}", file=sys.stderr)
            return 1
        print(f"OK: {manifest_path} is valid")
        write_hashes(baseline_dir, baseline_dir / "hashes.txt")
        print("OK: hashes.txt updated")
        return 0

    print("Build mode not yet implemented. Use --validate-only.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
