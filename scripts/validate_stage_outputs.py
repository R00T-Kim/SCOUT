#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from aiedge.stage_contracts import validate_run_stage_outputs


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate stage.json manifests and key stage artifacts in a run dir."
    )
    parser.add_argument(
        "--run-dir",
        required=True,
        help="Path to the run directory to validate",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir).expanduser().resolve()
    errors = validate_run_stage_outputs(run_dir)
    if errors:
        print(f"[FAIL] {run_dir}")
        for err in errors:
            print(f" - {err}")
        return 2

    print(f"[OK] {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
