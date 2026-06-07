#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from aiedge.phase01_readiness import (  # noqa: E402
    DEFAULT_MIN_REAL_PAIRS,
    DEFAULT_PHASE1_TARGET_REAL_PAIRS,
    DEFAULT_REPORT,
    build_phase01_readiness,
    write_phase01_readiness,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build the Phase 0/1 readiness ledger that proves whether SCOUT can "
            "enter the Phase 2 zero-day hypothesis lane."
        )
    )
    parser.add_argument("--repo-root", type=Path, default=_REPO_ROOT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument(
        "--min-real-firmware-pairs",
        type=int,
        default=DEFAULT_MIN_REAL_PAIRS,
        help="Minimum promotable real pair floor required for Phase 2 entry.",
    )
    parser.add_argument(
        "--phase1-target-real-pairs",
        type=int,
        default=DEFAULT_PHASE1_TARGET_REAL_PAIRS,
        help="Tracked Phase 1 scale target; reported separately from the Phase 2 entry floor.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("docs/pov/phase0_phase1_readiness.json"),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    payload = build_phase01_readiness(
        repo_root=args.repo_root,
        report_path=args.report,
        min_real_firmware_pairs=int(args.min_real_firmware_pairs),
        phase1_target_real_pairs=int(args.phase1_target_real_pairs),
    )
    write_phase01_readiness(args.out, payload)
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", end="")
    return 0 if payload.get("phase2_entry_ready") is True else 37


if __name__ == "__main__":
    raise SystemExit(main())
