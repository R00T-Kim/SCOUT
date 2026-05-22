#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from aiedge.aeg_readiness import (  # noqa: E402
    build_readiness_report,
    format_readiness_report,
    write_readiness_report,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Fail-closed AEG platform readiness audit: curated pattern-pair evidence, "
            "stable real-firmware pair report, and vulnerable/control dynamic-proof separation."
        )
    )
    parser.add_argument("--repo-root", type=Path, default=_REPO_ROOT)
    parser.add_argument("--patterns-dir", type=Path, default=None)
    parser.add_argument("--min-real-firmware-pairs", type=int, default=1)
    parser.add_argument(
        "--allow-unvalidated-patterns",
        action="store_true",
        help="Do not require every curated pattern card to have vulnerable/control evidence.",
    )
    parser.add_argument("--out", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    payload = build_readiness_report(
        repo_root=args.repo_root,
        patterns_dir=args.patterns_dir,
        require_all_patterns=not args.allow_unvalidated_patterns,
        min_real_firmware_pairs=int(args.min_real_firmware_pairs),
    )
    if args.out:
        write_readiness_report(args.out, payload)
    print(format_readiness_report(payload), end="")
    return 0 if payload.get("ready") is True else 35


if __name__ == "__main__":
    raise SystemExit(main())
