#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aiedge.phase3_readiness import (  # noqa: E402
    DEFAULT_PHASE3_READINESS,
    build_phase3_readiness,
    write_phase3_readiness,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build the Phase 3 AEG readiness artifact proving Plan IR, "
            "selection, reliability, backend, and taxonomy gates."
        )
    )
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_PHASE3_READINESS)
    parser.add_argument("--phase-start-commit", default=None)
    args = parser.parse_args()

    payload = build_phase3_readiness(
        repo_root=args.repo_root,
        phase_start_commit=args.phase_start_commit,
    )
    write_phase3_readiness(args.out, payload)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0 if payload.get("phase3_ready") is True else 37


if __name__ == "__main__":
    raise SystemExit(main())
