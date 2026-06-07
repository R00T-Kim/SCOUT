#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aiedge.phase12_progress import (
    DEFAULT_PAIRS,
    DEFAULT_PHASE1_MATRIX,
    DEFAULT_PHASE1_SCALE_TARGET,
    DEFAULT_PHASE2_DOSSIER,
    build_phase12_progress,
    write_phase12_progress,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Phase 1 pair matrix and Phase 2 novelty dossier artifacts.")
    parser.add_argument("--pairs", type=Path, default=DEFAULT_PAIRS)
    parser.add_argument("--phase1-out", type=Path, default=DEFAULT_PHASE1_MATRIX)
    parser.add_argument("--phase2-out", type=Path, default=DEFAULT_PHASE2_DOSSIER)
    parser.add_argument("--phase1-scale-target", type=int, default=DEFAULT_PHASE1_SCALE_TARGET)
    parser.add_argument("--phase-start-commit", default=None)
    args = parser.parse_args()

    payload = build_phase12_progress(
        pairs_path=args.pairs,
        phase1_scale_target=args.phase1_scale_target,
        phase_start_commit=args.phase_start_commit,
    )
    write_phase12_progress(phase1_path=args.phase1_out, phase2_path=args.phase2_out, payload=payload)
    summary = {
        "phase1_status": payload["phase1"]["status"],
        "phase2_status": payload["phase2"]["status"],
        "promotable_real_pair_count": payload["phase1"]["summary"]["promotable_real_pair_count"],
        "next_pair_run_queue": payload["phase1"]["summary"]["next_pair_run_queue"],
        "unknown_hypothesis_count": payload["phase2"]["dashboard"]["unknown_hypothesis_count"],
    }
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
