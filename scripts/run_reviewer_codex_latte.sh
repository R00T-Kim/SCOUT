#!/usr/bin/env bash
# Codex lane with AIEDGE_LATTE_SLICING=1 enabled + LARA fix active.
# Runs in parallel with the claude LATTE-on lane.
set -u
cd "$(dirname "$0")/.." || exit 99

LOG_DIR="logs/reviewer-sequential"
mkdir -p "$LOG_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_LOG="$LOG_DIR/codex_latte_${TS}.log"

export AIEDGE_LATTE_SLICING=1

{
  echo "=== reviewer codex LATTE-on launcher ==="
  echo "started_at_utc: $(date -u --iso-8601=seconds)"
  echo "pwd: $(pwd)"
  echo "pid: $$"
  echo "AIEDGE_LATTE_SLICING: $AIEDGE_LATTE_SLICING"
  echo

  python3 scripts/run_pair_eval.py \
      --driver codex \
      --parallel 2 \
      --time-budget-s 21600 \
      --results-dir benchmark-results/pair-eval-dedicated-local7-codex-6h-r2-latte-on
  rc=$?
  echo "codex_lane_exit: ${rc}"
  echo "finished_at_utc: $(date -u --iso-8601=seconds)"
} > "$RUN_LOG" 2>&1
