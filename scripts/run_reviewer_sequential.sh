#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.." || exit 99

LOG_DIR="logs/reviewer-sequential"
mkdir -p "$LOG_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_LOG="$LOG_DIR/run_${TS}.log"

{
  echo "=== reviewer sequential launcher ==="
  echo "started_at_utc: $(date -u --iso-8601=seconds)"
  echo "pwd: $(pwd)"
  echo "pid: $$"
  echo

  echo "### LANE 1: codex (6h budget) ###"
  python3 scripts/run_pair_eval.py \
      --driver codex \
      --parallel 2 \
      --time-budget-s 21600 \
      --results-dir benchmark-results/pair-eval-dedicated-local7-codex-6h-r2
  codex_rc=$?
  echo "codex_lane_exit: ${codex_rc}"
  echo "codex_lane_finished_at_utc: $(date -u --iso-8601=seconds)"
  echo

  echo "### LANE 2: claude-code (6h budget) ###"
  python3 scripts/run_pair_eval.py \
      --driver claude-code \
      --parallel 2 \
      --time-budget-s 21600 \
      --results-dir benchmark-results/pair-eval-dedicated-local7-claude-6h-r2
  claude_rc=$?
  echo "claude_lane_exit: ${claude_rc}"
  echo "claude_lane_finished_at_utc: $(date -u --iso-8601=seconds)"
  echo

  echo "=== launcher done ==="
  echo "codex_rc: ${codex_rc}"
  echo "claude_rc: ${claude_rc}"
} > "$RUN_LOG" 2>&1
