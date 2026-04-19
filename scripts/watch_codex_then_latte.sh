#!/usr/bin/env bash
# Watch Codex lane run_index.json. Once rows >= 14 (completion), kill the
# existing sequential launcher and spawn the LATTE-on Claude lane.
set -u
cd "$(dirname "$0")/.." || exit 99

LOG_DIR="logs/reviewer-sequential"
mkdir -p "$LOG_DIR"
HANDOFF_LOG="$LOG_DIR/watcher_handoff.log"
CODEX_IDX="benchmark-results/pair-eval-dedicated-local7-codex-6h-r2/run_index.json"

{
  echo "=== watcher started: $(date -u --iso-8601=seconds) pid=$$ ==="
  echo "watching: $CODEX_IDX"

  while true; do
    rows=$(python3 -c "import json; print(len(json.load(open('$CODEX_IDX'))['rows']))" 2>/dev/null || echo 0)
    if [ "$rows" -ge 14 ]; then
      echo "[$(date -u --iso-8601=seconds)] codex lane reached 14/14 rows. handoff start."
      # kill the existing sequential launcher + any residual claude lane it started
      pkill -TERM -f "run_reviewer_sequential.sh" 2>/dev/null && echo "  killed sequential launcher"
      sleep 3
      pkill -TERM -f "run_pair_eval.py.*claude-code" 2>/dev/null && echo "  killed LATTE-off claude pair_eval"
      sleep 3
      pkill -TERM -f "python3 -m aiedge" 2>/dev/null && echo "  killed residual aiedge children"
      sleep 5
      echo "[$(date -u --iso-8601=seconds)] spawning LATTE-on claude launcher"
      nohup setsid bash scripts/run_reviewer_claude_latte.sh </dev/null >>"$LOG_DIR/claude_latte_bootstrap.out" 2>&1 &
      disown
      echo "  new launcher pid group detached"
      echo "=== watcher done: $(date -u --iso-8601=seconds) ==="
      exit 0
    fi
    sleep 60
  done
} >> "$HANDOFF_LOG" 2>&1
