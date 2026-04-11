#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$HOME/SCOUT"
cd "$REPO_ROOT"
export PYTHONPATH="${REPO_ROOT}/src:${PYTHONPATH:-}"
export AIEDGE_LLM_DRIVER=codex

ARCHIVES_DIR="benchmark-results/tier2-llm-codex/archives"
OUT_BASE="benchmark-results/tier2-llm-codex-adv-rerun/runs"
LOG="benchmark-results/tier2-llm-codex-adv-rerun/rerun.log"
mkdir -p "$(dirname $LOG)"

echo "$(date) — Starting adversarial_triage rerun with codex" | tee -a "$LOG"

for bundle in $(ls -d "$ARCHIVES_DIR"/*/*); do
    vendor=$(basename $(dirname "$bundle"))
    sha=$(basename "$bundle")
    run_dir="$OUT_BASE/$vendor/$sha"
    
    # Skip if already has successful claude-code traces
    # Fresh copy from archive
    rm -rf "$run_dir"
    mkdir -p "$(dirname $run_dir)"
    cp -r "$bundle" "$run_dir"
    # Remove old llm_trace to avoid confusion
    rm -rf "$run_dir/stages/adversarial_triage/llm_trace"
    
    echo "$(date) [$vendor/$sha] starting..." | tee -a "$LOG"
    
    if python3 -m aiedge stages "$run_dir" --stages adversarial_triage --time-budget-s 1800 >> "$LOG" 2>&1; then
        echo "$(date) [$vendor/$sha] done" | tee -a "$LOG"
    else
        ec=$?
        # Check if rate limited
        if grep -q "usage limit\|hit your limit" "$LOG" 2>/dev/null; then
            echo "$(date) [$vendor/$sha] RATE LIMITED — stopping" | tee -a "$LOG"
            exit 1
        fi
        echo "$(date) [$vendor/$sha] exit=$ec" | tee -a "$LOG"
    fi
done

echo "$(date) — All done!" | tee -a "$LOG"
