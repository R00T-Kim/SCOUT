#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$HOME/SCOUT"
cd "$REPO_ROOT"
export PYTHONPATH="${REPO_ROOT}/src:${PYTHONPATH:-}"
export AIEDGE_LLM_DRIVER=codex
export AIEDGE_ADV_PARALLEL=4

ARCHIVES_DIR="benchmark-results/tier2-llm-codex/archives"
OUT_BASE="benchmark-results/tier2-llm-codex-adv-rerun/runs"
LOG="benchmark-results/tier2-llm-codex-adv-rerun/rerun-parallel.log"
PARALLEL=1

mkdir -p "$OUT_BASE" "$(dirname $LOG)"
echo "$(date) — Starting rerun (${PARALLEL} bundle x ${AIEDGE_ADV_PARALLEL} threads)" | tee "$LOG"

run_one() {
    local bundle="$1"
    local vendor=$(basename $(dirname "$bundle"))
    local sha=$(basename "$bundle")
    local run_dir="$OUT_BASE/$vendor/$sha"

    # Skip if already completed
    local sj="$run_dir/stages/adversarial_triage/stage.json"
    if [[ -f "$sj" ]]; then
        local debated=$(python3 -c "import json; d=json.load(open('$sj')); print(d.get('summary',{}).get('debated',0))" 2>/dev/null || echo 0)
        if [[ "$debated" -gt 0 ]]; then
            echo "$(date) [$vendor/$sha] SKIP (already debated=$debated)" | tee -a "$LOG"
            return 0
        fi
    fi

    # Only copy if run_dir doesn't exist yet (preserve partial results)
    if [[ ! -d "$run_dir/stages" ]]; then
        rm -rf "$run_dir"
        mkdir -p "$(dirname $run_dir)"
        cp -r "$bundle" "$run_dir"
    fi
    rm -rf "$run_dir/stages/adversarial_triage/llm_trace"

    local start=$(date +%s)
    local ec=0
    python3 -m aiedge stages "$run_dir" --stages adversarial_triage --time-budget-s 1800 2>&1 || ec=$?
    local dur=$(( $(date +%s) - start ))

    # Check rate limit
    local traces_dir="$run_dir/stages/adversarial_triage/llm_trace"
    if [[ -d "$traces_dir" ]]; then
        if grep -rl "usage limit\|hit your limit" "$traces_dir"/ 2>/dev/null | head -1 | grep -q .; then
            echo "$(date) [$vendor/$sha] RATE LIMITED after ${dur}s" | tee -a "$LOG"
            return 2
        fi
    fi

    echo "$(date) [$vendor/$sha] exit=$ec (${dur}s)" | tee -a "$LOG"
    return 0
}
export -f run_one
export PYTHONPATH AIEDGE_LLM_DRIVER AIEDGE_ADV_PARALLEL OUT_BASE LOG

BUNDLES=($(ls -d "$ARCHIVES_DIR"/*/*))
TOTAL=${#BUNDLES[@]}
echo "$(date) — $TOTAL bundles, $PARALLEL parallel" | tee -a "$LOG"

idx=0
active=0
for bundle in "${BUNDLES[@]}"; do
    idx=$((idx + 1))
    echo "[$idx/$TOTAL] $(basename $(dirname $bundle))/$(basename $bundle)" | tee -a "$LOG"
    run_one "$bundle" &
    active=$((active + 1))
    if [[ $active -ge $PARALLEL ]]; then
        wait -n 2>/dev/null || true
        active=$((active - 1))
    fi
done
wait || true

echo "$(date) — All done!" | tee -a "$LOG"
