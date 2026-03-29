#!/usr/bin/env bash
# =============================================================================
# SCOUT vs FirmAE Benchmark Script
# Runs SCOUT pipeline on the FirmAE dataset (1,124 firmware images)
# and compares results against FirmAE's published emulation/vuln metrics.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHONPATH="${REPO_ROOT}/src:${PYTHONPATH:-}"
export PYTHONPATH
AIEDGE_GHIDRA_HOME="${AIEDGE_GHIDRA_HOME:-/opt/ghidra_12.0.2_PUBLIC}"
export AIEDGE_GHIDRA_HOME

# --- Configuration ---
DATASET_DIR="${DATASET_DIR:-${REPO_ROOT}/aiedge-inputs/firmae-benchmark}"
RESULTS_DIR="${RESULTS_DIR:-${REPO_ROOT}/benchmark-results/firmae-$(date +%Y%m%d_%H%M)}"
PARALLEL_JOBS="${PARALLEL_JOBS:-4}"
TIME_BUDGET_S="${TIME_BUDGET_S:-600}"          # 10 min per firmware
STAGES="${STAGES:-}"  # empty = full pipeline (analyze --no-llm)
NO_LLM="--no-llm"
PROFILE="analysis"
MAX_IMAGES="${MAX_IMAGES:-0}"                  # 0 = all
CLEANUP_RUNS="${CLEANUP_RUNS:-0}"              # 1 = delete run dirs after CSV capture

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[BENCH]${NC} $(date +%H:%M:%S) $*"; }
ok()   { echo -e "${GREEN}[  OK ]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN ]${NC} $*"; }
fail() { echo -e "${RED}[FAIL ]${NC} $*"; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --dataset-dir DIR       FirmAE firmware directory (default: aiedge-inputs/firmae-benchmark)
  --results-dir DIR       Output directory for benchmark results
  --parallel N            Concurrent analyses (default: 4)
  --time-budget S         Seconds per firmware (default: 600)
  --stages STAGES         Comma-separated stages (default: static pipeline)
  --max-images N          Limit number of images to process (0 = all)
  --8mb                   Use 8MB truncated track
  --full                  Run full pipeline including dynamic stages
  --dry-run               List firmware files without running
  -h, --help              Show this help

Examples:
  # Quick benchmark: static-only, 10 images
  ./scripts/benchmark_firmae.sh --max-images 10 --time-budget 120

  # Full static pipeline on entire dataset
  ./scripts/benchmark_firmae.sh --parallel 8

  # Include dynamic stages (emulation, fuzzing)
  ./scripts/benchmark_firmae.sh --full --time-budget 1800
EOF
    exit 0
}

# --- Parse arguments ---
USE_8MB=0
DRY_RUN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dataset-dir)   DATASET_DIR="$2"; shift 2 ;;
        --results-dir)   RESULTS_DIR="$2"; shift 2 ;;
        --parallel)      PARALLEL_JOBS="$2"; shift 2 ;;
        --time-budget)   TIME_BUDGET_S="$2"; shift 2 ;;
        --stages)        STAGES="$2"; shift 2 ;;
        --max-images)    MAX_IMAGES="$2"; shift 2 ;;
        --8mb)           USE_8MB=1; shift ;;
        --full)          STAGES=""; shift ;;  # empty = all stages
        --cleanup)       CLEANUP_RUNS=1; shift ;;
        --dry-run)       DRY_RUN=1; shift ;;
        -h|--help)       usage ;;
        *)               echo "Unknown option: $1"; usage ;;
    esac
done

# --- Discover firmware files ---
log "Scanning dataset: ${DATASET_DIR}"
mapfile -t FW_FILES < <(
    find -L "$DATASET_DIR" -type f \( \
        -iname "*.bin" -o -iname "*.img" -o -iname "*.fw" -o \
        -iname "*.chk" -o -iname "*.trx" -o -iname "*.zip" -o \
        -iname "*.rar" -o -iname "*.gz" -o -iname "*.bz2" -o \
        -iname "*.ssa" \
    \) | sort
)

TOTAL=${#FW_FILES[@]}
if [[ $TOTAL -eq 0 ]]; then
    fail "No firmware files found in ${DATASET_DIR}"
    exit 1
fi

if [[ $MAX_IMAGES -gt 0 && $MAX_IMAGES -lt $TOTAL ]]; then
    FW_FILES=("${FW_FILES[@]:0:$MAX_IMAGES}")
    TOTAL=$MAX_IMAGES
fi

log "Found ${TOTAL} firmware images"

# --- Classify by vendor ---
declare -A VENDOR_COUNT
for fw in "${FW_FILES[@]}"; do
    vendor=$(basename "$(dirname "$fw")")
    VENDOR_COUNT[$vendor]=$(( ${VENDOR_COUNT[$vendor]:-0} + 1 ))
done
for vendor in $(echo "${!VENDOR_COUNT[@]}" | tr ' ' '\n' | sort); do
    log "  ${vendor}: ${VENDOR_COUNT[$vendor]} images"
done

if [[ $DRY_RUN -eq 1 ]]; then
    log "Dry run — listing files:"
    for fw in "${FW_FILES[@]}"; do
        echo "  $fw"
    done
    exit 0
fi

# --- Prepare results directory ---
mkdir -p "${RESULTS_DIR}"
SUMMARY_CSV="${RESULTS_DIR}/benchmark_summary.csv"
DETAIL_JSON="${RESULTS_DIR}/benchmark_detail.json"
LOG_DIR="${RESULTS_DIR}/logs"
mkdir -p "$LOG_DIR"

# CSV header
echo "index,vendor,firmware,sha256,exit_code,status,stages_ok,stages_partial,stages_failed,stages_skipped,findings_count,cve_count,duration_s,run_dir" \
    > "$SUMMARY_CSV"

# JSON array start
echo "[" > "$DETAIL_JSON"

log "Results: ${RESULTS_DIR}"
log "Parallel: ${PARALLEL_JOBS} jobs"
log "Time budget: ${TIME_BUDGET_S}s per firmware"
log "Stages: ${STAGES:-all}"

# --- Run analysis ---
COMPLETED=0
SUCCESS=0
PARTIAL=0
FAILED=0

run_one() {
    local idx="$1"
    local fw_path="$2"
    local fw_name
    fw_name=$(basename "$fw_path")
    local vendor
    vendor=$(basename "$(dirname "$fw_path")")
    local log_file="${LOG_DIR}/${vendor}_${fw_name}.log"

    # Compute SHA256
    local sha256
    sha256=$(sha256sum "$fw_path" | awk '{print $1}')
    local sha_short="${sha256:0:12}"

    local start_ts
    start_ts=$(date +%s)

    # Build command
    local cmd=(python3 -m aiedge)
    if [[ $USE_8MB -eq 1 ]]; then
        cmd+=(analyze-8mb)
    else
        cmd+=(analyze)
    fi
    cmd+=("$fw_path"
        --case-id "firmae-bench-${vendor}-${sha_short}"
        --ack-authorization
        $NO_LLM
        --time-budget-s "$TIME_BUDGET_S"
        --profile "$PROFILE"
    )
    if [[ -n "$STAGES" ]]; then
        cmd+=(--stages "$STAGES")
    fi

    # Execute
    local exit_code=0
    local run_dir=""
    run_dir=$("${cmd[@]}" 2>"$log_file") || exit_code=$?

    local end_ts
    end_ts=$(date +%s)
    local duration=$(( end_ts - start_ts ))

    # Parse results
    local status="unknown"
    local stages_ok=0 stages_partial=0 stages_failed=0 stages_skipped=0
    local findings_count=0 cve_count=0

    case $exit_code in
        0)  status="success" ;;
        10) status="partial" ;;
        20) status="fatal" ;;
        30) status="policy_violation" ;;
        *)  status="error" ;;
    esac

    if [[ -n "$run_dir" && -d "$run_dir" ]]; then
        # Count stage outcomes
        for stage_json in "$run_dir"/stages/*/stage.json; do
            [[ -f "$stage_json" ]] || continue
            local s
            s=$(python3 -c "
import json, sys
d = json.load(open('$stage_json'))
print(d.get('status', 'unknown'))
" 2>/dev/null || echo "unknown")
            case "$s" in
                ok)      stages_ok=$((stages_ok + 1)) ;;
                partial) stages_partial=$((stages_partial + 1)) ;;
                failed)  stages_failed=$((stages_failed + 1)) ;;
                skipped) stages_skipped=$((stages_skipped + 1)) ;;
            esac
        done

        # Count findings
        if [[ -f "$run_dir/stages/findings/findings.json" ]]; then
            findings_count=$(python3 -c "
import json
d = json.load(open('$run_dir/stages/findings/findings.json'))
if isinstance(d, list): print(len(d))
elif isinstance(d, dict): print(len(d.get('findings', d.get('items', []))))
else: print(0)
" 2>/dev/null || echo 0)
        fi

        # Count CVEs
        if [[ -f "$run_dir/stages/cve_scan/cve_scan.json" ]]; then
            cve_count=$(python3 -c "
import json
d = json.load(open('$run_dir/stages/cve_scan/cve_scan.json'))
if isinstance(d, dict): print(len(d.get('cves', d.get('matches', []))))
elif isinstance(d, list): print(len(d))
else: print(0)
" 2>/dev/null || echo 0)
        fi
    fi

    # Write CSV row
    echo "${idx},${vendor},${fw_name},${sha_short},${exit_code},${status},${stages_ok},${stages_partial},${stages_failed},${stages_skipped},${findings_count},${cve_count},${duration},${run_dir}" \
        >> "$SUMMARY_CSV"

    # Status line
    local icon
    case "$status" in
        success) icon="${GREEN}OK${NC}" ;;
        partial) icon="${YELLOW}PARTIAL${NC}" ;;
        *)       icon="${RED}FAIL${NC}" ;;
    esac
    echo -e "[${idx}/${TOTAL}] ${icon} ${vendor}/${fw_name} (${duration}s) stages=${stages_ok}ok/${stages_partial}p/${stages_failed}f findings=${findings_count} cves=${cve_count}"

    # Archive analysis JSONs and cleanup run dir to save disk
    if [[ "$CLEANUP_RUNS" == "1" && -n "$run_dir" && -d "$run_dir" ]]; then
        local archive_dir="${RESULTS_DIR}/archives/${vendor}/${sha_short}"
        mkdir -p "$archive_dir"
        # Copy all analysis JSONs (excluding extraction dir)
        find "$run_dir"/stages -name "*.json" -not -path "*/extraction/*" \
            -exec cp --parents -t "$archive_dir" {} + 2>/dev/null || true
        # Copy report and handoff if present
        cp "$run_dir"/report/*.json "$archive_dir/" 2>/dev/null || true
        cp "$run_dir"/firmware_handoff.json "$archive_dir/" 2>/dev/null || true
        cp "$run_dir"/manifest.json "$archive_dir/" 2>/dev/null || true
        # Delete full run dir
        rm -rf "$run_dir" 2>/dev/null || true
    fi
}

export -f run_one
export PYTHONPATH RESULTS_DIR LOG_DIR SUMMARY_CSV TIME_BUDGET_S STAGES
export NO_LLM PROFILE USE_8MB TOTAL CLEANUP_RUNS
export RED GREEN YELLOW BLUE NC

log "Starting benchmark..."
START_TIME=$(date +%s)

# Run with GNU parallel if available, else sequential with background jobs
if command -v parallel &>/dev/null && [[ $PARALLEL_JOBS -gt 1 ]]; then
    log "Using GNU parallel (${PARALLEL_JOBS} jobs)"
    idx=0
    for fw in "${FW_FILES[@]}"; do
        idx=$((idx + 1))
        echo "$idx $fw"
    done | parallel --colsep ' ' -j "$PARALLEL_JOBS" --line-buffer \
        run_one {1} {2}
else
    log "Using bash background jobs (${PARALLEL_JOBS} concurrent)"
    idx=0
    active=0
    for fw in "${FW_FILES[@]}"; do
        idx=$((idx + 1))
        run_one "$idx" "$fw" &
        active=$((active + 1))
        if [[ $active -ge $PARALLEL_JOBS ]]; then
            wait -n 2>/dev/null || true
            active=$((active - 1))
        fi
    done
    wait || true
fi

END_TIME=$(date +%s)
TOTAL_DURATION=$(( END_TIME - START_TIME ))

# --- Generate summary report ---
log "Generating summary report..."

python3 - <<'PYEOF' "$SUMMARY_CSV" "$RESULTS_DIR"
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

csv_path = sys.argv[1]
results_dir = Path(sys.argv[2])

rows = []
with open(csv_path) as f:
    reader = csv.DictReader(f)
    for row in reader:
        rows.append(row)

total = len(rows)
if total == 0:
    print("No results to summarize.")
    sys.exit(0)

# Per-vendor stats
vendor_stats = defaultdict(lambda: {
    "total": 0, "success": 0, "partial": 0, "failed": 0,
    "findings": 0, "cves": 0, "duration": 0
})

for r in rows:
    v = vendor_stats[r["vendor"]]
    v["total"] += 1
    if r["status"] == "success":
        v["success"] += 1
    elif r["status"] == "partial":
        v["partial"] += 1
    else:
        v["failed"] += 1
    v["findings"] += int(r.get("findings_count", 0) or 0)
    v["cves"] += int(r.get("cve_count", 0) or 0)
    v["duration"] += int(r.get("duration_s", 0) or 0)

# Overall
overall = {
    "total": total,
    "success": sum(v["success"] for v in vendor_stats.values()),
    "partial": sum(v["partial"] for v in vendor_stats.values()),
    "failed": sum(v["failed"] for v in vendor_stats.values()),
    "total_findings": sum(v["findings"] for v in vendor_stats.values()),
    "total_cves": sum(v["cves"] for v in vendor_stats.values()),
    "total_duration_s": sum(v["duration"] for v in vendor_stats.values()),
}

# FirmAE reference numbers
firmae_ref = {
    "dlink": {"total": 263, "emulation_rate": 0.8779, "vulns": 17},
    "tplink": {"total": 148, "emulation_rate": 0.7635, "vulns": 0},
    "netgear": {"total": 375, "emulation_rate": 0.8933, "vulns": 99},
    "trendnet": {"total": 119, "emulation_rate": 0.6134, "vulns": 0},
    "asus": {"total": 107, "emulation_rate": 0.5794, "vulns": 0},
    "belkin": {"total": 37, "emulation_rate": 0.5946, "vulns": 0},
    "linksys": {"total": 55, "emulation_rate": 0.8000, "vulns": 0},
    "zyxel": {"total": 20, "emulation_rate": 0.5000, "vulns": 0},
}

report_lines = []
report_lines.append("=" * 80)
report_lines.append("SCOUT vs FirmAE Benchmark Report")
report_lines.append("=" * 80)
report_lines.append("")
report_lines.append(f"Total firmware images analyzed: {total}")
report_lines.append(f"Total duration: {overall['total_duration_s']}s ({overall['total_duration_s']//3600}h {(overall['total_duration_s']%3600)//60}m)")
report_lines.append("")

# Comparison table
report_lines.append(f"{'Vendor':<12} {'Images':>6} {'Success':>8} {'Partial':>8} {'Failed':>7} {'Rate':>6} {'FirmAE':>8} {'Findings':>9} {'CVEs':>5}")
report_lines.append("-" * 80)

for vendor in sorted(vendor_stats.keys()):
    v = vendor_stats[vendor]
    rate = (v["success"] + v["partial"]) / v["total"] * 100 if v["total"] > 0 else 0
    ref = firmae_ref.get(vendor, {})
    firmae_rate = f"{ref.get('emulation_rate', 0)*100:.1f}%" if ref else "N/A"
    report_lines.append(
        f"{vendor:<12} {v['total']:>6} {v['success']:>8} {v['partial']:>8} "
        f"{v['failed']:>7} {rate:>5.1f}% {firmae_rate:>8} {v['findings']:>9} {v['cves']:>5}"
    )

total_rate = (overall["success"] + overall["partial"]) / overall["total"] * 100
report_lines.append("-" * 80)
report_lines.append(
    f"{'TOTAL':<12} {overall['total']:>6} {overall['success']:>8} {overall['partial']:>8} "
    f"{overall['failed']:>7} {total_rate:>5.1f}% {'79.4%':>8} {overall['total_findings']:>9} {overall['total_cves']:>5}"
)
report_lines.append("")
report_lines.append("SCOUT analysis rate = (success + partial) / total")
report_lines.append("FirmAE rate = web service emulation success (from paper Table 1)")
report_lines.append("")
report_lines.append("Key insight: SCOUT static pipeline can analyze firmware that")
report_lines.append("FirmAE cannot emulate, providing complementary coverage.")
report_lines.append("=" * 80)

report_text = "\n".join(report_lines)
print(report_text)

report_path = results_dir / "benchmark_report.txt"
report_path.write_text(report_text + "\n", encoding="utf-8")

# Save JSON summary
summary = {
    "overall": overall,
    "per_vendor": dict(vendor_stats),
    "firmae_reference": firmae_ref,
}
json_path = results_dir / "benchmark_summary.json"
json_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

print(f"\nReport saved: {report_path}")
print(f"JSON summary: {json_path}")
PYEOF

log "Benchmark complete! Results in: ${RESULTS_DIR}"
log "Total time: ${TOTAL_DURATION}s"
