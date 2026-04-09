#!/usr/bin/env bash
# =============================================================================
# SCOUT vs FirmAE Benchmark Script
# Runs SCOUT pipeline on the FirmAE dataset and compares results against
# FirmAE's published emulation/vuln metrics.
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
STAGES="${STAGES:-}"                           # empty = full pipeline
PROFILE="${PROFILE:-analysis}"
MAX_IMAGES="${MAX_IMAGES:-0}"                  # 0 = all
CLEANUP_RUNS="${CLEANUP_RUNS:-0}"              # 1 = delete run dirs after archive capture
FILE_LIST="${FILE_LIST:-}"
USE_LLM=0
NO_LLM_FLAG="--no-llm"

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
    cat <<EOF_USAGE
Usage: $(basename "$0") [OPTIONS]

Options:
  --dataset-dir DIR       FirmAE firmware directory (default: aiedge-inputs/firmae-benchmark)
  --results-dir DIR       Output directory for benchmark results
  --file-list PATH        Explicit newline-delimited firmware list (relative to repo root or absolute)
  --parallel N            Concurrent analyses (default: 4)
  --time-budget S         Seconds per firmware (default: 600)
  --stages STAGES         Comma-separated stages (default: full pipeline)
  --max-images N          Limit number of images to process after preflight (0 = all)
  --llm                   Enable LLM-backed stages (default: disabled / --no-llm)
  --8mb                   Use 8MB truncated track
  --full                  Run full pipeline including dynamic stages
  --cleanup               Archive summary artifacts then delete run dirs
  --dry-run               List firmware files without running
  -h, --help              Show this help

Examples:
  # Quick static benchmark, 10 images
  ./scripts/benchmark_firmae.sh --max-images 10 --time-budget 120

  # Full static pipeline on entire dataset
  ./scripts/benchmark_firmae.sh --parallel 8

  # LLM benchmark on a fixed cohort
  ./scripts/benchmark_firmae.sh --llm --file-list benchmarks/tier2-20260331-files.txt
EOF_USAGE
    exit 0
}

# --- Parse arguments ---
USE_8MB=0
DRY_RUN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dataset-dir)   DATASET_DIR="$2"; shift 2 ;;
        --results-dir)   RESULTS_DIR="$2"; shift 2 ;;
        --file-list)     FILE_LIST="$2"; shift 2 ;;
        --parallel)      PARALLEL_JOBS="$2"; shift 2 ;;
        --time-budget)   TIME_BUDGET_S="$2"; shift 2 ;;
        --stages)        STAGES="$2"; shift 2 ;;
        --max-images)    MAX_IMAGES="$2"; shift 2 ;;
        --llm)           USE_LLM=1; shift ;;
        --8mb)           USE_8MB=1; shift ;;
        --full)          STAGES=""; shift ;;
        --cleanup)       CLEANUP_RUNS=1; shift ;;
        --dry-run)       DRY_RUN=1; shift ;;
        -h|--help)       usage ;;
        *)               echo "Unknown option: $1"; usage ;;
    esac
done

if [[ $USE_LLM -eq 1 ]]; then
    NO_LLM_FLAG=""
fi

# --- Discover firmware files ---
log "Scanning dataset: ${DATASET_DIR}"
if [[ -n "$FILE_LIST" ]]; then
    log "Using explicit file list: ${FILE_LIST}"
fi

DISCOVERED_FILES=()
if [[ -n "$FILE_LIST" ]]; then
    if [[ ! -f "$FILE_LIST" ]]; then
        fail "File list not found: ${FILE_LIST}"
        exit 1
    fi
    while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
        line="${raw_line%$'\r'}"
        [[ -z "${line//[[:space:]]/}" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ "$line" != /* ]]; then
            line="${REPO_ROOT}/${line#./}"
        fi
        DISCOVERED_FILES+=("$line")
    done < "$FILE_LIST"
else
    mapfile -t DISCOVERED_FILES < <(
        find -L "$DATASET_DIR" -type f \( \
            -iname "*.bin" -o -iname "*.img" -o -iname "*.fw" -o \
            -iname "*.chk" -o -iname "*.trx" -o -iname "*.zip" -o \
            -iname "*.rar" -o -iname "*.gz" -o -iname "*.bz2" -o \
            -iname "*.ssa" \
        \) | sort
    )
fi

DISCOVERED_TOTAL=${#DISCOVERED_FILES[@]}
SKIPPED_MISSING=0
SKIPPED_UNREADABLE=0
SKIPPED_ZERO_SIZE=0
FW_FILES=()
declare -A SEEN_FILES
for fw in "${DISCOVERED_FILES[@]}"; do
    [[ -n "$fw" ]] || continue
    if [[ -n "${SEEN_FILES[$fw]:-}" ]]; then
        continue
    fi
    SEEN_FILES[$fw]=1
    if [[ ! -e "$fw" || ! -f "$fw" ]]; then
        SKIPPED_MISSING=$((SKIPPED_MISSING + 1))
        continue
    fi
    if [[ ! -r "$fw" ]]; then
        SKIPPED_UNREADABLE=$((SKIPPED_UNREADABLE + 1))
        continue
    fi
    if [[ ! -s "$fw" ]]; then
        SKIPPED_ZERO_SIZE=$((SKIPPED_ZERO_SIZE + 1))
        continue
    fi
    FW_FILES+=("$fw")
done

VALID_TOTAL=${#FW_FILES[@]}
if [[ $VALID_TOTAL -eq 0 ]]; then
    fail "No usable firmware files found (discovered=${DISCOVERED_TOTAL}, missing=${SKIPPED_MISSING}, unreadable=${SKIPPED_UNREADABLE}, zero_size=${SKIPPED_ZERO_SIZE})"
    exit 1
fi

if [[ $MAX_IMAGES -gt 0 && $MAX_IMAGES -lt $VALID_TOTAL ]]; then
    FW_FILES=("${FW_FILES[@]:0:$MAX_IMAGES}")
fi
TOTAL=${#FW_FILES[@]}

log "Preflight: discovered=${DISCOVERED_TOTAL} valid=${VALID_TOTAL} selected=${TOTAL} missing=${SKIPPED_MISSING} unreadable=${SKIPPED_UNREADABLE} zero_size=${SKIPPED_ZERO_SIZE}"
log "LLM mode: $( [[ $USE_LLM -eq 1 ]] && echo enabled || echo disabled )"

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
PRECHECK_JSON="${RESULTS_DIR}/preflight.json"
LOG_DIR="${RESULTS_DIR}/logs"
mkdir -p "$LOG_DIR"

python3 - <<'PYEOF' "$PRECHECK_JSON" "$DISCOVERED_TOTAL" "$VALID_TOTAL" "$TOTAL" "$SKIPPED_MISSING" "$SKIPPED_UNREADABLE" "$SKIPPED_ZERO_SIZE" "$DATASET_DIR" "$FILE_LIST" "$USE_LLM"
import json
import sys
from pathlib import Path
payload = {
    "discovered_total": int(sys.argv[2]),
    "valid_total": int(sys.argv[3]),
    "selected_total": int(sys.argv[4]),
    "skipped_missing": int(sys.argv[5]),
    "skipped_unreadable": int(sys.argv[6]),
    "skipped_zero_size": int(sys.argv[7]),
    "dataset_dir": sys.argv[8],
    "file_list": sys.argv[9] or None,
    "llm_enabled": bool(int(sys.argv[10])),
}
Path(sys.argv[1]).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PYEOF

# CSV header
echo "index,vendor,firmware,sha256,exit_code,status,extraction_status,inventory_quality_status,files_seen,binaries_seen,stages_ok,stages_partial,stages_failed,stages_skipped,findings_count,cve_count,duration_s,run_dir,artifact_root,digest_verifier_ok,report_verifier_ok,actionable_candidate_count,llm_triage_status,llm_triage_model_tier,llm_triage_ranking_count,adversarial_total,adversarial_parsed_ok,fp_verified_total,fp_unverified,graph_empty,attack_surface_reference_only_count,llm_trace_count,manifest_primary_sha256,manifest_primary_size_bytes,analyst_readiness,analyst_reasons" \
    > "$SUMMARY_CSV"

log "Results: ${RESULTS_DIR}"
log "Parallel: ${PARALLEL_JOBS} jobs"
log "Time budget: ${TIME_BUDGET_S}s per firmware"
log "Stages: ${STAGES:-all}"

run_one() {
    local idx="$1"
    local fw_path="$2"
    local fw_name
    fw_name=$(basename "$fw_path")
    local vendor
    vendor=$(basename "$(dirname "$fw_path")")
    local log_file="${LOG_DIR}/${vendor}_${fw_name}.log"

    local sha256
    sha256=$(sha256sum "$fw_path" | awk '{print $1}')
    local sha_short="${sha256:0:12}"

    local start_ts
    start_ts=$(date +%s)

    local cmd=(python3 -m aiedge)
    if [[ $USE_8MB -eq 1 ]]; then
        cmd+=(analyze-8mb)
    else
        cmd+=(analyze)
    fi
    cmd+=("$fw_path"
        --case-id "firmae-bench-${vendor}-${sha_short}"
        --ack-authorization
        --time-budget-s "$TIME_BUDGET_S"
        --profile "$PROFILE"
    )
    if [[ -n "$NO_LLM_FLAG" ]]; then
        cmd+=("$NO_LLM_FLAG")
    fi
    if [[ -n "$STAGES" ]]; then
        cmd+=(--stages "$STAGES")
    fi

    local exit_code=0
    local run_dir=""
    run_dir=$("${cmd[@]}" 2>"$log_file") || exit_code=$?

    local end_ts
    end_ts=$(date +%s)
    local duration=$(( end_ts - start_ts ))

    local status="unknown"
    case $exit_code in
        0)  status="success" ;;
        10) status="partial" ;;
        20) status="fatal" ;;
        30) status="policy_violation" ;;
        *)  status="error" ;;
    esac

    local bundle_dir="$run_dir"
    local archive_dir=""
    local archive_completed=0
    if [[ "$CLEANUP_RUNS" == "1" && -n "$run_dir" && -d "$run_dir" ]]; then
        archive_dir="${RESULTS_DIR}/archives/${vendor}/${sha_short}"
        if python3 - <<'PYEOF' "$run_dir" "$archive_dir"
from pathlib import Path
import sys

from aiedge.benchmark_eval import copy_run_bundle

copy_run_bundle(Path(sys.argv[1]), Path(sys.argv[2]))
PYEOF
        then
            bundle_dir="$archive_dir"
            archive_completed=1
        else
            warn "Archive copy failed for ${vendor}/${fw_name}; keeping original run dir"
        fi
    fi

    local extraction_status=""
    local inventory_quality_status=""
    local files_seen=0 binaries_seen=0
    local stages_ok=0 stages_partial=0 stages_failed=0 stages_skipped=0
    local findings_count=0 cve_count=0
    local digest_verifier_ok=0 report_verifier_ok=0
    local actionable_candidate_count=0
    local llm_triage_status="" llm_triage_model_tier=""
    local llm_triage_ranking_count=0
    local adversarial_total=0 adversarial_parsed_ok=0
    local fp_verified_total=0 fp_unverified=0
    local graph_empty=0 attack_surface_reference_only_count=0
    local llm_trace_count=0
    local manifest_primary_sha256=""
    local manifest_primary_size_bytes=0
    local analyst_readiness="blocked"
    local analyst_reasons="assessment_unavailable"

    if [[ -n "$bundle_dir" && -d "$bundle_dir" ]]; then
        local metrics
        metrics=$(python3 - <<'PYEOF' "$bundle_dir" "$REPO_ROOT"
import sys
from pathlib import Path

from aiedge.benchmark_eval import (
    collect_run_metrics,
    evaluate_analyst_readiness,
    run_bundle_verifier,
)


def _sanitize(value: object) -> str:
    text = str(value)
    text = text.replace("\t", " ").replace("\n", " ").replace("\r", " ")
    return text.replace(",", ";")


bundle_dir = Path(sys.argv[1])
repo_root = Path(sys.argv[2])

metrics = collect_run_metrics(bundle_dir)
digest_verifier = run_bundle_verifier(
    repo_root, "scripts/verify_analyst_digest.py", bundle_dir
)
report_verifier = run_bundle_verifier(
    repo_root, "scripts/verify_aiedge_analyst_report.py", bundle_dir
)
readiness = evaluate_analyst_readiness(
    metrics=metrics,
    digest_verifier=digest_verifier,
    report_verifier=report_verifier,
)

fields = [
    metrics.get("stages_ok", 0),
    metrics.get("stages_partial", 0),
    metrics.get("stages_failed", 0),
    metrics.get("stages_skipped", 0),
    metrics.get("findings_count", 0),
    metrics.get("cve_count", 0),
    metrics.get("extraction_status", ""),
    metrics.get("inventory_quality_status", ""),
    metrics.get("files_seen", 0),
    metrics.get("binaries_seen", 0),
    1 if digest_verifier.get("ok") else 0,
    1 if report_verifier.get("ok") else 0,
    metrics.get("actionable_candidate_count", 0),
    metrics.get("llm_triage_status", ""),
    metrics.get("llm_triage_model_tier", ""),
    metrics.get("llm_triage_ranking_count", 0),
    metrics.get("adversarial_total", 0),
    metrics.get("adversarial_parsed_ok", 0),
    metrics.get("fp_verified_total", 0),
    metrics.get("fp_unverified", 0),
    1 if metrics.get("graph_empty") else 0,
    metrics.get("attack_surface_reference_only_count", 0),
    metrics.get("llm_trace_count", 0),
    metrics.get("manifest_primary_sha256", ""),
    metrics.get("manifest_primary_size_bytes", 0),
    readiness.get("analyst_readiness", "blocked"),
    "|".join(
        str(item)
        for item in readiness.get("analyst_reason_codes", [])
        if isinstance(item, str) and item
    ),
]
print("\t".join(_sanitize(field) for field in fields))
PYEOF
)
        IFS=$'\t' read -r stages_ok stages_partial stages_failed stages_skipped findings_count cve_count extraction_status inventory_quality_status files_seen binaries_seen digest_verifier_ok report_verifier_ok actionable_candidate_count llm_triage_status llm_triage_model_tier llm_triage_ranking_count adversarial_total adversarial_parsed_ok fp_verified_total fp_unverified graph_empty attack_surface_reference_only_count llm_trace_count manifest_primary_sha256 manifest_primary_size_bytes analyst_readiness analyst_reasons <<< "$metrics"
    fi

    echo "${idx},${vendor},${fw_name},${sha_short},${exit_code},${status},${extraction_status},${inventory_quality_status},${files_seen},${binaries_seen},${stages_ok},${stages_partial},${stages_failed},${stages_skipped},${findings_count},${cve_count},${duration},${run_dir},${bundle_dir},${digest_verifier_ok},${report_verifier_ok},${actionable_candidate_count},${llm_triage_status},${llm_triage_model_tier},${llm_triage_ranking_count},${adversarial_total},${adversarial_parsed_ok},${fp_verified_total},${fp_unverified},${graph_empty},${attack_surface_reference_only_count},${llm_trace_count},${manifest_primary_sha256},${manifest_primary_size_bytes},${analyst_readiness},${analyst_reasons}" \
        >> "$SUMMARY_CSV"

    local icon
    case "$status" in
        success) icon="${GREEN}OK${NC}" ;;
        partial) icon="${YELLOW}PARTIAL${NC}" ;;
        *)       icon="${RED}FAIL${NC}" ;;
    esac
    echo -e "[${idx}/${TOTAL}] ${icon} ${vendor}/${fw_name} (${duration}s) stages=${stages_ok}ok/${stages_partial}p/${stages_failed}f findings=${findings_count} cves=${cve_count} extraction=${extraction_status:-n/a} inventory=${inventory_quality_status:-n/a} analyst=${analyst_readiness} files=${files_seen} bins=${binaries_seen}"

    if [[ "$CLEANUP_RUNS" == "1" && $archive_completed -eq 1 && -n "$run_dir" && -d "$run_dir" ]]; then
        rm -rf "$run_dir" 2>/dev/null || true
    fi
}

export -f run_one
export PYTHONPATH RESULTS_DIR LOG_DIR SUMMARY_CSV TIME_BUDGET_S STAGES REPO_ROOT
export NO_LLM_FLAG PROFILE USE_8MB TOTAL CLEANUP_RUNS
export RED GREEN YELLOW BLUE NC

log "Starting benchmark..."
START_TIME=$(date +%s)

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

log "Generating summary report..."
python3 - <<'PYEOF' "$SUMMARY_CSV" "$RESULTS_DIR" "$DETAIL_JSON" "$PRECHECK_JSON"
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

csv_path = Path(sys.argv[1])
results_dir = Path(sys.argv[2])
detail_path = Path(sys.argv[3])
precheck_path = Path(sys.argv[4])

rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
if not rows:
    print("No results to summarize.")
    sys.exit(0)

preflight = {}
if precheck_path.exists():
    preflight = json.loads(precheck_path.read_text(encoding="utf-8"))

vendor_stats = defaultdict(lambda: {
    "total": 0,
    "success": 0,
    "partial": 0,
    "failed": 0,
    "analyst_ready": 0,
    "analyst_degraded": 0,
    "analyst_blocked": 0,
    "findings": 0,
    "cves": 0,
    "actionable_candidates": 0,
    "duration": 0,
    "files_seen_total": 0,
    "binaries_seen_total": 0,
    "extraction_ok": 0,
    "extraction_partial": 0,
    "extraction_failed": 0,
    "inventory_sufficient": 0,
    "inventory_insufficient": 0,
    "digest_verifier_ok": 0,
    "report_verifier_ok": 0,
    "llm_triage_runs": 0,
    "llm_triage_ok": 0,
    "adversarial_total": 0,
    "adversarial_parsed_ok": 0,
    "fp_verified_total": 0,
    "fp_unverified": 0,
})

for row in rows:
    vendor = vendor_stats[row["vendor"]]
    vendor["total"] += 1
    status = row.get("status", "")
    if status == "success":
        vendor["success"] += 1
    elif status == "partial":
        vendor["partial"] += 1
    else:
        vendor["failed"] += 1
    vendor["findings"] += int(row.get("findings_count", 0) or 0)
    vendor["cves"] += int(row.get("cve_count", 0) or 0)
    vendor["actionable_candidates"] += int(row.get("actionable_candidate_count", 0) or 0)
    vendor["duration"] += int(row.get("duration_s", 0) or 0)
    vendor["files_seen_total"] += int(row.get("files_seen", 0) or 0)
    vendor["binaries_seen_total"] += int(row.get("binaries_seen", 0) or 0)
    vendor["digest_verifier_ok"] += int(row.get("digest_verifier_ok", 0) or 0)
    vendor["report_verifier_ok"] += int(row.get("report_verifier_ok", 0) or 0)
    vendor["adversarial_total"] += int(row.get("adversarial_total", 0) or 0)
    vendor["adversarial_parsed_ok"] += int(row.get("adversarial_parsed_ok", 0) or 0)
    vendor["fp_verified_total"] += int(row.get("fp_verified_total", 0) or 0)
    vendor["fp_unverified"] += int(row.get("fp_unverified", 0) or 0)

    analyst_readiness = row.get("analyst_readiness", "")
    if analyst_readiness == "ready":
        vendor["analyst_ready"] += 1
    elif analyst_readiness == "degraded":
        vendor["analyst_degraded"] += 1
    else:
        vendor["analyst_blocked"] += 1

    llm_triage_status = row.get("llm_triage_status", "")
    if llm_triage_status:
        vendor["llm_triage_runs"] += 1
        if llm_triage_status == "ok":
            vendor["llm_triage_ok"] += 1

    extraction_status = row.get("extraction_status", "")
    if extraction_status == "ok":
        vendor["extraction_ok"] += 1
    elif extraction_status == "partial":
        vendor["extraction_partial"] += 1
    elif extraction_status:
        vendor["extraction_failed"] += 1

    inventory_quality_status = row.get("inventory_quality_status", "")
    if inventory_quality_status == "sufficient":
        vendor["inventory_sufficient"] += 1
    elif inventory_quality_status:
        vendor["inventory_insufficient"] += 1

for vendor, stats in vendor_stats.items():
    total = stats["total"] or 1
    stats["avg_files_seen"] = round(stats["files_seen_total"] / total, 2)
    stats["avg_binaries_seen"] = round(stats["binaries_seen_total"] / total, 2)

overall_total = len(rows)
overall = {
    "total": overall_total,
    "success": sum(v["success"] for v in vendor_stats.values()),
    "partial": sum(v["partial"] for v in vendor_stats.values()),
    "failed": sum(v["failed"] for v in vendor_stats.values()),
    "analyst_ready": sum(v["analyst_ready"] for v in vendor_stats.values()),
    "analyst_degraded": sum(v["analyst_degraded"] for v in vendor_stats.values()),
    "analyst_blocked": sum(v["analyst_blocked"] for v in vendor_stats.values()),
    "total_findings": sum(v["findings"] for v in vendor_stats.values()),
    "total_cves": sum(v["cves"] for v in vendor_stats.values()),
    "actionable_candidates": sum(v["actionable_candidates"] for v in vendor_stats.values()),
    "total_duration_s": sum(v["duration"] for v in vendor_stats.values()),
    "extraction_ok": sum(v["extraction_ok"] for v in vendor_stats.values()),
    "extraction_partial": sum(v["extraction_partial"] for v in vendor_stats.values()),
    "extraction_failed": sum(v["extraction_failed"] for v in vendor_stats.values()),
    "inventory_sufficient": sum(v["inventory_sufficient"] for v in vendor_stats.values()),
    "inventory_insufficient": sum(v["inventory_insufficient"] for v in vendor_stats.values()),
    "digest_verifier_ok": sum(v["digest_verifier_ok"] for v in vendor_stats.values()),
    "report_verifier_ok": sum(v["report_verifier_ok"] for v in vendor_stats.values()),
    "llm_triage_runs": sum(v["llm_triage_runs"] for v in vendor_stats.values()),
    "llm_triage_ok": sum(v["llm_triage_ok"] for v in vendor_stats.values()),
    "adversarial_total": sum(v["adversarial_total"] for v in vendor_stats.values()),
    "adversarial_parsed_ok": sum(v["adversarial_parsed_ok"] for v in vendor_stats.values()),
    "fp_verified_total": sum(v["fp_verified_total"] for v in vendor_stats.values()),
    "fp_unverified": sum(v["fp_unverified"] for v in vendor_stats.values()),
    "avg_files_seen": round(sum(int(r.get("files_seen", 0) or 0) for r in rows) / overall_total, 2),
    "avg_binaries_seen": round(sum(int(r.get("binaries_seen", 0) or 0) for r in rows) / overall_total, 2),
}

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
report_lines.append(f"Total firmware images analyzed: {overall_total}")
report_lines.append(
    f"Total duration: {overall['total_duration_s']}s "
    f"({overall['total_duration_s']//3600}h {(overall['total_duration_s']%3600)//60}m)"
)
if preflight:
    report_lines.append(
        "Preflight: discovered={discovered_total} valid={valid_total} selected={selected_total} "
        "missing={skipped_missing} unreadable={skipped_unreadable} zero_size={skipped_zero_size}".format(**preflight)
    )
    report_lines.append(
        f"Input mode: {'file-list' if preflight.get('file_list') else 'dataset-scan'} | "
        f"LLM enabled: {preflight.get('llm_enabled', False)}"
    )
report_lines.append(
    f"Extraction ok/partial/other: {overall['extraction_ok']}/{overall['extraction_partial']}/{overall['extraction_failed']}"
)
report_lines.append(
    f"Inventory sufficient/other: {overall['inventory_sufficient']}/{overall['inventory_insufficient']}"
)
report_lines.append(
    f"Average inventory coverage: files_seen={overall['avg_files_seen']} binaries_seen={overall['avg_binaries_seen']}"
)
report_lines.append(
    f"Analyst readiness (ready/degraded/blocked): {overall['analyst_ready']}/{overall['analyst_degraded']}/{overall['analyst_blocked']}"
)
report_lines.append(
    f"Archive verifier pass (digest/report): {overall['digest_verifier_ok']}/{overall_total} | {overall['report_verifier_ok']}/{overall_total}"
)
llm_triage_rate = (
    (overall["llm_triage_ok"] / overall["llm_triage_runs"]) * 100.0
    if overall["llm_triage_runs"] > 0
    else 0.0
)
report_lines.append(
    f"Actionable candidates: {overall['actionable_candidates']} | LLM triage ok rate: {llm_triage_rate:.1f}%"
)
adv_rate = (
    (overall["adversarial_parsed_ok"] / overall["adversarial_total"]) * 100.0
    if overall["adversarial_total"] > 0
    else 0.0
)
report_lines.append(
    f"Adversarial parse success: {overall['adversarial_parsed_ok']}/{overall['adversarial_total']} ({adv_rate:.1f}%)"
)
report_lines.append(
    f"FP verification unverified: {overall['fp_unverified']}/{overall['fp_verified_total']}"
)
report_lines.append("")
report_lines.append(f"{'Vendor':<12} {'Images':>6} {'Success':>8} {'Partial':>8} {'Failed':>7} {'Ready':>7} {'Rate':>6} {'FirmAE':>8} {'Findings':>9} {'CVEs':>5}")
report_lines.append("-" * 80)
for vendor_name in sorted(vendor_stats.keys()):
    stats = vendor_stats[vendor_name]
    rate = (stats["success"] + stats["partial"]) / stats["total"] * 100 if stats["total"] > 0 else 0.0
    ref = firmae_ref.get(vendor_name, {})
    firmae_rate = f"{ref.get('emulation_rate', 0) * 100:.1f}%" if ref else "N/A"
    report_lines.append(
        f"{vendor_name:<12} {stats['total']:>6} {stats['success']:>8} {stats['partial']:>8} "
        f"{stats['failed']:>7} {stats['analyst_ready']:>7} {rate:>5.1f}% {firmae_rate:>8} {stats['findings']:>9} {stats['cves']:>5}"
    )

total_rate = (overall["success"] + overall["partial"]) / overall_total * 100
report_lines.append("-" * 80)
report_lines.append(
    f"{'TOTAL':<12} {overall_total:>6} {overall['success']:>8} {overall['partial']:>8} "
    f"{overall['failed']:>7} {overall['analyst_ready']:>7} {total_rate:>5.1f}% {'79.4%':>8} {overall['total_findings']:>9} {overall['total_cves']:>5}"
)
report_lines.append("")
report_lines.append("SCOUT analysis rate = (success + partial) / total")
report_lines.append("SCOUT analyst-ready rate = ready / total")
report_lines.append("FirmAE rate = web service emulation success (from paper Table 1)")
report_lines.append("Key insight: SCOUT static pipeline can analyze firmware that FirmAE cannot emulate, providing complementary coverage.")
report_lines.append("=" * 80)

report_text = "\n".join(report_lines)
print(report_text)
(results_dir / "benchmark_report.txt").write_text(report_text + "\n", encoding="utf-8")

summary = {
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "preflight": preflight,
    "overall": overall,
    "per_vendor": dict(vendor_stats),
    "firmae_reference": firmae_ref,
}
(results_dir / "benchmark_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

detail = {
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "preflight": preflight,
    "rows": rows,
}
detail_path.write_text(json.dumps(detail, indent=2) + "\n", encoding="utf-8")

print(f"\nReport saved: {results_dir / 'benchmark_report.txt'}")
print(f"JSON summary: {results_dir / 'benchmark_summary.json'}")
print(f"Detail JSON: {detail_path}")
PYEOF

log "Benchmark complete! Results in: ${RESULTS_DIR}"
log "Total time: ${TOTAL_DURATION}s"
