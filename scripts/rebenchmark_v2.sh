#!/usr/bin/env bash
# =============================================================================
# SCOUT Rebenchmark v2.1 — Apply v2.1 improvements to Tier 1 benchmark
#
# Improvements applied:
#   - 25 new CVE signatures (expanded NVD coverage)
#   - 3 new FP reduction rules (static FP rules)
#   - 2-tier confidence caps (static-only findings capped at 0.60)
#   - D-Link SHRS decryption support
#
# Strategy:
#   Phase 1: Re-run cve_scan + fp_verification on alive existing runs
#   Phase 2: Fresh analyze on firmware files (--dlink-only or full)
#            Uses original firmae-benchmark dataset
#
# Usage:
#   scripts/rebenchmark_v2.sh [OPTIONS]
#
# Options:
#   --dlink-only        Phase 2: only D-Link firmware (263 files)
#   --phase1-only       Only re-run stages on alive existing runs
#   --phase2-only       Only run fresh analysis on firmware files
#   --parallel N        Concurrent jobs (default: 4)
#   --time-budget S     Seconds per firmware for Phase 2 (default: 600)
#   --max-images N      Limit Phase 2 firmware count (0 = all)
#   --cleanup           Delete run dirs after CSV capture (saves disk)
#   --dry-run           Show what would run without executing
#   -h, --help          Show this help
#
# Examples:
#   # Dry run to inspect scope
#   scripts/rebenchmark_v2.sh --dry-run
#
#   # D-Link only (extraction + cve_scan improvements)
#   scripts/rebenchmark_v2.sh --dlink-only
#
#   # Phase 1 only (re-run stages on alive 17 runs)
#   scripts/rebenchmark_v2.sh --phase1-only
#
#   # Full rebenchmark (all 1124 firmware files, 4 parallel)
#   scripts/rebenchmark_v2.sh --parallel 4 --time-budget 600
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHONPATH="${REPO_ROOT}/src:${PYTHONPATH:-}"
export PYTHONPATH
AIEDGE_GHIDRA_HOME="${AIEDGE_GHIDRA_HOME:-/opt/ghidra_12.0.2_PUBLIC}"
export AIEDGE_GHIDRA_HOME

# --- Configuration defaults ---
DATASET_DIR="${DATASET_DIR:-${REPO_ROOT}/aiedge-inputs/firmae-benchmark}"
RESULTS_DIR="${REPO_ROOT}/benchmark-results/rebenchmark-v2"
PREV_CSV="${REPO_ROOT}/benchmark-results/firmae-20260330_0259/benchmark_summary.csv"
PARALLEL_JOBS=4
TIME_BUDGET_S=600
MAX_IMAGES=0
CLEANUP_RUNS=0
DRY_RUN=0
DLINK_ONLY=0
PHASE1_ONLY=0
PHASE2_ONLY=0
NO_LLM="--no-llm"
PROFILE="analysis"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${BLUE}[REBENCH]${NC} $(date +%H:%M:%S) $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $*"; }
warn() { echo -e "${YELLOW}[ WARN ]${NC} $*"; }
fail() { echo -e "${RED}[ FAIL ]${NC} $*"; }
info() { echo -e "${CYAN}[ INFO ]${NC} $*"; }

usage() {
    sed -n '/^# Usage:/,/^# ====/p' "$0" | grep '^#' | sed 's/^# \?//'
    exit 0
}

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dlink-only)    DLINK_ONLY=1; shift ;;
        --phase1-only)   PHASE1_ONLY=1; shift ;;
        --phase2-only)   PHASE2_ONLY=1; shift ;;
        --parallel)      PARALLEL_JOBS="$2"; shift 2 ;;
        --time-budget)   TIME_BUDGET_S="$2"; shift 2 ;;
        --max-images)    MAX_IMAGES="$2"; shift 2 ;;
        --cleanup)       CLEANUP_RUNS=1; shift ;;
        --dry-run)       DRY_RUN=1; shift ;;
        -h|--help)       usage ;;
        *)               echo "Unknown option: $1"; usage ;;
    esac
done

# =============================================================================
# PHASE 1: Re-run cve_scan + fp_verification on alive existing runs
# =============================================================================

phase1_rerun_stages() {
    log "=== Phase 1: Re-running stages on alive existing runs ==="

    # Find alive runs that match the previous benchmark CSV
    local alive_runs=()
    if [[ -f "$PREV_CSV" ]]; then
        # Build sha256 set from CSV
        local sha_set
        sha_set=$(python3 -c "
import csv
with open('$PREV_CSV') as f:
    reader = csv.DictReader(f)
    for row in reader:
        print(row['sha256'].strip())
")
    fi

    local runs_dir="${REPO_ROOT}/aiedge-runs"
    if [[ ! -d "$runs_dir" ]]; then
        warn "No aiedge-runs directory found — skipping Phase 1"
        return
    fi

    for run_path in "$runs_dir"/*/; do
        [[ -d "$run_path" ]] || continue
        local run_name
        run_name=$(basename "$run_path")
        if [[ "$run_name" == *sha256-* ]]; then
            local sha_part="${run_name#*sha256-}"
            sha_part="${sha_part:0:12}"
            # Check if in previous benchmark CSV
            if echo "$sha_set" | grep -q "^${sha_part}$" 2>/dev/null; then
                alive_runs+=("$run_path")
            fi
        fi
    done

    local total_p1=${#alive_runs[@]}
    if [[ $total_p1 -eq 0 ]]; then
        warn "No alive run_dirs from previous benchmark found — Phase 1 skipped"
        info "All ${TOTAL_CSV:-1123} run_dirs from the Tier 1 benchmark were deleted (--cleanup)"
        return
    fi

    log "Found ${total_p1} alive run(s) from previous benchmark"

    if [[ $DRY_RUN -eq 1 ]]; then
        info "[dry-run] Would re-run cve_scan,fp_verification on:"
        for rp in "${alive_runs[@]}"; do
            echo "  $rp"
        done
        return
    fi

    mkdir -p "${RESULTS_DIR}/phase1/logs"
    local p1_csv="${RESULTS_DIR}/phase1/rerun_summary.csv"
    echo "run_dir,vendor,sha256,before_cve_count,after_cve_count,status,duration_s" > "$p1_csv"

    local idx=0
    local active=0
    for run_path in "${alive_runs[@]}"; do
        idx=$((idx + 1))
        _rerun_stages_one "$idx" "$total_p1" "$run_path" "$p1_csv" &
        active=$((active + 1))
        if [[ $active -ge $PARALLEL_JOBS ]]; then
            wait -n 2>/dev/null || wait
            active=$((active - 1))
        fi
    done
    wait || true

    ok "Phase 1 complete — results: ${p1_csv}"
}

_rerun_stages_one() {
    local idx="$1"
    local total="$2"
    local run_path="$3"
    local csv_out="$4"

    local run_name
    run_name=$(basename "$run_path")
    local sha_part="${run_name#*sha256-}"
    sha_part="${sha_part:0:12}"
    local vendor="unknown"
    local log_file="${RESULTS_DIR}/phase1/logs/${run_name}.log"

    # Detect vendor from run manifest if available
    if [[ -f "${run_path}/manifest.json" ]]; then
        vendor=$(python3 -c "
import json
d = json.load(open('${run_path}/manifest.json'))
print(d.get('vendor', d.get('case_id', 'unknown')).split('-')[2] if '-' in d.get('case_id','') else 'unknown')
" 2>/dev/null || echo "unknown")
    fi

    # Count CVEs before rerun
    local before_cve=0
    if [[ -f "${run_path}/stages/cve_scan/cve_matches.json" ]]; then
        before_cve=$(python3 -c "
import json
d = json.load(open('${run_path}/stages/cve_scan/cve_matches.json'))
if isinstance(d, dict): print(len(d.get('cves', d.get('matches', []))))
elif isinstance(d, list): print(len(d))
else: print(0)
" 2>/dev/null || echo 0)
    fi

    local start_ts
    start_ts=$(date +%s)
    local exit_code=0

    python3 -m aiedge stages "$run_path" \
        --stages cve_scan,fp_verification \
        $NO_LLM \
        --time-budget-s 300 \
        >"$log_file" 2>&1 || exit_code=$?

    local end_ts
    end_ts=$(date +%s)
    local duration=$(( end_ts - start_ts ))

    # Count CVEs after rerun
    local after_cve=0
    if [[ -f "${run_path}/stages/cve_scan/cve_matches.json" ]]; then
        after_cve=$(python3 -c "
import json
d = json.load(open('${run_path}/stages/cve_scan/cve_matches.json'))
if isinstance(d, dict): print(len(d.get('cves', d.get('matches', []))))
elif isinstance(d, list): print(len(d))
else: print(0)
" 2>/dev/null || echo 0)
    fi

    local status="ok"
    [[ $exit_code -ne 0 ]] && status="error(${exit_code})"

    echo "${run_path},${vendor},${sha_part},${before_cve},${after_cve},${status},${duration}" >> "$csv_out"

    local delta=$(( after_cve - before_cve ))
    local delta_str=""
    [[ $delta -gt 0 ]] && delta_str=" ${GREEN}+${delta} CVE${NC}"
    [[ $delta -lt 0 ]] && delta_str=" ${RED}${delta} CVE${NC}"
    [[ $delta -eq 0 ]] && delta_str=" (no change)"

    echo -e "[P1 ${idx}/${total}] ${run_name} cve: ${before_cve}->${after_cve}${delta_str} (${duration}s)"
}

# =============================================================================
# PHASE 2: Fresh analysis on firmware files
# =============================================================================

phase2_fresh_analyze() {
    log "=== Phase 2: Fresh analysis with v2.1 improvements ==="

    # Discover firmware files
    local find_args=()
    if [[ $DLINK_ONLY -eq 1 ]]; then
        find_args=(-L "${DATASET_DIR}/dlink")
        log "D-Link only mode: ${DATASET_DIR}/dlink"
    else
        find_args=(-L "${DATASET_DIR}")
    fi

    mapfile -t FW_FILES < <(
        find "${find_args[@]}" -type f \( \
            -iname "*.bin" -o -iname "*.img" -o -iname "*.fw" -o \
            -iname "*.chk" -o -iname "*.trx" -o -iname "*.zip" -o \
            -iname "*.rar" -o -iname "*.gz" -o -iname "*.bz2" -o \
            -iname "*.enc" -o -iname "*.shrs" -o -iname "*.ssa" \
        \) 2>/dev/null | sort
    )

    local TOTAL=${#FW_FILES[@]}
    if [[ $TOTAL -eq 0 ]]; then
        fail "No firmware files found"
        return 1
    fi

    if [[ $MAX_IMAGES -gt 0 && $MAX_IMAGES -lt $TOTAL ]]; then
        FW_FILES=("${FW_FILES[@]:0:$MAX_IMAGES}")
        TOTAL=$MAX_IMAGES
    fi

    log "Found ${TOTAL} firmware files"

    # Vendor distribution
    declare -A VENDOR_COUNT
    for fw in "${FW_FILES[@]}"; do
        local vendor
        vendor=$(basename "$(dirname "$fw")")
        VENDOR_COUNT[$vendor]=$(( ${VENDOR_COUNT[$vendor]:-0} + 1 ))
    done
    for v in $(echo "${!VENDOR_COUNT[@]}" | tr ' ' '\n' | sort); do
        log "  ${v}: ${VENDOR_COUNT[$v]} images"
    done

    if [[ $DRY_RUN -eq 1 ]]; then
        info "[dry-run] Would analyze ${TOTAL} firmware files:"
        for fw in "${FW_FILES[@]:0:10}"; do
            echo "  $fw"
        done
        [[ $TOTAL -gt 10 ]] && echo "  ... and $((TOTAL - 10)) more"
        return
    fi

    mkdir -p "${RESULTS_DIR}/phase2/logs"
    local p2_csv="${RESULTS_DIR}/phase2/benchmark_summary.csv"
    echo "index,vendor,firmware,sha256,exit_code,status,stages_ok,stages_partial,stages_failed,stages_skipped,findings_count,cve_count,duration_s,run_dir" \
        > "$p2_csv"

    export RESULTS_DIR PARALLEL_JOBS TIME_BUDGET_S NO_LLM PROFILE
    export CLEANUP_RUNS TOTAL
    export RED GREEN YELLOW BLUE CYAN NC
    export -f _analyze_one

    log "Starting Phase 2 (${PARALLEL_JOBS} parallel, ${TIME_BUDGET_S}s budget each)..."
    local START_TIME
    START_TIME=$(date +%s)

    if command -v parallel &>/dev/null && [[ $PARALLEL_JOBS -gt 1 ]]; then
        log "Using GNU parallel (${PARALLEL_JOBS} jobs)"
        local idx=0
        for fw in "${FW_FILES[@]}"; do
            idx=$((idx + 1))
            echo "$idx $fw"
        done | parallel --colsep ' ' -j "$PARALLEL_JOBS" --line-buffer \
            _analyze_one {1} {2} "$p2_csv" "$TOTAL"
    else
        log "Using bash background jobs (${PARALLEL_JOBS} concurrent)"
        local idx=0
        local active=0
        for fw in "${FW_FILES[@]}"; do
            idx=$((idx + 1))
            _analyze_one "$idx" "$fw" "$p2_csv" "$TOTAL" &
            active=$((active + 1))
            if [[ $active -ge $PARALLEL_JOBS ]]; then
                wait -n 2>/dev/null || wait
                active=$((active - 1))
            fi
        done
        wait || true
    fi

    local END_TIME
    END_TIME=$(date +%s)
    local TOTAL_DURATION=$(( END_TIME - START_TIME ))
    log "Phase 2 complete in ${TOTAL_DURATION}s"

    # Generate comparison report
    _generate_comparison_report "$p2_csv"
}

_analyze_one() {
    local idx="$1"
    local fw_path="$2"
    local csv_out="$3"
    local total="$4"

    local fw_name
    fw_name=$(basename "$fw_path")
    local vendor
    vendor=$(basename "$(dirname "$fw_path")")
    local log_file="${RESULTS_DIR}/phase2/logs/${vendor}_${fw_name}.log"

    local sha256
    sha256=$(sha256sum "$fw_path" | awk '{print $1}')
    local sha_short="${sha256:0:12}"

    local start_ts
    start_ts=$(date +%s)

    local cmd=(python3 -m aiedge analyze "$fw_path"
        --case-id "rebench-v2-${vendor}-${sha_short}"
        --ack-authorization
        $NO_LLM
        --time-budget-s "$TIME_BUDGET_S"
        --profile "$PROFILE"
    )

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

    local stages_ok=0 stages_partial=0 stages_failed=0 stages_skipped=0
    local findings_count=0 cve_count=0

    if [[ -n "$run_dir" && -d "$run_dir" ]]; then
        for stage_json in "$run_dir"/stages/*/stage.json; do
            [[ -f "$stage_json" ]] || continue
            local s
            s=$(python3 -c "
import json,sys
d=json.load(open('$stage_json'))
print(d.get('status','unknown'))
" 2>/dev/null || echo "unknown")
            case "$s" in
                ok)      stages_ok=$((stages_ok + 1)) ;;
                partial) stages_partial=$((stages_partial + 1)) ;;
                failed)  stages_failed=$((stages_failed + 1)) ;;
                skipped) stages_skipped=$((stages_skipped + 1)) ;;
            esac
        done

        if [[ -f "$run_dir/stages/findings/findings.json" ]]; then
            findings_count=$(python3 -c "
import json
d=json.load(open('$run_dir/stages/findings/findings.json'))
if isinstance(d,list): print(len(d))
elif isinstance(d,dict): print(len(d.get('findings',d.get('items',[]))))
else: print(0)
" 2>/dev/null || echo 0)
        fi

        if [[ -f "$run_dir/stages/cve_scan/cve_matches.json" ]]; then
            cve_count=$(python3 -c "
import json
d=json.load(open('$run_dir/stages/cve_scan/cve_matches.json'))
if isinstance(d,dict): print(len(d.get('matches',d.get('cves',[]))))
elif isinstance(d,list): print(len(d))
else: print(0)
" 2>/dev/null || echo 0)
        fi
    fi

    # Thread-safe CSV append
    local row="${idx},${vendor},${fw_name},${sha_short},${exit_code},${status},${stages_ok},${stages_partial},${stages_failed},${stages_skipped},${findings_count},${cve_count},${duration},${run_dir}"
    (flock 200; echo "$row" >> "$csv_out") 200>"${csv_out}.lock"

    local icon
    case "$status" in
        success) icon="${GREEN}OK${NC}" ;;
        partial) icon="${YELLOW}PARTIAL${NC}" ;;
        *)       icon="${RED}FAIL${NC}" ;;
    esac
    echo -e "[P2 ${idx}/${total}] ${icon} ${vendor}/${fw_name} (${duration}s) stages=${stages_ok}ok/${stages_partial}p/${stages_failed}f cves=${cve_count}"

    # Cleanup if requested
    if [[ "$CLEANUP_RUNS" == "1" && -n "$run_dir" && -d "$run_dir" ]]; then
        local archive_dir="${RESULTS_DIR}/phase2/archives/${vendor}/${sha_short}"
        mkdir -p "$archive_dir"
        find "$run_dir"/stages -name "*.json" -not -path "*/extraction/*" \
            -exec cp --parents -t "$archive_dir" {} + 2>/dev/null || true
        cp "$run_dir"/report/*.json "$archive_dir/" 2>/dev/null || true
        cp "$run_dir"/firmware_handoff.json "$archive_dir/" 2>/dev/null || true
        cp "$run_dir"/manifest.json "$archive_dir/" 2>/dev/null || true
        rm -rf "$run_dir" 2>/dev/null || true
    fi
}

_generate_comparison_report() {
    local new_csv="$1"
    local report="${RESULTS_DIR}/comparison_report.txt"
    local report_json="${RESULTS_DIR}/comparison_report.json"

    log "Generating comparison report..."

    python3 - <<PYEOF "$PREV_CSV" "$new_csv" "$report" "$report_json"
import csv, json, sys
from collections import defaultdict
from pathlib import Path

prev_csv_path = sys.argv[1]
new_csv_path  = sys.argv[2]
report_path   = sys.argv[3]
json_path     = sys.argv[4]

def load_csv(path):
    rows = []
    try:
        with open(path) as f:
            for row in csv.DictReader(f):
                rows.append(row)
    except FileNotFoundError:
        pass
    return rows

def stats(rows):
    total = len(rows)
    if total == 0:
        return {"total": 0}
    success = sum(1 for r in rows if r.get("status") == "success")
    partial = sum(1 for r in rows if r.get("status") == "partial")
    fatal   = sum(1 for r in rows if r.get("status") in ("fatal", "error"))
    total_cve = sum(int(r.get("cve_count", 0) or 0) for r in rows)
    total_findings = sum(int(r.get("findings_count", 0) or 0) for r in rows)
    avg_dur = sum(float(r.get("duration_s", 0) or 0) for r in rows) / total
    cve_positive = sum(1 for r in rows if int(r.get("cve_count", 0) or 0) > 0)
    by_vendor = defaultdict(lambda: {"total":0,"success":0,"partial":0,"fatal":0,"cves":0,"findings":0})
    for r in rows:
        v = r.get("vendor", "unknown")
        by_vendor[v]["total"] += 1
        s = r.get("status","")
        if s == "success": by_vendor[v]["success"] += 1
        elif s == "partial": by_vendor[v]["partial"] += 1
        else: by_vendor[v]["fatal"] += 1
        by_vendor[v]["cves"] += int(r.get("cve_count",0) or 0)
        by_vendor[v]["findings"] += int(r.get("findings_count",0) or 0)
    return {
        "total": total,
        "success": success,
        "partial": partial,
        "fatal": fatal,
        "success_rate": round(success / total * 100, 1),
        "partial_rate": round(partial / total * 100, 1),
        "fatal_rate": round(fatal / total * 100, 1),
        "total_cve": total_cve,
        "cve_per_fw": round(total_cve / total, 3),
        "cve_positive_fw": cve_positive,
        "cve_positive_rate": round(cve_positive / total * 100, 1),
        "total_findings": total_findings,
        "findings_per_fw": round(total_findings / total, 3),
        "avg_duration_s": round(avg_dur, 1),
        "by_vendor": dict(by_vendor),
    }

prev_rows = load_csv(prev_csv_path)
new_rows  = load_csv(new_csv_path)

prev_s = stats(prev_rows)
new_s  = stats(new_rows)

def delta(a, b, key, pct=False):
    va = a.get(key, 0) or 0
    vb = b.get(key, 0) or 0
    d = vb - va
    if pct:
        return f"{vb:.1f}% (was {va:.1f}%, delta {d:+.1f}%)"
    return f"{vb} (was {va}, delta {d:+})"

lines = []
lines.append("=" * 70)
lines.append("SCOUT v2.1 Rebenchmark — Comparison Report")
lines.append("=" * 70)
lines.append("")
lines.append(f"Previous benchmark: {prev_csv_path}")
lines.append(f"New benchmark:      {new_csv_path}")
lines.append("")
lines.append("--- Overall ---")
lines.append(f"  Firmware analyzed:  {delta(prev_s, new_s, 'total')}")
lines.append(f"  Success rate:       {delta(prev_s, new_s, 'success_rate', pct=True)}")
lines.append(f"  Partial rate:       {delta(prev_s, new_s, 'partial_rate', pct=True)}")
lines.append(f"  Fatal rate:         {delta(prev_s, new_s, 'fatal_rate', pct=True)}")
lines.append(f"  Total CVEs:         {delta(prev_s, new_s, 'total_cve')}")
lines.append(f"  CVE/firmware:       {delta(prev_s, new_s, 'cve_per_fw')}")
lines.append(f"  CVE-positive FW:    {delta(prev_s, new_s, 'cve_positive_fw')}")
lines.append(f"  CVE-positive rate:  {delta(prev_s, new_s, 'cve_positive_rate', pct=True)}")
lines.append(f"  Total findings:     {delta(prev_s, new_s, 'total_findings')}")
lines.append(f"  Findings/firmware:  {delta(prev_s, new_s, 'findings_per_fw')}")
lines.append(f"  Avg duration (s):   {delta(prev_s, new_s, 'avg_duration_s')}")
lines.append("")

# Vendor breakdown (new only if prev is empty/subset)
if new_rows:
    lines.append("--- Vendor Breakdown (new run) ---")
    for vendor, vs in sorted(new_s.get("by_vendor", {}).items(),
                              key=lambda x: -x[1]["total"]):
        total_v = vs["total"]
        ok_v    = vs["success"]
        pt_v    = vs["partial"]
        ft_v    = vs["fatal"]
        cvs_v   = vs["cves"]
        fnd_v   = vs["findings"]
        lines.append(
            f"  {vendor:<12} {total_v:4d} fw  "
            f"ok={ok_v} partial={pt_v} fatal={ft_v}  "
            f"cves={cvs_v} findings={fnd_v}"
        )
    lines.append("")

report_text = "\n".join(lines)
print(report_text)

with open(report_path, "w") as f:
    f.write(report_text)

result = {
    "prev": prev_s,
    "new": new_s,
    "improvements": {
        "cve_delta": (new_s.get("total_cve", 0) or 0) - (prev_s.get("total_cve", 0) or 0),
        "cve_positive_delta": (new_s.get("cve_positive_fw", 0) or 0) - (prev_s.get("cve_positive_fw", 0) or 0),
        "findings_delta": (new_s.get("total_findings", 0) or 0) - (prev_s.get("total_findings", 0) or 0),
        "success_rate_delta": round(
            (new_s.get("success_rate", 0) or 0) - (prev_s.get("success_rate", 0) or 0), 1),
    }
}
with open(json_path, "w") as f:
    json.dump(result, f, indent=2)

print(f"\nReport saved: {report_path}")
print(f"JSON saved:   {json_path}")
PYEOF
}

# =============================================================================
# Main
# =============================================================================

main() {
    log "SCOUT Rebenchmark v2.1"
    log "Results dir: ${RESULTS_DIR}"
    log "Prev CSV:    ${PREV_CSV}"
    log "D-Link only: ${DLINK_ONLY}"
    log "Phase 1 only: ${PHASE1_ONLY} | Phase 2 only: ${PHASE2_ONLY}"
    log "Parallel: ${PARALLEL_JOBS} | Time budget: ${TIME_BUDGET_S}s"
    [[ $DRY_RUN -eq 1 ]] && warn "DRY RUN MODE — no analysis will be executed"
    echo ""

    mkdir -p "${RESULTS_DIR}"

    # Count total CSV entries for reference
    TOTAL_CSV=0
    [[ -f "$PREV_CSV" ]] && TOTAL_CSV=$(( $(wc -l < "$PREV_CSV") - 1 ))
    log "Previous benchmark: ${TOTAL_CSV} entries in CSV"

    if [[ $PHASE2_ONLY -eq 0 ]]; then
        phase1_rerun_stages
        echo ""
    fi

    if [[ $PHASE1_ONLY -eq 0 ]]; then
        phase2_fresh_analyze
        echo ""
    fi

    log "=== Rebenchmark complete ==="
    log "Results: ${RESULTS_DIR}"
    ls -lh "${RESULTS_DIR}" 2>/dev/null || true
}

main "$@"
