#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PYTHONPATH="${PYTHONPATH:-$REPO_ROOT/src}"
RUN_DIR=""
CORPUS_MANIFEST="benchmarks/corpus/manifest.json"
METRICS_OUT=""
QUALITY_OUT=""
LLM_FIXTURE=""

FAILED=0

usage() {
  cat <<'EOF'
Usage: scripts/release_gate.sh --run-dir <PATH> [--manifest <PATH>] [--metrics-out <PATH>] [--quality-out <PATH>] [--llm-fixture <PATH>]

Unified release governance gate (single entrypoint).

Sub-gates:
  - CONTRACT_FINAL: scripts/verify_aiedge_final_report.py
  - CONTRACT_ANALYST: scripts/verify_aiedge_analyst_report.py
  - QUALITY_METRICS: aiedge quality-metrics
  - QUALITY_POLICY: aiedge release-quality-gate
  - EXPLOIT_TIER_POLICY: schema tier checks plus exploit_policy artifact checks when present
  - TAMPER_SUITE: pytest tests/test_tamper_suite.py
EOF
}

gate_line() {
  local kind="$1"
  local token="$2"
  local msg="$3"
  echo "[GATE][$kind][$token] $msg"
}

gate_fail() {
  local token="$1"
  local msg="$2"
  FAILED=1
  gate_line "FAIL" "$token" "$msg"
}

gate_pass() {
  local token="$1"
  local msg="$2"
  gate_line "PASS" "$token" "$msg"
}

gate_info() {
  local token="$1"
  local msg="$2"
  gate_line "INFO" "$token" "$msg"
}

run_gate_cmd() {
  local token="$1"
  shift
  local out_file
  out_file="$(mktemp)"
  set +e
  "$@" >"$out_file" 2>&1
  local rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    gate_fail "$token" "exit_code=$rc"
    while IFS= read -r line; do
      [[ -n "$line" ]] && echo "[GATE][LOG][$token] $line"
    done <"$out_file"
  else
    gate_pass "$token" "exit_code=0"
  fi
  rm -f "$out_file"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-dir)
      RUN_DIR="$2"
      shift 2
      ;;
    --manifest)
      CORPUS_MANIFEST="$2"
      shift 2
      ;;
    --metrics-out)
      METRICS_OUT="$2"
      shift 2
      ;;
    --quality-out)
      QUALITY_OUT="$2"
      shift 2
      ;;
    --llm-fixture)
      LLM_FIXTURE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$RUN_DIR" ]]; then
  echo "[GATE][FAIL][ARGUMENTS] --run-dir is required" >&2
  exit 2
fi

if [[ -z "$METRICS_OUT" ]]; then
  METRICS_OUT="$RUN_DIR/metrics.json"
fi
if [[ -z "$QUALITY_OUT" ]]; then
  QUALITY_OUT="$RUN_DIR/quality_gate.json"
fi

if [[ ! -d "$RUN_DIR" ]]; then
  echo "[GATE][FAIL][ARGUMENTS] run dir not found: $RUN_DIR" >&2
  exit 2
fi

mkdir -p "$(dirname "$METRICS_OUT")"
mkdir -p "$(dirname "$QUALITY_OUT")"

run_gate_cmd "CONTRACT_FINAL" python3 "$SCRIPT_DIR/verify_aiedge_final_report.py" --run-dir "$RUN_DIR"
run_gate_cmd "CONTRACT_ANALYST" python3 "$SCRIPT_DIR/verify_aiedge_analyst_report.py" --run-dir "$RUN_DIR"

run_gate_cmd "QUALITY_METRICS" env PYTHONPATH="$PYTHONPATH" python3 -m aiedge quality-metrics --manifest "$CORPUS_MANIFEST" --out "$METRICS_OUT"
QUALITY_POLICY_CMD=(env PYTHONPATH="$PYTHONPATH" python3 -m aiedge release-quality-gate --metrics "$METRICS_OUT" --report "$RUN_DIR/report/report.json" --llm-primary --out "$QUALITY_OUT")
if [[ -n "$LLM_FIXTURE" ]]; then
  QUALITY_POLICY_CMD+=(--llm-fixture "$LLM_FIXTURE")
fi
run_gate_cmd "QUALITY_POLICY" "${QUALITY_POLICY_CMD[@]}"

EXPLOIT_CHECK_OUTPUT="$(mktemp)"
set +e
PYTHONPATH="$PYTHONPATH" python3 - <<'PY' "$RUN_DIR" >"$EXPLOIT_CHECK_OUTPUT" 2>&1
import json
import sys
from pathlib import Path

from aiedge.schema import validate_report

run_dir = Path(sys.argv[1]).resolve()
report_path = run_dir / "report" / "report.json"
if not report_path.is_file():
    print("missing report/report.json")
    raise SystemExit(1)

payload_any = json.loads(report_path.read_text(encoding="utf-8"))
if not isinstance(payload_any, dict):
    print("report/report.json is not an object")
    raise SystemExit(1)

tier_errors = sorted(
    err for err in validate_report(payload_any) if err.startswith("TIER_")
)
if tier_errors:
    for err in tier_errors:
        print(err)
    raise SystemExit(1)

policy_json = run_dir / "stages" / "exploit_policy" / "policy.json"
if policy_json.is_file():
    policy_any = json.loads(policy_json.read_text(encoding="utf-8"))
    if not isinstance(policy_any, dict):
        print("exploit_policy policy.json is not an object")
        raise SystemExit(1)

    status = policy_any.get("status")
    if status == "failed":
        print("exploit_policy policy status failed")
        raise SystemExit(1)

    for key in ("forbidden", "blocked", "tier_violations"):
        value = policy_any.get(key)
        if isinstance(value, list) and value:
            print(f"exploit_policy {key} is non-empty")
            raise SystemExit(1)
    print("enforced=schema_tier_and_exploit_policy_artifact")
else:
    print("enforced=schema_tier_only (exploit_policy artifact absent)")
PY
EXPLOIT_RC=$?
set -e
if [[ "$EXPLOIT_RC" -ne 0 ]]; then
  gate_fail "EXPLOIT_TIER_POLICY" "tier/schema policy checks failed"
  while IFS= read -r line; do
    [[ -n "$line" ]] && echo "[GATE][LOG][EXPLOIT_TIER_POLICY] $line"
  done <"$EXPLOIT_CHECK_OUTPUT"
else
  gate_pass "EXPLOIT_TIER_POLICY" "tier/schema policy checks passed"
  while IFS= read -r line; do
    [[ -n "$line" ]] && gate_info "EXPLOIT_TIER_POLICY" "$line"
  done <"$EXPLOIT_CHECK_OUTPUT"
fi
rm -f "$EXPLOIT_CHECK_OUTPUT"

if [[ "${AIEDGE_SKIP_TAMPER_TESTS:-0}" == "1" ]]; then
  gate_info "TAMPER_SUITE" "skipped by AIEDGE_SKIP_TAMPER_TESTS=1"
else
  run_gate_cmd "TAMPER_SUITE" python3 -m pytest -q "$REPO_ROOT/tests/test_tamper_suite.py"
fi

if [[ "$FAILED" -ne 0 ]]; then
  gate_line "FAIL" "RELEASE_GOVERNANCE" "one_or_more_subgates_failed"
  exit 1
fi

gate_line "PASS" "RELEASE_GOVERNANCE" "all_subgates_passed"
