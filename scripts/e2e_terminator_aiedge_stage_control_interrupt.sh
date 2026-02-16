#!/usr/bin/env bash
set -euo pipefail

SCOUT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
E2E_SCRIPT="$SCOUT_ROOT/scripts/e2e_terminator_aiedge_stage_control.sh"

signal_name="${1:-INT}"
if [[ "$signal_name" != "INT" && "$signal_name" != "TERM" ]]; then
  echo "[FAIL] Usage: $0 [INT|TERM]" >&2
  exit 1
fi

expected_rc=130
if [[ "$signal_name" == "TERM" ]]; then
  expected_rc=143
fi

set +e
run_output="$(E2E_KEEP_WORKDIR=1 E2E_SELF_INTERRUPT="$signal_name" "$E2E_SCRIPT" 2>&1)"
run_rc=$?
set -e

if [[ "$run_rc" -ne "$expected_rc" ]]; then
  echo "[FAIL] Expected self-interrupt exit $expected_rc, got $run_rc" >&2
  printf '%s\n' "$run_output" >&2
  exit 1
fi

ownership_file=""
while IFS= read -r line; do
  if [[ "$line" =~ ^\[INFO\]\ Ownership\ tracking\ file:\ (.+)$ ]]; then
    ownership_file="${BASH_REMATCH[1]}"
    break
  fi
done <<< "$run_output"

if [[ -z "$ownership_file" ]]; then
  echo "[FAIL] Could not find ownership tracking path in E2E output" >&2
  printf '%s\n' "$run_output" >&2
  exit 1
fi

if [[ ! -f "$ownership_file" ]]; then
  echo "[FAIL] Ownership tracking file missing: $ownership_file" >&2
  exit 1
fi

while IFS= read -r pid; do
  if [[ -z "$pid" ]]; then
    continue
  fi
  if kill -0 -- "$pid" 2>/dev/null; then
    echo "[FAIL] Owned PID still alive after self-interrupt cleanup: $pid" >&2
    exit 1
  fi
  if kill -0 -- "-$pid" 2>/dev/null; then
    echo "[FAIL] Owned PGID still alive after self-interrupt cleanup: $pid" >&2
    exit 1
  fi
done < <(
  python3 - <<'PY' "$ownership_file"
import json
import sys

tracking_path = sys.argv[1]
with open(tracking_path, "r", encoding="utf-8") as fh:
    payload = json.load(fh)

for entry in payload.get("owned_sessions", []):
    pid = entry.get("terminator_bg_pid")
    if isinstance(pid, int) and pid > 0:
        print(pid)
PY
)

work_dir="$(dirname "$ownership_file")"
rm -rf "$work_dir"

echo "[PASS] interrupt cleanup verified for SIG$signal_name"
