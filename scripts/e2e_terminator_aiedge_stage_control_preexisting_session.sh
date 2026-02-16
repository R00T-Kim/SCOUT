#!/usr/bin/env bash
set -euo pipefail

SCOUT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TERMINATOR_PATH="/home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/terminator.sh"
E2E_SCRIPT="$SCOUT_ROOT/scripts/e2e_terminator_aiedge_stage_control.sh"

if [[ ! -f "$TERMINATOR_PATH" ]]; then
  echo "[FAIL] Missing terminator script: $TERMINATOR_PATH" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/e2e-terminator-preexisting.XXXXXX")"
FIRMWARE_PATH="$WORK_DIR/preexisting_fixture_firmware.bin"
PREEXISTING_PID=""

cleanup() {
  if [[ -n "$PREEXISTING_PID" ]]; then
    local target=""
    if kill -0 -- "-$PREEXISTING_PID" 2>/dev/null; then
      target="-$PREEXISTING_PID"
    elif kill -0 -- "$PREEXISTING_PID" 2>/dev/null; then
      target="$PREEXISTING_PID"
    fi

    if [[ -n "$target" ]]; then
      kill -TERM -- "$target" 2>/dev/null || true
      sleep 0.5
      if kill -0 -- "$target" 2>/dev/null; then
        kill -KILL -- "$target" 2>/dev/null || true
      fi
    fi
  fi

  rm -rf "$WORK_DIR"
}

trap cleanup EXIT

python3 - <<'PY' "$FIRMWARE_PATH"
import secrets
import sys
from pathlib import Path

firmware = Path(sys.argv[1])
firmware.write_bytes(f"SCOUT_PREEXISTING_FIXTURE_{secrets.token_hex(8)}\n".encode("utf-8"))
PY

set +e
preexisting_output="$(env -i PATH="$PATH" HOME="$HOME" \
  TERMINATOR_ACK_AUTHORIZATION=1 \
  TERMINATOR_MODEL=haiku \
  "$TERMINATOR_PATH" firmware "$FIRMWARE_PATH" 2>&1)"
preexisting_rc=$?
set -e

if [[ "$preexisting_rc" -ne 0 ]]; then
  echo "[FAIL] Could not start preexisting Terminator firmware session" >&2
  printf '%s\n' "$preexisting_output" >&2
  exit 1
fi

while IFS= read -r line; do
  if [[ "$line" =~ ^\[\*\]\ PID:\ ([0-9]+)$ ]]; then
    PREEXISTING_PID="${BASH_REMATCH[1]}"
    break
  fi
done <<< "$preexisting_output"

if [[ -z "$PREEXISTING_PID" ]]; then
  echo "[FAIL] Could not parse preexisting Terminator PID" >&2
  printf '%s\n' "$preexisting_output" >&2
  exit 1
fi

if ! kill -0 -- "$PREEXISTING_PID" 2>/dev/null && ! kill -0 -- "-$PREEXISTING_PID" 2>/dev/null; then
  echo "[FAIL] Preexisting Terminator PID is not alive before main E2E: $PREEXISTING_PID" >&2
  exit 1
fi

kill -STOP -- "$PREEXISTING_PID" 2>/dev/null || true

echo "[INFO] Preexisting Terminator PID: $PREEXISTING_PID"

"$E2E_SCRIPT"

if ! kill -0 -- "$PREEXISTING_PID" 2>/dev/null && ! kill -0 -- "-$PREEXISTING_PID" 2>/dev/null; then
  echo "[FAIL] Main E2E terminated preexisting Terminator PID: $PREEXISTING_PID" >&2
  exit 1
fi

kill -CONT -- "$PREEXISTING_PID" 2>/dev/null || true

echo "[PASS] preexisting Terminator PID survived main E2E: $PREEXISTING_PID"
