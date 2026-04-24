#!/usr/bin/env bash
# SCOUT emulation container entrypoint.
#
# Exit code contract (parsed by aiedge.emulation._try_tier1):
#   0   = FirmAE boot succeeded (network up, services respond)
#   1   = argument / setup error
#   2   = FirmAE boot failed (boot_log present but no IP)
#   3   = FirmAE extractor failed (firmware image unparseable)
#   124 = internal timeout (shouldn't happen; docker run --stop-timeout wins)
#
# CRITICAL: never swallow FirmAE's exit code with "|| echo". SCOUT uses
# returncode==0 as the sole signal that tier-1 emulation succeeded.
set -euo pipefail

export USER="${USER:-root}"
export HOME="${HOME:-/root}"

FIRMWARE_PATH="${1:-}"
MODE="${2:-auto}"

if [[ -z "$FIRMWARE_PATH" ]]; then
    echo "usage: entrypoint.sh <firmware_path> [mode]" >&2
    exit 1
fi

if [[ ! -f "$FIRMWARE_PATH" ]]; then
    echo "firmware not found at: $FIRMWARE_PATH" >&2
    exit 1
fi

# FirmAE needs PostgreSQL for firmadyne image tracking.
if command -v pg_isready &>/dev/null; then
    service postgresql start >/dev/null 2>&1 || true
    for _ in $(seq 1 10); do
        pg_isready -q && break
        sleep 1
    done
fi

run_firmae() {
    # Propagate FirmAE's exit code; do not mask with echo/|| chains.
    local rc=0
    if [[ -x /opt/FirmAE/run.sh ]]; then
        cd /opt/FirmAE
        ./run.sh -c auto "$FIRMWARE_PATH" || rc=$?
        return $rc
    fi
    echo "FirmAE not installed at /opt/FirmAE" >&2
    return 1
}

case "$MODE" in
    firmae|auto)
        run_firmae
        exit $?
        ;;
    qemu-user)
        # QEMU user-mode is driven from the Python side; entrypoint has
        # nothing to do here. Report no-op success so the caller knows
        # the container started OK but user-mode probes must run out-of-band.
        echo "qemu-user mode: probes are executed by aiedge.emulation_qemu" >&2
        exit 0
        ;;
    *)
        echo "unknown mode: $MODE (expected: auto|firmae|qemu-user)" >&2
        exit 1
        ;;
esac
