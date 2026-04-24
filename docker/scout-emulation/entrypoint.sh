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

# Detach any stale loop devices pointing at the FirmAE scratch area.
# Docker containers share the host's /dev namespace, so attachments
# from previous failed boots persist. If we leave them in place, the
# patched add_partition below can pick up an old loop whose partition
# node has a dead major:minor.
for stale in $(losetup -l -n 2>/dev/null | awk '$6 ~ /FirmAE\/scratch/ {print $1}'); do
    losetup -d "${stale}" 2>/dev/null || true
done

# FirmAE's ``firmae.config::add_partition`` polls for ``/dev/loopNp1``
# and additionally requires ``ls -al ${DEV_PATH} | grep -q "disk"`` --
# i.e. the partition node must be owned by group ``disk``. In a Docker
# container with ``--privileged``, ``systemd-udevd`` can be started and
# the kernel does emit ``add`` uevents for new loop partitions, but the
# uevents do not always propagate into the container's /dev tmpfs on
# the host's kernel configuration, leaving the partition nodes missing
# indefinitely. 2026-04-24 R7000 boot confirmed: 3h stall at
# ``----Mounting QEMU Image----``. 2026-04-25 retry with udevd running
# unblocked the first iteration after one manual mknod + chgrp disk,
# then failed again in the check-mode second iteration.
#
# Workaround: start a sidecar that polls ``losetup`` and, for every
# loop attached to a file inside /opt/FirmAE/scratch/, mknods the
# corresponding ``/dev/loopNp1`` node with the expected major:minor
# from sysfs and chgrp's it to ``disk``. This replicates what udev
# would do on a bare-metal host. The sidecar exits when FirmAE's
# run.sh exits.
if command -v /usr/lib/systemd/systemd-udevd >/dev/null 2>&1; then
    if ! pgrep -x systemd-udevd >/dev/null 2>&1; then
        /usr/lib/systemd/systemd-udevd --daemon >/dev/null 2>&1 || true
    fi
    if command -v udevadm >/dev/null 2>&1; then
        udevadm trigger --action=add --subsystem-match=block >/dev/null 2>&1 || true
        udevadm settle --timeout=5 >/dev/null 2>&1 || true
    fi
fi

# Patch FirmAE's add_partition to do the mknod+chgrp synchronously
# after losetup -Pf returns, closing the race where a background
# sidecar would miss the short mkfs window between ``losetup -Pf`` and
# ``mkfs.ext2``. Without this, even with udevd + a background poller,
# the check-mode second iteration regularly finds a stale /dev/loopNp1
# node and e2fsck reports "Bad magic number in super-block".
#
# The patched add_partition:
#   1. calls losetup -Pf (original behaviour)
#   2. polls losetup output for the loop that was just created
#   3. builds /dev/loopNp1 by reading /sys/block/loopN/loopNp1/dev
#   4. rm's any stale node, mknod's the current major:minor, chgrp disk
#   5. returns the path (FirmAE's existing caller expects echo)
if [ -f /opt/FirmAE/firmae.config ]; then
    # Replace the upstream add_partition with our container-aware version.
    # sed would be fragile; use a Python single-shot with a delimiter.
    python3 - <<'PYEOF'
import re
path = "/opt/FirmAE/firmae.config"
with open(path, "r", encoding="utf-8") as f:
    src = f.read()
if "# patched by scout-emulation" in src:
    raise SystemExit(0)
pattern = re.compile(r"^add_partition\s*\(\)\s*\{.*?^\}\s*$", re.MULTILINE | re.DOTALL)
replacement = (
    "# patched by scout-emulation (see entrypoint.sh)\n"
    "add_partition () {\n"
    "    # Use --show to get the NEW loop device directly. Docker\n"
    "    # containers share the host /dev, so parsing `losetup` output\n"
    "    # for the backing file matches STALE loops from prior failed\n"
    "    # runs (e.g. /dev/loop14 attached to an earlier makeImage\n"
    "    # iteration) -- the partition node on a stale loop has a dead\n"
    "    # minor:major, so e2fsck sees a bogus superblock and fails.\n"
    "    local LOOP_DEV\n"
    "    LOOP_DEV=$(losetup --show -Pf \"${1}\")\n"
    "    if [ -z \"${LOOP_DEV}\" ]; then\n"
    "        echo \"add_partition: losetup --show -Pf failed for ${1}\" >&2\n"
    "        return 1\n"
    "    fi\n"
    "    local BASE; BASE=$(basename \"${LOOP_DEV}\")\n"
    "    local DEV_PATH=\"/dev/${BASE}p1\"\n"
    "    # Wait for kernel to populate /sys/block/.../p1\n"
    "    local WAITED=0\n"
    "    while [ ! -e \"/sys/block/${BASE}/${BASE}p1\" ]; do\n"
    "        sleep 0.1\n"
    "        WAITED=$((WAITED + 1))\n"
    "        if [ ${WAITED} -gt 50 ]; then\n"
    "            echo \"add_partition: /sys/block/${BASE}/${BASE}p1 missing after 5s\" >&2\n"
    "            return 1\n"
    "        fi\n"
    "    done\n"
    "    # Materialise the partition device node (udev is unreliable\n"
    "    # inside containers; see scout-emulation/entrypoint.sh).\n"
    "    local DEV_NUM\n"
    "    DEV_NUM=$(cat \"/sys/block/${BASE}/${BASE}p1/dev\" 2>/dev/null)\n"
    "    if [ -n \"${DEV_NUM}\" ]; then\n"
    "        local MAJ=\"${DEV_NUM%%:*}\"\n"
    "        local MIN=\"${DEV_NUM##*:}\"\n"
    "        # Always rm+mknod so the node tracks the CURRENT major:minor.\n"
    "        rm -f \"${DEV_PATH}\"\n"
    "        mknod -m 0660 \"${DEV_PATH}\" b \"${MAJ}\" \"${MIN}\" 2>/dev/null || true\n"
    "        chgrp disk \"${DEV_PATH}\" 2>/dev/null || true\n"
    "    fi\n"
    "    while (! ls -al \"${DEV_PATH}\" | grep -q \"disk\"); do sleep 0.1; done\n"
    "    echo \"${DEV_PATH}\"\n"
    "}\n"
)
new_src, n = pattern.subn(replacement, src, count=1)
if n != 1:
    raise SystemExit(f"expected 1 substitution, did {n}")
with open(path, "w", encoding="utf-8") as f:
    _ = f.write(new_src)
PYEOF
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
