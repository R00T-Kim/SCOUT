#!/usr/bin/env bash
# Build the scout-emulation Docker image (FirmAE + QEMU).
#
# Size estimate: 1.5-2 GB (FirmAE's download.sh pulls kernel images).
# Time estimate: 20-40 min on a cold cache / broadband connection.
#
# Override the pinned FirmAE commit:
#   FIRMAE_COMMIT=<sha> ./build.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v docker >/dev/null 2>&1; then
    echo "[!] docker binary not on PATH; install Docker first." >&2
    exit 1
fi

IMAGE="${AIEDGE_EMULATION_IMAGE:-scout-emulation:latest}"
COMMIT="${FIRMAE_COMMIT:-}"

echo "[*] Building ${IMAGE}"
echo "    context: ${SCRIPT_DIR}"
if [[ -n "${COMMIT}" ]]; then
    echo "    FirmAE commit override: ${COMMIT}"
    docker build \
        --build-arg "FIRMAE_COMMIT=${COMMIT}" \
        -t "${IMAGE}" \
        "${SCRIPT_DIR}"
else
    docker build -t "${IMAGE}" "${SCRIPT_DIR}"
fi

echo "[+] Done. Verify with: docker image inspect ${IMAGE}"
echo "    SCOUT picks it up automatically when AIEDGE_EMULATION_IMAGE is unset."
