#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[*] Building scout-emulation image..."
docker build -t scout-emulation:latest "$SCRIPT_DIR"
echo "[+] Done. Image: scout-emulation:latest"
