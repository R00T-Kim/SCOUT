#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

FIRMWARE_PATH="${FIRMWARE_PATH:-$REPO_ROOT/ER-e50.v3.0.1.tar}"
PYTHONPATH_VALUE="${PYTHONPATH:-$REPO_ROOT/src}"
CASE_ID="${CASE_ID:-e2e-er-e50-inventory-regression}"
TIME_BUDGET_S="${TIME_BUDGET_S:-120}"

EVIDENCE_DIR="$REPO_ROOT/.sisyphus/evidence/aiedge-pipeline-gap-hardening/task6-e2e"
PATHS_FILE="$EVIDENCE_DIR/paths.txt"

mkdir -p "$EVIDENCE_DIR"

if [[ ! -f "$FIRMWARE_PATH" ]]; then
  echo "[FAIL] firmware not found: $FIRMWARE_PATH" >&2
  exit 2
fi

set +e
ANALYZE_OUT=$(PYTHONPATH="$PYTHONPATH_VALUE" python3 -m aiedge analyze "$FIRMWARE_PATH" \
  --case-id "$CASE_ID" \
  --ack-authorization \
  --no-llm \
  --time-budget-s "$TIME_BUDGET_S" \
  --profile analysis \
  --stages tooling,extraction,structure,carving,firmware_profile,inventory)
ANALYZE_RC=$?
set -e

if [[ "$ANALYZE_RC" != "0" && "$ANALYZE_RC" != "10" ]]; then
  echo "[FAIL] aiedge analyze returned $ANALYZE_RC" >&2
  exit "$ANALYZE_RC"
fi

RUN_DIR="$ANALYZE_OUT"

python3 - <<'PY' "$RUN_DIR" "$EVIDENCE_DIR" "$PATHS_FILE"
import json
import shutil
import sys
from pathlib import Path


def fail(msg: str, code: int = 1) -> None:
    print(f"[FAIL] {msg}", file=sys.stderr)
    raise SystemExit(code)


run_dir = Path(sys.argv[1]).resolve()
evidence_dir = Path(sys.argv[2]).resolve()
paths_file = Path(sys.argv[3]).resolve()

if not run_dir.is_dir():
    fail(f"run_dir missing or not a directory: {run_dir}")

inventory_json = run_dir / "stages" / "inventory" / "inventory.json"
inventory_stage_json = run_dir / "stages" / "inventory" / "stage.json"
firmware_profile_json = run_dir / "stages" / "firmware_profile" / "firmware_profile.json"
firmware_profile_stage_json = run_dir / "stages" / "firmware_profile" / "stage.json"
binwalk_log = run_dir / "stages" / "extraction" / "binwalk.log"

if not inventory_json.is_file():
    fail(f"inventory.json missing: {inventory_json}")
if not inventory_stage_json.is_file():
    fail(f"inventory stage.json missing: {inventory_stage_json}")

inventory_text = inventory_json.read_text(encoding="utf-8")
if "/home/" in inventory_text:
    fail("inventory.json contains forbidden '/home/' substring")

try:
    inventory_obj = json.loads(inventory_text)
except json.JSONDecodeError as exc:
    fail(f"inventory.json invalid JSON: {exc}")

reason = inventory_obj.get("reason")
if reason == "inventory_recovered_from_exception":
    fail("inventory reason indicates exception recovery")

coverage_metrics = inventory_obj.get("coverage_metrics")
if not isinstance(coverage_metrics, dict):
    fail("coverage_metrics missing or invalid")

files_seen = coverage_metrics.get("files_seen")
roots_scanned = coverage_metrics.get("roots_scanned")

if not isinstance(files_seen, int) or files_seen <= 0:
    fail(f"coverage_metrics.files_seen must be > 0, got: {files_seen}")
if not isinstance(roots_scanned, int) or roots_scanned <= 0:
    fail(f"coverage_metrics.roots_scanned must be > 0, got: {roots_scanned}")

evidence_dir.mkdir(parents=True, exist_ok=True)
shutil.copy2(inventory_json, evidence_dir / "inventory.json")
shutil.copy2(inventory_stage_json, evidence_dir / "inventory.stage.json")

firmware_profile_exists = firmware_profile_json.is_file()
if firmware_profile_exists:
    shutil.copy2(firmware_profile_json, evidence_dir / "firmware_profile.json")

lines = [
    f"run_dir={run_dir}",
    f"inventory_json={inventory_json}",
    f"inventory_stage_json={inventory_stage_json}",
    f"firmware_profile_stage_json={firmware_profile_stage_json}",
]

if firmware_profile_exists:
    lines.append(f"firmware_profile_json={firmware_profile_json}")
else:
    lines.append("firmware_profile_json=missing")

if binwalk_log.exists():
    lines.append(f"binwalk_log={binwalk_log}")

paths_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

print(f"[OK] run_dir: {run_dir}")
print(f"[OK] evidence_dir: {evidence_dir}")
print(f"[OK] paths: {paths_file}")
print(
    "[OK] coverage metrics "
    f"files_seen={files_seen} roots_scanned={roots_scanned} reason={reason}"
)
PY

echo "[PASS] e2e_er_e50_inventory_regression"
