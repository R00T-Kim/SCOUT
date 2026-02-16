#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PYTHONPATH="${PYTHONPATH:-$REPO_ROOT/src}"
WORK_DIR="${WORK_DIR:-$(mktemp -d)}"
FAST_MODE="${FAST_MODE:-0}"
CANONICAL_TIME_BUDGET_S="${CANONICAL_TIME_BUDGET_S:-60}"
NON8MB_TIME_BUDGET_S="${NON8MB_TIME_BUDGET_S:-10}"

mkdir -p "$WORK_DIR"

fail() {
  local token="$1"
  local msg="$2"
  echo "[FAIL][$token] $msg" >&2
  exit 1
}

run_non8mb_track() {
  local track_dir="$WORK_DIR/non8mb"
  mkdir -p "$track_dir"

  local fw="$track_dir/firmware_stub.bin"
  python3 - <<'PY' "$fw"
import hashlib
import sys
from pathlib import Path

target = Path(sys.argv[1])
pattern = (b"AIEdgeNon8MBFixture" * 4096)[:131072]
target.write_bytes(pattern)
digest = hashlib.sha256(pattern).hexdigest()
print(digest)
PY

  local run1
  local run2
  local out
  local rc

  set +e
  out=$(PYTHONPATH="$PYTHONPATH" python3 -m aiedge analyze "$fw" \
    --case-id "e2e-non8mb-analysis" \
    --ack-authorization \
    --no-llm \
    --time-budget-s "$NON8MB_TIME_BUDGET_S" \
    --profile analysis \
    --stages tooling,extraction,inventory)
  rc=$?
  set -e
  if [[ "$rc" != "0" && "$rc" != "10" ]]; then
    fail "MATRIX_NON8MB_RUN1" "aiedge analyze returned $rc"
  fi
  run1="$out"

  set +e
  out=$(PYTHONPATH="$PYTHONPATH" python3 -m aiedge analyze "$fw" \
    --case-id "e2e-non8mb-analysis" \
    --ack-authorization \
    --no-llm \
    --time-budget-s "$NON8MB_TIME_BUDGET_S" \
    --profile analysis \
    --stages tooling,extraction,inventory)
  rc=$?
  set -e
  if [[ "$rc" != "0" && "$rc" != "10" ]]; then
    fail "MATRIX_NON8MB_RUN2" "aiedge analyze returned $rc"
  fi
  run2="$out"

  PYTHONPATH="$PYTHONPATH" python3 - <<'PY' "$fw" "$run1" "$run2" "$track_dir"
import hashlib
import json
import sys
from pathlib import Path

from aiedge.determinism import assert_bundles_equal, collect_run_bundle

fw = Path(sys.argv[1]).resolve()
run1 = Path(sys.argv[2]).resolve()
run2 = Path(sys.argv[3]).resolve()
track_dir = Path(sys.argv[4]).resolve()

for run in (run1, run2):
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    track = manifest.get("track")
    if isinstance(track, dict) and track.get("track_id") == "8mb":
        raise SystemExit(f"[FAIL][MATRIX_NON8MB_TRACK] unexpected 8mb marker in {run}")

bundle1 = collect_run_bundle(run1)
bundle2 = collect_run_bundle(run2)
assert_bundles_equal(bundle1, bundle2)

data = fw.read_bytes()
fw_sha = hashlib.sha256(data).hexdigest()

repro = {
    "track": "non8mb",
    "firmware": {
        "sha256": fw_sha,
        "size_bytes": len(data),
    },
    "analysis": {
        "bundle_digest": bundle1.digest_sha256,
        "run_count": 2,
    },
}

repro_path = track_dir / "repro_bundle.json"
repro_path.write_text(
    json.dumps(repro, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)

evidence_index = {
    "track": "non8mb",
    "artifacts": {
        "repro_bundle_json": "non8mb/repro_bundle.json",
    },
    "bundle_digest": bundle1.digest_sha256,
}
evidence_path = track_dir / "evidence_index.json"
evidence_path.write_text(
    json.dumps(evidence_index, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)

print(f"[OK] non8mb determinism digest={bundle1.digest_sha256}")
print(f"[OK] non8mb repro bundle: {repro_path}")
print(f"[OK] non8mb evidence index: {evidence_path}")
PY
}

run_canonical_track() {
  local canonical_dir="$WORK_DIR/canonical_8mb"
  mkdir -p "$canonical_dir"
  WORK_DIR="$canonical_dir" TIME_BUDGET_S="$CANONICAL_TIME_BUDGET_S" bash "$SCRIPT_DIR/e2e_aiedge_8mb_track.sh"
}

if [[ "$FAST_MODE" == "1" ]]; then
  echo "[GATE][INFO][MATRIX_CANONICAL_SKIPPED] FAST_MODE=1 skips canonical 8MB track"
else
  run_canonical_track
fi

run_non8mb_track

python3 - <<'PY' "$WORK_DIR" "$FAST_MODE"
import json
import sys
from pathlib import Path

work_dir = Path(sys.argv[1]).resolve()
fast_mode = sys.argv[2] == "1"

matrix = {
    "tracks": {
        "canonical_8mb": {
            "executed": not fast_mode,
            "artifacts": {
                "repro_bundle_json": "canonical_8mb/repro_bundle.json",
                "evidence_index_json": "canonical_8mb/evidence_index.json",
            },
        },
        "non8mb": {
            "executed": True,
            "artifacts": {
                "repro_bundle_json": "non8mb/repro_bundle.json",
                "evidence_index_json": "non8mb/evidence_index.json",
            },
        },
    }
}

matrix_path = work_dir / "matrix_evidence_index.json"
matrix_path.write_text(
    json.dumps(matrix, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
print(f"[OK] matrix evidence index: {matrix_path}")
print(f"[PASS] {work_dir}")
PY
