#!/usr/bin/env bash
set -euo pipefail

CANONICAL_INPUT="/home/rootk1m/SCOUT/aiedge-runs/2026-02-12_1633_sha256-387d97fd9251/input/firmware.bin"
RUNS=${RUNS:-3}
TIME_BUDGET_S=${TIME_BUDGET_S:-120}

WORK_DIR=${WORK_DIR:-"$(mktemp -d)"}
OUT_JSON=${OUT_JSON:-"$WORK_DIR/perf.json"}

PYTHONPATH=/home/rootk1m/SCOUT/src

runs_json="[]"

mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

for i in $(seq 1 "$RUNS"); do
  set +e
  run_dir=$(PYTHONPATH="$PYTHONPATH" python3 -m aiedge analyze-8mb "$CANONICAL_INPUT" \
    --case-id "perf-8mb-$i" \
    --ack-authorization \
    --no-llm \
    --time-budget-s "$TIME_BUDGET_S" \
    --profile analysis \
    --stages tooling,extraction,inventory,emulation)
  rc=$?
  set -e
  if [[ "$rc" != "0" && "$rc" != "10" ]]; then
    echo "aiedge returned $rc" >&2
    exit "$rc"
  fi

  if [[ -z "$run_dir" ]]; then
    echo "failed to get run_dir" >&2
    exit 20
  fi

  perf=$(RUN_DIR="$run_dir" PYTHONPATH="$PYTHONPATH" python3 - <<'PY'
import json
import os
from pathlib import Path

from aiedge.perf import collect_run_perf

run_dir = Path(os.environ["RUN_DIR"]).resolve()
p = collect_run_perf(run_dir)
print(json.dumps({
  "run_dir": str(p.run_dir),
  "total_stage_time_s": p.total_stage_time_s,
  "stage_durations_s": p.stage_durations_s,
}, sort_keys=True))
PY
  )
  runs_json=$(python3 - <<PY
import json
arr = json.loads('''$runs_json''')
arr.append(json.loads('''$perf'''))
print(json.dumps(arr))
PY
  )
done

PYTHONPATH="$PYTHONPATH" python3 - <<PY > "$OUT_JSON"
import json
from pathlib import Path
from aiedge.perf import RunPerf, summarize_runs

runs_raw = json.loads('''$runs_json''')
runs = []
for r in runs_raw:
  runs.append(RunPerf(run_dir=Path(r["run_dir"]), stage_durations_s=r["stage_durations_s"], total_stage_time_s=float(r["total_stage_time_s"])) )
summary = summarize_runs(runs)
out = {"runs": runs_raw, "summary": {
  "total_p50_s": summary.total_p50_s,
  "total_p95_s": summary.total_p95_s,
  "stage_p50_s": summary.stage_p50_s,
  "stage_p95_s": summary.stage_p95_s,
}}
print(json.dumps(out, indent=2, sort_keys=True))
PY

echo "$OUT_JSON"
