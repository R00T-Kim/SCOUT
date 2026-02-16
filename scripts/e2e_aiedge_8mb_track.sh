#!/usr/bin/env bash
set -euo pipefail

CANONICAL_INPUT="/home/rootk1m/SCOUT/aiedge-runs/2026-02-12_1633_sha256-387d97fd9251/input/firmware.bin"
PYTHONPATH="/home/rootk1m/SCOUT/src"

WORK_DIR="${WORK_DIR:-$(mktemp -d)}"
cd "$WORK_DIR"

GRAPHVIZ_ROOT="/home/rootk1m/SCOUT/.local/graphviz"
GRAPHVIZ_BIN="$GRAPHVIZ_ROOT/usr/bin"
GRAPHVIZ_LIB="$GRAPHVIZ_ROOT/usr/lib/x86_64-linux-gnu"
GRAPHVIZ_PLUGIN_CONFIG="$GRAPHVIZ_LIB/graphviz/config6a"

ensure_graphviz_dot() {
  export PATH="$GRAPHVIZ_BIN:$PATH"
  export LD_LIBRARY_PATH="$GRAPHVIZ_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

  if ! command -v dot >/dev/null 2>&1; then
    echo "[FAIL] Graphviz dot not found (checked $GRAPHVIZ_BIN and PATH)" >&2
    exit 31
  fi

  if [[ ! -s "$GRAPHVIZ_PLUGIN_CONFIG" ]]; then
    dot -c >/dev/null 2>&1 || {
      echo "[FAIL] dot -c failed while bootstrapping plugin config" >&2
      exit 32
    }
    if [[ ! -s "$GRAPHVIZ_PLUGIN_CONFIG" ]]; then
      echo "[FAIL] Graphviz plugin config missing/empty after dot -c: $GRAPHVIZ_PLUGIN_CONFIG" >&2
      exit 33
    fi
  fi
}

run_once() {
  local profile="$1"
  shift
  local out
  local rc
  set +e
  out=$(PYTHONPATH="$PYTHONPATH" python3 -m aiedge analyze-8mb "$CANONICAL_INPUT" \
    --case-id "e2e-8mb-${profile}" \
    --ack-authorization \
    --no-llm \
    --time-budget-s 60 \
    --profile "$profile" \
    "$@")
  rc=$?
  set -e
  if [[ "$rc" != "0" && "$rc" != "10" ]]; then
    echo "[FAIL] aiedge returned $rc" >&2
    exit "$rc"
  fi
  echo "$out"
}

RUN1=$(run_once analysis --stages tooling,extraction,inventory,emulation)
RUN2=$(run_once analysis --stages tooling,extraction,inventory,emulation)

PYTHONPATH="$PYTHONPATH" python3 - <<PY
import json
from pathlib import Path

from aiedge.determinism import assert_bundles_equal, collect_run_bundle

run1 = Path("$RUN1").resolve()
run2 = Path("$RUN2").resolve()

for run in (run1, run2):
    m = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    assert m.get("profile") == "analysis"
    track = m.get("track")
    assert isinstance(track, dict)
    assert track.get("track_id") == "8mb"

b1 = collect_run_bundle(run1)
b2 = collect_run_bundle(run2)
assert_bundles_equal(b1, b2)
print("[OK] determinism bundle equal")
PY

RUN_FINAL1=$(run_once analysis)
RUN_FINAL2=$(run_once analysis)
python3 /home/rootk1m/SCOUT/scripts/verify_aiedge_final_report.py --run-dir "$RUN_FINAL1"
python3 /home/rootk1m/SCOUT/scripts/verify_aiedge_final_report.py --run-dir "$RUN_FINAL2"
python3 /home/rootk1m/SCOUT/scripts/verify_aiedge_analyst_report.py --run-dir "$RUN_FINAL1"
python3 /home/rootk1m/SCOUT/scripts/verify_aiedge_analyst_report.py --run-dir "$RUN_FINAL2"

ensure_graphviz_dot
for run in "$RUN_FINAL1" "$RUN_FINAL2"; do
  dot_path="$run/stages/graph/comm_graph.dot"
  svg_path="$run/stages/graph/comm_graph.svg"
  if [[ ! -f "$dot_path" ]]; then
    echo "[FAIL] graph DOT missing: $dot_path" >&2
    exit 34
  fi
  dot -Tsvg "$dot_path" -o "$svg_path"
  echo "[OK] graph DOT rendered: $dot_path"
done

if PYTHONPATH="$PYTHONPATH" python3 -m aiedge analyze-8mb "$CANONICAL_INPUT" \
  --case-id e2e-8mb-exploit-missing \
  --ack-authorization \
  --no-llm \
  --time-budget-s 10 \
  --profile exploit \
  --stages exploit_gate \
  >/dev/null 2>&1; then
  echo "[FAIL] exploit profile should require gate vars" >&2
  exit 30
fi

RUN_POC1=$(PYTHONPATH="$PYTHONPATH" python3 -m aiedge analyze-8mb "$CANONICAL_INPUT" \
  --case-id e2e-8mb-exploit \
  --ack-authorization \
  --no-llm \
  --time-budget-s 30 \
  --profile exploit \
  --exploit-flag flag \
  --exploit-attestation authorized \
  --exploit-scope lab-only \
  --stages exploit_gate,exploit_chain,exploit_policy)

RUN_POC2=$(PYTHONPATH="$PYTHONPATH" python3 -m aiedge analyze-8mb "$CANONICAL_INPUT" \
  --case-id e2e-8mb-exploit \
  --ack-authorization \
  --no-llm \
  --time-budget-s 30 \
  --profile exploit \
  --exploit-flag flag \
  --exploit-attestation authorized \
  --exploit-scope lab-only \
  --stages exploit_gate,exploit_chain,exploit_policy)

PYTHONPATH="$PYTHONPATH" python3 - <<PY
import hashlib
import json
from pathlib import Path

from aiedge.determinism import assert_bundles_equal, collect_run_bundle


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _assert_emulation_isolation(run: Path) -> None:
    stage_json = run / "stages" / "emulation" / "stage.json"
    log_path = run / "stages" / "emulation" / "emulation.log"
    if not stage_json.is_file():
        raise SystemExit(f"[FAIL] emulation stage.json missing: {stage_json}")
    if not log_path.is_file():
        raise SystemExit(f"[FAIL] emulation log missing: {log_path}")

    stage = json.loads(stage_json.read_text(encoding="utf-8"))
    status = stage.get("status")
    if status not in ("ok", "partial"):
        raise SystemExit(f"[FAIL] emulation status unexpected ({status}) at {stage_json}")

    evidence = stage.get("artifacts")
    if not isinstance(evidence, list):
        raise SystemExit(f"[FAIL] emulation artifacts missing at {stage_json}")

    expected_log_rel = "stages/emulation/emulation.log"
    if not any(isinstance(item, dict) and item.get("path") == expected_log_rel for item in evidence):
        raise SystemExit(
            f"[FAIL] emulation artifacts missing {expected_log_rel} at {stage_json}"
        )

    log_text = log_path.read_text(encoding="utf-8")
    if "--network none" not in log_text:
        raise SystemExit(f"[FAIL] emulation log missing '--network none': {log_path}")

    print(f"[OK] emulation isolation evidence: stage={stage_json} log={log_path}")


def _assert_inventory_depth(run: Path) -> None:
    inventory_path = run / "stages" / "inventory" / "inventory.json"
    summary = None
    if inventory_path.is_file():
        inventory_obj = json.loads(inventory_path.read_text(encoding="utf-8"))
        summary = inventory_obj.get("summary")
    if not inventory_path.is_file():
        raise SystemExit(f"[FAIL] inventory.json missing: run_dir={run} summary={summary}")
    if not isinstance(summary, dict):
        raise SystemExit(f"[FAIL] inventory summary missing: run_dir={run} summary={summary}")

    files = summary.get("files")
    configs = summary.get("configs")
    binaries = summary.get("binaries")

    if not isinstance(files, int) or files <= 0:
        raise SystemExit(f"[FAIL] inventory summary.files must be > 0: run_dir={run} summary={summary}")
    if not isinstance(configs, int) or not isinstance(binaries, int) or (configs + binaries) <= 0:
        raise SystemExit(
            f"[FAIL] inventory summary.configs + summary.binaries must be > 0: run_dir={run} summary={summary}"
        )

    print(f"[OK] inventory depth: run_dir={run} summary={summary}")


def _assert_analyst_artifact_hashes_equal(run1: Path, run2: Path) -> None:
    tracked_artifacts = (
        "report/analyst_report.json",
        "stages/graph/comm_graph.json",
        "stages/attack_surface/attack_surface.json",
        "stages/threat_model/threat_model.json",
        "stages/functional_spec/functional_spec.json",
    )

    for rel in tracked_artifacts:
        p1 = run1 / rel
        p2 = run2 / rel
        if not p1.is_file():
            raise SystemExit(f"[FAIL] determinism artifact missing in run1: {p1}")
        if not p2.is_file():
            raise SystemExit(f"[FAIL] determinism artifact missing in run2: {p2}")

        h1 = _sha256_file(p1)
        h2 = _sha256_file(p2)
        if h1 != h2:
            raise SystemExit(
                f"[FAIL] deterministic analyst artifact hash mismatch for {rel}: run1={h1} run2={h2}"
            )

    print("[OK] deterministic analyst artifact hashes match")


canonical = Path("$CANONICAL_INPUT").resolve()
repro_bundle_path = Path("$WORK_DIR") / "repro_bundle.json"
evidence_index_path = Path("$WORK_DIR") / "evidence_index.json"
perf_json_path = Path("$WORK_DIR") / "perf.json"

analysis_run1 = Path("$RUN_FINAL1").resolve()
analysis_run2 = Path("$RUN_FINAL2").resolve()
poc_run1 = Path("$RUN_POC1").resolve()
poc_run2 = Path("$RUN_POC2").resolve()

for run in (analysis_run1, analysis_run2):
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("profile") != "analysis":
        raise SystemExit(f"[FAIL] expected analysis profile: {run}")
    track = manifest.get("track")
    if not isinstance(track, dict) or track.get("track_id") != "8mb":
        raise SystemExit(f"[FAIL] missing canonical track marker: {run}")
    _assert_emulation_isolation(run)
    _assert_inventory_depth(run)

analysis_bundle_1 = collect_run_bundle(analysis_run1)
analysis_bundle_2 = collect_run_bundle(analysis_run2)
assert_bundles_equal(analysis_bundle_1, analysis_bundle_2)
_assert_analyst_artifact_hashes_equal(analysis_run1, analysis_run2)

for run in (poc_run1, poc_run2):
    for stage in ("exploit_gate", "exploit_chain", "exploit_policy"):
        stage_json = run / "stages" / stage / "stage.json"
        obj = json.loads(stage_json.read_text(encoding="utf-8"))
        if obj.get("status") != "ok":
            policy_json = run / "stages" / "exploit_policy" / "policy.json"
            raise SystemExit(
                f"[FAIL] {stage} status is not ok: {obj.get('status')} stage_json={stage_json} policy_json={policy_json}"
            )
    policy_json = run / "stages" / "exploit_policy" / "policy.json"
    if not policy_json.is_file():
        raise SystemExit(f"[FAIL] exploit_policy evidence missing: {policy_json}")

poc_bundle_1 = collect_run_bundle(poc_run1)
poc_bundle_2 = collect_run_bundle(poc_run2)
assert_bundles_equal(poc_bundle_1, poc_bundle_2)

repro = {
    "firmware": {
        "path": str(canonical),
        "sha256": _sha256_file(canonical),
        "size_bytes": canonical.stat().st_size,
    },
    "flows": {
        "analysis_final": {
            "command": [
                "python3",
                "-m",
                "aiedge",
                "analyze-8mb",
                str(canonical),
                "--case-id",
                "e2e-8mb-analysis",
                "--ack-authorization",
                "--no-llm",
                "--time-budget-s",
                "60",
                "--profile",
                "analysis",
            ],
            "run_dirs": [str(analysis_run1), str(analysis_run2)],
            "bundle_digests": [analysis_bundle_1.digest_sha256, analysis_bundle_2.digest_sha256],
        },
        "poc_exploit": {
            "command": [
                "python3",
                "-m",
                "aiedge",
                "analyze-8mb",
                str(canonical),
                "--case-id",
                "e2e-8mb-exploit",
                "--ack-authorization",
                "--no-llm",
                "--time-budget-s",
                "30",
                "--profile",
                "exploit",
                "--exploit-flag",
                "flag",
                "--exploit-attestation",
                "authorized",
                "--exploit-scope",
                "lab-only",
                "--stages",
                "exploit_gate,exploit_chain,exploit_policy",
            ],
            "run_dirs": [str(poc_run1), str(poc_run2)],
            "bundle_digests": [poc_bundle_1.digest_sha256, poc_bundle_2.digest_sha256],
        },
    },
}
repro_bundle_path.write_text(json.dumps(repro, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

evidence_index = {
    "artifacts": {
        "perf_json": str(perf_json_path),
        "repro_bundle_json": str(repro_bundle_path),
    },
    "flows": {
        "analysis_final": {
            "run_dirs": [str(analysis_run1), str(analysis_run2)],
        },
        "poc_exploit": {
            "run_dirs": [str(poc_run1), str(poc_run2)],
        },
    },
}
evidence_index_path.write_text(
    json.dumps(evidence_index, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)

print(f"[OK] replay verify: analysis-final digest={analysis_bundle_1.digest_sha256}")
print(f"[OK] replay verify: poc digest={poc_bundle_1.digest_sha256}")
print(f"[OK] repro bundle: {repro_bundle_path}")
print(f"[OK] evidence index: {evidence_index_path}")
print(f"[OK] exploit-gated stages ok")
PY

OUT=$(RUNS=1 TIME_BUDGET_S=60 WORK_DIR="$WORK_DIR" OUT_JSON="$WORK_DIR/perf.json" \
  bash /home/rootk1m/SCOUT/scripts/perf_8mb_track.sh)
test -f "$OUT"
echo "[OK] perf json: $OUT"

echo "[PASS] $WORK_DIR"
