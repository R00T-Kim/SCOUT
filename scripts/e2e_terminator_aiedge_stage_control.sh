#!/usr/bin/env bash
set -euo pipefail

SCOUT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TERMINATOR_PATH="/home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/terminator.sh"
TERMINATOR_REPORT_ROOT="/home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/reports"

if [[ ! -f "$TERMINATOR_PATH" ]]; then
  echo "[FAIL] Missing terminator script: $TERMINATOR_PATH" >&2
  exit 1
fi

if [[ ! -d "$TERMINATOR_REPORT_ROOT" ]]; then
  mkdir -p "$TERMINATOR_REPORT_ROOT"
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/e2e-terminator-aiedge.XXXXXX")"
OWNED_SESSION_CLEANUP_DONE=0
WORKDIR_CLEANUP_DONE=0
E2E_KEEP_WORKDIR="${E2E_KEEP_WORKDIR:-0}"
E2E_SELF_INTERRUPT="${E2E_SELF_INTERRUPT:-}"

if [[ "$E2E_KEEP_WORKDIR" != "0" && "$E2E_KEEP_WORKDIR" != "1" ]]; then
  echo "[FAIL] E2E_KEEP_WORKDIR must be 0 or 1 (got: $E2E_KEEP_WORKDIR)" >&2
  exit 1
fi

if [[ -n "$E2E_SELF_INTERRUPT" && "$E2E_SELF_INTERRUPT" != "INT" && "$E2E_SELF_INTERRUPT" != "TERM" ]]; then
  echo "[FAIL] E2E_SELF_INTERRUPT must be INT or TERM (got: $E2E_SELF_INTERRUPT)" >&2
  exit 1
fi

E2E_SELF_INTERRUPT_TRIGGERED=0

cleanup_owned_sessions() {
  local trigger="${1:-EXIT}"
  local ownership_file="$WORK_DIR/terminator_owned_sessions.json"
  local survivors=0

  if [[ "$OWNED_SESSION_CLEANUP_DONE" -eq 1 ]]; then
    return 0
  fi
  OWNED_SESSION_CLEANUP_DONE=1

  if [[ ! -f "$ownership_file" ]]; then
    echo "[INFO] [$trigger] No owned session file found; skipping process cleanup"
    return 0
  fi

  while IFS=$'\t' read -r pid report_dir; do
    if [[ -z "$pid" ]]; then
      continue
    fi

    if [[ ! "$pid" =~ ^[0-9]+$ ]] || [[ "$pid" -le 0 ]]; then
      echo "[WARN] [$trigger] Invalid owned PID '$pid' (report_dir=$report_dir); skipping"
      continue
    fi

    local kill_target=""
    local kill_target_kind=""
    if kill -0 -- "-$pid" 2>/dev/null; then
      kill_target="-$pid"
      kill_target_kind="pgid"
    elif kill -0 -- "$pid" 2>/dev/null; then
      kill_target="$pid"
      kill_target_kind="pid"
    else
      echo "[INFO] [$trigger] Owned PID $pid already dead (report_dir=$report_dir)"
      continue
    fi

    echo "[INFO] [$trigger] Sending TERM to owned PID $pid via $kill_target_kind target $kill_target (report_dir=$report_dir)"
    kill -TERM -- "$kill_target" 2>/dev/null || true

    local waited=0
    while kill -0 -- "$kill_target" 2>/dev/null && [[ "$waited" -lt 20 ]]; do
      sleep 0.25
      waited=$((waited + 1))
    done

    if kill -0 -- "$kill_target" 2>/dev/null; then
      echo "[WARN] [$trigger] Owned PID $pid still alive after TERM; sending KILL"
      kill -KILL -- "$kill_target" 2>/dev/null || true
      sleep 0.1
      if kill -0 -- "$kill_target" 2>/dev/null; then
        echo "[FAIL] [$trigger] Owned PID $pid still alive after KILL" >&2
        survivors=$((survivors + 1))
      else
        echo "[INFO] [$trigger] Owned PID $pid terminated via KILL"
      fi
    else
      echo "[INFO] [$trigger] Owned PID $pid terminated via TERM"
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
    report_dir = entry.get("report_dir", "")
    if pid is None:
        continue
    print(f"{pid}\t{report_dir}")
PY
  )

  if [[ "$survivors" -gt 0 ]]; then
    echo "[FAIL] [$trigger] Cleanup detected $survivors surviving owned session(s)" >&2
    return 1
  fi

  return 0
}

cleanup() {
  local trigger="${1:-EXIT}"
  if [[ "$WORKDIR_CLEANUP_DONE" -eq 1 ]]; then
    return 0
  fi
  WORKDIR_CLEANUP_DONE=1

  cleanup_owned_sessions "$trigger"

  if [[ "$E2E_KEEP_WORKDIR" == "1" ]]; then
    echo "[INFO] [$trigger] Keeping work directory: $WORK_DIR"
  else
    rm -rf "$WORK_DIR"
  fi
}

trap 'cleanup EXIT' EXIT
trap 'cleanup INT; exit 130' INT
trap 'cleanup TERM; exit 143' TERM

E2E_RUN_ID="$(python3 - <<'PY'
import uuid

print(f"e2e-{uuid.uuid4()}")
PY
)"
OWNERSHIP_TRACKING_FILE="$WORK_DIR/terminator_owned_sessions.json"

FIRMWARE_PATH="$WORK_DIR/fixture_firmware.bin"
RUNS_ROOT="$WORK_DIR/aiedge-runs"
export FIRMWARE_PATH
export RUNS_ROOT
export PYTHONPATH="$SCOUT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

python3 - <<'PY'
import os
import secrets
from pathlib import Path

firmware = Path(os.environ["FIRMWARE_PATH"])
firmware.write_bytes(f"SCOUT_E2E_FIRMWARE_FIXTURE_{secrets.token_hex(8)}\n".encode("utf-8"))
PY

latest_report_dir() {
  local latest
  latest="$(ls -td "$TERMINATOR_REPORT_ROOT"/20* 2>/dev/null | head -1 || true)"
  printf '%s' "$latest"
}

init_ownership_tracking() {
  python3 - <<'PY' "$OWNERSHIP_TRACKING_FILE" "$E2E_RUN_ID"
import json
import sys
from datetime import datetime, timezone

tracking_path = sys.argv[1]
e2e_run_id = sys.argv[2]

payload = {
    "schema_version": 1,
    "e2e_run_id": e2e_run_id,
    "created_at": datetime.now(timezone.utc).isoformat(),
    "owned_sessions": [],
}

with open(tracking_path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2)
    fh.write("\n")
PY
}

run_and_assert_exit_with_output() {
  local expected="$1"
  local output_var="$2"
  shift 2
  local rc
  local output
  set +e
  output="$("$@" 2>&1)"
  rc=$?
  set -e
  printf -v "$output_var" '%s' "$output"
  if [[ "$rc" -ne "$expected" ]]; then
    echo "[FAIL] Expected exit $expected, got $rc: $*" >&2
    if [[ -n "$output" ]]; then
      printf '%s\n' "$output" >&2
    fi
    exit 1
  fi
}

extract_terminator_pid() {
  local output="$1"
  local line
  local pid=""
  while IFS= read -r line; do
    if [[ "$line" =~ ^\[\*\]\ PID:\ ([0-9]+)$ ]]; then
      pid="${BASH_REMATCH[1]}"
      break
    fi
  done <<< "$output"

  if [[ -z "$pid" ]]; then
    echo "[FAIL] Could not parse Terminator PID from output" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi

  printf '%s' "$pid"
}

record_owned_session() {
  local terminator_bg_pid="$1"
  local report_dir="$2"
  python3 - <<'PY' "$OWNERSHIP_TRACKING_FILE" "$E2E_RUN_ID" "$terminator_bg_pid" "$report_dir"
import json
import sys

tracking_path = sys.argv[1]
e2e_run_id = sys.argv[2]
terminator_bg_pid = int(sys.argv[3])
report_dir = sys.argv[4]

with open(tracking_path, "r", encoding="utf-8") as fh:
    payload = json.load(fh)

if payload.get("e2e_run_id") != e2e_run_id:
    raise SystemExit("ownership tracking e2e_run_id mismatch")

owned_sessions = payload.setdefault("owned_sessions", [])
owned_sessions.append(
    {
        "e2e_run_id": e2e_run_id,
        "terminator_bg_pid": terminator_bg_pid,
        "report_dir": report_dir,
    }
)

with open(tracking_path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2)
    fh.write("\n")
PY
}

trigger_self_interrupt_if_requested() {
  if [[ -z "$E2E_SELF_INTERRUPT" || "$E2E_SELF_INTERRUPT_TRIGGERED" -eq 1 ]]; then
    return 0
  fi

  E2E_SELF_INTERRUPT_TRIGGERED=1
  echo "[INFO] Triggering self interrupt via SIG$E2E_SELF_INTERRUPT"
  kill "-$E2E_SELF_INTERRUPT" "$$"
}

assert_exit_code() {
  local expected="$1"
  shift
  local rc
  if "$@"; then
    rc=0
  else
    rc=$?
  fi
  if [[ "$rc" -ne "$expected" ]]; then
    echo "[FAIL] Expected exit $expected, got $rc: $*" >&2
    exit 1
  fi
}

init_ownership_tracking
echo "[INFO] Ownership tracking file: $OWNERSHIP_TRACKING_FILE"

echo "[CHECK] AIEdge subset execution and attempt history"
python3 - <<'PY'
import json
import os
from pathlib import Path

from aiedge.run import create_run, run_subset
from aiedge.schema import validate_report

firmware_path = os.environ["FIRMWARE_PATH"]
runs_root = Path(os.environ["RUNS_ROOT"])

info = create_run(
    firmware_path,
    case_id="e2e-stage-control",
    ack_authorization=True,
    runs_root=runs_root,
)

_ = run_subset(info, ["tooling"], time_budget_s=120, no_llm=True)

stage_manifest = info.run_dir / "stages" / "tooling" / "stage.json"
if not stage_manifest.is_file():
    raise SystemExit(f"missing stage manifest: {stage_manifest}")

unexpected_manifest = info.run_dir / "stages" / "inventory" / "stage.json"
if unexpected_manifest.exists():
    raise SystemExit(f"unexpected non-selected stage manifest: {unexpected_manifest}")

stage_names = sorted(
    p.name for p in (info.run_dir / "stages").iterdir() if p.is_dir()
)
if stage_names != ["tooling"]:
    raise SystemExit(f"subset run executed unexpected stages: {stage_names}")

_ = run_subset(info, ["tooling"], time_budget_s=120, no_llm=True)

attempt1 = info.run_dir / "stages" / "tooling" / "attempts" / "attempt-1" / "stage.json"
attempt2 = info.run_dir / "stages" / "tooling" / "attempts" / "attempt-2" / "stage.json"
if not attempt1.is_file() or not attempt2.is_file():
    raise SystemExit("expected attempt-1 and attempt-2 manifests")

report_path = info.run_dir / "report" / "report.json"
report_obj = json.loads(report_path.read_text(encoding="utf-8"))
errors = validate_report(report_obj)
if errors:
    raise SystemExit("report schema errors: " + " | ".join(errors))

completion = report_obj.get("run_completion")
if not isinstance(completion, dict):
    raise SystemExit("report missing run_completion object")
if completion.get("is_final") is not False or completion.get("is_partial") is not True:
    raise SystemExit("subset report must be non-final (run_completion)")

completeness = report_obj.get("report_completeness")
if not isinstance(completeness, dict):
    raise SystemExit("report missing report_completeness object")
if completeness.get("gate_passed") is not False:
    raise SystemExit("subset report must fail completeness gate")

print(f"[OK] AIEdge run_dir: {info.run_dir}")
PY

echo "[CHECK] Terminator firmware mode without authorization"
assert_exit_code 1 env -i PATH="$PATH" HOME="$HOME" \
  "$TERMINATOR_PATH" firmware "$FIRMWARE_PATH"

sleep 1

echo "[CHECK] Terminator firmware analysis profile with authorization"
before_analysis="$(latest_report_dir)"
analysis_output=""
run_and_assert_exit_with_output 0 analysis_output env -i PATH="$PATH" HOME="$HOME" \
  TERMINATOR_ACK_AUTHORIZATION=1 \
  TERMINATOR_MODEL=haiku \
  "$TERMINATOR_PATH" firmware "$FIRMWARE_PATH"
after_analysis="$(latest_report_dir)"
analysis_pid="$(extract_terminator_pid "$analysis_output")"
if [[ -z "$after_analysis" ]]; then
  echo "[FAIL] No report directory found after analysis profile run" >&2
  exit 1
fi
if [[ "$after_analysis" == "$before_analysis" ]]; then
  echo "[FAIL] Could not detect new report directory for analysis profile run" >&2
  exit 1
fi
record_owned_session "$analysis_pid" "$after_analysis"
trigger_self_interrupt_if_requested
analysis_handoff="$after_analysis/firmware_handoff.json"
if [[ ! -f "$analysis_handoff" ]]; then
  echo "[FAIL] Missing analysis firmware handoff: $analysis_handoff" >&2
  exit 1
fi
ANALYSIS_HANDOFF="$analysis_handoff" python3 - <<'PY'
import json
import os
from pathlib import Path

from aiedge.schema import validate_report


def assert_bundle_artifacts_exist(handoff_obj: dict, run_dir: Path) -> None:
    bundles = handoff_obj.get("bundles")
    if not isinstance(bundles, list) or not bundles:
        raise SystemExit("analysis handoff missing non-empty bundles")

    run_dir_resolved = run_dir.resolve()
    for idx, bundle in enumerate(bundles, start=1):
        if not isinstance(bundle, dict):
            raise SystemExit(f"bundle #{idx} is not an object")
        artifacts = bundle.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise SystemExit(f"bundle #{idx} missing non-empty artifacts")
        for artifact in artifacts:
            if not isinstance(artifact, str) or not artifact.strip():
                raise SystemExit(f"bundle #{idx} contains invalid artifact path")
            rel_path = Path(artifact)
            if rel_path.is_absolute():
                raise SystemExit(f"bundle #{idx} artifact must be run-relative: {artifact}")
            artifact_path = (run_dir / rel_path).resolve()
            try:
                artifact_path.relative_to(run_dir_resolved)
            except ValueError as exc:
                raise SystemExit(f"bundle #{idx} artifact escapes run_dir: {artifact}") from exc
            if not artifact_path.exists():
                raise SystemExit(f"bundle #{idx} artifact missing under run_dir: {artifact}")

handoff_path = os.environ["ANALYSIS_HANDOFF"]
obj = json.loads(open(handoff_path, encoding="utf-8").read())
if obj.get("profile") != "analysis":
    raise SystemExit("analysis handoff profile mismatch")
policy = obj.get("policy")
if not isinstance(policy, dict):
    raise SystemExit("analysis handoff missing policy")
for key in ("max_reruns_per_stage", "max_total_stage_attempts", "max_wallclock_per_run"):
    if key not in policy:
        raise SystemExit(f"analysis policy missing key: {key}")

aiedge = obj.get("aiedge")
if not isinstance(aiedge, dict):
    raise SystemExit("analysis handoff missing aiedge")

run_dir_raw = aiedge.get("run_dir")
if not isinstance(run_dir_raw, str) or not run_dir_raw.strip():
    raise SystemExit("analysis handoff missing non-empty aiedge.run_dir")
run_dir = Path(run_dir_raw)
if not run_dir.is_dir():
    raise SystemExit(f"analysis handoff aiedge.run_dir is not a directory: {run_dir}")

run_id = aiedge.get("run_id")
if not isinstance(run_id, str):
    raise SystemExit("analysis handoff aiedge.run_id must be a string")
if not run_id.strip():
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.is_file():
        raise SystemExit("analysis handoff missing non-empty aiedge.run_id and manifest.json")
    manifest_obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_run_id = manifest_obj.get("run_id")
    if not isinstance(manifest_run_id, str) or not manifest_run_id.strip():
        raise SystemExit("analysis handoff/manifest missing non-empty run_id")
    run_id = manifest_run_id

assert_bundle_artifacts_exist(obj, run_dir)

report_path = run_dir / "report" / "report.json"
if not report_path.is_file():
    raise SystemExit(f"analysis run missing report file: {report_path}")
report_obj = json.loads(report_path.read_text(encoding="utf-8"))
errors = validate_report(report_obj)
if errors:
    raise SystemExit("analysis run report schema errors: " + " | ".join(errors))

print(f"[OK] analysis handoff aiedge run verified: {run_dir}")
PY

analysis_bundle_count_before="$(python3 - <<'PY' "$analysis_handoff"
import json
import sys

handoff_path = sys.argv[1]
obj = json.loads(open(handoff_path, encoding="utf-8").read())
bundles = obj.get("bundles")
if not isinstance(bundles, list):
    raise SystemExit("analysis handoff bundles must be a list")
print(len(bundles))
PY
)"

analysis_run_dir="$(python3 - <<'PY' "$analysis_handoff"
import json
import sys

handoff_path = sys.argv[1]
obj = json.loads(open(handoff_path, encoding="utf-8").read())
run_dir = obj.get("aiedge", {}).get("run_dir")
if not isinstance(run_dir, str) or not run_dir.strip():
    raise SystemExit("analysis handoff missing non-empty aiedge.run_dir")
print(run_dir)
PY
)"

set +e
python3 /home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/aiedge_handoff_adapter.py stages --handoff "$analysis_handoff" --stages tooling --log-file "$after_analysis/session.log"
adapter_rc=$?
set -e
if [[ "$adapter_rc" -ne 0 && "$adapter_rc" -ne 10 ]]; then
  echo "[FAIL] Adapter rerun returned unexpected exit code: $adapter_rc" >&2
  exit 1
fi

analysis_attempt2="$analysis_run_dir/stages/tooling/attempts/attempt-2/stage.json"
if [[ ! -f "$analysis_attempt2" ]]; then
  echo "[FAIL] Adapter rerun did not produce attempt-2: $analysis_attempt2" >&2
  exit 1
fi

analysis_bundle_count_after="$(python3 - <<'PY' "$analysis_handoff"
import json
import sys

handoff_path = sys.argv[1]
obj = json.loads(open(handoff_path, encoding="utf-8").read())
bundles = obj.get("bundles")
if not isinstance(bundles, list):
    raise SystemExit("analysis handoff bundles must be a list")
print(len(bundles))
PY
)"

if (( analysis_bundle_count_after <= analysis_bundle_count_before )); then
  echo "[FAIL] Adapter rerun did not increase bundle count ($analysis_bundle_count_before -> $analysis_bundle_count_after)" >&2
  exit 1
fi

echo "[OK] Adapter rerun accepted (exit=$adapter_rc) and increased bundles ($analysis_bundle_count_before -> $analysis_bundle_count_after)"

sleep 1

echo "[CHECK] Terminator firmware exploit profile missing gate variables"
assert_exit_code 1 env -i PATH="$PATH" HOME="$HOME" \
  TERMINATOR_ACK_AUTHORIZATION=1 \
  TERMINATOR_FIRMWARE_PROFILE=exploit \
  TERMINATOR_MODEL=haiku \
  "$TERMINATOR_PATH" firmware "$FIRMWARE_PATH"

sleep 1

echo "[CHECK] Terminator firmware exploit profile with full gate variables"
before_exploit="$(latest_report_dir)"
exploit_output=""
run_and_assert_exit_with_output 0 exploit_output env -i PATH="$PATH" HOME="$HOME" \
  TERMINATOR_ACK_AUTHORIZATION=1 \
  TERMINATOR_FIRMWARE_PROFILE=exploit \
  TERMINATOR_EXPLOIT_FLAG=LAB-ONLY \
  TERMINATOR_EXPLOIT_ATTESTATION=authorized-lab-run \
  TERMINATOR_EXPLOIT_SCOPE=test-scope \
  TERMINATOR_MODEL=haiku \
  "$TERMINATOR_PATH" firmware "$FIRMWARE_PATH"
after_exploit="$(latest_report_dir)"
exploit_pid="$(extract_terminator_pid "$exploit_output")"
if [[ -z "$after_exploit" ]]; then
  echo "[FAIL] No report directory found after exploit profile run" >&2
  exit 1
fi
if [[ "$after_exploit" == "$before_exploit" ]]; then
  echo "[FAIL] Could not detect new report directory for exploit profile run" >&2
  exit 1
fi
record_owned_session "$exploit_pid" "$after_exploit"
exploit_handoff="$after_exploit/firmware_handoff.json"
if [[ ! -f "$exploit_handoff" ]]; then
  echo "[FAIL] Missing exploit firmware handoff: $exploit_handoff" >&2
  exit 1
fi
EXPLOIT_HANDOFF="$exploit_handoff" python3 - <<'PY'
import json
import os
from pathlib import Path


def assert_bundle_artifacts_exist(handoff_obj: dict, run_dir: Path) -> None:
    bundles = handoff_obj.get("bundles")
    if not isinstance(bundles, list) or not bundles:
        raise SystemExit("exploit handoff missing non-empty bundles")

    run_dir_resolved = run_dir.resolve()
    for idx, bundle in enumerate(bundles, start=1):
        if not isinstance(bundle, dict):
            raise SystemExit(f"bundle #{idx} is not an object")
        artifacts = bundle.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise SystemExit(f"bundle #{idx} missing non-empty artifacts")
        for artifact in artifacts:
            if not isinstance(artifact, str) or not artifact.strip():
                raise SystemExit(f"bundle #{idx} contains invalid artifact path")
            rel_path = Path(artifact)
            if rel_path.is_absolute():
                raise SystemExit(f"bundle #{idx} artifact must be run-relative: {artifact}")
            artifact_path = (run_dir / rel_path).resolve()
            try:
                artifact_path.relative_to(run_dir_resolved)
            except ValueError as exc:
                raise SystemExit(f"bundle #{idx} artifact escapes run_dir: {artifact}") from exc
            if not artifact_path.exists():
                raise SystemExit(f"bundle #{idx} artifact missing under run_dir: {artifact}")

handoff_path = os.environ["EXPLOIT_HANDOFF"]
obj = json.loads(open(handoff_path, encoding="utf-8").read())
if obj.get("profile") != "exploit":
    raise SystemExit("exploit handoff profile mismatch")
gate = obj.get("exploit_gate")
if not isinstance(gate, dict):
    raise SystemExit("exploit handoff missing exploit_gate")
if gate.get("flag") != "LAB-ONLY":
    raise SystemExit("exploit gate flag mismatch")
if gate.get("attestation") != "authorized-lab-run":
    raise SystemExit("exploit gate attestation mismatch")
if gate.get("scope") != "test-scope":
    raise SystemExit("exploit gate scope mismatch")

aiedge = obj.get("aiedge")
if not isinstance(aiedge, dict):
    raise SystemExit("exploit handoff missing aiedge")

run_dir_raw = aiedge.get("run_dir")
if not isinstance(run_dir_raw, str) or not run_dir_raw.strip():
    raise SystemExit("exploit handoff missing non-empty aiedge.run_dir")
run_dir = Path(run_dir_raw)
if not run_dir.is_dir():
    raise SystemExit(f"exploit handoff aiedge.run_dir is not a directory: {run_dir}")

assert_bundle_artifacts_exist(obj, run_dir)

print(f"[OK] exploit handoff aiedge artifacts verified: {run_dir}")
PY

echo "[OK] Owned Terminator sessions tracked in: $OWNERSHIP_TRACKING_FILE"
cleanup NORMAL
echo "[PASS] e2e terminator/aiedge stage-control checks completed"
