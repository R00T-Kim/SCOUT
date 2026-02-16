# E2E Terminator-AIEdge Stage Control

This check script validates the stage-control path across AIEdge and Terminator firmware mode.

## Run

From SCOUT:

```bash
./scripts/e2e_terminator_aiedge_stage_control.sh
```

On success the script exits `0` and prints `[PASS]`.

Optional interrupt cleanup verification:

```bash
./scripts/e2e_terminator_aiedge_stage_control_interrupt.sh INT
./scripts/e2e_terminator_aiedge_stage_control_interrupt.sh TERM
```

Optional unrelated-session safety verification:

```bash
./scripts/e2e_terminator_aiedge_stage_control_preexisting_session.sh
```

## What It Checks

1. AIEdge subset execution:
   - Creates a run via `aiedge.run.create_run`.
   - Runs only `tooling` via `aiedge.run.run_subset`.
   - Verifies `stages/tooling/stage.json` exists and non-selected stage manifests are not created.
2. Attempt history:
   - Runs the same subset twice on the same run.
   - Verifies `stages/tooling/attempts/attempt-1/stage.json` and `attempt-2/stage.json` both exist.
3. Report schema:
    - Loads `report/report.json` and validates it with `aiedge.schema.validate_report`.
    - Requires an empty validation error list.
    - Asserts subset runs are non-final (`run_completion.is_final=false`) and completeness gate fails (`report_completeness.gate_passed=false`).
4. Terminator firmware profile gates:
     - Without `TERMINATOR_ACK_AUTHORIZATION=1`: expects exit `1`.
     - `analysis` profile with authorization: expects exit `0` and checks newest `reports/20*` has `firmware_handoff.json` containing `profile=analysis`, policy keys, non-empty `aiedge.run_dir`, non-empty `aiedge.run_id`, and non-empty `bundles[].artifacts` where each artifact exists under that run directory.
      - For the same analysis handoff `run_dir`, validates `report/report.json` through `aiedge.schema.validate_report`.
      - Ensures report contract gating fields exist (`run_completion`, `ingestion_integrity`, `report_completeness`).
      - Captures analysis `bundles` count, runs adapter rerun command `python3 /home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/aiedge_handoff_adapter.py stages --handoff "$analysis_handoff" --stages tooling --log-file "$after_analysis/session.log"`, accepts adapter exit `0` or `10`, requires `stages/tooling/attempts/attempt-2/stage.json`, and asserts `bundles` length increases.
     - `exploit` profile without required vars: expects exit `1`.
     - `exploit` profile with required vars: expects exit `0` and checks newest `reports/20*` has `firmware_handoff.json` with `profile=exploit`, `exploit_gate`, non-empty `aiedge.run_dir`, and `bundles[].artifacts` existing under that run directory.
5. Ownership tracking artifact:
     - Creates a unique per-run marker `e2e_run_id`.
     - Writes `$WORK_DIR/terminator_owned_sessions.json` as machine-readable ownership metadata for this E2E invocation only.
     - Tracks each owned Terminator firmware background launch with `e2e_run_id`, `terminator_bg_pid`, and `report_dir`.
     - Supports multiple sessions in one run via `owned_sessions[]` (for example, analysis + exploit checks).
6. Owned-session teardown guarantees:
     - On normal success path, cleanup runs before `[PASS]` and fails the E2E if any owned PID survives TERM/KILL escalation.
     - On signal path (`INT`/`TERM`), trap cleanup runs with the same survivor check and signal-specific exit code (`130`/`143`).
     - Cleanup is idempotent, uses PGID-first (`-$pid`) then PID fallback (`$pid`), and can preserve `$WORK_DIR` with `E2E_KEEP_WORKDIR=1`.
7. Self-interrupt mode:
      - `E2E_SELF_INTERRUPT=INT|TERM` triggers a self-signal right after the first owned session is recorded.
      - This enables deterministic interrupt-path testing without interactive input.
8. Unrelated-session safety mode:
      - `scripts/e2e_terminator_aiedge_stage_control_preexisting_session.sh` starts an extra Terminator firmware run before main E2E.
      - Verifies that preexisting PID stays alive after main E2E and then terminates that preexisting PID explicitly.

## Ownership Artifact Schema

Path: `$WORK_DIR/terminator_owned_sessions.json`

```json
{
  "schema_version": 1,
  "e2e_run_id": "e2e-<uuid>",
  "created_at": "<RFC3339 timestamp>",
  "owned_sessions": [
    {
      "e2e_run_id": "e2e-<uuid>",
      "terminator_bg_pid": 12345,
      "report_dir": "/home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/reports/20260101_010203"
    }
  ]
}
```

Semantics:
- `owned_sessions[]` lists only sessions created during the current E2E process.
- Cleanup/termination only targets PIDs listed in `owned_sessions[]` for the current E2E invocation.

## Environment Controls

- `E2E_KEEP_WORKDIR=1`: do not delete the temporary `$WORK_DIR` during cleanup.
- `E2E_SELF_INTERRUPT=INT|TERM`: trigger self-interrupt after first `record_owned_session`.

## Notes

- The script uses `set -euo pipefail`.
- It creates a temporary workspace with `mktemp -d` and cleans it with a trap.
- It does not wait for background Claude completion in Terminator firmware mode; it only verifies placeholder artifacts created at launch.
- `scripts/e2e_terminator_aiedge_stage_control_interrupt.sh` runs the self-interrupt path, verifies exit code and owned PID death, then removes the preserved workdir.
- `scripts/e2e_terminator_aiedge_stage_control_preexisting_session.sh` proves main E2E only cleans owned sessions and does not terminate unrelated preexisting Terminator firmware runs.
