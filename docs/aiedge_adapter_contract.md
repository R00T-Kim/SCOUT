# SCOUT Stage Adapter Contract (JSON-first)

Contract goal: let an external orchestrator (e.g., Terminator) request AIEdge stage execution/re-execution using a stable JSON request/response format. This contract is intentionally JSON-first; logs are not an API.

## Versioning

- `contract_version`: semantic-ish string (start with `"1"`).
- Backward-compatibility rule: add fields as optional; never repurpose existing fields.

## Concepts

### run_ref

- `run_ref.run_id`: orchestrator-chosen identifier for correlation.
- `run_ref.run_dir_abs`: absolute path to the AIEdge run directory (executor-owned evidence store).
- Optional: pre-extracted rootfs path may be supplied out-of-band and persisted as `manifest.rootfs_input_path` (CLI `--rootfs`) for extraction-stage ingestion.

### stage_names

- Ordered list of stage names to run.
- Stage name strings must be sanitized and map to an internal Stage factory.

Current stage keys include (non-exhaustive):
- `tooling`, `extraction`, `structure`, `carving`, `firmware_profile`, `inventory`, `emulation`
- OTA: `ota`, `ota_payload`, `ota_fs`, `ota_roots`, `ota_boottriage`
- Exploit (lab-gated, non-weaponized evidence): `exploit_gate`, `exploit_chain`, `exploit_policy`

### profile + exploit_gate

- `profile`:
  - `analysis`: default; run safe analysis stages.
  - `exploit`: authorized/lab only; enables exploit-chain stages.
- `exploit_gate` is REQUIRED when `profile="exploit"`.
  - `exploit_gate.flag`: run-local control token ("flag")
  - `exploit_gate.attestation`: statement that target/use is authorized
  - `exploit_gate.scope`: explicit scope (string)

### budgets

Budgets are enforced by the executor and recorded in per-stage manifests.

- `time_budget_s`: total wallclock budget for the request.
- `per_stage_timeout_s`: wallclock timeout applied per stage.
- `max_bytes_written`: approximate write budget for artifacts.

### idempotency_key

Optional key to dedupe repeated requests. If provided, the executor SHOULD avoid duplicating side effects and SHOULD record attempt metadata.

## Status values

Align with `src/aiedge/stage.py`:

- `ok`
- `partial`
- `failed`
- `skipped`

## Artifacts and hashing

- Response artifacts MUST reference run-relative paths and include a sha256 for integrity.
- Each executed stage MUST emit a per-stage manifest at:
  - `stages/<stage_name>/stage.json`

Minimum manifest fields:

- `contract_version`
- `stage_name`
- `stage_key` (hash of identity + inputs + params)
- `attempt` (int)
- `status`
- `limitations[]`
- `inputs[]` (paths + sha256)
- `artifacts[]` (paths + sha256)
- `started_at`, `finished_at`, `duration_s`

Inventory artifact compatibility note (backward-compatible):

- `stages/inventory/inventory.json` MAY include optional `errors[]` with structured recoverable scan/write failures.
- `stages/inventory/inventory.json` MAY include optional `coverage_metrics` counters describing partial/complete scan coverage.
- Consumers MUST treat both fields as optional and preserve compatibility when absent.

Firmware profile artifact compatibility note (backward-compatible):

- If `firmware_profile` executes, `stages/firmware_profile/firmware_profile.json` MAY be present as deterministic branch-planning evidence.
- Consumers MUST treat this artifact as optional and preserve compatibility when absent.

Optional exploit-chain evidence note (backward-compatible):

- When exploit-chain stages run, `stages/exploit_chain/milestones.json` MAY include:
  - `canonical_input` with `path`, `sha256`, and `sha256_source`
  - `exploit_gate` metadata captured for evidence provenance
- Consumers MUST treat these fields as optional and preserve compatibility when absent.

Firmware handoff compatibility note (backward-compatible):

- After `analyze` or `stages`, executors MAY emit `run_dir/firmware_handoff.json`.
- Consumers should treat it as optional but, when present, expect:
  - `profile`
  - `policy` (`max_reruns_per_stage`, `max_total_stage_attempts`, `max_wallclock_per_run`)
  - `aiedge.run_id`, `aiedge.run_dir`
  - non-empty `bundles[].artifacts` (run-relative paths)

## Terminator → SCOUT Feedback Protocol

### Feedback Registry Format

Terminator writes verdicts to `aiedge-feedback/registry.json` (or the path specified by `AIEDGE_FEEDBACK_DIR`):

```json
{
  "schema_version": "terminator-feedback-v1",
  "verdicts": [
    {
      "finding_fingerprint": "sha256:...",
      "verdict": "false_positive",
      "confidence_override": 0.15,
      "rationale": "String match was in test data",
      "original_run_id": "aiedge-run-20260315-...",
      "timestamp": "2026-03-16T00:00:00Z"
    }
  ]
}
```

Valid `verdict` values: `confirmed`, `false_positive`, `wont_fix`, `needs_info`.

### SCOUT Consumption

SCOUT reads feedback from `AIEDGE_FEEDBACK_DIR` env var (default: `aiedge-feedback/`).

Verdicts affect:
- **Finding scores:** `confirmed` boosts score (×1.15), `false_positive` suppresses (×0.5). `confidence_override` applies directly when present.
- **Duplicate gate novelty:** `confirmed` verdicts can reopen previously suppressed findings. `false_positive` verdicts reduce novelty score of similar new findings.
- **Candidate prioritization:** `wont_fix` sets priority to `"low"`.

### Feedback Request (SCOUT → Terminator)

`firmware_handoff.json` includes a `feedback_request` section with priority findings most in need of Terminator review:

```json
{
  "feedback_request": {
    "priority_findings": ["candidate-id-1", "candidate-id-2"],
    "expected_feedback_path": "aiedge-feedback/registry.json",
    "feedback_schema_version": "terminator-feedback-v1"
  }
}
```

Priority selection favours candidates with mid-range confidence (0.4–0.7) and chain-backed candidates without prior feedback.

## Example request/response

See:

- `docs/aiedge_stage_request.json`
- `docs/aiedge_stage_response.json`
