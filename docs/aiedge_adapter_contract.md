# AIEdge Stage Adapter Contract (JSON-first)

Contract goal: let an external orchestrator (e.g., Terminator) request AIEdge stage execution/re-execution using a stable JSON request/response format. This contract is intentionally JSON-first; logs are not an API.

## Versioning

- `contract_version`: semantic-ish string (start with `"1"`).
- Backward-compatibility rule: add fields as optional; never repurpose existing fields.

## Concepts

### run_ref

- `run_ref.run_id`: orchestrator-chosen identifier for correlation.
- `run_ref.run_dir_abs`: absolute path to the AIEdge run directory (executor-owned evidence store).

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

## Example request/response

See:

- `docs/aiedge_stage_request.json`
- `docs/aiedge_stage_response.json`
