# analyst_digest-v1 Contract

This document defines the strict JSON contract for `report/analyst_digest.json`.

Design constraints:
- The digest is computed, not narrated.
- The digest must not add claims outside verifier outputs and structured evidence.
- All artifact references must be run-relative paths (no absolute paths).
- Missing, partial, or tampered evidence must fail closed.

## Schema Version

- `schema_version` (required): exact string `analyst_digest-v1`

## Required Top-Level Fields

- `schema_version`: string, exact value `analyst_digest-v1`
- `run`: object
- `top_risk_summary`: object
- `finding_verdicts`: array of objects
- `exploitability_verdict`: object
- `evidence_index`: array of objects
- `next_actions`: array of non-empty strings

Unknown top-level keys are invalid.

## Field Contract

### `run` (required)

- `run_id` (required): non-empty string
- `firmware_sha256` (required): lowercase hex string, length 64
- `generated_at` (required): non-empty string timestamp

### `top_risk_summary` (required)

- `total_findings` (required): integer >= 0
- `severity_counts` (required): object with all keys present:
  - `critical`, `high`, `medium`, `low`, `info`
  - each value is integer >= 0

### `finding_verdicts` (required)

Each entry contains machine-derived status for one finding:

- `finding_id` (required): non-empty string
- `verdict` (required): enum
  - `VERIFIED`
  - `ATTEMPTED_INCONCLUSIVE`
  - `NOT_ATTEMPTED`
  - `NOT_APPLICABLE`
- `reason_codes` (required): non-empty array of reason-code enum values
- `evidence_refs` (required): non-empty array of run-relative paths
- `verifier_refs` (required): non-empty array of run-relative paths

### `exploitability_verdict` (required)

- `state` (required): same enum as `finding_verdicts[].verdict`
- `reason_codes` (required): non-empty array of reason-code enum values
- `aggregation_rule` (required): exact string `worst_state_precedence_v1`

### `evidence_index` (required)

Each entry:

- `ref` (required): run-relative path
- `sha256` (required): lowercase hex string, length 64

### `next_actions` (required)

- Array of non-empty strings.
- Recommended actions only; no new exploitability claims.

## Verdict Enum

Exact verdict values:

- `VERIFIED`
- `ATTEMPTED_INCONCLUSIVE`
- `NOT_ATTEMPTED`
- `NOT_APPLICABLE`

`NOT_APPLICABLE` must only be used with explicit machine-checkable reason codes and must not be used to bypass failed or missing proof gates.

## Deterministic Reason Codes

Allowed reason codes:

- `VERIFIED_ALL_GATES_PASSED`
- `VERIFIED_REPRO_3_OF_3`
- `ATTEMPTED_EVIDENCE_TAMPERED`
- `ATTEMPTED_VERIFIER_FAILED`
- `ATTEMPTED_REPRO_INSUFFICIENT`
- `ATTEMPTED_EVIDENCE_INCOMPLETE`
- `NOT_ATTEMPTED_REQUIRED_VERIFIER_MISSING`
- `NOT_ATTEMPTED_DYNAMIC_VALIDATION_MISSING`
- `NOT_ATTEMPTED_RUN_INCOMPLETE`
- `NOT_APPLICABLE_NO_RELEVANT_FINDINGS`
- `NOT_APPLICABLE_PLATFORM_UNSUPPORTED`

Reason-code precedence (high to low, deterministic ordering):

1. `ATTEMPTED_EVIDENCE_TAMPERED`
2. `ATTEMPTED_VERIFIER_FAILED`
3. `ATTEMPTED_REPRO_INSUFFICIENT`
4. `ATTEMPTED_EVIDENCE_INCOMPLETE`
5. `NOT_ATTEMPTED_REQUIRED_VERIFIER_MISSING`
6. `NOT_ATTEMPTED_DYNAMIC_VALIDATION_MISSING`
7. `NOT_ATTEMPTED_RUN_INCOMPLETE`
8. `NOT_APPLICABLE_NO_RELEVANT_FINDINGS`
9. `NOT_APPLICABLE_PLATFORM_UNSUPPORTED`
10. `VERIFIED_ALL_GATES_PASSED`
11. `VERIFIED_REPRO_3_OF_3`

`reason_codes` arrays must be unique and sorted by this precedence.

## Multi-Finding Aggregation Rule

Aggregation rule ID: `worst_state_precedence_v1`

State precedence (worst to best):

1. `ATTEMPTED_INCONCLUSIVE`
2. `NOT_ATTEMPTED`
3. `VERIFIED`
4. `NOT_APPLICABLE`

Digest `exploitability_verdict.state` is selected as the highest-priority state present across `finding_verdicts[].verdict`.

Deterministic tie behavior:

- If multiple findings share the selected state, `exploitability_verdict.reason_codes` is the set-union of reason codes from findings in that state, sorted by reason precedence.
- If `finding_verdicts` is empty, state must be `NOT_APPLICABLE` with reason `NOT_APPLICABLE_NO_RELEVANT_FINDINGS`.

## Provenance and Claim Boundary

- Digest fields are derived only from structured evidence artifacts and verifier outputs.
- Digest must not add freeform exploitability claims.
- Any referenced artifact path must remain run-relative.
