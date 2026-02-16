# AIEdge Duplicate Gate Contract (Phase 1)

This document defines the fingerprint contract, duplicate taxonomy, and registry schema used for cross-run dedupe of claims/findings.

## Scope

- Phase 1 scope is claim-level duplicate decisions only.
- Cross-run registry behavior is not implemented in this task.
- Existing evidence requirements and report gate semantics remain unchanged.

## Fingerprint Contract

- `fingerprint_version`: `"claim-fp-v1"`.
- Hash algorithm: SHA-256 lowercase hex digest.
- Preimage envelope (canonical JSON):
  - `fingerprint_version` (string)
  - `claim` (canonicalized object)

Canonicalization rules for `claim-fp-v1`:

- Deterministic object normalization:
  - Keys are sorted lexicographically.
  - Non-string keys are stringified.
  - Excluded volatile keys are removed.
- Deterministic list normalization:
  - Each item is recursively normalized.
  - Normalized list is sorted by canonical JSON text of each item.
- Float normalization:
  - Round to 6 decimals (matches `src/aiedge/determinism.py`).
- JSON serialization:
  - `sort_keys=true`
  - `separators=(",", ":")`
  - `ensure_ascii=true` (ASCII-only preimage)
- Excluded volatile/non-portable fields (minimum set):
  - Timestamps and run/session identifiers: `created_at`, `updated_at`, `started_at`, `finished_at`, `timestamp`, `run_id`, `stage_run_id`, `trace_id`, `session_id`
  - Run-variant paths and path lists: `path`, `paths`, `evidence_ref`, `evidence_refs`, `evidence_path`, `evidence_paths`, `file`, `files`
  - Raw binary payload fields: `blob`, `blobs`, `raw_blob`, `raw_blobs`, `binary`, `binary_blob`, `raw_bytes`
  - Any key ending with `_at`, `_ts`, `_timestamp`, `_path`, `_paths`, `_blob`, `_bytes`

Reference implementation for this contract lives in `src/aiedge/fingerprinting.py`.

## Duplicate Taxonomy (Phase 1)

Taxonomy version: `duplicate-taxonomy-v1`

### 1) `exact_fingerprint_duplicate`

Machine-checkable rule:

- Input: `current_claim`, `existing_registry_record`
- Compute `fp_current = sha256(canonical_preimage(current_claim, claim-fp-v1))`
- Compare against `existing_registry_record.fingerprint`
- Classify as `exact_fingerprint_duplicate` iff all conditions are true:
  - `existing_registry_record.fingerprint_version == "claim-fp-v1"`
  - `existing_registry_record.fingerprint == fp_current`

### 2) `near_duplicate` (defined only; not implemented in Phase 1)

Machine-checkable placeholder rule:

- Classify as `near_duplicate` only when a future near-match scorer emits:
  - `near_duplicate_score` in `[0.0, 1.0]`
  - `near_duplicate_score >= near_duplicate_threshold`
  - `fp_current != existing_registry_record.fingerprint`
- Phase 1 behavior: always `not_evaluated`.

### 3) `context_changed_reopen`

Machine-checkable rule:

- Let `fp_current` be exact-match equal to an existing fingerprint.
- Let `ctx_current` and `ctx_last_seen` be deterministic context digests (future Task 3 novelty context payload).
- Classify as `context_changed_reopen` iff:
  - exact fingerprint match is true, and
  - `ctx_current != ctx_last_seen`
- Operational semantics: force retriage even though claim fingerprint is unchanged.

Phase 1 note: taxonomy is defined now; context digest production and reopen automation are implemented later.

## Registry JSON Schema Contract (for Task 2)

Schema version: `duplicate-registry-v1`

Top-level fields:

- `schema_version` (required, const `duplicate-registry-v1`)
- `created_at` (required, RFC3339 date-time)
- `records` (required object keyed by fingerprint)

Record object fields (minimum audit set):

- `fingerprint` (required, 64-char lowercase hex SHA-256)
- `fingerprint_version` (required, const `claim-fp-v1`)
- `first_seen_run_id` (required)
- `last_seen_at` (required, RFC3339 date-time)
- `sources` (required, non-empty array)
  - each source includes at minimum `run_id`
  - optional `finding_id`, `claim_path`
- `last_classification` (optional enum):
  - `exact_fingerprint_duplicate`
  - `near_duplicate`
  - `context_changed_reopen`

The reference JSON Schema object is exported as `DUPLICATE_REGISTRY_JSON_SCHEMA` from `src/aiedge/fingerprinting.py`.

## Bounded Growth Strategy (document-only)

Phase 2+ implementation should enforce bounded storage while preserving auditability:

- Keep one primary record per fingerprint key (no key fan-out).
- Keep `sources` as capped history (for example most recent N entries).
- Periodically compact stale records using retention policy windows.
- Preserve aggregate counters and first-seen metadata before compaction.
- Run compaction deterministically (stable key order, deterministic cutoff criteria).
