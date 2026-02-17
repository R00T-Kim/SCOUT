# AIEdge Report Contract (report/report.json)

This document describes the machine-consumable report fields that gate whether results are safe to consume.

## Required Semantics

- `run_completion`:
  - `is_final`: `true` only for full, finalized runs.
  - `is_partial`: `true` for subset runs and other non-final outputs.
  - `required_stage_statuses`: must include `tooling`, `extraction`, `inventory`, `findings`.

- `ingestion_integrity`:
  - `source_input`: metadata for the user-provided input path.
  - `analyzed_input`: metadata for the copied bytes analyzed under `input/firmware.bin`.
  - `overview_link`: booleans asserting `overview` metadata matches analyzed input.

- `report_completeness`:
  - `gate_passed`: `true` only when required stage inputs are present and stage status invariants are satisfied.
  - When `gate_passed=false`, consumers must treat findings as provisional and avoid "no issues" conclusions.

## Final Report Verifier

- Scope note: this verifier is canonical 8MB-only (requires `manifest.track.track_id="8mb"`). ER-e50 `analysis` manifests omit `manifest.track`, so this verifier will fail on ER-e50 `analysis` runs by design.

- `scripts/verify_aiedge_final_report.py --run-dir <run_dir>` validates finalized report contract invariants for the canonical 8MB track.
- It asserts:
  - `report.report_completeness.gate_passed=true`
  - `report.run_completion.is_final=true`
  - `report.run_completion.conclusion_ready=true`
  - `report.run_completion.required_stage_statuses.findings != "pending"`
  - `manifest.track.track_id="8mb"`, matching canonical SHA-256 prefix and size
  - `manifest` input/analyzed/source SHA-256 and byte-size fields all match canonical 8MB values
  - `report.duplicate_gate` is required and must include:
    - `taxonomy_version="duplicate-taxonomy-v1"`
    - `artifact` as a run-relative existing path (canonical output: `report/duplicate_gate.json`)
  - the referenced duplicate artifact must load as JSON with:
    - `schema_version="duplicate-gate-v1"`
    - `novelty` and `ranked` keys present as lists
  - Duplicate gate is triage metadata only; it MUST NOT suppress or remove items from top-level `report.findings`.
  - `report.duplicate_gate` provides novelty/suppression metadata; it does not remove items from `report.findings`.
  - `report.firmware_lineage` is required and must include:
    - `details.lineage` and `details.lineage_diff` as run-relative existing paths
    - referenced lineage JSON artifacts with `schema_version=1`

## Analyst Report Verifier

- ER-e50 `analysis` operator gates (fail-closed) are:

```bash
python3 scripts/verify_analyst_digest.py --run-dir <run_dir>
python3 scripts/verify_aiedge_analyst_report.py --run-dir <run_dir>
```

- `scripts/verify_aiedge_analyst_report.py --run-dir <run_dir>` is fail-closed for `CONTRACT_ANALYST` in release governance.
- Required stage artifacts include:
  - findings artifacts are emitted by `run_findings()` (integrated step), so `stages/findings/stage.json` is not expected
  - `stages/findings/pattern_scan.json` with `schema_version="pattern-scan-v1"`
  - `stages/findings/binary_strings_hits.json` with `schema_version="binary-strings-hits-v1"`
- For all stage artifacts checked by the verifier:
  - any JSON string value that looks like an absolute path (`/`-prefixed or `^[A-Za-z]:\\`) is rejected
  - `evidence_refs` must remain run-relative and resolve under the run directory

## Analyst Digest Verifier (Digest-First Entry)

- Canonical digest artifacts:
  - `report/analyst_digest.json`
  - `report/analyst_digest.md`
- Contract reference: `docs/analyst_digest_contract.md` (`analyst_digest-v1`).
- Verifier command (fail-closed):

```bash
python3 scripts/verify_analyst_digest.py --run-dir <run_dir>
```

- Operator interpretation:
  - Digest is the first analyst entrypoint, not a replacement for proof gates.
  - `VERIFIED` must be backed by successful digest verification and successful verified-chain verifier checks.
  - Any digest/verifier mismatch or missing artifact must be treated as non-verified.

Compatibility note:

- This digest contract supplements analyst/operator flow and does not change final report contract semantics under `report/report.json`.

## Profiles (Analysis vs Exploit)

- `manifest.json.profile`:
  - `analysis`: default
  - `exploit`: authorized/lab only; requires gate fields
- `manifest.json.exploit_gate` (required when `profile="exploit"`):
  - `flag`, `attestation`, `scope`

Executor behavior:
- Exploit-related stages MUST be skipped when `profile!=exploit`.
- Exploit-related stages MUST fail when `profile=exploit` but `exploit_gate` fields are missing.
- Exploit profile evidence MUST include `stages/exploit_chain/milestones.json` with deterministic `canonical_input` binding and `exploit_gate` metadata when available.

## Findings Evidence

- Findings policy (locked): top-level `report/report.json` `findings` MUST include `info` severity items (no severity-based suppression at report aggregation).

- Each finding MUST include a non-empty `evidence[]` list.
- Each evidence entry MUST include a run-relative `path`.
- If an evidence entry includes `snippet`, it SHOULD include `snippet_sha256` and MUST avoid raw secret disclosure.

## Audit Package Contract

The operator handoff package is valid only when these artifacts and keys are present and consistent:

- `manifest.json`
  - required key: `ref_md_sha256` (non-empty string)
- `report/report.json`
  - required key: `overview.ref_md_sha256` (non-empty string)
  - invariant: must equal `manifest.ref_md_sha256`
- `metrics.json`
  - required key: `corpus_id` (non-empty string)
- `quality_gate.json`
  - required key: `verdict` (`pass` or `fail`)

Validation entrypoint:

```bash
python3 scripts/audit_package_validate.py --run-dir <run-dir>
```

Deterministic summary output fields:

- `corpus_id`: copied from `metrics.json.corpus_id`
- `ref_md_sha256`: copied from `manifest.json.ref_md_sha256`
- `metrics_verdict`: copied from `quality_gate.json.verdict`
- `commit_sha`: best-effort commit identifier (`GITHUB_SHA`/`CI_COMMIT_SHA`/`git rev-parse HEAD` when available)

The validator is fail-closed: any missing/invalid artifact or required key sets `ok=false`, emits stable `errors[]`, and exits non-zero.

## LLM-Primary Quality Gate Contract

When release governance runs `release-quality-gate`, LLM-primary policy is enabled by default. `quality_gate.json` must be interpreted with these LLM-related fields:

- `policy.llm_primary`: `true` when LLM-primary checks were applied.
- `llm_gate_path`: provenance for LLM verdict input:
  - `report.llm` when verdict is derived from `report.llm.status` (`ok` -> `pass`, otherwise `fail`)
  - fixture path when `--llm-fixture <path>` is provided
- `errors[].error_token`: fail-closed LLM token set includes:
  - `QUALITY_GATE_LLM_REQUIRED`: no usable LLM payload for an llm-primary run (for CLI, typically missing `--report`)
  - `QUALITY_GATE_LLM_INVALID`: LLM payload exists but verdict is not `pass` or `fail`
  - `QUALITY_GATE_LLM_VERDICT_MISS`: LLM verdict missing or resolved verdict is `fail`

Operator note:

- `scripts/release_gate.sh` forwards `--llm-fixture` when provided and always executes quality policy with `--llm-primary`; failures above surface through `QUALITY_POLICY` gate logs and `quality_gate.json.errors[]`.

## Duplicate Gate + Lineage Governance

- For canonical finalized 8MB runs, release governance now requires both `report.duplicate_gate` and `report.firmware_lineage` fields as described in the final verifier section.
- Placeholder/optional semantics no longer apply for canonical final contract validation.
