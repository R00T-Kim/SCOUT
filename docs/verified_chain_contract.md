# verified_chain Contract (v1)

This document defines the machine-verifiable contract for:

- `verified_chain/verified_chain.json`

Validation entrypoint:

- `python3 scripts/verify_verified_chain.py --run-dir <RUN_DIR>`

## Required Run Layout

The verifier fails closed if any required directory is missing.

- `verified_chain/verified_chain.json`
- `stages/dynamic_validation/`
- `exploits/`

All linked paths must be run-relative and must resolve inside `run_dir`.

## Contract Shape

`verified_chain/verified_chain.json` must contain:

- `schema_version`: `"verified-chain-v1"`
- `generated_at`: ISO8601 timestamp
- `run_id`: non-empty string
- `firmware`: object
  - `sha256`: lowercase 64-hex digest
  - `profile`: non-empty string
- `tool_versions`: object
  - `firmae_commit`: non-empty string (placeholder allowed)
  - `firmae_version`: non-empty string (placeholder allowed)
  - `tcpdump`: non-empty string
  - `iproute2`: non-empty string
- `timestamps`: object
  - `started_at`: ISO8601 timestamp
  - `finished_at`: ISO8601 timestamp
- `dynamic_validation`: object
  - `bundle_dir`: run-relative directory path (normally `stages/dynamic_validation`)
  - `isolation_verified`: bool
  - `evidence_refs`: non-empty run-relative path list
- `verdict`: object
  - `state`: `pass|fail|inconclusive`
  - `reason_codes`: non-empty machine-checkable reason code list
  - `evidence_refs`: non-empty run-relative path list
- `attempts`: non-empty list of attempt objects
  - `attempt`: int
  - `status`: `pass|fail|inconclusive`
  - `bundle_dir`: run-relative directory path under `exploits/chain_<id>/`
  - `started_at`: ISO8601 timestamp
  - `finished_at`: ISO8601 timestamp
  - `evidence_refs`: non-empty run-relative path list
- `evidence_refs`: non-empty run-relative path list

## Verdict Semantics

Allowed reason codes:

- `repro_3_of_3`
- `isolation_verified`
- `poc_repro_failed`
- `isolation_violation`
- `boot_flaky`
- `boot_timeout`
- `missing_dynamic_bundle`
- `missing_exploit_bundle`
- `missing_required_artifact`
- `invalid_contract`

State rules:

- `pass`
  - must include `repro_3_of_3` and `isolation_verified`
  - must contain exactly 3 attempts
  - all 3 attempts must have `status == pass`
- `fail`
  - must include at least one fail-class reason code
- `inconclusive`
  - must include at least one inconclusive-class reason code

## Verifier Output Contract

Exit codes:

- `0`: contract and evidence links validate
- `1`: verification failed

Stdout line format:

- success: `[OK] verified_chain contract verified: <run_dir>`
- failure: `[FAIL] <reason_code>: <detail>`

Reason codes are deterministic and suitable for machine checks.
