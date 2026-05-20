# SCOUT AEG E2E Validation Gate

SCOUT is AEG-first. A RAG/AutoPoC change is not considered platform-ready just because unit tests pass or a plugin is generated. The claim must be evaluated against an authorized lab run that proves exploitability and rejects false positives.

## Required E2E evidence

A passing AEG run must provide all of the following artifacts:

1. `stages/exploit_autopoc/exploit_autopoc.json`
   - `summary.runner_pass >= 1`
   - proves at least one lab runner attempt passed.
2. `stages/poc_validation/poc_validation.json`
   - `status == "ok"`
   - `verification_reason_codes` includes `repro_3_of_3`
   - proves generated/selected PoC evidence is reproducible, not only syntactically valid.
3. `verified_chain/verified_chain.json`
   - `verdict.state == "pass"`
   - `verdict.reason_codes` includes `isolation_verified`
   - proves the run stayed in an isolated authorized lab boundary.
4. `quality_metrics.json`
   - `overall.fpr <= 0.10` by default.
   - proves the broader run did not pass by accepting an excessive false-positive rate.
5. `stages/fp_verification/verified_alerts.json`
   - no high/critical alert used for the AEG claim may be marked `fp_verdict == "FP"`.

## Gate command

After a real lab run finishes:

```bash
python scripts/aeg_e2e_gate.py aiedge-runs/<run_id> --out aiedge-runs/<run_id>/aeg_e2e_gate.json
```

The script exits `0` only when every dynamic proof and FP/FPR check passes. It exits `31` on fail-closed evidence gaps.

## Real-run workflow

```bash
# 1. Analyze an authorized lab firmware target under exploit profile.
./scout analyze firmware.bin --profile exploit

# 2. Run/continue the exploit DAG stages under lab-only authorization.
./scout stages aiedge-runs/<run_id> --stages exploit_autopoc,poc_validation,exploit_policy

# 3. Build and verify the final dynamic evidence chain.
python scripts/build_verified_chain.py --run-dir aiedge-runs/<run_id>
python scripts/verify_verified_chain.py --run-dir aiedge-runs/<run_id>

# 4. Enforce AEG platform gate: dynamic proof + FP/FPR evidence.
python scripts/aeg_e2e_gate.py aiedge-runs/<run_id>
```

## Pair/FP evaluation expectation

For RAG corpus expansion, one known-vulnerable target is not enough. Each new pattern family should eventually be evaluated against:

- a known-vulnerable firmware or lab harness where the pattern should verify,
- a patched or control firmware where the same pattern should not verify,
- run-level quality metrics showing acceptable FPR,
- FP verification artifacts showing high/critical AEG candidates were not rejected as false positives.

Blocked or unsupported dynamic validation is **not** counted as FP, but it is also **not** counted as verified AEG success.
