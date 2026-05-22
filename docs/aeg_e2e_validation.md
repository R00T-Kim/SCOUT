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
./scout aeg-e2e-gate aiedge-runs/<run_id> --out aiedge-runs/<run_id>/aeg_e2e_gate.json
```

The product CLI exits `0` only when every dynamic proof and FP/FPR check passes. It exits `31` on fail-closed evidence gaps. `python scripts/aeg_e2e_gate.py ...` remains available as a compatibility wrapper.

## Synthetic vulnerable/control pair

CI also carries a synthetic AEG pair that exercises the real AutoPoC runner,
`poc_validation`, `verified_chain`, and FP/FPR gate over two local loopback lab
services:

- **vulnerable** service returns a privileged `SCOUT_LEAK` proof and must pass;
- **patched/control** service accepts the same probes without leaking and must fail closed;
- the patched/control case also records high-severity FP and FPR evidence so the gate proves it is not merely checking runner status.

Run it locally:

```bash
python scripts/run_aeg_synthetic_pair.py --work-root /tmp/scout-aeg-synthetic-pair
python scripts/run_aeg_synthetic_pair.py --pattern cgi_param_cmd_injection --work-root /tmp/scout-aeg-cgi-pair
python scripts/run_aeg_synthetic_pair.py --pattern config_derived_cmd_injection --work-root /tmp/scout-aeg-config-pair
cat /tmp/scout-aeg-synthetic-pair/synthetic_aeg_pair_summary.json
```

The synthetic pair is a CI-safe regression proxy. It proves the AEG gate can
separate a reproducible lab proof from a patched/control false positive. Real
firmware release claims must cite a known-vulnerable/patched firmware pair in
addition to this synthetic regression.

The harness currently validates `memory_stateful_probe`, `cgi_param_cmd_injection`, and `config_derived_cmd_injection` as synthetic pair evidence. The first real firmware pair is `netgear_passwordrecovered_auth_bypass` for Netgear R7000 CVE-2017-5521, with the stable report at `docs/pov/netgear-r7000-cve-2017-5521_real_pair.json`. Inspect card-level readiness with:

```bash
python scripts/check_exploit_pattern_evidence.py
```

For a release-facing AEG platform readiness audit, use the stricter integrated
gate. It requires every curated pattern to have vulnerable/control pair evidence,
at least one real known-vulnerable/patched firmware pair, and a stable real-pair
artifact whose report proves the vulnerable side passed while patched/control
failed a dynamic proof check:

```bash
./scout aeg-readiness --out docs/pov/aeg_platform_readiness.json
```

The current checked-in readiness snapshot is
`docs/pov/aeg_platform_readiness.json`; it is an offline audit artifact, not a
substitute for rerunning the real firmware-pair harness when firmware inputs or
AutoPoC behavior changes. The lower-level script entry point remains available
as `python scripts/check_aeg_platform_readiness.py` for direct automation and compatibility.

When a known-vulnerable/patched firmware pair has completed the same gate, record
the card-level evidence through the recorder rather than manually editing the
pattern card:

```bash
./scout aeg-real-pair \
  --pair-id <manifest-pair-id> \
  --fetch --no-llm \
  --pattern-id <pattern-id> \
  --out docs/pov/<stable-pair-evidence>.json

# Or reuse existing authorized lab runs and only evaluate promotion readiness.
python scripts/check_real_firmware_pair_aeg.py \
  --pair-id <manifest-pair-id> \
  --vulnerable-run-dir aiedge-runs/<known-vulnerable-run> \
  --control-run-dir aiedge-runs/<patched-control-run> \
  --pattern-id <pattern-id> \
  --out docs/pov/<stable-pair-evidence>.json

python scripts/record_pattern_pair_evidence.py <pattern-id> \
  --kind real_firmware_pair \
  --vulnerable-run-dir aiedge-runs/<known-vulnerable-run> \
  --control-run-dir aiedge-runs/<patched-control-run> \
  --artifact docs/pov/<stable-pair-evidence>.json \
  --vulnerable-firmware-sha256 <sha256> \
  --control-firmware-sha256 <sha256> \
  --cve CVE-YYYY-NNNN \
  --apply
```

The run wrapper executes or reuses the selected official pair, reruns the
required post-analysis AEG stages, derives run-level FP/FPR metrics from the
FP verification artifact, rebuilds the verified evidence chain, and then emits
a fail-closed pair report through the preflight command. It checks the manifest
firmware SHA-256 values, re-runs the AEG E2E gate on both runs, lists missing
gate artifacts, and only returns success when the pair is promotable. The
recorder performs the same gate checks before mutating a card: vulnerable must
pass, both sides must have complete gate artifacts, and patched/control must
fail at least one dynamic proof check. For `real_firmware_pair`, the recorder
also requires a stable evidence artifact, both firmware SHA-256 values, and a
CVE or target-family label so ad-hoc lab runs cannot be mislabeled as
release-grade firmware-pair proof.

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
./scout aeg-e2e-gate aiedge-runs/<run_id>
```

## Pair/FP evaluation expectation

For RAG corpus expansion, one known-vulnerable target is not enough. Each new pattern family should eventually be evaluated against:

- a known-vulnerable firmware or lab harness where the pattern should verify,
- a patched or control firmware where the same pattern should not verify,
- run-level quality metrics showing acceptable FPR,
- FP verification artifacts showing high/critical AEG candidates were not rejected as false positives.

Blocked or unsupported dynamic validation is **not** counted as FP, but it is also **not** counted as verified AEG success.
