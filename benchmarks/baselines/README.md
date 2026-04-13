# SCOUT Benchmark Baselines

This directory contains hash-anchored benchmark baselines for each SCOUT
release. See `docs/benchmark_governance.md` for the freeze rule and
governance policy.

## Structure

Each subdirectory `v<X.Y.Z>/` contains:
- `manifest.json` — version, date, driver, firmware count, hash, methodology
- `tier1_static.json` — static-only baseline (required if claim made)
- `tier2_llm.json` — LLM baseline with driver-specific metadata
- `single_firmware/` — single-firmware validation results
- `hashes.txt` — SHA-256 hashes of all artifacts

## Releases

- `v2.5.0/` — current. Carry-over baselines from earlier versions; fresh
  corpus re-validation pending.

## Validating an Existing Baseline

```bash
# Validate current baseline manifest
python3 scripts/build_benchmark_baseline.py --version v2.5.0 --validate-only
```

## Generating a New Baseline

Build mode is not yet implemented; `manifest.json` is hand-curated until
corpus re-validation produces an authoritative snapshot. See
`docs/benchmark_governance.md` "Current state (v2.5.0)" for details.
