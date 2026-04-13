# Benchmark Governance Policy

Status: **Skeleton (since v2.5.0)** — Freeze rule defined, full enforcement pending corpus re-validation
Owner: SCOUT maintainers

> **Current state (v2.5.0)**: This document defines the policy. The
> `check_doc_consistency.py` script enforces structural rules (deterministic,
> tier count, CRA wording, stage count) but **does not yet enforce the
> bare-number freeze rule**. README still contains carry-over numbers from
> v2.4.0/v2.3.0 baselines, marked as historical until fresh corpus
> re-validation lands.

## Purpose

Establish strict rules for what numbers may appear in user-facing documentation
(README, CHANGELOG, status.md, marketing) to ensure every quantitative claim
about SCOUT is reproducible and traceable to a frozen baseline.

## Core Rule (Freeze Rule)

> **README의 모든 수치는 `benchmarks/baselines/<version>/manifest.json`에 존재하는 값만 쓴다.
> baseline manifest에 없는 수치는 README/CHANGELOG/status에 등장 금지.**

This is enforced by `scripts/check_doc_consistency.py` (PR #9) in CI.

## Detailed Rules

### Rule 1: Official Baseline
- An "official baseline" is a hash-anchored snapshot committed under
  `benchmarks/baselines/<version>/`
- Each baseline must have a `manifest.json` declaring: version, date, driver,
  firmware count, hash, methodology
- A baseline must be reproducible from a specific git tag (1:1 matching)

### Rule 2: Marketing Claims
Every numeric claim in README must include 4 metadata fields:
1. baseline version (e.g., `v2.4.0`)
2. firmware count (e.g., `1,123 firmware`)
3. driver (e.g., `claude-code` or `static-only`)
4. validation date (e.g., `2026-04-05`)

Example (correct):
> "Tier 1 baseline (v2.4.0, 2026-04-05, static-only): 1,123 firmware, 99.2% analysis rate"

Example (forbidden — bare number):
> "99.2% analysis rate"

### Rule 3: Single-Firmware Validation
Single-firmware results (e.g., R7000 verification) belong in a clearly
labeled "Single-firmware validation" section. They MUST NOT be presented
as corpus-level conclusions or compared with baselines as if equivalent.

Example (correct):
> "Single-firmware validation (R7000, codex driver, 2026-04-13):
> adversarial_triage parse_failures 100→0"

Example (forbidden):
> "v2.5.0 reduced parse failures by 100x"  ← implies generalization

### Rule 4: Legacy Archive
Old benchmark numbers may be retained in a clearly labeled
"historical/legacy — no longer official baseline" section. They must NOT
be cited in marketing copy or precision/recall claims.

### Rule 5: Reproducibility
Each baseline directory must contain a script or exact command to reproduce
the snapshot. The hash chain must verify against `hashes.txt`.

### Rule 6: CI Enforcement
`scripts/check_doc_consistency.py` validates:
- All numeric claims in README have 4-metadata format
- All numeric claims correspond to entries in `benchmarks/baselines/<version>/manifest.json`
- No bare numbers in README/CHANGELOG outside of `benchmarks/baselines/`

## Baseline Directory Structure

```
benchmarks/baselines/
├── README.md
├── v2.5.0/
│   ├── manifest.json        # version, date, driver, firmware count, hash
│   ├── tier1_static.json    # static-only baseline
│   ├── tier2_llm.json       # LLM baseline (driver-specific)
│   ├── single_firmware/     # R7000 etc. (separate from corpus)
│   │   └── r7000_codex.json
│   └── hashes.txt           # SHA-256 of all artifacts
```

## Migration from Legacy

Existing claims in README.md and CHANGELOG.md that lack baseline metadata
must be either:
1. Updated to include the 4 metadata fields, OR
2. Demoted to a "historical" section with a "no longer official baseline"
   warning, OR
3. Removed entirely.

## v2.5.0 Status (as of 2026-04-13)

- Tier 1 baseline: legacy from v2.4.0 (1,123 firmware, 2026-04-05). Not
  re-validated against v2.5.0. Marked as "carry-over baseline" until
  fresh run.
- Tier 2 baseline: legacy from v2.3.0 (36 firmware, 2026-04-09,
  claude-code driver). Not re-validated against v2.5.0. Carry-over.
- Single-firmware validation: R7000 (codex driver, 2026-04-13). Documented
  as v2.5.0 single-firmware validation, NOT corpus-level claim.

A fresh corpus re-validation against v2.5.0 is pending and will produce
`benchmarks/baselines/v2.5.0/` artifacts.
