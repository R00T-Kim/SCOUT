# Results Overview — Phase 2C.6 baseline + follow-on lanes

This page is the single-entry reporting surface for the completed 2C.6 baseline refresh and the follow-on reviewer lanes.

The Tier 1 corpus refresh is now complete; pair-eval / ROC / E2E sections remain intentionally `TBD` until those lanes execute.

## Source of truth

- fresh rerun aggregate: `benchmark-results/2c6-fresh-full-final/aggregate.json`
- resolved row manifest: `benchmark-results/2c6-fresh-full-final/combined_best_summary.csv`
- corpus source: `aiedge-inputs/firmae-benchmark`
- rerun waves: `2c6-fresh-full-v2`, `2c6-fresh-full-v2-resume`, `2c6-fresh-full-v2-r3`, `2c6-fresh-full-v2-r4`
- follow-on evaluation lanes:
  - `docs/benchmark_pair_gap.md`
  - `docs/pair_eval_lane.md`
- demo write-up target: `docs/results_overview.md`

## 1) Target list

### Full corpus inventory

| Field | Value |
| --- | --- |
| total targets | `1123` |
| vendor distribution | `asus 107 / belkin 37 / dlink 262 / linksys 55 / netgear 375 / tplink 148 / trendnet 119 / zyxel 20` |
| inclusion rule | `best-view aggregation across fresh rerun waves; success preferred over partial/fatal/error` |
| exclusion rule | `out-of-corpus bookkeeping anomaly 1건 제외, filename alias 1건(normalized)` |
| target manifest | `benchmark-results/2c6-fresh-full-final/combined_best_summary.csv` |

### Representative targets to call out explicitly

| Vendor | Target | Corpus role | Notes |
| --- | --- | --- | --- |
| Netgear | R7000 | `TBD` | Known pilot reference |
| TP-Link | Archer C7 v5 (OpenWrt) | `TBD` | Known pilot reference |
| Tenda | AC10 | `TBD` | Known pilot reference |
| Trendnet | TEW-827DRU v2.10 | `TBD` | Known pilot reference |

### Pair-eval candidate targets

| Pair family | Vuln / patched label | Binary / archive source | Status |
| --- | --- | --- | --- |
| Netgear R7000 | `TBD` | `TBD` | Pair lane only |
| TP-Link Archer C7 multi-version | `TBD` | `TBD` | Pair lane only |
| D-Link DIR-859 | `TBD` | `TBD` | Pair lane only |

## 2) Findings by category

Fill this table from the final rerun summary.

| Category | Count | Share | Notes |
| --- | --- | --- | --- |
| vulnerability | `TBD` | `TBD` | `TBD` |
| misconfiguration | `TBD` | `TBD` | `TBD` |
| pipeline_artifact | `TBD` | `TBD` | `TBD` |
| unclassified | `TBD` | `TBD` | `TBD` |

## 3) Tier distribution

Fill this table from the final `evidence_tier` summary.

| Tier | Count | Share | Notes |
| --- | --- | --- | --- |
| symbol_only | `TBD` | `TBD` | `TBD` |
| static_colocated | `TBD` | `TBD` | `TBD` |
| static_interproc | `TBD` | `TBD` | `TBD` |
| pcode_verified | `TBD` | `TBD` | `TBD` |
| dynamic_verified | `TBD` | `TBD` | `TBD` |
| unknown | `TBD` | `TBD` | `TBD` |

## 4) Pair eval

This section is for the follow-on `[B-1]` lane. It should be populated only from
pair-labeled vuln/patched runs that come from extraction-success inputs.

| Metric | Value |
| --- | --- |
| pair corpus size | `4` |
| vuln targets | `4` |
| patched targets | `4` |
| recall | `0.25` |
| false-positive rate | `0.25` |
| label source | `target cve_id present in stages/cve_scan/cve_matches.json` |
| exclusions | `0` |

### Pair corpus notes

- Full candidate list and CVE mapping is in `docs/pair_corpus_candidates.md` (10 candidate pairs + 2 gaps documented).
- **M0 minimum set** (local, no external sourcing needed — 4 pairs, 8 runs):
  - Netgear R7000 V1.0.7.12 → V1.0.9.34 (CVE-2017-5521)
  - D-Link DIR-868L K02 → K04 (CVE-2018-10970 ref)
  - D-Link DIR-850L FW105 → FW115 (CVE-2019-20213 / CVE-2019-6258 ref)
  - TP-Link Archer C7 v2 2015 → 2016 (CVE-2017-13772 ref)
- **Gaps** requiring external sourcing (see `docs/benchmark_pair_gap.md`):
  - DIR-859 pre-1.06B01 (vuln-side missing locally)
  - OpenWrt Archer C7 v5 pre-23.05 (baseline control missing)
- **Exclusions**: any pair whose vuln-side fails extraction (`partial` or worse) must be held back; only `extraction=ok` subset feeds the pair-labeled recall/FPR calculation. This aligns with the "pipeline capable ≠ value delivered" framing.
- **Pair type**: all M0 pairs are **version-paired** within the same vendor model line. Patch-level pairs (minor build number diffs) are parked under §5 of `docs/pair_corpus_candidates.md` as P3 future expansion.
- **M0 actual numbers are now populated** from `benchmark-results/pair-eval/pair_eval_summary.json`. Expansion to additional local/gap pairs remains a follow-on step.

## 5) Calibration

This section is for the `[C]` lane.

| Metric | Value |
| --- | --- |
| confidence threshold / cap | `0.78` (single observed M0 point) |
| ROC / PR source | `benchmark-results/pair-eval/pair_eval_summary.json` |
| calibration subset | `4 pairs / 8 success runs` |
| TP | `1` |
| FP | `1` |
| TN | `3` |
| FN | `3` |

### Calibration notes

- M0 produced a **degenerate single-threshold ROC point** because every pair-side resolved to the same top vulnerability finding (`web.exec_sink_overlap`, `confidence=0.78`, `evidence_tier=symbol_only`).
- The current curve is **pair-subset only** (4 local pairs / 8 runs), not corpus-wide.
- Only `extraction=ok` / `inventory=sufficient` runs were scored; no runs were excluded in M0.

## 6) E2E demo

R7000 2C.2 smoke run anchor: `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c`. Full walk-through is in `docs/r7000_e2e_demo.md`. Below is the high-level index so this page can stay the single-entry reference.

### Step 1 — static finding

- input artifact: `aiedge-inputs/netgear/R7000-V1.0.11.136_10.2.120.chk`
- stage output: `stages/findings/findings.json` (3 findings, reasoning_trail_count=1)
- primary finding: `aiedge.findings.web.exec_sink_overlap` (category=vulnerability, severity=high, confidence=0.78, priority_score=0.465)
- affected binaries: `squashfs-root/opt/rcagent/cgi/rccommand.cgi`, `/opt/remote/bin/RMT_invite.cgi`, `/usr/sbin/httpd`

### Step 2 — LLM triage

- input artifact: same `stages/findings/findings.json`
- reasoning trace: `findings[0].reasoning_trail` has 5 entries — `synthesis_match` → `fp_verification.llm_verdict=maintain` (sonnet) → `adversarial_triage.advocate=exploit_path_plausible` (sonnet) → `adversarial_triage.critic=downgrade` (sonnet) → `adversarial_triage.decision=downgrade` (Δ -0.2, confidence 0.550 → 0.350)
- verdict artifacts: `stages/fp_verification/stage.json` (100 artifacts), `stages/adversarial_triage/stage.json` (201 artifacts)

### Step 3 — emulation

- input artifact: `stages/emulation/stage.json` (status=ok, 1 artifact)
- execution artifact: `stages/emulation/emulation.log`
- observation: lightweight FirmAE profile ran to completion; dynamic_validation downstream is `partial` (10 artifacts, `stages/dynamic_validation/dynamic_validation.json`)

### Step 4 — fuzzing

- input artifact: `stages/fuzzing/stage.json`
- fuzz artifact: none on this run
- observation: **fuzzing=skipped** on this run — time/tooling budget outside the 2C.2 smoke scope. Pipeline wiring is verified (stage registered, dry-run config parses) but no fuzz campaign was executed. Fuzz-to-crash lane deferred to a follow-on run documented in `docs/r7000_e2e_demo.md` §8.

### Step 5 — exploit-chain hypothesis

- input artifact: `stages/chain_construction/chains.json` (50 chains, summary: `{same_binary: 50, llm_generated: 3, cross_binary: 0, total: 50}`)
- chain artifact: `stages/exploit_chain/milestones.json` (3 milestones, `exploit_gate: {scope: lab-only, flag: lab, attestation: authorized}`, `milestones[0].reachability=partial`)
- conclusion: verdict state = `inconclusive` with `missing_exploit_bundle` reason. `stages/poc_validation/poc_validation.json` status=failed with block reason `POLICY_PREREQ_STAGE_ARTIFACT_MISSING` — this is the **governance fail-closed** signal, not a system error.

## Reference snapshot — confirmed baseline refresh

Use these numbers only as the already-confirmed baseline refresh reference.
Do **not** overwrite the final rerun summary with them.

- corpus size: **1114**
- vendor distribution:
  - netgear: **375**
  - dlink: **262**
  - tplink: **148**
  - trendnet: **112**
  - asus: **105**
  - linksys: **55**
  - belkin: **37**
  - zyxel: **20**
- extraction baseline:
  - `ok`: **706**
  - `partial`: **408**
  - `sufficient`: **698**
  - `insufficient`: **416**
- SBOM / CVE baseline:
  - SBOM `nonzero`: **0 / 1114**
  - CVE source `known_signature_only`: **712**
  - CVE source `missing`: **402**
