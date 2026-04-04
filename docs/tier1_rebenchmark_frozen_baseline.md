# Tier 1 Frozen Baseline — `firmae-sasquatch-20260401_235630`

이 문서는 sasquatch 반영 후 재실행한 Tier 1 정적 벤치마크의 **동결 기준선(frozen baseline)** 을 기록합니다.

## Baseline identity

- Results dir: `benchmark-results/firmae-sasquatch-20260401_235630`
- Scope: `aiedge-inputs/firmae-benchmark`
- Mode: static-first Tier 1
- Command shape:
  - `./scripts/benchmark_firmae.sh --cleanup --parallel 4 --time-budget 600`
- Profile: `analysis`
- LLM: disabled (`--no-llm`)
- Runs archived with cleanup enabled

## Final overall results

- Total firmware: `1123`
- Success: `1110`
- Partial: `4`
- Failed: `9`
- Success + Partial analysis rate: `99.2%`
- Total findings: `3523`
- Total CVE matches: `13893`
- Extraction ok / partial / failed: `1110 / 4 / 0`
- Inventory sufficient / insufficient: `1104 / 10`
- Average files seen: `1940.4`
- Average binaries seen: `1027.53`
- Total duration: `846654s` (~`235.18h`)

## Comparison anchor

Compare all future work against:

- Previous Tier 1 baseline: `benchmark-results/firmae-20260330_0259`
- This frozen baseline: `benchmark-results/firmae-sasquatch-20260401_235630`

Do **not** mutate findings taxonomy, severity mapping, or benchmark semantics when making direct baseline-to-baseline comparisons. Any such change must be measured as a separate follow-up experiment.

## Tier 1 interpretation

- This baseline measures **pipeline completion / artifact usability**, not exploit confirmation.
- Major improvement versus prior baseline is conversion of large numbers of `partial` runs into `success`.
- CVE counts in this baseline are the first trustworthy benchmark-level CVE aggregate after fixing CSV summary collection.

## Emulation note

- Tier 1 benchmark runs used `profile=analysis`, so exploit-only stages such as `dynamic_validation` and `fuzzing` were not part of the benchmark success criteria.
- However, SCOUT’s base pipeline still includes an `emulation` stage attempt in normal analysis runs.
- Archived `report.json` post-processing over the 1114 non-fatal runs showed:
  - `used_tier=tier1`: `1102`
  - `used_tier=tier2`: `12`
- This should be interpreted as **base emulation path success**, not service-verified full-system runtime validation success.
- Treat this baseline as **static-first with broad base emulation attempts**, not as a full dynamic-validation benchmark.

## Tier 2 execution note

Historical Tier 2 cohort file:

- `benchmarks/tier2-20260331-files.txt`

Current local mirror status:

- 39 historical entries
- 36 executable non-zero files
- 3 zero-byte files skipped in current workspace mirror:
  - `aiedge-inputs/firmae-benchmark-2025/asus/FW_RT_AX86U_300438824401.zip`
  - `aiedge-inputs/firmae-benchmark-2025/dlink/DIR-842-REVC-v3.13B10.zip`
  - `aiedge-inputs/firmae-benchmark-2025/netgear/R6900-V1.0.2.8.zip`

Executable Tier 2 file list for reproducible reruns:

- `benchmarks/tier2-20260331-executable-files.txt`

Use the executable list for actual Tier 2 runs, while keeping the original 39-file list as the historical cohort reference.
