# Finding Diversity Gate

> Phase 2C+.5 (Pivot 2026-04-19) — pair-eval lane gate that detects degenerate
> evidence-tier coverage by measuring finding-id share concentration.

## Why this gate exists

The 2026-04-19 reviewer eval lane analysis surfaced a structural failure that
neither precision/recall nor confidence caps caught: **every pair-side row in the
local-7 lane mapped to the same `finding_id`** (`aiedge.findings.web.exec_sink_overlap`,
`evidence_tier=symbol_only`). The pair-level recall and FP rate looked plausible
(0.142857 each) yet the underlying tier-ROC was *degenerate* — there was nothing
to discriminate between vulnerable and patched runs because the detection layer
collapsed onto a single finding.

The diversity gate quantifies this collapse and blocks releases that ship it.

## Definition

```
finding_diversity_index = max_count(finding_id) / total_rows
```

- `1.0` — degenerate (every row mapped to a single `finding_id`)
- `1/N` — fully diverse (every row a distinct `finding_id`)
- `0.0` — empty input (callers decide whether to treat as violation)

The index is a **maximum-share** metric, not entropy. It is robust to long-tail
distributions and surfaces the dominant finding bucket directly.

## Threshold

| Env variable | Default | Direction |
|---|---|---|
| `AIEDGE_PAIR_DIVERSITY_MAX` | `0.5` | gate fails when index `>=` threshold |

The default `0.5` was chosen as a first-cut: any single `finding_id` accounting
for 50%+ of pair rows is treated as a degenerate signal. Once the corpus grows
past 10 pairs the threshold should be re-evaluated against representative runs
(see Phase 2C+.4 vendor-extraction expansion).

## Inputs

The gate consumes the pair-eval findings CSV produced by
`scripts/run_pair_eval.py`. Schema (relevant columns):

| Column | Use |
|---|---|
| `finding_id` | counted into the share distribution |
| `ground_truth` | optional filter via `load_pair_eval_finding_ids(only_ground_truth=...)` |

Empty `finding_id` rows are skipped silently. Missing CSV raises
`QUALITY_GATE_INVALID_PAIR_EVAL`.

## Output schema

```json
{
  "schema_version": 1,
  "verdict": "pass" | "fail",
  "passed": true | false,
  "findings_source": "<path string>",
  "policy": {
    "finding_diversity_max": 0.5,
    "finding_diversity_max_env": "AIEDGE_PAIR_DIVERSITY_MAX"
  },
  "measured": {
    "finding_diversity_index": 0.0..1.0,
    "sample_size": <int>
  },
  "errors": [
    {
      "error_token": "QUALITY_GATE_DIVERSITY_MISS",
      "metric": "finding_diversity_index",
      "source_field": "pair_eval_findings.finding_id",
      "actual": 1.0,
      "threshold": 0.5,
      "operator": "<",
      "sample_size": 14,
      "message": "..."
    }
  ]
}
```

## Wiring into `release_gate.sh`

The unified release gate wires this in as the `PAIR_EVAL_DIVERSITY` sub-gate. It
is **opt-in** via `--pair-eval-findings`:

```bash
scripts/release_gate.sh \
  --run-dir aiedge-runs/<id> \
  --pair-eval-findings benchmark-results/pair-eval/pair_eval_findings.csv
```

When the flag is omitted the gate is skipped with an `INFO` line so existing
release flows continue working unchanged.

## Current baseline (2026-04-19)

Running the gate against the trusted summary-reuse local-7 lane:

```
sample_size = 14   (7 pairs × 2 sides)
finding_diversity_index = 1.0   (degenerate — single finding for all rows)
verdict = fail
```

This matches the Pivot 2026-04-19 [diagnosis](../docs/status.md): Phase 2D entry
is gated until detection coverage produces at least two distinct findings across
the pair lane. The gate makes that requirement enforceable instead of advisory.

## Phase 2D entry exit-gate hook

The diversity gate is one of the five Phase 2D entry exit-gate thresholds
defined in [`docs/status.md`](status.md):

| Gate | Threshold | Tooling |
|---|---|---|
| Detection recall | `≥ 0.40` | `pair_eval_summary.json` |
| Tier discriminability | `≥ 2 nonzero TP tiers` | `pair_eval_findings.csv` |
| **Finding diversity** | **`< 0.5`** | **this gate** |
| Dedicated rerun | `≥ 1 driver success` | `pair-eval-dedicated-*` lanes |
| Corpus size | `≥ 10 pairs` | `benchmarks/pair-eval/pairs.json` |

The other four are tracked in their own places; this gate only owns the
diversity threshold.

## Related artifacts

- `src/aiedge/quality_policy.py` — `compute_pair_eval_diversity_index`,
  `load_pair_eval_finding_ids`, `evaluate_pair_eval_diversity_gate`
- `scripts/run_pair_eval.py` — adds `timeout_diagnostic.json` for dedicated
  rerun timeout investigations (companion 2C+.5 work)
- `scripts/release_gate.sh` — `PAIR_EVAL_DIVERSITY` sub-gate
- `tests/test_finding_diversity_gate.py` — unit + baseline tests
