# Quality Gate SLOs

SCOUT enforces four statistical thresholds before a run may be promoted. These are evaluated by `quality_policy.py` and exposed through two CLI commands.

---

## Threshold Definitions

| Metric | Default | Operator | Env Override |
|--------|---------|----------|-------------|
| Precision | 0.90 | >= | `AIEDGE_QG_PRECISION_MIN` |
| Recall | 0.60 | >= | `AIEDGE_QG_RECALL_MIN` |
| High-severity false positive rate | 0.10 | <= | `AIEDGE_QG_FPR_MAX` |
| Abstain rate | 0.25 | <= | `AIEDGE_QG_ABSTAIN_MAX` |

All four thresholds must pass simultaneously. A single miss fails the gate.

---

## What Each Metric Means

### Precision (`overall.precision`)

Of all findings SCOUT emits, what fraction are genuine vulnerabilities. A precision of 0.90 means at most 10 % of findings are false positives across all severity levels. SCOUT computes this from the corpus-validated `quality_metrics.json` produced by `quality-metrics`.

### Recall (`overall.recall`)

Of all known true vulnerabilities in the corpus, what fraction SCOUT surfaces. A recall of 0.60 means SCOUT must catch at least 60 % of seeded ground-truth issues. This is deliberately lower than precision because SCOUT is a static evidence engine — some classes of runtime-only bugs are structurally undetectable without emulation.

### High-Severity False Positive Rate (`overall.fpr`)

Proxy for the false-positive rate among high- and critical-severity findings specifically, measured as `overall.fpr` from the metrics payload. Capped at 0.10: no more than 10 % of high/critical findings may be wrong. This threshold exists because a false high-severity finding causes expensive manual triage.

### Abstain Rate (`abstain_rate`)

Fraction of pipeline stages or analysis units that produced no verdict (skipped, timed out, or encountered an unsupported binary type). Capped at 0.25: SCOUT must deliver a verdict on at least 75 % of what it examines. High abstain rates indicate tooling gaps (missing extractors, unsupported architectures) that leave coverage holes.

---

## How the Quality Gate Works

### `quality-gate` (non-release)

```bash
./scout quality-gate aiedge-runs/<run_id>
```

Reads `quality_metrics.json` from the run directory, evaluates all four thresholds, and exits 0 (pass) or 20 (fail). Does not require a report file. Does not enforce the confirmed-findings constraint. Suitable for CI checks on development runs.

### `release-quality-gate` (release)

```bash
./scout release-quality-gate aiedge-runs/<run_id>
# or
scripts/release_gate.sh --run-dir aiedge-runs/<run_id>
```

Runs the same four threshold checks, then adds a release constraint: if any threshold is missed **and** the run contains confirmed high- or critical-severity findings, an additional `QUALITY_GATE_RELEASE_CONSTRAINT` error is emitted. This prevents releasing a build that both fails statistical QA and contains known unresolved high-severity issues.

The release gate also optionally evaluates an LLM gate verdict (`llm_gate_payload`) when `--llm-primary` is set.

### Output format

Both commands write a `quality_gate.json` artifact:

```json
{
  "schema_version": 1,
  "verdict": "pass" | "fail",
  "passed": true | false,
  "policy": { ... effective thresholds ... },
  "measured": { ... actual metric values ... },
  "errors": [ ... per-threshold miss details ... ]
}
```

Error objects include `error_token`, `metric`, `actual`, `threshold`, `operator`, and `message` for machine-readable downstream consumption.

---

## Overriding Thresholds via Environment Variables

All four thresholds read from environment variables at evaluation time. The defaults are unchanged when no variable is set.

```bash
# Tighten precision for a release track
AIEDGE_QG_PRECISION_MIN=0.95 ./scout release-quality-gate aiedge-runs/<run_id>

# Relax recall during initial corpus bootstrap
AIEDGE_QG_RECALL_MIN=0.45 ./scout quality-gate aiedge-runs/<run_id>

# Allow more abstains on a constrained embedded target
AIEDGE_QG_ABSTAIN_MAX=0.40 ./scout quality-gate aiedge-runs/<run_id>

# Tighten FPR for a high-assurance audit
AIEDGE_QG_FPR_MAX=0.05 ./scout release-quality-gate aiedge-runs/<run_id>
```

Invalid values (non-numeric) are silently ignored and the default is used. The effective thresholds are always recorded in `quality_gate.json` under `policy`, so the values used for a given run are auditable.

### Variable reference

| Variable | Controls | Default |
|----------|----------|---------|
| `AIEDGE_QG_PRECISION_MIN` | Minimum required precision | `0.9` |
| `AIEDGE_QG_RECALL_MIN` | Minimum required recall | `0.6` |
| `AIEDGE_QG_FPR_MAX` | Maximum allowed high-severity FPR | `0.1` |
| `AIEDGE_QG_ABSTAIN_MAX` | Maximum allowed abstain rate | `0.25` |

---

## Design Rationale

The default thresholds reflect SCOUT's role as a deterministic static evidence engine feeding a human analyst:

- **Precision 0.90** — analysts act on SCOUT output; false positives waste analyst time directly.
- **Recall 0.60** — SCOUT cannot detect all runtime vulnerabilities statically; 60 % is a realistic floor for static + dynamic-optional analysis.
- **FPR 0.10** — high/critical findings trigger escalation; a 10 % cap balances coverage against alert fatigue.
- **Abstain 0.25** — more than 25 % abstention suggests systematic tool failure, not edge-case gaps.

These defaults should be treated as SLOs for the analysis pipeline. Override them per-environment only with documented rationale.
