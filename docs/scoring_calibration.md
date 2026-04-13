# Scoring Calibration: Detection Confidence vs Priority Score

**Status**: Phase 2B PR #15 (additive). Existing consumers reading `confidence` continue to work.

## Why two scores?

Before PR #15, every CVE finding carried a single `confidence` field that combined:

- **Static evidence depth** (symbol cooccurrence vs decompiled code vs P-code dataflow)
- **Reachability multiplier** (`directly_reachable` 1.0 ... `unreachable` 0.5)
- **Backport penalty** (-0.30 if the component shows a distro patch revision)
- **EPSS additive** (+0.10 / +0.05 / -0.05 depending on FIRST.org EPSS bucket)

External reviewers (Gemini, ChatGPT) flagged this as a category error:

> "EPSS is a population-level exploitation likelihood -- making it modify
>  detection confidence makes the field look like a ranking heuristic, not
>  a probability of true positive."

PR #15 splits the single field into **two scores with distinct semantics**:

| Score | Meaning | Range | Source |
|-------|---------|-------|--------|
| `confidence` (a.k.a. `detection_confidence`) | Probability that the finding reflects a real vulnerability. Pure static evidence depth. | 0.0 - 1.0 | `confidence_caps.py` (capped) |
| `priority_score` | Operational priority for analyst triage. Combines detection confidence with EPSS, reachability, CVSS, backport. | 0.0 - 1.0 | `scoring.compute_priority_score()` |

**Iron rule**: if you want to rank findings by "look at this first", read
`priority_score`. If you want to know "is this a true positive", read
`confidence`. They are no longer the same thing.

## Detection confidence (`confidence`)

Strict static-evidence-only signal, capped at the appropriate level from
`confidence_caps.py`:

| Cap constant | Value | When |
|--------------|-------|------|
| `SYMBOL_COOCCURRENCE_CAP` | 0.40 | Symbol co-occurrence only -- no code path confirmed |
| `STATIC_CODE_VERIFIED_CAP` | 0.55 | Decompiled code inspected but no LLM taint trace |
| `STATIC_ONLY_CAP` | 0.60 | Generic static-only ceiling (legacy) |
| `PCODE_VERIFIED_CAP` | 0.75 | P-code SSA dataflow confirmed source -> sink |

CVE findings emitted by `cve_scan.py` are always capped at
`STATIC_CODE_VERIFIED_CAP` (0.55) -- NVD evidence by itself is "decompiled
code level" at best, never P-code-confirmed.

EPSS, reachability, backport status, and CVSS **do not** modify this
field. They feed `priority_score` instead.

### Stage -> field mapping

| Stage | Sets `confidence` | Sets `priority_score` |
|-------|-------------------|------------------------|
| `cve_scan` | yes (static cap) | yes (full PriorityInputs) |
| `pattern_scan` | yes | via `findings.py` default (uses `confidence` only) |
| `taint_propagation` | yes (P-code cap when verified) | via `findings.py` default |
| `findings` (assembler) | normalizes existing field | fills `priority_score` for any finding missing it |

## Priority score (`priority_score`)

Operational priority for analyst triage. **NOT** a probability of true
positive.

```
priority_score = clamp01(
    detection_confidence * 0.50           # 50% weight: detection
  + epss_score           * 0.25           # 25% weight: EPSS (if known)
  + reachability_mult    * 0.15           # 15% weight: reachability
  + (cvss_base / 10.0)   * 0.10           # 10% weight: CVSS
  - backport_penalty                      # -0.20 if backport_present
)
```

Reachability multipliers (different from the legacy `_REACHABILITY_MULTIPLIERS`
in `cve_scan.py` -- these were retuned for the priority weighting):

| Reachability | Multiplier |
|--------------|-----------:|
| `directly_reachable` | 1.0 |
| `potentially_reachable` | 0.7 |
| `unknown` (or missing) | 0.5 |
| `unreachable` | 0.2 |

Backport penalty: a flat **-0.20** when `backport_present=True`. The
finding is still surfaced; it just ranks lower than an unpatched peer.

Both EPSS and CVSS are optional inputs -- when `None`, their term is
omitted from the sum (NOT replaced with zero), so a finding with no CVSS
data does not get artificially penalized.

## `priority_inputs` JSON schema

Every finding with a `priority_score` also carries a `priority_inputs`
object documenting which signals were combined. Schema:

```jsonc
{
  "detection_confidence": 0.55,        // float 0.0-1.0; the static-evidence cap
  "epss_score": 0.42,                  // float 0.0-1.0 or null (FIRST.org EPSS)
  "epss_percentile": 0.93,             // float 0.0-1.0 or null (companion percentile)
  "reachability": "directly_reachable",// string or null
  "backport_present": false,           // boolean
  "cvss_base": 9.8                     // float 0.0-10.0 or null
}
```

This object is intentionally serialized verbatim so analysts can audit
the priority computation without re-running the scorer.

## Buckets

`scoring.priority_bucket()` (and the parallel
`quality_metrics._priority_bucket_label()`) classify a `priority_score`
into one of four operational buckets:

| Bucket | Range |
|--------|-------|
| `critical` | `>= 0.80` |
| `high` | `0.60 - 0.80` |
| `medium` | `0.40 - 0.60` |
| `low` | `< 0.40` |

`quality_metrics.count_findings_by_priority()` aggregates a finding list
into bucket counts. Pre-PR #15 findings (which lack `priority_score`)
land in an `unscored` bucket; the existing per-confidence aggregation is
preserved unchanged.

## Before / after example

Hypothetical CVE: `CVE-2024-9999` in `dnsmasq 2.0` -- CVSS 9.8 critical,
EPSS 0.42 (very high), reachability `directly_reachable`, no backport.

### Before PR #15 (single field)

```python
match_conf = 0.90                                 # exact CPE match
score      = 9.8                                  # CVSS base
confidence = 0.90 * 9.8/10.0 * 0.6 = 0.5292       # _finding_confidence
confidence = min(0.60, 0.5292)      = 0.5292      # _STATIC_CONFIDENCE_CAP
confidence *= 1.0 (directly_reachable)            # reach multiplier
confidence += 0.10 (EPSS >= 0.10)   = 0.6292      # EPSS additive
confidence  = min(0.60, 0.6292)     = 0.60        # capped again

# Single field reads:
finding["confidence"] == 0.60
```

The `0.60` is read by some downstream UIs as "we are 60% sure this is a
real vulnerability". That is **wrong** -- the static evidence alone only
supports 0.53; the rest of the bump comes from EPSS, which says nothing
about whether *this binary* is actually vulnerable.

### After PR #15 (two fields)

```python
match_conf = 0.90
score      = 9.8

# detection_confidence: static evidence only, capped at STATIC_CODE_VERIFIED_CAP
detection_confidence = 0.90 * 9.8/10.0 * 0.6 = 0.5292
detection_confidence = min(0.55, 0.5292)     = 0.5292

# priority_score: operational signal from the scorer
priority_score = (
    0.5292 * 0.50                  # detection      = 0.2646
  + 0.42   * 0.25                  # EPSS           = 0.1050
  + 1.0    * 0.15                  # reachability   = 0.1500
  + 0.98   * 0.10                  # CVSS / 10      = 0.0980
  - 0.0                            # no backport
) = 0.6176                         # clamped to [0,1] -> 0.6176

# Two fields read:
finding["confidence"]     == 0.5292   # strict detection -- unchanged by EPSS
finding["priority_score"] == 0.6176   # operational priority -- EPSS visible
finding["priority_inputs"] == {
    "detection_confidence": 0.5292,
    "epss_score":           0.42,
    "epss_percentile":      0.93,
    "reachability":         "directly_reachable",
    "backport_present":     False,
    "cvss_base":            9.8,
}
```

The detection number now honestly reflects what the static evidence
supports; the EPSS boost is visible in `priority_score` and traceable in
`priority_inputs` for analyst audit.

### Backport variant

Same finding, but `backport_present=True` (component has an `opkg`
distro patch revision):

```python
detection_confidence == 0.5292        # UNCHANGED -- backport doesn't lie about evidence
priority_score       == 0.6176 - 0.20 = 0.4176   # bumped down to medium bucket
```

Detection stays anchored to the static evidence; priority drops because
the vuln may already be patched in this image.

## Migration notes

- **Schema version is NOT bumped.** Both `priority_score` and
  `priority_inputs` are additive optional fields, exactly like
  `category` in PR #7a.
- **Existing consumers reading `confidence` continue to work** -- they
  will just see lower numbers for CVE findings (no more EPSS additive).
- **New ranking UIs should read `priority_score`** instead of
  `confidence`. The `priority_inputs` field exposes the inputs for full
  auditability.
- **Quality metrics**: a new `count_findings_by_priority()` helper
  produces per-bucket counts. The existing per-confidence and
  per-category aggregations are unchanged.
- **SARIF export**: `properties.scout_priority_score` and
  `properties.scout_priority_inputs` mirror the new fields. The existing
  `properties.confidence` key is unchanged.
