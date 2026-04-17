# R7000 End-to-End Demo (Reviewer Item B-2)

This document is the **reviewer-facing walkthrough** for the Netgear R7000. It is intentionally honest: it shows a complete evidence path, but it does **not** overclaim confirmed exploitability where the bundle remains inconclusive.

It is anchored to the existing **v2.6.0 post-merge validation artifacts** for the Netgear R7000 and uses the later SBOM follow-up only as a separate reference point when needed. Where a stage did not complete cleanly, this doc says so explicitly.

## Canonical anchors

- Canonical firmware input:
  - `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/input/firmware.bin`
  - sha256: `b28bf08e9d2c32d12d5a7bda45a93066d8bdf97274defc30f15fc36a437d02fb`
- Main post-merge validation run:
  - `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c`
- Static/SBOM follow-up reference run:
  - `benchmark-results/2c1-sbom-pilot/post_from_existing/2026-04-13_1014_sha256-b28bf08e9d2c`

## Evidence status at a glance

| Step | Story beat | Current evidence status | Anchor artifacts |
|---|---|---:|---|
| 1 | Static finding | available | `report/report.json`, `stages/findings/findings.json` |
| 2 | LLM triage reasoning trail | available | `stages/adversarial_triage/triaged_findings.json`, `stages/fp_verification/verified_alerts.json`, `report/analyst_report.md` |
| 3 | Emulation / dynamic validation | partial | `stages/emulation/stage.json`, `stages/emulation/emulation.log`, `stages/dynamic_validation/dynamic_validation.json`, `verified_chain/verified_chain.json` |
| 4 | Fuzzing / PoC context | incomplete in this bundle | `stages/fuzzing/stage.json`, `stages/poc_refinement/stage.json`, `stages/exploit_autopoc/exploit_autopoc.json`, `stages/poc_validation/poc_validation.json` |
| 5 | Exploit chain / verdict | inconclusive | `stages/exploit_chain/milestones.json`, `stages/exploit_policy/stage.json`, `verified_chain/verified_chain.json`, `report/report.json` |

## 1) Static finding

Start with the shipped v2.6.0 R7000 validation run:

- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/report/report.json`
- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/stages/findings/findings.json`

Suggested reviewer narrative:

1. The pipeline surfaces a top-level finding:
   - `aiedge.findings.web.exec_sink_overlap`
   - title: **Web-exposed component with command-exec sink overlap**
2. The findings bundle is not empty:
   - `findings.json` contains **3 findings** (verified):
     - `finding[0]`: `aiedge.findings.web.exec_sink_overlap` — carries the full 5-entry `reasoning_trail` (see §2)
     - `finding[1]`: `aiedge.findings.inventory.string_hits_present` — trail length 0 (no LLM engagement on this run)
     - `finding[2]`: `aiedge.findings.exploit.candidate_plan` — trail length 0
   - `reasoning_trail_count` in the run is **1** — meaning exactly 1 of 3 findings carries a trail, matching the selective-triage semantics (LLM only engages on the synthesis finding that plausibly represents a real vulnerability)
3. The finding is framed as evidence-bearing, not as a final exploit verdict.

Use the report as the first screenshot / artifact reference:

- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/report/analyst_report.md`

## 2) LLM triage reasoning trail

Use the LLM-triaged evidence chain to show *why* the finding was kept, downgraded, or prioritized.

Primary artifacts:

- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/stages/adversarial_triage/triaged_findings.json`
- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/stages/fp_verification/verified_alerts.json`
- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/report/analyst_report.md`

Suggested reviewer narrative:

1. The reasoning trail records advocate / critic / decision style evidence.
2. The trail is there to explain the triage decision, not to assert exploitability by itself.
3. If a trail entry references a matched downstream evidence lineage, cite it as provenance only.

Do **not** write this step as “the exploit is proven here.”  
It is a reasoning / triage step, not a final exploit verdict.

### Verified reasoning_trail content (finding[0])

Actually inspected from `stages/findings/findings.json` on this run. 1 finding has a trail, and that finding carries 5 entries. All five are recorded below exactly as written to the artifact — no paraphrasing or invention.

Finding identifier: `aiedge.findings.web.exec_sink_overlap`
- category: `vulnerability`
- severity: `high`
- confidence: `0.78`
- priority_score: `0.465`
- affected binaries (real evidence paths):
  - `stages/extraction/_firmware.bin.extracted/squashfs-root/opt/rcagent/cgi/rccommand.cgi`
  - `stages/extraction/_firmware.bin.extracted/squashfs-root/opt/remote/bin/RMT_invite.cgi`
  - `stages/extraction/_firmware.bin.extracted/squashfs-root/usr/sbin/httpd`

| # | stage | step | verdict | model | rationale (first ~200 chars, verbatim) |
|---|-------|------|---------|-------|----------------------------------------|
| 0 | `findings` | `synthesis_match` | `matched_alerts` | — | "Matched 1 downstream alerts to 1 affected binaries (1 triaged, 1 verified). Sampled top 1 alerts by confidence: system→system@rccommand.cgi." |
| 1 | `fp_verification` | `llm_verdict` | `maintain` | `sonnet` | "The provided path shows HTTP input flowing into system() and then to another system() call, with no evidence of sanitizer functions, constant-only branch selection, or fixed system-file sourcing." |
| 2 | `adversarial_triage` | `advocate` | `exploit_path_plausible` | `sonnet` | "The finding is consistent with real remote command injection because attacker-controlled HTTP input is shown reaching shell execution in a CGI context: HTTP_REQUEST → rccommand.cgi:system() → ..." |
| 3 | `adversarial_triage` | `critic` | `downgrade` | `sonnet` | "This record is insufficient to claim practical RCE: it shows only a coarse static chain (HTTP → system → system) without argument-level proof that attacker bytes reach the final command string." |
| 4 | `adversarial_triage` | `decision` | `downgrade` | — | "Critic cited a strong mitigation; confidence reduced from 0.550 to 0.350" (delta = -0.2) |

**Observation**: finding[1] (`inventory.string_hits_present`) and finding[2] (`exploit.candidate_plan`) have empty trails on this run; only the top synthesis finding carries the debate. This matches the reviewer-intended "selective LLM triage" semantics — trail is attached where LLM actually engaged.

## 3) Emulation / dynamic validation

Use the emulation and dynamic validation artifacts to show the runtime test boundary.

Primary artifacts:

- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/stages/emulation/stage.json`
- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/stages/emulation/emulation.log`
- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/stages/dynamic_validation/dynamic_validation.json`
- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/verified_chain/verified_chain.json`

Useful facts already confirmed in the bundle:

- `emulation` stage status: `ok`
- `dynamic_validation` status: `partial`
- `verified_chain.execution.mode`: `sequential`
- `verified_chain.execution.max_workers`: `1`

Suggested reviewer narrative:

1. Show the emulation log as the controlled runtime evidence.
2. Show that dynamic validation exists, but keep the status honest.
3. If the dynamic verdict remains inconclusive, say so explicitly.

## 4) Fuzzing / PoC context

This bundle contains exploit-development context, but **not** a fully closed fuzzing proof.

Primary artifacts:

- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/stages/fuzzing/stage.json`
- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/stages/poc_refinement/stage.json`
- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/stages/exploit_autopoc/exploit_autopoc.json`
- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/stages/poc_validation/poc_validation.json`

Known current statuses in this run:

- `fuzzing`: `skipped`
- `exploit_autopoc`: `partial`
- `poc_validation`: `failed`

Suggested reviewer narrative:

1. Present the PoC / fuzzing lane as contextual support.
2. If you do not have a completed fuzzing campaign for this exact firmware, say that directly.
3. Use this step to explain the evidence pipeline, not to overclaim a working exploit.

## 5) Exploit chain / verdict

This is the final reviewer-facing verdict step.

Primary artifacts:

- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/stages/exploit_chain/milestones.json`
- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/stages/exploit_policy/stage.json`
- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/verified_chain/verified_chain.json`
- `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c/report/report.json`

Known verdict details in the bundle:

- `verified_chain.verdict.state`: `inconclusive`
- `verified_chain.verdict.reason_codes`: includes `missing_exploit_bundle`
- `exploit_chain` stage status: `ok`
- `exploit_policy` stage status: `skipped`

### Verified chain_construction summary

Actually inspected from `stages/chain_construction/chains.json` → `summary`:

```json
{
  "cross_binary": 0,
  "cross_binary_ipc": 0,
  "llm_generated": 3,
  "same_binary": 50,
  "total_chains": 50
}
```

50 chains constructed on this run:
- 47 are `same_binary` static chains (evidence: decompiled colocation, e.g. `chains[0]` — "Same-binary chain: `sscanf` → `sprintf` in `FUN_00016730` @ `00016730`")
- 3 are `llm_generated` hypotheses
- 0 cross-binary or cross-binary IPC (expected — this is single-firmware deterministic static output)

Each chain carries a `missing_evidence` field. `chains[0].missing_evidence` is:
- "Dynamic validation of data flow"
- "Runtime confirmation of exploitability"

This is the self-reported gap the chain itself advertises — not hidden.

### Verified exploit_chain gate

From `stages/exploit_chain/milestones.json`:

```json
{
  "exploit_gate": {
    "attestation": "authorized",
    "flag": "lab",
    "scope": "lab-only"
  }
}
```

`milestones[0]` (`reachability`) carries the honest note:
> "Reachability stage output not found; defaulting to partial. Run the reachability stage for accurate assessment."

### Verified poc_validation block reason

`stages/poc_validation/poc_validation.json` → `status: failed` with block:

```json
{
  "blocked": [
    {
      "note": "Required exploit-stage artifacts are missing.",
      "reason_code": "POLICY_PREREQ_STAGE_ARTIFACT_MISSING",
      "target": "stages"
    }
  ]
}
```

This is exactly the "governance fail-closed" behavior the architecture guarantees — SCOUT refuses to emit a PoC success verdict when prerequisite artifacts are missing. It is a feature, not an incident.

Suggested reviewer narrative:

1. The chain assembly exists and is audit-ready.
2. The verdict is still **inconclusive** because the bundle does not establish exploitability end-to-end.
3. The correct claim is “evidence assembled, exploitability not yet proven,” not “confirmed exploit.”

## Suggested one-line summary for the reviewer

> The R7000 demo shows a complete evidence flow from static finding to triage, runtime validation, and exploit-chain scaffolding, but the current bundle still ends in an **inconclusive** verdict and does **not** claim confirmed exploitability.

## What this skeleton must not claim

- It must not claim a working exploit if the verdict is still `inconclusive`.
- It must not collapse `partial`, `skipped`, or `failed` stages into success.
- It must not confuse the SBOM follow-up rerun with the exploit demo itself.

## Recommended reviewer-facing framing

- Slide 1: static finding from `report/analyst_report.md`
- Slide 2: reasoning trail excerpt from `stages/adversarial_triage/triaged_findings.json` / `stages/findings/findings.json`
- Slide 3: emulation + dynamic validation boundary from `stages/emulation/emulation.log` and `stages/dynamic_validation/dynamic_validation.json`
- Slide 4: exploit-chain scaffolding from `stages/chain_construction/chains.json`
- Slide 5: final honest verdict from `verified_chain/verified_chain.json` (`inconclusive`, `missing_exploit_bundle`)



## Reviewer-facing claim boundary

Use this demo to show that SCOUT can carry one firmware from static finding → LLM triage → runtime validation boundary → exploit-chain scaffolding under governance controls. Do **not** describe this bundle as a working exploit or a confirmed compromise; the correct final state is still `inconclusive`.
