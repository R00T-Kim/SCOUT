# Analyst Viewer Cockpit: Card-to-Artifact Mapping

This document defines what the analyst cockpit cards show, exactly which artifacts/fields they come from, and how to interpret empty/blocked states.

## Goals

- One screen answers: verdict (and why), attack-surface scale, verification/gate state, and where to look for evidence.
- Reduce manual file-hopping while preserving evidence provenance.

## Trust Boundary (Fail-Closed)

- `report/viewer.html` is a convenience UI only; it must not be treated as a verifier.
- Verifier scripts remain authoritative:
  - `python3 scripts/verify_analyst_digest.py --run-dir <run_dir>`
  - `python3 scripts/verify_aiedge_analyst_report.py --run-dir <run_dir>`
- Missing/partial/tampered evidence must be interpreted fail-closed (blocked/unknown), not as pass.

## Viewer Data Loading Model

The viewer attempts to load run-local JSON via relative fetches and falls back to embedded bootstrap JSON when fetch is unavailable (notably under `file://`).

Primary payloads:

- `report/analyst_overview.json` (`schema_version=analyst_overview-v1`)
- `report/analyst_digest.json` and `report/analyst_digest.md` (`schema_version=analyst_digest-v1`)
- `report/report.json` (aggregated run report)

## Gate applicability vs verifier pass/fail

Two different concepts must not be conflated:

- Applicability / presence gates (viewer-side): derived from manifest + artifact presence (e.g., `verified_chain` may be `blocked` or `not_applicable`).
- Verifier outcomes (authoritative): produced only by running verifier scripts. A viewer "pass" badge must never imply verifier pass.

## Safety Rules for Any Links/Paths Shown

- Only show run-relative paths (paths that resolve under `<run_dir>/`).
- Never show absolute filesystem paths.
- Never emit clickable remote URLs (no `http(s)` scheme).
- Never allow `..` traversal in clickable references.
- If a reference fails safety checks, render it as plain text with a "not clickable" note and offer a copy-path affordance.

---

## Card 1: Executive Verdict

Purpose: Answer "What is the current verdict, why, and what next?"

| Field | Primary source | Fallback | JSON key paths | Empty state |
|------|-----------------|----------|----------------|------------|
| Verdict state | `report/analyst_digest.json` | `report/analyst_overview.json` | `exploitability_verdict.state` / `summary.exploitability_verdict.state` | If missing: show `blocked` and "digest not available" |
| Reason codes | `report/analyst_digest.json` | `report/analyst_overview.json` | `exploitability_verdict.reason_codes[]` / `summary.exploitability_verdict.reason_codes[]` | If missing: show `unknown` reason |
| Next actions | `report/analyst_digest.json` | none | `next_actions[]` | If empty/missing: show `unknown` and instruct to re-run digest verifier |
| Report completeness | `report/report.json` | `report/analyst_overview.json` | `report_completeness.gate_passed` / `summary.report_completeness.gate_passed` | If missing: `blocked` |
| Run completion status | `report/report.json` | none | `run_completion.is_final`, `run_completion.is_partial`, `run_completion.required_stage_statuses` | If missing: `blocked` |

Copy/link behavior:

- Provide run-relative links to the digest artifacts: `report/analyst_digest.md`, `report/analyst_digest.json`.

---

## Card 2: Attack Surface Scale

Purpose: Answer "How big is the attack surface, at a glance?" (counts only; no new claims).

| Field | Primary source | Fallback | JSON key paths | Empty state |
|------|-----------------|----------|----------------|------------|
| Endpoints | `report/analyst_overview.json` | `report/report.json` (if available) | `summary.attack_surface_summary.summary.endpoints` and/or `summary.endpoints_summary.summary.endpoints` | If missing: show `unknown` |
| Surfaces | `report/analyst_overview.json` | `report/report.json` | `summary.attack_surface_summary.summary.surfaces` | If missing: `unknown` |
| Unknowns | `report/analyst_overview.json` | `report/report.json` | `summary.attack_surface_summary.summary.unknowns` | If missing: `unknown` |
| Non-promoted | `report/analyst_overview.json` | `report/report.json` | `summary.attack_surface_summary.summary.non_promoted` | If missing: `unknown` |
| Inventory scale | `report/analyst_overview.json` | `report/report.json` | `summary.inventory_summary.summary.files`, `summary.inventory_summary.summary.binaries` | If missing: `unknown` |
| Extraction scale | `report/analyst_overview.json` | `report/report.json` | `summary.extraction_summary.summary.extracted_file_count` | If missing: `unknown` |

Copy/link behavior:

- Link to `report/analyst_overview.json`.
- Link to `report/report.json`.

---

## Card 3: Verification Status

Purpose: Answer "What is blocked, what is not applicable, and what needs verifiers?"

| Concept | Primary source | Fallback | JSON key paths | Notes |
|--------|-----------------|----------|----------------|------|
| Overview gates | `report/analyst_overview.json` | none | `gates[]` items: `{id,status,reasons[]}` | These are *viewer-side* applicability/presence indicators, not verifier pass/fail |
| Report completeness | `report/analyst_overview.json` | `report/report.json` | `summary.report_completeness.status`, `summary.report_completeness.gate_passed` / `report_completeness.*` | Completeness is necessary but not sufficient for VERIFIED |
| Verified-chain prerequisite | `report/analyst_overview.json` | none | `gates[]` item where `id="verified_chain"` | `blocked` often means missing verifier artifacts (fail-closed) |
| 8MB contract applicability | `report/analyst_overview.json` | `manifest.json` (if present) | `gates[]` item `id="final_report_contract_8mb"` | `not_applicable` when `track!=8mb or track missing` |

Copy/link behavior:

- Link to the verifier commands (text only) and to `report/analyst_overview.json`.

---

## Card 4: Evidence Navigator

Purpose: Answer "Where do I click to see the evidence quickly?"

| Item | Primary source | Fallback | JSON key paths | Safety behavior |
|------|-----------------|----------|----------------|----------------|
| Canonical links | `report/analyst_overview.json` | none | `links.*` (e.g., `links.viewer_html`, `links.report_json`) | Enforce run-relative; if unsafe, render as text |
| Artifact presence list | `report/analyst_overview.json` | none | `artifacts[]` (each: `ref`, `status`, optional `sha256`, `required`) | If missing required artifact => highlight as blocked |
| Digest evidence index | `report/analyst_digest.json` | `report/analyst_digest.md` | `evidence_index[]` refs + sha256 | Render refs as safe links/text; show sha256 for provenance |
| Finding evidence refs | `report/analyst_digest.json` | none | `finding_verdicts[].evidence_refs[]` | Render refs as safe links/text |
| Finding verifier refs | `report/analyst_digest.json` | none | `finding_verdicts[].verifier_refs[]` | If empty, render "none"; do not infer pass |

Suggested default evidence shortcuts (run-relative):

- `report/analyst_digest.md`
- `report/analyst_digest.json`
- `report/analyst_overview.json`
- `report/report.json`
- `report/viewer.html`

## Card 5: Runtime Communication Model

Purpose: Answer "어떤 런타임 통신 관계가 관측됐고, 어떤 근거로 연결되었는가?"  

| Field | Primary source | Fallback | JSON key paths | Empty state |
|------|-----------------|----------|----------------|------------|
| Status | `report/analyst_overview.json` | `report/report.json` | `summary.runtime_model.status` / `runtime_model.status` | `blocked` |
| Hosts | `report/analyst_overview.json` | none | `summary.runtime_model.summary.hosts` | `0` |
| Services | `report/analyst_overview.json` | none | `summary.runtime_model.summary.services` | `0` |
| Components | `report/analyst_overview.json` | none | `summary.runtime_model.summary.components` | `0` |
| D+E rows | `report/analyst_overview.json` | `report/report.json` | `summary.runtime_model.summary.rows_dynamic_exploit` | `0` |
| Evidence matrix | `stages/graph/communication_matrix.json` (from `graph` stage) | none | `rows[].host`, `rows[].service`, `rows[].observation`, `rows[].evidence_badge` | `[]` |

Copy/link behavior:

- 권장 확인 경로: `stages/graph/communication_graph.json`, `stages/graph/communication_matrix.json`, `stages/graph/communication_matrix.csv`
- 근거 결합이 필요한 경우 `stages/graph/communication_graph.cypher` 또는 `stages/graph/communication_graph.queries.cypher`로 상관성 검증 가능

신뢰 규칙:
- `runtime` 근거가 있는 항목은 `evidence`/`runtime` 태그가 함께 있어야 하며, `D+E` 또는 `D+E+V`가 포함된 행은 우선도 높음.
- 관측 증거 없는 값은 `blocked/unknown`로 남겨야 하며 verifier 결과를 대신하지 않음.

---

## Real ER Run Example (Concrete Values)

Run: `aiedge-runs/2026-02-17_1041_sha256-e3d3fe0697bc/`

- Verdict:
  - `report/analyst_digest.json` -> `exploitability_verdict.state = "NOT_ATTEMPTED"`
  - `report/analyst_digest.json` -> `exploitability_verdict.reason_codes = ["NOT_ATTEMPTED_REQUIRED_VERIFIER_MISSING"]`
- Next actions:
  - `report/analyst_digest.json` -> `next_actions[0] = "Run required verifier pipeline to produce verified_chain artifacts."`
- Attack surface scale:
  - `report/analyst_overview.json` -> `summary.attack_surface_summary.summary.endpoints = 1781`
  - `report/analyst_overview.json` -> `summary.attack_surface_summary.summary.surfaces = 47`
  - `report/analyst_overview.json` -> `summary.attack_surface_summary.summary.unknowns = 200`
  - `report/analyst_overview.json` -> `summary.attack_surface_summary.summary.non_promoted = 105`
- Report completeness:
  - `report/report.json` -> `report_completeness.gate_passed = true`
  - `report/report.json` -> `run_completion.is_final = true` and `run_completion.required_stage_statuses.inventory = "partial"`

Interpretation (fail-closed):

- Even with completeness passed, `NOT_ATTEMPTED` means the run is not promotable to VERIFIED status yet.
- The cockpit should surface next actions and the missing prerequisites without upgrading verifier meaning.
