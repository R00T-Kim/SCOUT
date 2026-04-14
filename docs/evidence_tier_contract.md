# Evidence Tier Contract (2C.3)

`evidence_tier`는 SCOUT finding이 **어떤 수준의 증거** 위에 서 있는지 나타내는 additive field다.

## 목적

- `confidence` 하나에 섞여 있던 서로 다른 증거 수준을 분리한다.
- `confidence`는 **같은 tier 내부의 상대 점수**로만 읽는다.
- tier가 다른 finding끼리는 `confidence` 숫자만으로 직접 비교하지 않는다.

## Tier 값

| Tier | 의미 |
|---|---|
| `symbol_only` | import/symbol co-occurrence, binary-analysis fallback, graph-only 신호 등 약한 정적 단서 |
| `static_colocated` | 같은 함수/같은 컴포넌트 수준의 정적 근거 |
| `static_interproc` | 함수 간 / 경로 수준의 정적 근거 |
| `pcode_verified` | Ghidra P-code 수준의 정적 검증 |
| `dynamic_verified` | 동적 재현/실행 기반 검증 |
| `unknown` | 위 분류로 안전하게 귀속할 수 없는 finding |

## 현재 매핑

### Method 기반

| Method | Tier |
|---|---|
| `static_inference` | `symbol_only` |
| `static_inference_ba` | `symbol_only` |
| `source_sink_graph` | `symbol_only` |
| `attack_surface_fallback` | `symbol_only` |
| `decompiled_colocated` | `static_colocated` |
| `decompiled_interprocedural` | `static_interproc` |
| `llm_taint_trace` | `static_interproc` |
| `pcode_verified` / `pcode_dataflow` / `pcode_colocated` | `pcode_verified` |

### Heuristic 기반

- `exploitability_tier in {dynamic_repro, exploitability_assessed}` → `dynamic_verified`
- `cve_id` 또는 `families`에 `cve_match` 포함 → `static_colocated`
- `aiedge.findings.web.exec_sink_overlap` → `symbol_only`
- 나머지 → `unknown`

## Surface rollout

- `stages/findings/findings.json`
  - 각 finding에 `evidence_tier`
  - top-level `tier_counts`
- `stages/cve_scan/cve_matches.json`
  - `finding_candidates[*].evidence_tier`
- `stages/taint_propagation/*`
  - alerts/results entry에 `evidence_tier`
- `stages/fp_verification/verified_alerts.json`
  - `verified_alerts[*].evidence_tier`
- `stages/adversarial_triage/triaged_findings.json`
  - `triaged_findings[*].evidence_tier`
- SARIF
  - `properties.scout_evidence_tier`
- MCP
  - `scout_list_findings` optional `evidence_tier` filter
  - `scout_filter_by_category` summary entry에 `evidence_tier`
  - `scout_filter_by_evidence_tier` 신규

## Consumer guidance

- triage/ranking은:
  1. 먼저 `evidence_tier`
  2. 그 다음 `confidence`
  3. 그 다음 `priority_score`
  순으로 읽는 것이 안전하다.
- `unknown`은 “낮은 위험”이 아니라 **아직 tier contract에 귀속되지 않은 finding**을 뜻한다.
