# Pair Evaluation Lane (post-2C.6)

이 문서는 reviewer 항목:

- **[B-1] known-CVE vulnerable/patched pair 기반 recall + FP rate**
- **[C] confidence cap ROC / tier별 TP/FP 근거**

를 위해 **2C.6 이후 별도 evaluation lane**으로 수행할 작업을 정의한다.

## 왜 별도 lane인가

현재 2C.6 corpus rerun은:

- SBOM/CVE 재측정
- corpus-wide output refresh
- vendor별 rerun baseline 갱신

에는 유효하지만,

- vulnerable/patched pair label
- ground-truth TP/FP
- tier ROC

를 자동으로 주지 않는다.

즉 2C.6 완료 후에도 reviewer 숫자 [B-1]/[C]는 별도 lane이 필요하다.

## 목표

### B-1
- vulnerable firmware에서:
  - known CVE recall
- patched firmware에서:
  - FP rate

### C
- tier별 TP/FP 분포
- confidence cap ROC 근거

## 최소 corpus 목표

초기 목표는 **5–10 pair**다.

### corpus source constraint

- pair corpus는 **반드시 extraction-success runs**에서만 구성한다.
- extraction이 partial/failed인 firmware는 seed 후보에서 제외한다.

### seed 후보

- **Netgear R7000**
  - 예: `CVE-2017-5521` 계열
- **TP-Link Archer C7** multi-version
- **D-Link DIR-859**
  - 예: `CVE-2019-17621` 계열

후보 선정 기준:

1. vulnerable version / patched version 둘 다 확보 가능
2. firmware artifact hash를 남길 수 있음
3. CVE reference가 공개 문서로 검증 가능
4. source run이 extraction-success subset에 속함

## lane 산출물

### 입력 corpus manifest

예상 파일:
- `benchmarks/pair-eval/pairs.json`

예상 shape:

```json
{
  "schema_version": "pair-eval-v1",
  "pairs": [
    {
      "pair_id": "netgear-r7000-cve-2017-5521",
      "vendor": "netgear",
      "model": "R7000",
      "cve_id": "CVE-2017-5521",
      "vulnerable": {
        "firmware_path": "...",
        "sha256": "..."
      },
      "patched": {
        "firmware_path": "...",
        "sha256": "..."
      }
    }
  ]
}
```

### 실행 결과

예상 출력:
- `benchmark-results/pair-eval/runs/...`
- `benchmark-results/pair-eval/pair_eval_summary.csv`
- `benchmark-results/pair-eval/pair_eval_summary.json`
- `benchmark-results/pair-eval/pair_eval_report.md`

## 로깅 요구사항

### pair-grounded finding log

각 run/pair마다 최소:

- `pair_id`
- `side`: `vulnerable|patched`
- `cve_id`
- `finding_id`
- `category`
- `evidence_tier`
- `confidence`
- `priority_score`
- `matched_cve_id`
- `ground_truth`
  - `tp`
  - `fp`
  - `fn`
  - `tn` (필요 시 집계 레벨)

### tier ROC log

추가 aggregate:

- `tp_by_tier`
- `fp_by_tier`
- `fn_by_tier`
- `precision_by_tier`
- `recall_by_tier`

## 평가 규칙

### vulnerable side

- target CVE를 직접 surface한 finding이 있으면 recall hit
- missed면 FN
- scoring은 extraction-success runs만 집계한다.

### patched side

- target CVE 또는 동등 claim을 유지하면 FP
- clean하면 TN/clean
- scoring은 extraction-success runs만 집계한다.

### tier 평가

- `symbol_only`
- `static_colocated`
- `static_interproc`
- `pcode_verified`
- `dynamic_verified`
- `unknown`

각 tier별로 TP/FP를 따로 집계한다.
이 집계 역시 extraction-success runs에서만 수행한다.

## recommended implementation order

1. pair corpus manifest 생성
2. pair run executor 추가
3. finding→ground truth matcher 추가
4. tier별 TP/FP logger 추가
5. summary/ROC report 생성

## 현재 상태

- 2C.6: completed
- pair gap 문서: `docs/benchmark_pair_gap.md`
- pair eval lane: **M0 completed (4 local pairs / 8 extraction-success runs reused from 2C.6)**

### M0 result snapshot

- pair corpus size: **4**
- resolved vulnerable runs: **4**
- resolved patched runs: **4**
- recall: **0.25**
- false-positive rate: **0.25**
- tier ROC snapshot: **symbol_only only** (`tp=1`, `fp=1`, `fn=3`, `tn=3`)

Interpretation:
- **R7000** hit the target CVE on both vulnerable and patched images (`tp` + `fp`)
- **DIR-868L / DIR-850L / Archer C7 v2** stayed `fn` on vulnerable and `tn` on patched in this M0 lane
- the current ROC is degenerate because every selected pair-side mapped to the same top vulnerability finding (`web.exec_sink_overlap`, `confidence=0.78`, `evidence_tier=symbol_only`)

Generated outputs:
- `benchmark-results/pair-eval/pair_eval_summary.csv`
- `benchmark-results/pair-eval/pair_eval_summary.json`
- `benchmark-results/pair-eval/pair_eval_report.md`
- `benchmark-results/pair-eval/pair_eval_findings.csv`

즉, 이 문서는 더 이상 초안만이 아니라 **M0 실행 결과를 가진 운영 문서**다.
