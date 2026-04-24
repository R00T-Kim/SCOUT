# Confidence Semantic Break — v2.6

v2.6은 `confidence`의 의미를 바꿨다. 이 문서는 **v2.5.x 이전 consumer**가 v2.6 결과를 어떻게 읽어야 하는지 명시한다.

## 한 줄 요약

- **v2.5.x 이전**: `confidence`가 detection + EPSS + reachability + backport + CVSS 성격을 일부 섞어 가졌다.
- **v2.6+**: `confidence`는 **detection evidence only**.
- 운영 우선순위는 `priority_score` / `priority_inputs`가 맡는다.

즉,

> v2.6의 `confidence`는 더 이상 "운영 우선순위 점수"가 아니다.

## Before / After

| 버전 | `confidence` 의미 | 운영 우선순위 | 해석 |
|---|---|---|---|
| v2.5.x 이하 | detection + 운영 신호 혼합 | 사실상 `confidence` 하나에 혼합 | 점수는 편했지만 의미가 오염됨 |
| v2.6+ | detection evidence only | `priority_score`, `priority_inputs` | detection과 ranking을 분리 |

## 왜 바꿨나

외부 리뷰에서 핵심 비판은 다음이었다.

- EPSS / reachability / backport가 detection confidence에 섞이면
  `confidence`가 탐지 신뢰도인지 운영 우선순위인지 불명확하다.
- 결과적으로 `confidence` 하나만 보고는
  "실제로 증거가 강한 finding"과
  "운영상 먼저 봐야 할 finding"을 구분할 수 없다.

v2.6은 이 문제를 해결하기 위해:

- `confidence` = **증거 강도**
- `priority_score` = **운영 우선순위**
- `priority_inputs` = **우선순위 근거**

로 쪼갰다.

## 현재 의미

### `confidence`
- 정적/구조적/증거 기반 detection 신호만 반영
- evidence tier와 함께 읽어야 함
- high priority finding이어도 evidence가 약하면 confidence는 낮을 수 있음

### `priority_score`
- EPSS
- reachability
- backport
- CVSS
- detection confidence 일부

를 섞은 **운영 triage 점수**

### `priority_inputs`
- `priority_score`를 구성한 입력 신호를 표면화
- score 하나로 숨기지 않고 설명 가능하게 함

## Consumer migration guide

### 하지 말아야 하는 것

- v2.6 결과에서 `confidence >= X`를 그대로 v2.5.x와 같은 의미로 비교
- `confidence`만으로 remediation priority를 정하기

### 해야 하는 것

- detection gate:
  - `confidence`
  - `evidence_tier`
- triage/ranking:
  - `priority_score`
  - `priority_inputs`

를 분리해서 읽는다.

## 권장 해석

### detection quality를 보고 싶을 때
- `confidence`
- `evidence_tier`
- `reasoning_trail`

### 운영 우선순위를 정하고 싶을 때
- `priority_score`
- `priority_bucket_counts`
- `priority_inputs`

## 문서 규율

README / status / results overview에서는:

- `confidence`를 exploitability 또는 business priority로 설명하지 않는다.
- exploitability / triage ordering은 `priority_score` 또는 future pair-eval lane으로 설명한다.
- ROC / threshold 문맥에서는 `confidence`와 `priority_score`를 섞어 쓰지 않는다.

---

## v2.7.2 후속: `DECOMPILED_COLOCATED_CAP` 분리 (Phase 2C++.1)

v2.7.2는 `confidence` 의미는 그대로 두고 **cap 계층만 5단계로 확장**했다. 이전에는 `taint_propagation.decompiled_colocated`가 inline 리터럴 `0.50`을 사용해 semantic이 `confidence_caps.py` 밖에 흩어져 있었다.

### 변경 전/후

| 버전 | decompiled_colocated cap | 근거 |
|---|---|---|
| v2.4–v2.7.1 | 0.50 (inline literal) | 주석 "slightly above co-occurrence(0.40)" — 유일한 문서화 |
| v2.7.2+ | 0.45 (`DECOMPILED_COLOCATED_CAP`) | 상수 + docstring + unit test로 고정 |

### 새 cap 계층 (5 tier ascending)

```
SYMBOL_COOCCURRENCE       0.40   심볼 공존만. 코드 경로 미확인
DECOMPILED_COLOCATED      0.45   디컴파일 body 내 공존. inline CALL 노출 분 +0.05
STATIC_CODE_VERIFIED      0.55   디컴파일 코드 검토됨, LLM taint trace는 없음
STATIC_ONLY               0.60   static_reference observation ceiling
PCODE_VERIFIED            0.75   P-code SSA dataflow로 source→sink 확증
```

### 왜 0.45인가 (v2.4.0 외부 리뷰 반영)

v2.4.0 외부 리뷰(`docs/upgrade_plz.md`)는 Strategy 3 `decompiled_colocated`의 confidence 0.60이 symbol co-occurrence(0.40)과 evidence 수준이 본질적으로 같은데 +0.20 bonus를 받는다고 지적했다. v2.5–v2.7.1 동안 inline 값이 0.50으로 낮아졌지만 cap 계층 밖에 있어 semantic이 흐렸다. v2.7.2는:

1. `confidence_caps.py`에 별도 상수 분리 → semantic ladder 외부 인용 가능
2. 0.50 → **0.45** 추가 하향 — SYMBOL_COOCCURRENCE(0.40) 바로 위 위치가 "증거 수준 동등 + inline CALL 노출분 +0.05"를 정확히 표현
3. STATIC_CODE_VERIFIED(0.55) 아래 유지 — SSA def-use proof 없음을 명시

### Consumer 영향

- `v2.7.1 이전 결과에서 decompiled_colocated confidence 0.50을 봐왔던 downstream consumer`: v2.7.2부터 동일 evidence class가 0.45로 보고됨. ROC threshold가 0.50에 고정돼 있었다면 **true positive 일부가 아래로 밀려날 수 있음**.
- 완화: `priority_score`는 이 cap 변화에 영향받지 않음 (weights 재계산 없음). detection threshold를 0.45로 조정하면 v2.7.1 이전과 recall 동일.
- CVE finding은 `cve_scan.py`에서 `STATIC_CODE_VERIFIED_CAP=0.55`를 그대로 쓰므로 영향 없음.
