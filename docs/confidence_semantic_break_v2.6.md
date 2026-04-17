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
