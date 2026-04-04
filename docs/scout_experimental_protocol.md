# SCOUT 실험 프로토콜

이 문서는 팀원이 **SCOUT를 실제로 사용해 취약점 후보를 찾고, 도구 피드백을 남기고, 재현 가능한 실험 결과를 축적**하기 위한 운영 프로토콜입니다.  
체크리스트가 아니라, **같은 방식으로 반복 가능한 실험 절차**를 정의하는 것이 목적입니다.

---

## 1. 실험 목표

SCOUT의 목표는 Full Exploit Agent가 아니라, 다음을 만족하는 **분석가 보조 도구**임을 검증하는 것입니다.

1. 공개/허가된 펌웨어에서 **우선 확인할 취약점 후보**를 안정적으로 제시한다.
2. 각 후보에 대해 **증거 경로(evidence refs)** 와 **검증 방향(validation plan)** 을 제공한다.
3. 추출/인벤토리/그래프/리포트/뷰어 품질에 대해 **실사용자 피드백**을 수집한다.

이 프로토콜에서의 성공은 “무조건 취약점을 새로 찾는다”가 아니라,

> **SCOUT가 실제 분석 workflow에서 시간을 줄이고, 우선순위를 더 잘 잡게 도와주는지**

를 확인하는 것입니다.

---

## 2. 대상 선정 규칙

실험 대상은 **가능한 한 real-world 공개 펌웨어**만 사용합니다. 기본 우선순위는 아래와 같습니다.

1. 제조사가 공개한 실제 제품 펌웨어 이미지
2. 이미 공개된 CVE 또는 vendor advisory가 존재하는 실제 제품 펌웨어
3. 기존에 팀이 수동 분석을 완료한 실제 제품 기준 샘플

워게임/CTF/교육용 펌웨어는 기본 평가군에서 제외합니다. 정말 불가피하게 사용할 경우에도 **별도 보조 트랙**으로만 기록하고, main benchmark / main precision-recall 수치에는 섞지 않습니다.

### 제외 대상

- 출처가 불명확한 사설 이미지
- 권한 없는 장비/실환경만을 요구하는 대상
- 법적/윤리적으로 검증 범위가 불명확한 대상

### 권장 샘플 구성

- **Known-vulnerable set**: 공개 CVE / vendor advisory가 존재하는 실제 제품 펌웨어
- **Likely-vulnerable set**: 공개 펌웨어지만 취약점 여부는 미확정
- **Regression set**: 팀이 이미 한 번 본 샘플 (비교/재현성 확인용)

---

## 3. 실행 프로토콜

## Phase A — 기본 분석 run 생성

모든 샘플은 먼저 `analysis` profile로 시작합니다.

```bash
./scout analyze <firmware> \
  --case-id <case_id> \
  --profile analysis \
  --ref-md ref.md
```

### 이 단계에서 반드시 기록할 것

- firmware 파일명 / sha256
- run_id / run_dir
- extraction status
- inventory quality status
- findings 수
- cve 수

### extraction이 부족하면

다음 중 하나로 처리합니다.

1. **그대로 blocked** 로 기록
2. 가능하면 **pre-extracted rootfs** 로 재실행

```bash
./scout analyze <firmware> \
  --case-id <case_id>-rootfs \
  --profile analysis \
  --no-llm \
  --rootfs <extracted_rootfs_dir>
```

이 경우 반드시 “수동 rootfs 개입”으로 별도 표시합니다.

---

## Phase B — 1차 분석가 리뷰

각 샘플은 반드시 아래 순서로 검토합니다.

1. `report/analyst_digest.md`
2. `report/analyst_digest.json`
3. `report/report.json`
4. `report/viewer.html` 또는 `./scout tui`

### 리뷰 시점 판단 기준

각 샘플을 아래 네 가지 중 하나로 분류합니다.

- **Validated candidate**: 실제 검증 가치가 높고 후속 실험 진행
- **Plausible candidate**: 그럴듯하지만 아직 근거 부족
- **False positive / low value**: 증거가 약하거나 실질 가치가 낮음
- **Blocked by extraction/runtime**: 추출 또는 실행 환경 부족

### 각 샘플에서 반드시 뽑을 것

- 상위 취약점 후보 `1~3개`
- 각 후보의 evidence refs
- 왜 이 후보를 고른 건지 한 줄 설명
- 다음 validation step

---

## Phase C — 검증 단계

기본 원칙:

- 먼저 **정적 근거 기반 validation plan** 을 세운다
- 그 다음에만 동적 검증을 시도한다
- 실험 범위는 **lab-only / authorized** 여야 한다

### 검증 단계 분기

#### C-1. 정적 검증만 수행

아래 중 하나면 정적 검증만 수행합니다.

- extraction/inventory는 충분하지만 runtime까지 갈 필요 없음
- 분석가가 false positive 여부만 확인하면 됨
- 후보가 낮은 우선순위

#### C-2. 동적 검증 시도

아래 조건이면 동적 검증을 시도합니다.

- evidence refs가 충분함
- 입력점과 sink가 비교적 분명함
- 재현 가능한 lab 범위 안임

권장 명령:

```bash
./scout stages <run_dir> --stages dynamic_validation
```

필요 시:

```bash
./scout stages <run_dir> --stages dynamic_validation,exploit_autopoc
```

단, exploit 관련 단계는 **허가된 범위에서만** 수행합니다.

---

## Phase D — 결과 기록

각 샘플마다 아래 형식의 기록을 남깁니다.

### 필수 메타데이터

- sample id
- firmware filename
- firmware sha256
- run_id
- run_dir
- extraction status
- inventory quality
- findings count
- cve count

### 필수 분석 결과

- top candidate 1~3개
- 각 candidate의 finding id / title
- 핵심 evidence refs
- analyst verdict
  - validated / plausible / false_positive / blocked
- validation notes
- tool feedback

### 필수 피드백

아래 카테고리 중 최소 1개 이상 기록합니다.

- extraction quality issue
- inventory noise issue
- graph / relationship issue
- findings priority issue
- digest / viewer usability issue
- missing evidence issue
- false positive issue
- runtime / emulation limitation

---

## 4. 측정 지표

## Tool quality metrics

- extraction ok rate
- inventory sufficient rate
- success / partial / fatal
- findings per firmware
- cve-positive firmware rate
- high-severity finding rate

## Analyst usefulness metrics

- time to first actionable candidate
- number of candidates actually reviewed
- validated candidate ratio
- false positive ratio
- blocked-by-extraction ratio
- “SCOUT가 없었으면 못 봤을 후보” 여부

## Runtime usefulness metrics

- emulation stage ok 여부
- dynamic validation 시도 여부
- 실제 runtime artifact 생성 여부
- validation plan의 실행 가능성

---

## 5. 운영 규칙

1. **한 번에 1 firmware씩 verdict를 닫는다.**
2. “좋아 보인다”가 아니라 반드시 **evidence refs** 를 함께 남긴다.
3. extraction이 부족하면 억지로 취약점 판단하지 않고 **blocked** 로 둔다.
4. 동적 검증은 **허가된 lab 범위**에서만 수행한다.
5. SCOUT의 가치는 “최종 판정 자동화”보다 **우선순위와 증거 정리**에 있다는 점을 유지한다.

---

## 6. 권장 산출물

실험이 끝나면 아래 산출물을 정리합니다.

- 샘플별 짧은 Markdown 노트
- 전체 요약표 (CSV/Markdown)
- top validated/plausible candidates 표
- blocked / fatal 원인 표
- 도구 개선 요청 목록

### 트랙 분리 규칙

- **Main track**: real-world 공개 펌웨어만 포함
- **Auxiliary track**: 교육용/데모/워게임 샘플 (필요 시만)

Main track과 Auxiliary track의 결과는 한 표에 합치지 않습니다.

---

## 7. 한 줄 운영 원칙

> SCOUT는 취약점을 “자동으로 확정”하는 도구가 아니라,  
> **분석가가 다음에 무엇을 봐야 하는지 빠르게 결정하게 돕는 실험적 보조 도구**로 평가한다.
