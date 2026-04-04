# SCOUT 평가용 판정 기준

이 문서는 SCOUT 결과를 **논문화/발표 가능한 방식으로 수치화**하기 위한 판정 기준입니다.  
핵심은 `후보(candidate)` 단위, `취약점(cluster)` 단위, `실행(run)` 단위를 분리해서 기록하는 것입니다.

---

## 1. 평가 단위

## 1-1. 후보(candidate) 단위

SCOUT가 한 번의 run에서 생성한 개별 finding/candidate 1건을 의미합니다.

이 단위로 계산하는 지표:

- raw precision
- false positive rate
- duplicate rate
- blocked / unverified rate
- top-k hit rate

## 1-2. 취약점(cluster) 단위

서로 다른 candidate라도 **실제 root cause가 같으면 하나의 cluster** 로 묶습니다.

예:

- 같은 CGI 입력점에서 같은 `system()` sink로 가는 여러 후보
- 같은 CVE를 서로 다른 evidence path로 중복 보고한 후보

이 단위로 계산하는 지표:

- deduplicated precision
- recall
- known CVE hit rate
- unique confirmed count

## 1-3. 실행(run) 단위

동일한 옵션과 환경으로 수행한 한 번의 분석 캠페인입니다.

이 단위로 계산하는 지표:

- success / partial / fatal
- wall time
- extraction quality
- inventory quality
- emulation success
- campaign cost

---

## 2. 수동 판정 라벨

모든 candidate는 아래 라벨 중 **정확히 하나**로 닫습니다.

### `TP_confirmed`

실제 root cause가 맞고, 재현 또는 강한 검증 증거가 확보된 경우.

조건 예시:

- dynamic validation artifact 존재
- PoC skeleton이 실제 비정상 동작을 재현
- known CVE 또는 정답과 명확히 매칭

### `FP_rejected`

후보가 틀렸거나, 반증되었거나, 취약점으로 보기 어려운 경우.

조건 예시:

- 입력이 sink까지 도달하지 않음
- sink가 있으나 attacker-controlled path가 아님
- 단순 string overlap으로만 탐지됨
- 분석가 수동 검증 결과 취약점 아님

### `UNVERIFIED_blocked`

취약점 여부를 판단할 만큼의 실행/환경/시간이 확보되지 않은 경우.

조건 예시:

- extraction 불충분
- emulation 불가
- 하드웨어/프로토콜 의존성 부족
- validation time budget 초과

**주의:** `UNVERIFIED_blocked` 는 FP로 세면 안 됩니다.

### `DUPLICATE_alias`

다른 candidate와 동일한 root cause로 묶이는 경우.

조건 예시:

- evidence path만 다르고 같은 취약점
- 동일 컴포넌트/동일 sink/동일 entrypoint
- known CVE 하나에 여러 alert가 매달림

### `INFO_non_actionable`

냄새는 있지만 취약점 candidate로 보긴 어렵고, 정보성으로만 유지하는 경우.

조건 예시:

- 일반적인 노출 신호
- 추가 triage는 가능하지만 직접적인 취약점은 아님
- tool feedback은 유효하나 vulnerability metric에는 넣기 애매함

---

## 3. 판정 절차

각 candidate는 아래 순서대로 판정합니다.

1. **evidence refs 확인**
2. **source / sink / call chain / IPC chain 확인**
3. **known CVE / 공개 advisory / 기존 수동 ground truth 매칭 확인**
4. **동적 검증 가능 여부 판단**
5. 아래 중 하나로 종료:
   - TP_confirmed
   - FP_rejected
   - UNVERIFIED_blocked
   - DUPLICATE_alias
   - INFO_non_actionable

### 우선순위 규칙

동일 cluster에 여러 candidate가 있으면:

1. TP_confirmed가 하나라도 있으면 cluster는 TP
2. TP는 없고 FP만 있으면 cluster는 FP
3. TP/FP 없이 blocked만 있으면 cluster는 UNVERIFIED
4. duplicate는 개별 candidate에는 남기되, cluster 대표 1건만 남김

---

## 4. 지표 계산 규칙

## 후보(candidate) 기준

- `raw_alert_precision = TP_confirmed_alerts / evaluated_alerts`
- `false_positive_rate = FP_rejected_alerts / evaluated_alerts`
- `duplicate_rate = DUPLICATE_alias_alerts / total_alerts`
- `unverified_rate = UNVERIFIED_blocked_alerts / total_alerts`

여기서:

- `evaluated_alerts = TP_confirmed + FP_rejected`
- `UNVERIFIED_blocked` 는 precision 분모에 넣지 않음

## 취약점(cluster) 기준

- `dedup_precision = TP_confirmed_clusters / evaluated_clusters`
- `ground_truth_recall = matched_ground_truth_vulns / total_ground_truth_vulns`
- `known_cve_hit_rate = matched_known_cve_samples / total_known_cve_samples`

## run 기준

- `success_rate = success_runs / total_runs`
- `partial_rate = partial_runs / total_runs`
- `fatal_rate = fatal_runs / total_runs`
- `mean_time_to_first_tp = Σ(time_to_first_tp_per_sample) / sample_count`

---

## 5. CSV 템플릿별 사용법

## `scout_campaign_runs_template.csv`

run 실행 설정과 품질 지표를 기록합니다.

필수 목적:

- 옵션 동결
- extractor 버전 기록
- 실행 환경 통일
- 벤치마크 재현성 확보

## `scout_candidate_registry_template.csv`

후보 1건당 최종 판정을 기록합니다.

핵심 컬럼:

- `candidate_id`
- `cluster_id`
- `stage_origin`
- `finding_id`
- `manual_label`
- `validation_env`
- `gt_mapping`
- `duplicate_of`

## `scout_ground_truth_registry_template.csv`

known CVE, 공개 advisory, 기존 수동 분석 결과를 기록합니다.

핵심 목적:

- recall 계산
- known-vuln benchmark 구성
- candidate ↔ ground truth 매핑 고정

---

## 6. 운영 원칙

1. **Known-vuln 평가와 novel discovery 평가는 섞지 않습니다.**
2. **Blocked는 FP가 아닙니다.**
3. **Raw alert와 deduplicated cluster를 둘 다 공개합니다.**
4. **Extractor / CLI / env 옵션은 반드시 기록합니다.**
5. **Stage origin을 남겨 어떤 모듈이 실제 기여했는지 추적합니다.**

---

## 7. 권장 기본값

- `manual_label` 기본 후보군:
  - `TP_confirmed`
  - `FP_rejected`
  - `UNVERIFIED_blocked`
  - `DUPLICATE_alias`
  - `INFO_non_actionable`
- `validation_env` 권장 값:
  - `static_only`
  - `firmware_rootfs_only`
  - `qemu_user`
  - `firmae`
  - `pandawan`
  - `hardware`
- `gt_mapping` 권장 값:
  - `known_cve`
  - `vendor_advisory`
  - `manual_known_issue`
  - `none`

---

## 8. 한 줄 원칙

> SCOUT 평가는 “후보를 얼마나 많이 뽑았는가”보다  
> **분석 가능한 run에서 후보를 얼마나 정확하게, 얼마나 재현 가능하게 정리했는가**로 판단합니다.
