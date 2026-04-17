# Benchmark Pair Gap (Reviewer Items B-1 / C)

이 문서는 현재 Phase 2C에서 수행 중인 **2C.6 full corpus rerun**이 무엇을 해결하고, 무엇을 해결하지 못하는지 명시한다.

## 요약

- 현재 2C.6 rerun은 **SBOM/CVE 재측정**과 corpus-wide output refresh에는 유효하다.
- 다만 reviewer-facing 숫자는 **extraction success rate**를 먼저 분리해야 한다. `pipeline capable != value delivered` 이므로, SBOM fix 영향은 전체 corpus가 아니라 **extraction-success subset**에서만 해석해야 한다.
- 하지만 reviewer item:
  - **[B-1] known-CVE vulnerable/patched pair 기반 recall + FP rate**
  - **[C] confidence cap ROC / tier별 TP/FP 근거**
  는 **현재 코퍼스만으로 자동 산출되지 않는다.**

즉, 2C.6이 끝나도 다음 숫자는 바로 나오지 않는다:

- pair-grounded recall
- patched-version FP rate
- tier별 TP/FP
- confidence cap ROC

## 왜 현재 2C.6으로는 부족한가

현재 2C.6이 물고 있는 코퍼스는:

- `benchmark-results/firmae-20260330_0259/archives/*/*`

이며, 현재 확인 기준:

- bundle count: **1114**
- vendor distribution:
  - `netgear 375`
  - `dlink 262`
  - `tplink 148`
  - `trendnet 112`
  - `asus 105`
  - `linksys 55`
  - `belkin 37`
  - `zyxel 20`

이 코퍼스/메타데이터에는:

- `patched` / `vulnerable` pair label
- ground-truth TP/FP label
- tier별 TP/FP logging schema

가 없다.

또한 현재 2C.6 rerun summary row는:

- `cve_count`
- `digest_verifier_ok`
- `report_verifier_ok`
- `analyst_readiness`
- stage 상태/artifact 기반 metric

을 기록하지만,

- `tp_by_tier`
- `fp_by_tier`
- `pair_id`
- `ground_truth_label`

같은 필드는 기록하지 않는다.

## 현재 2C.6이 주는 것

2C.6 종료 후 바로 말할 수 있는 것:

- corpus-wide rerun coverage
- vendor별 rerun 분포
- firmware별 `sbom/cve_scan` delta
- `still_zero` / `zero_to_nonzero` / `nonzero_expanded` 분포
- representative real-firmware validation 결과

## 현재 2C.6이 주지 않는 것

2C.6 종료 후에도 별도 lane 없이는 말할 수 없는 것:

- vulnerable/patched pair recall
- patched-version FP rate
- tier ROC
- confidence cap calibration curve

## 대응 계획

reviewer 항목 [B-1] + [C]는 **별도 evaluation lane**으로 묶는다.

### lane 목표

- known-CVE vulnerable/patched pair를 5–10쌍 수집
- pair corpus 기준은 **extraction-success runs**에서만 잡는다.
- pair corpus 기준:
  - vulnerable side recall
  - patched side FP rate
  - tier별 TP/FP
  - confidence cap ROC
  를 동시에 산출

### 초기 pair 후보

- Netgear **R7000** (e.g. CVE-2017-5521 family)
- TP-Link **Archer C7** multi-version
- D-Link **DIR-859** (e.g. CVE-2019-17621 family)

> seed 선정 원칙: 후보 버전은 모두 extraction-success runs에서만 골라야 한다. extraction이 실패한 firmware는 pair-labeled recall/FP와 tier ROC의 ground truth로 쓰지 않는다.

## 현재 상태

- 2C.6: **completed**
- pair eval lane: **M0 completed (4 local pairs / 8 runs)**

즉 현재 상태는:

1. 2C.6 corpus baseline refresh 완료
2. 2C.7 문서/릴리즈 close-out 완료
3. reviewer item [B-1] / [C]는 M0에서 **recall 0.25 / false-positive rate 0.25**를 확보했고, 다음 단계는 표본 확장이다

## Operator note

2C.7 release 문구에는 아래를 반드시 반영해야 한다:

- “2C.6 rerun refreshed the corpus baseline”
- “pair-labeled evaluation for [B-1]/[C] remains a follow-on lane”

그래야 현재 corpus rerun 결과를 과장하지 않는다.
