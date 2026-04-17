# Pair Corpus Candidates — Reviewer Items [B-1] and [C]

> **Purpose**: 리뷰어 [B-1] (CVE recall/FP rate 벤치마크)와 [C] (confidence cap ROC 근거) 동시 대응을 위한 **vulnerable ↔ patched 펌웨어 쌍 후보 리스트**.
>
> **Scope**: 이 문서는 후보 정리 + 로컬 가용성 체크 + CVE 매핑 참고점을 담는다. **실측은 별도 eval lane 실행 시점**에 진행되며, 이 문서의 매핑은 공식 어드바이저리/NVD에서 가져온 참고치다. 실제 detection recall/FP rate 수치는 실행 이후 `docs/results_overview.md`에 기입한다.
>
> **Honest disclaimer**: 아래 표의 "CVE-X → patched in version Y" 매핑은 벤더 security advisory를 참고로 기록한 것이며, **SCOUT가 실제로 각 버전에서 탐지/미탐지하는지는 eval lane 실행 후에만 확정**된다. 현재 단계에서는 "pair가 존재한다"는 주장만 한다.

---

## 1. 왜 pair corpus가 따로 필요한가

2C.6 fresh full rerun은 1124개 corpus를 돌리지만, 그 corpus는 vulnerable/patched pair 라벨이 **없다**. 리뷰어 [B-1]이 요구한 "알려진 CVE가 있는 펌웨어 버전 recall + 패치된 버전 FP rate"는 **pair가 명시된 별도 corpus**가 있어야 의미를 가진다.

즉 본 문서는:
- 2C.6 broad corpus 결과와는 **독립된 평가 lane**의 입력 후보
- 각 쌍이 "SCOUT가 CVE-X를 탐지하는가? 패치된 버전에서 FP를 내는가?"를 동시에 answer할 수 있는 구조
- 별도 규격: `docs/pair_eval_lane.md` 참고

---

## 2. Pair quality criteria

eval lane에 넣기 위한 pair 자격 기준:

| 기준 | 설명 |
|------|------|
| (a) 동일 모델/제품 | vendor model이 같아야 함 (동일 binary family 가정). 다른 제품 비교는 noise |
| (b) CVE 공식 매핑 | NVD / vendor advisory에서 "vulnerable version set" + "fixed version" 기재 확인 |
| (c) 두 버전 로컬 존재 | 실제 파일이 `aiedge-inputs/` 아래에 있어야 함 — 없으면 "gap" 표시 |
| (d) extraction 가능성 | 두 버전 모두 SCOUT extraction이 ok/partial로 종결 가능한 포맷 (binwalk 친화적) |
| (e) 명확한 sink 차이 | 패치가 소스 코드 레벨에서 관찰 가능한 sink 제거/입력 검증 추가여야 static detection에 의미가 있음 |

---

## 3. 후보 pair 테이블

**로컬 가용성 기준**으로 우선 정리. 각 rows의 CVE는 공식 advisory 참조점이며 SCOUT 실측은 eval lane 실행 이후에만 확정된다.

| # | 모델 | Vulnerable firmware (local) | Patched firmware (local) | 매핑 참고 CVE | 로컬 상태 | 우선 |
|---|------|----------------------------|--------------------------|---------------|----------|------|
| 1 | Netgear R7000 | `aiedge-inputs/firmae-benchmark/netgear/R7000-V1.0.7.12_1.2.5.zip` | `aiedge-inputs/firmae-benchmark/netgear/R7000-V1.0.9.34_10.2.36.zip` | CVE-2017-5521 (admin auth bypass via `BRS_*.html`) | 둘 다 존재 | **P0** |
| 2 | Netgear R7000 (장거리) | `aiedge-inputs/firmae-benchmark/netgear/R7000-V1.0.3.56_1.1.25.zip` | `aiedge-inputs/netgear/R7000-V1.0.11.136_10.2.120.chk` | CVE-2017-5521 + downstream patches | 둘 다 존재 (후자는 `netgear/` 원본) | P1 |
| 3 | D-Link DIR-859 | **missing** (pre-1.06B01 요구) | `aiedge-inputs/firmae-benchmark/dlink/DIR-859_REVA_FIRMWARE_PATCH_1.06B01.zip` | CVE-2019-17621 (UPnP SOAPAction 명령 주입) | vuln missing — 외부 수급 필요 | P0 (gap) |
| 4 | D-Link DIR-868L | `aiedge-inputs/firmae-benchmark/dlink/DIR868LB1_FW200KR-K02.bin` | `aiedge-inputs/firmae-benchmark/dlink/DIR868LWB1_FW200KR-K04.bin` | CVE-2018-10970 (HNAP 인증 우회) | 둘 다 존재 | P1 |
| 5 | D-Link DIR-825 rev B1 | `aiedge-inputs/firmae-benchmark/dlink/DIR825B1_FW201SS05_KR_.bin` | `aiedge-inputs/firmae-benchmark/dlink/DIR825B1_FW202SSB15beta01.bin` | CVE-2017-6190 등 (HNAP1 명령 주입) | 둘 다 존재 | P2 |
| 6 | D-Link DIR-825 rev C1 | `aiedge-inputs/firmae-benchmark/dlink/DIR825C1_FW301B12.bin` | `aiedge-inputs/firmae-benchmark/dlink/DIR825C1_FW304b03.bin` | CVE-2019-6257 (captcha command injection) | 둘 다 존재 | P2 |
| 7 | D-Link DIR-850L | `aiedge-inputs/firmae-benchmark/dlink/DIR850L_FW105KRb03_d4oi_20130425.bin` | `aiedge-inputs/firmae-benchmark/dlink/DIR850L_FW115KRb05.bin` | CVE-2019-20213 + CVE-2019-6258 (HNAP 여러 주입) | 둘 다 존재 (early→late) | P1 |
| 8 | TP-Link Archer C7 v2 | `aiedge-inputs/firmae-benchmark/tplink/Archer_C7_V2_150311_KR.zip` | `aiedge-inputs/firmae-benchmark/tplink/Archer_C7_KR__V2_160912_1474960467427z.zip` | CVE-2017-13772 (HTTP header stack BOF) | 둘 다 존재 | P1 |
| 9 | TP-Link Archer C7 v4 | `aiedge-inputs/firmae-benchmark/tplink/Archer_C7_V4_170609.zip` | `aiedge-inputs/firmae-benchmark/tplink/Archer_C7_US__V4_180425.zip` | CVE-2019-17152 (diagnostic.htm 명령 주입) | 둘 다 존재 | P2 |
| 10 | OpenWrt Archer C7 v5 | **missing** (older OpenWrt 23.05 이전) | `aiedge-inputs/openwrt/openwrt-23.05.5-ath79-generic-tplink_archer-c7-v5-squashfs-factory.bin` | N/A (baseline 비교용, vendor stock vs OpenWrt) | vuln-side 외부 수급 필요 | 보조 |

### 조합 점검

- **CVE detection recall** (vuln 쪽만): 10 pair 중 8 pair는 vulnerable 파일이 로컬에 존재 → recall test 가능
- **FP rate** (patched 쪽만): 10 pair 중 9 pair는 patched 파일이 존재 → FP test 가능
- **완전 쌍** (둘 다 존재): 7개 (#1, #2, #4, #5, #6, #7, #8, #9 일부) → 앞으로 eval lane에 바로 투입 가능

---

## 4. 외부 수급이 필요한 gap

다음 두 개는 vuln-side 파일이 로컬에 없으므로 별도 수급이 필요하다. 이 gap은 `docs/benchmark_pair_gap.md`에도 참조한다.

### Gap A: DIR-859 pre-1.06B01

- 필요 버전: DIR-859 REVA firmware versions *before* 1.06B01 (e.g. 1.05, 1.04)
- 수급 경로:
  - D-Link legacy FTP archive
  - Wayback Machine 캐시
  - internetarchive.org 펌웨어 집합
- CVE 참고: CVE-2019-17621 — SOAPAction UPnP handler 명령 주입
- **이 gap이 해소되어야** DIR-859 pair eval이 가능

### Gap B: OpenWrt Archer C7 v5 pre-23.05.5

- 필요 버전: OpenWrt 22.x 또는 21.x의 Archer C7 v5 build
- 수급 경로: downloads.openwrt.org `archive/` 하위
- 주의: OpenWrt CVE 매핑은 upstream Linux/dnsmasq/busybox 기반이라 R7000 등 vendor CVE와는 성격이 다름. baseline "CVE-less" 대조군으로 활용

---

## 5. 2순위 후보 (local에 있으나 CVE 매핑이 모호한 pair)

아래는 동일 모델 multi-version이 local에 있지만 공식 CVE 매핑이 명확하지 않아 P3 이하로 분류. 시간 허락 시 확장용.

| 모델 | 버전 쌍 후보 | 비고 |
|------|------------|------|
| Netgear R6400 | V1.0.1.6_1.0.4 vs V1.0.1.24_1.0.18 | CVE-2016-6277 참고 (stack overflow) |
| Netgear R8500 | V1.0.2.26 vs V1.0.2.116 | 매핑 불명, 차분 비교 대상 |
| Netgear R6300v2 | V1.0.3.22 vs V1.0.4.28 | CVE-2017-5521 계열 가능성 |
| D-Link DIR-842 | A1_FW103KRB03 vs A1_FW103KRB09 | minor build, 차분 확인 필요 |

---

## 6. Eval lane 실행 설계 (요약)

상세는 `docs/pair_eval_lane.md` 참고. 본 문서의 pair 리스트가 그 lane의 **입력 카탈로그** 역할을 한다.

순서:
1. 각 pair에 대해 `./scout analyze <vuln> --ack-authorization` 실행 → findings.json 수집
2. 각 pair에 대해 `./scout analyze <patched> --ack-authorization` 실행 → findings.json 수집
3. CVE 매핑 ground truth와 대조:
   - vuln run에 해당 CVE-관련 finding이 있는가? → **TP** (recall 기여)
   - patched run에 동일 finding이 있는가? → **FP** (rate 기여)
4. `scripts/score_pair_corpus.py` (예정, stdlib only)가 per-pair/per-CVE JSON을 생성
5. 결과를 `docs/results_overview.md` § "Pair eval lane"에 기입

**동시에 [C] ROC용 데이터 수집**:
- 각 finding의 `evidence_tier` + `confidence`를 추출
- TP/FP 분류와 함께 tier-by-confidence ROC 점을 계산
- tier 별 optimal threshold를 `docs/confidence_caps_calibration.md` (예정)에 기재
- 현재 `confidence_caps.py`의 4개 cap (0.40/0.55/0.60/0.75)과 비교해서 근거 제시

즉 **한 번의 pair eval 실행 = [B-1] + [C] 동시 answer**.

---

## 7. 즉시 진행 가능한 최소 세트 (M0)

gap 해소 전에도 시작할 수 있는 최소 eval set:

| 최소 pair | vuln → patched | 이유 |
|----------|---------------|------|
| P0 #1 | R7000 V1.0.7.12 → V1.0.9.34 | 가장 잘 알려진 CVE (2017-5521), ground truth 명확 |
| P1 #4 | DIR-868L K02 → K04 | 벤더가 명시한 minor upgrade, HNAP 차분 관찰 유력 |
| P1 #7 | DIR-850L FW105 → FW115 | 2013→2017 큰 delta, 여러 CVE 커버 가능성 |
| P1 #8 | Archer C7 v2 2015 → 2016 | v2 내부 patch, HTTP header BOF 차분 |

**4 pair = 8 run**으로 M0 eval lane을 가동할 수 있다. 각 pair별로 SCOUT full analyze 시간은 R7000 기준 ~15~25분, 총 ~2~3시간 (순차 기준).

---

## 8. 이 문서의 update cadence

- gap (DIR-859 pre-1.06B01, OpenWrt pre-23.05) 수급이 들어오면 Gap 섹션 조정
- eval lane 실행 결과 숫자는 **이 문서에 기입하지 않음** — 숫자는 `docs/results_overview.md` 단일 소스
- 새로운 pair 후보 발견 시 §3 또는 §5에 추가

---

## 9. 참고 — 매핑 출처

각 CVE의 공식 매핑 출처 (reviewer가 cross-check할 수 있도록):

- CVE-2017-5521: NVD + Netgear advisory PSV-2017-0005 (R7000 포함 다수 모델)
- CVE-2019-17621: NVD + D-Link security advisory 문서 (DIR-859 REVA 1.06B01에서 SOAPAction 파라미터 검증 추가)
- CVE-2018-10970: NVD + D-Link DIR-868L HNAP 관련
- CVE-2017-13772: NVD + TP-Link Archer C9/C7 v2 HTTP header buffer overflow (Cisco Talos 공개)
- CVE-2019-17152: NVD + TP-Link Archer C7 v4 diagnostic.htm command injection
- CVE-2019-20213 / CVE-2019-6258: NVD + D-Link DIR-850L HNAP

> **재확인**: 본 문서의 CVE 매핑은 "candidate" 수준이며, eval lane 실행 시 SCOUT 실측 결과가 이 매핑을 지지/반박할 수 있다. 이 점은 `docs/results_overview.md`에서 실측 이후 최종 반영된다.
