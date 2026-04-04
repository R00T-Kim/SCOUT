# Tier 1 재검증 최종 분석 (sasquatch 반영)

기준선:

- Previous baseline: `benchmark-results/firmae-20260330_0259`
- Frozen baseline: `benchmark-results/firmae-sasquatch-20260401_235630`

이 문서는 sasquatch 반영 후 재실행한 Tier 1 벤치마크의 **최종 결과, 비정상 케이스 분류, 벤더별 delta, emulation 후처리 해석**을 기록합니다.

---

## 1. 최종 요약

| Metric | Previous | Frozen baseline | Delta |
|---|---:|---:|---:|
| Total firmware | 1123 | 1123 | 0 |
| Success | 706 | 1110 | +404 |
| Partial | 408 | 4 | -404 |
| Failed | 9 | 9 | 0 |
| Analysis rate (`success + partial`) | 99.2% | 99.2% | 0.0%p |
| Success rate | 62.9% | 98.8% | +35.9%p |
| Findings total | 2702 | 3523 | +821 |
| CVE matches total | 0* | 13893 | +13893 |
| Total duration | 703809s | 846654s | +142845s |

\* 이전 baseline의 CVE 집계는 benchmark summary 수집 경로 문제로 신뢰 가능한 비교 기준이 아님.

### 핵심 해석

- 이번 재검증의 본질은 **partial 408개를 success 404개로 회복**한 품질 개선입니다.
- fatal은 동일한 수준(9건)으로 유지되어, 전체 파이프라인 안정성은 주로 **extraction / inventory quality 회복**으로 개선되었습니다.
- success run에서 extraction과 inventory가 거의 전부 usable 상태가 되었고, findings 총량도 약 30% 증가했습니다.

---

## 2. partial / fatal 원인 분류

비정상 케이스는 총 13건입니다.

### A. Partial 4건 — extraction insufficiency / encrypted-like packaging

| Vendor | Firmware | Status | Root cause group | Evidence |
|---|---|---|---|---|
| tplink | `RE400_V1_170111.zip` | partial | extraction insufficiency / high entropy | `extraction partial`, `inventory insufficient`, entropy 8.00, `provide --rootfs PATH` |
| tplink | `TL-WA801ND_US__V5_170905.zip` | partial | extraction insufficiency / high entropy | 동일 패턴 |
| trendnet | `TEW-410APBplus_0.0.0.zip` | partial | extraction insufficiency / high entropy | entropy 7.99, SBOM/graph/surfaces degraded |
| trendnet | `TEW-411BRPplus_2.07.zip` | partial | extraction insufficiency / high entropy | entropy 7.97, 동일 degraded chain |

해석:

- 네 건 모두 `extraction_status=partial`, `inventory_quality_status=insufficient`.
- sasquatch로도 복구되지 않는 **암호화/특수 포맷 계열**로 보이며, 별도 vendor extraction chain 또는 수동 rootfs 투입이 필요합니다.

### B. Fatal 2건 — broken absolute symlink traversal

| Vendor | Firmware | Root cause group | Evidence |
|---|---|---|---|
| asus | `FW_RT_N10_1024.zip` | broken absolute symlink | `lib/modules/2.4.20/build -> /root/RT-N10/src/linux/linux` |
| asus | `FW_WL_330gE_2020.zip` | broken absolute symlink | `lib/modules/2.4.20/build -> /root/WL330gE/src/linux/linux` |

해석:

- rootfs 내부의 절대 symlink를 따라가다 `Permission denied`로 fatal 종료.
- sasquatch 문제가 아니라 **외부 절대경로 symlink 처리 예외**입니다.

### C. Fatal 7건 — extracted web asset permission handling

| Vendor | Firmware family | Root cause group | Evidence |
|---|---|---|---|
| trendnet | `TEG-082WS`, `TEG-204WS`, `TEG-284WS`, `TEG-40128`, `TFC-1600MM`, `TPE-1620WS`, `TPE-5028WS` | extracted web asset permission handling | `var/www/qos_policy_view.js`, `var/www/theme_css.css` 접근 시 `Permission denied` |

해석:

- Trendnet 스위치/컨버터 계열의 추출된 웹 자산 일부 접근에서 fatal 발생.
- symlink 문제가 아니라 **추출된 파일 permission handling / file walk 예외**로 보입니다.

---

## 3. 벤더별 delta

| Vendor | Success Δ | Partial Δ | Failed Δ | Findings Δ | CVEs (new) |
|---|---:|---:|---:|---:|---:|
| asus | +29 | -29 | 0 | +57 | 435 |
| belkin | +21 | -21 | 0 | +43 | 18 |
| dlink | +89 | -89 | 0 | +189 | 931 |
| linksys | +28 | -28 | 0 | +73 | 107 |
| netgear | +154 | -154 | 0 | +315 | 9583 |
| tplink | +46 | -46 | 0 | +66 | 1797 |
| trendnet | +35 | -35 | 0 | +78 | 551 |
| zyxel | +2 | -2 | 0 | 0 | 471 |

### 벤더별 해석

- **D-Link / Netgear / TP-Link / Linksys**: partial 대량 회복이 가장 두드러짐
- **Belkin**: 짧은 old baseline 대비 duration이 늘었지만, success와 findings가 뚜렷하게 개선
- **Trendnet**: 성공률은 좋아졌지만 fatal cluster(7건)가 남아 있어 별도 안정화 패치 우선순위가 높음
- **Zyxel**: success 안정화는 소폭 개선, findings는 동일

---

## 4. Findings / CVE / 품질 해석

### Findings

- Total findings: `3523`
- Distribution:
  - `0`: 9
  - `1`: 62
  - `2`: 45
  - `3`: 670
  - `4`: 324
  - `5`: 13

해석:

- 이전 baseline에서 `1-finding` run이 많았던 것과 달리, 이번 baseline은 **3~4 findings**를 안정적으로 생성하는 run이 크게 늘었습니다.
- 이는 placeholder성 incomplete run이 줄고, **정상 evidence bundle 생성이 표준화**되었음을 의미합니다.

### CVE

- Total CVE matches: `13893`
- CVE-positive firmware: `806 / 1123`

해석:

- 이 수치는 **고유 취약점 수**가 아니라, component/version 기반 매칭 총합입니다.
- 특히 Netgear 계열에서 80~258 수준의 large cluster가 반복되므로, 이후 triage에서는 **CVE cluster dedup / overmatching 검토**가 필요합니다.

### 품질

- Extraction ok / partial / failed: `1110 / 4 / 0`
- Inventory sufficient / insufficient: `1104 / 10`
- Average files seen: `1940.4`
- Average binaries seen: `1027.53`

해석:

- 이번 라운드는 “탐지 로직 개선”보다 **추출과 inventory 완주율 회복**이 핵심 성과입니다.

---

## 5. Emulation 후처리 분석

### 집계 기준

- archived `report.json`의 `emulation.status`
- archived `report.json`의 `emulation.details.used_tier`

### 결과

Non-fatal runs (`success + partial = 1114`) 기준:

- `('ok', 'tier1') = 1102`
- `('ok', 'tier2') = 12`

Vendor별 분포:

- asus: tier1 104 / tier2 1
- belkin: tier1 37
- dlink: tier1 259 / tier2 3
- linksys: tier1 54 / tier2 1
- netgear: tier1 371 / tier2 4
- tplink: tier1 147 / tier2 1
- trendnet: tier1 110 / tier2 2
- zyxel: tier1 20

### 해석 주의

이 값은 **full-system runtime validation success rate** 가 아닙니다.

`src/aiedge/emulation.py` 기준으로 `status="ok"` 는 아래 경로 중 하나를 통과하면 성립할 수 있습니다.

1. `scout-emulation:latest` Docker path가 0 종료 (`used_tier='tier1'`)
2. Pandawan path가 0 종료 (현재 baseline에서는 관측되지 않음)
3. QEMU user-mode probe가 반응 (`used_tier='tier2'`)
4. rootfs inspection fallback이 성공 (이번 집계에선 report 기준 `used_tier`로는 관측되지 않음)

즉 이 숫자는:

> **“base emulation path executed successfully”**

를 의미하며,

> **“서비스 기동까지 확인된 full-system emulation success”**

를 의미하지는 않습니다.

### 실무 의미

- Tier 1 baseline이 단순 static-only는 아니었고, **base emulation stage가 광범위하게 실행**되었다는 점은 확인됨
- 하지만 논문화/발표에서는 이 수치를 **runtime-meaningful emulation success**로 과장하면 안 됨
- 후속 라운드에서는 `boot/service/probe observed` 기준의 별도 emulation metric이 필요함

---

## 6. 다음 단계

1. Fatal 9건 fail-open 처리 여부 판단
   - broken symlink traversal
   - extracted web asset permission handling
2. Partial 4건 vendor extraction chain 개선 여부 검토
3. Tier 2 LLM cohort는 extraction viability를 다시 점검한 뒤 비교 baseline으로 사용할지 결정
4. Findings taxonomy refinement는 **이 frozen baseline 이후 별도 실험 라운드**로 분리
