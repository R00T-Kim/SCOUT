# SBOM Schema Fix Impact Pilot (2C.1)

`8e0bb82`의 SBOM schema fix가 실제 펌웨어 결과를 얼마나 바꾸는지 빠르게 확인하기 위한 파일럿 측정이다.

## 요약

- **주 결론:** `2C.6` 범위는 **전체 재측정 필수**다.
- 이유:
  - 파일럿 **6개 샘플 중 4개**에서 component count가 변했다.
  - 변화가 **vendor stock 0→N** 케이스에만 국한되지 않았다.
    - R7000: `0 → 4`
    - Tenda AC10: `0 → 3`
    - Archer C7 v5 (OpenWrt): `146 → 150`
    - Trendnet TEW-827DRU v2.10: `190 → 197`
  - downstream `cve_scan` 결과도 함께 바뀌었다.
    - R7000: CVE bucket이 새로 생성되고 `epss_enriched=165`
    - Tenda AC10: CVE bucket이 새로 생성되고 `epss_enriched=24`
    - Trendnet: CVE bucket/EPSS enrichment가 확장됨
- **보조 결론:** RAX80, Archer C7 stock zip은 여전히 `0`이므로 `8e0bb82`만으로 닫히지 않는 잔여 탐지 공백도 있다. 이것도 전체 재측정이 필요한 이유다.

## 측정 방법

### Pre baseline

- pre 값은 **이미 존재하는 historical run**을 사용했다.
- 이유: 해당 run들은 모두 extraction/inventory가 정상적으로 생성된 상태라서, `sbom.py` 변경 영향만 분리해서 보기 좋다.

### Post measurement

- current HEAD에서 **기존 run의 extraction/inventory를 재사용**해 `sbom`(필요 시 `cve_scan`)만 다시 실행했다.
- 사용 패턴:
  - 정상 extraction/inventory가 있는 historical run을 `benchmark-results/2c1-sbom-pilot/` 아래의 최소 run으로 복제 또는 심링크
  - `./scout stages <run_dir> --stages sbom[,cve_scan] --no-llm --quiet`

### 폐기한 측정 경로

- fresh `create_run + run_subset(tooling,extraction,...,sbom,cve_scan)` 경로는 이번 파일럿의 공식 근거에서 제외했다.
- 이유: R7000 / Archer C7 / RAX80에서 extraction이 `partial`로 조기 종료되며 inventory roots가 비어 **false zero**를 만들었기 때문이다.
- 해당 시험 run은 `benchmark-results/2c1-sbom-pilot/post/`에 남아 있지만, 아래 표에는 포함하지 않았다.

## Targets

| Target | Input path | SHA-256 | Pre run | Post run |
|---|---|---|---|---|
| R7000 | `aiedge-inputs/netgear/R7000-V1.0.11.136_10.2.120.chk` | `b28bf08e9d2c32d12d5a7bda45a93066d8bdf97274defc30f15fc36a437d02fb` | `aiedge-runs/2026-04-13_1014_sha256-b28bf08e9d2c` | `benchmark-results/2c1-sbom-pilot/post_from_existing/2026-04-13_1014_sha256-b28bf08e9d2c` |
| Archer C7 v5 (OpenWrt) | `aiedge-inputs/openwrt/openwrt-23.05.5-ath79-generic-tplink_archer-c7-v5-squashfs-factory.bin` | `bf9eeb5af38ac5d3ec58208f51fda54f18877684fc64adc2a7822faf434d6754` | `aiedge-runs/2026-04-13_1014_sha256-bf9eeb5af38a` | `benchmark-results/2c1-sbom-pilot/post_from_existing/2026-04-13_1014_sha256-bf9eeb5af38a` |
| Tenda AC10 | `aiedge-inputs/firmae-benchmark-2025/tenda/US_AC10V1.0re_V15.03.06.46_multi_TDE01.zip` | `0f4d79adabb99ec8ed1123bdb2e5a1302489bfc15413f88acbcec6ad0168d768` | `aiedge-runs/2026-04-08_0420_sha256-0f4d79adabb9` | `benchmark-results/2c1-sbom-pilot/post_from_existing/2026-04-08_0420_sha256-0f4d79adabb9` |
| Trendnet TEW-827DRU v2.10 | `aiedge-inputs/firmae-benchmark-2025/trendnet/TEW-827DRU-v2-2.10B01.zip` | `817a67c7001ccafd24dcbe7152547f7d00c7ff92ffa840720b40d5bd2ad577ff` | `aiedge-runs/2026-04-04_2204_sha256-817a67c7001c` | `benchmark-results/2c1-sbom-pilot/post_from_existing/2026-04-04_2204_sha256-817a67c7001c` |
| RAX80 | `aiedge-inputs/firmae-benchmark-2025/netgear/RAX80-V1.0.11.148.zip` | `417726b11ada0a23b953f7e1d246e0cc7649118d7bdf39e5e684dac9f59495c7` | `aiedge-runs/2026-04-04_2244_sha256-417726b11ada` | `benchmark-results/2c1-sbom-pilot/symlink_runs/2026-04-04_2244_sha256-417726b11ada` |

### Supplementary check

같은 모델의 vendor stock zip variant도 따로 봤다.

| Target | Input path | SHA-256 | Pre run | Post run |
|---|---|---|---|---|
| Archer C7 v5 (stock zip) | `aiedge-inputs/firmae-benchmark-2025/tplink/ArcherC7-V5-220715.zip` | baseline run manifest 기준 동일 input | `aiedge-runs/2026-04-04_2058_sha256-5d322bba6e05` | `benchmark-results/2c1-sbom-pilot/symlink_runs/2026-04-04_2058_sha256-5d322bba6e05` |

## Results

`C/H/M/L`은 `critical/high/medium/low` bucket을 뜻한다.  
`—`는 pre run에 `cve_scan` 결과가 없거나 이번 pilot에서 `sbom`만 재실행한 경우다.

| Target | Pre components | Post components | Delta | Pre CVE (C/H/M/L) | Post CVE (C/H/M/L) | Pre EPSS | Post EPSS | Note |
|---|---:|---:|---:|---|---|---:|---:|---|
| R7000 | 0 | 4 | +4 | — | 13/50/90/12 | — | 165 | vendor stock zero→non-zero 대표 케이스 |
| Archer C7 v5 (OpenWrt) | 146 | 150 | +4 | 1/0/5/1 | 1/0/5/1 | 7 | 7 | OpenWrt 계열도 component set이 확장됨 |
| Tenda AC10 | 0 | 3 | +3 | — | 3/11/6/4 | — | 24 | vendor stock zero→non-zero |
| Trendnet TEW-827DRU v2.10 | 190 | 197 | +7 | 11/31/37/12 | 13/29/43/11 | — | 96 | 이미 non-zero였어도 downstream CVE 결과가 변함 |
| RAX80 | 0 | 0 | 0 | — | — | — | — | 이번 fix만으로는 여전히 zero |

### Supplementary

| Target | Pre components | Post components | Delta | Note |
|---|---:|---:|---:|---|
| Archer C7 v5 (stock zip) | 0 | 0 | 0 | 같은 모델이라도 vendor zip variant는 여전히 zero |

## Interpretation

### 1) 이 fix는 실제로 큰 영향을 준다

- `0 → N`으로 바뀐 샘플이 두 개(R7000, Tenda)다.
- 기존에 component가 있던 샘플도 늘었다.
  - Archer OpenWrt: `146 → 150`
  - Trendnet: `190 → 197`

### 2) 영향은 vendor stock에만 한정되지 않는다

- OpenWrt 계열도 component set이 변했다.
- 따라서 `2C.6`을 “vendor stock만 재측정”으로 축소하면 안 된다.

### 3) downstream 지표도 바뀐다

- R7000/Tenda는 기존 0-component baseline에서는 나오지 않던 CVE/EPSS 결과가 새로 생겼다.
- Trendnet은 기존 non-zero baseline에서도 CVE bucket이 다시 분포했다.

### 4) 아직 남은 공백도 있다

- RAX80, Archer stock zip은 이번 fix 후에도 `0`이다.
- 이건 “재측정이 불필요”하다는 뜻이 아니라, **0으로 남는 population을 별도로 분류해야 한다**는 뜻이다.
- 즉, 2C.6은 단순 평균 갱신이 아니라 **(a) zero→non-zero, (b) non-zero→expanded, (c) still-zero** 세 그룹을 분리해서 봐야 한다.

## 2C.6 Scope Decision

**결론: `2C.6`은 전체 재측정 필수.**

선택지별 판정:

- `전체 재측정` → **채택**
- `vendor stock만` → 기각
- `불필요` → 기각

채택 이유:

1. 샘플 변경이 vendor stock에만 국한되지 않음
2. CVE/EPSS downstream 결과가 실제로 변함
3. unchanged zero 샘플도 존재하므로 전체 population 재분류가 필요함

## Recommended 2C.6 Execution Shape

- corpus 재측정 결과는 최소 3개 버킷으로 나눠 보고할 것:
  - `zero_to_nonzero`
  - `nonzero_expanded`
  - `still_zero`
- `still_zero`는 별도 follow-up queue로 넘겨
  - extraction issue
  - inventory schema issue 외 잔여 SBOM detection gap
  - genuinely component-sparse firmware
  를 분리해야 한다.

## Verification Notes

- 본 문서의 수치는 아래 artifact에서 재구성 가능하다.
  - historical pre runs: `aiedge-runs/*`
  - post reruns: `benchmark-results/2c1-sbom-pilot/post_from_existing/*`
  - supplementary sbom-only reruns: `benchmark-results/2c1-sbom-pilot/symlink_runs/*`
- 문서 일관성 검사는 `python3 scripts/check_doc_consistency.py`로 확인했다.
