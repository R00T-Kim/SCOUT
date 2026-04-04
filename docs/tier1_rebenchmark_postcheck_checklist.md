# Tier 1 재검증 종료 후 체크리스트

Tier 1 재검증이 끝난 직후, 결과를 빠르게 검토하고 다음 단계(Tier 2, findings 개선, dynamic refinement)로 이어가기 위한 체크리스트입니다.

## A. 실행 완료 확인

- [ ] benchmark 프로세스 종료 확인
- [ ] `benchmark_summary.csv` row 수가 기대값과 일치하는지 확인
- [ ] `benchmark_summary.json`, `benchmark_report.txt`, `benchmark_detail.json` 생성 확인
- [ ] 로그 마지막에 summary generation 완료 메시지 확인

## B. 최상위 결과 비교

- [ ] 전체 `success / partial / fatal` 최종 수치 확인
- [ ] 기존 Tier 1 대비 success rate delta 확인
- [ ] partial rate delta 확인
- [ ] fatal 2개가 그대로인지 / 추가됐는지 확인
- [ ] 평균 duration 변화 확인

## C. 품질 회복 확인

- [ ] extraction `ok` 비율 확인
- [ ] inventory `sufficient` 비율 확인
- [ ] 기존 partial → success 전환 개수 확인
- [ ] vendor별 partial 회복 규모 확인

핵심 질문:

- [ ] sasquatch 효과가 특정 vendor에만 큰지 확인
- [ ] 전체적으로 일관적인지 확인

## D. Findings 분석

- [ ] findings 총량 확인
- [ ] findings/fw 평균 계산
- [ ] findings count 분포 확인 (`0/1/2/3/4/5`)
- [ ] 기존 1-finding run 감소 여부 확인
- [ ] top finding IDs 확인
- [ ] severity 분포 확인
- [ ] high finding이 몇 개 firmware에서 나왔는지 확인
- [ ] high finding이 특정 ID 하나에 과도하게 수렴하는지 재확인

## E. CVE 분석

- [ ] 총 CVE 수 확인
- [ ] CVE-positive firmware 수 확인
- [ ] vendor별 CVE-positive 비율 확인
- [ ] CVE 상위 샘플 20개 추출
- [ ] Netgear / D-Link의 CVE cluster 반복 여부 확인
- [ ] 동일 계열 firmware의 version별 CVE 수 변동 확인

핵심 질문:

- [ ] 실제 탐지 향상인지 확인
- [ ] 집계/중복/버전 매칭 과민성인지 확인

## F. Vendor별 분석

각 vendor에 대해:

- [ ] 현재 success / partial / fatal 확인
- [ ] 기존 대비 delta 확인
- [ ] findings 증가량 확인
- [ ] CVE 증가량 확인
- [ ] 평균 duration 변화 확인
- [ ] extraction / inventory 품질 상태 확인

우선순위 vendor:

1. D-Link
2. Netgear
3. Belkin
4. Linksys
5. Asus 및 나머지

## G. Fatal 분석

- [ ] fatal firmware 목록 정리
- [ ] fatal 원인 분류
  - [ ] permission
  - [ ] extraction edge case
  - [ ] toolchain
  - [ ] path handling
- [ ] sasquatch와 무관한지 확인
- [ ] 재현 가능한지 확인
- [ ] hotfix 가치가 있는지 판단

## H. Tier 2 준비 체크

- [ ] `--llm` 동작 재확인
- [ ] `benchmarks/tier2-20260331-files.txt` 코호트 재확인
- [ ] 39개 모두 존재/읽기 가능 확인
- [ ] cleanup 정책 결정
- [ ] Tier 2 결과 디렉토리 네이밍 확정
- [ ] Tier 1 동일 subset과 직접 비교 가능한지 확인

## I. 다음 라운드 의사결정

- [ ] 먼저 Tier 2 재실행할지 결정
- [ ] fatal hotfix를 먼저 할지 결정
- [ ] findings taxonomy 개선을 바로 할지 결정
- [ ] Pandawan subset 실험으로 갈지 결정

## 종료 후 바로 뽑을 추천 산출물

- [ ] 최종 비교 표: old Tier 1 vs new Tier 1
- [ ] vendor별 delta 표
- [ ] findings top-N 표
- [ ] CVE cluster 표
- [ ] fatal 원인 메모
- [ ] Tier 2 실행 커맨드
