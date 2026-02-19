# SCOUT Docs Index

이 문서는 SCOUT 저장소의 "문서 시작점"입니다.

## 1) 큰 그림 (청사진)

- `docs/blueprint.md`
  - 펌웨어 입력 → run_dir(증거 저장소) → stage 산출물 → 판정(tribunal/judge) → 동적 검증 evidence → confirmed 승격
  - Full-chain을 "무기화"가 아니라 "증거 기반 검증"으로 정의하고 가드레일을 명시합니다.

## 2) 현재 구현 상태

- `docs/status.md`
  - 지금 어디까지 구현됐는지
  - 무엇이 깨져있는지(known issues)
  - 다음 우선순위

## 3) 실행/검증 런북

- `docs/runbook.md`
  - `./scout analyze` / `./scout stages`
  - (원하면) `python3 -m aiedge analyze` / `python3 -m aiedge stages`도 직접 실행 가능
  - 결정론/계약 검증 스크립트
  - Terminator 연동 E2E(있는 경우)

## 4) 저수준 계약(Contracts)

아래 문서들은 오케스트레이터(예: Terminator)와의 연동을 위해 필요한 계약/산출물 규격을 고정합니다.

- `docs/aiedge_adapter_contract.md`
- `docs/aiedge_firmware_artifacts_v1.md`
- `docs/aiedge_report_contract.md`
- `docs/aiedge_duplicate_gate_contract.md`
