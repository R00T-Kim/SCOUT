# Status

이 문서는 "현재 구현 상태"를 솔직하게 기록합니다.

## 현재 구현됨

- AIEdge CLI: `./scout analyze`, `./scout stages` (래퍼 권장)
- 동일 기능은 `python3 -m aiedge analyze`, `python3 -m aiedge stages`로 직접 실행 가능
- Stage evidence store(run_dir): StageFactory stage는 `stages/<name>/stage.json` 기반 artifact hashing을 사용하고, findings는 `run_findings()`가 `stages/findings/*.json`을 직접 생성
- `firmware_profile` stage:
  - `stages/firmware_profile/stage.json`과 `stages/firmware_profile/firmware_profile.json` 생성이 확인됨
  - `firmware_profile.json` 누락을 전제로 한 과거 run_dir 예시는 stale 상태이므로 문서에서 제거하거나 최신 run으로 갱신해야 함
- Inventory stage는 "죽지 않고" `inventory.json`/`string_hits.json`을 남김
- TUI/뷰어 진입 가이드는 `./scout tui` 단축키(`ti/tw/to`) 및 `./scout serve`를 기준으로 정렬되어 최신 상태입니다.

## Known Issues (중요)

- ER-e50.v3.0.1에서 inventory가 다음 형태로 끝남:
  - `reason = inventory_recovered_from_exception`
  - `errors[]`에 `PermissionError`
  - `coverage_metrics.files_seen = 0` (실질적으로 스캔이 0)
  - 예: `aiedge-runs/2026-02-16_0536_sha256-e3d3fe0697bc/stages/inventory/inventory.json`

이 상태는 "예외를 삼켜서 파이프라인이 멈추진 않지만, 결과가 유용하지 않다"에 해당합니다.

## 다음 우선순위

1) inventory가 rootfs에서 실제로 파일을 스캔하도록 예외 처리/루트 선정 경로를 수정
2) firmware_profile.json 내용(분기 계획 branch_plan)이 downstream에 의미 있게 반영되도록 체크
3) (오케스트레이터 레이어) tribunal/judge + validator evidence를 통한 confirmed 승격 정책을 end-to-end로 E2E화
