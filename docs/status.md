# Status

이 문서는 "현재 구현 상태"를 솔직하게 기록합니다.

## 현재 구현됨

- AIEdge CLI: `./scout analyze`, `./scout stages` (래퍼 권장)
- 동일 기능은 `python3 -m aiedge analyze`, `python3 -m aiedge stages`로 직접 실행 가능
- Stage evidence store(run_dir): StageFactory stage는 `stages/<name>/stage.json` 기반 artifact hashing을 사용하고, findings는 `run_findings()`가 `stages/findings/*.json`을 직접 생성
- `analyze`/`analyze-8mb`에 `--rootfs <DIR>` 지원 (사전 추출 rootfs 직접 ingest)
- `firmware_profile` stage:
  - `stages/firmware_profile/stage.json`과 `stages/firmware_profile/firmware_profile.json` 생성이 확인됨
  - ELF 교차검증(`arch_guess`, `elf_hints`)으로 OS/arch 오탐 완화
- Inventory stage는 "죽지 않고" `inventory.json`/`string_hits.json`/`binary_analysis.json`을 남김
- extraction/inventory 품질 게이트(coverage threshold) 반영:
  - sparse 결과는 `quality.status=insufficient`로 표시되고 `partial`로 강등될 수 있음
- `firmware_handoff.json` 자동 생성 (analyze + stages)
- TUI/뷰어 진입 가이드는 `./scout tui` 단축키(`ti/tw/to`) 및 `./scout serve`를 기준으로 정렬되어 최신 상태입니다.

## Known Issues (중요)

- 샌드박스/호스트 정책에 따라 `serve --once`가 포트 바인딩 권한 문제로 실패할 수 있음 (`Operation not permitted`).
- 다층 벤더 포맷은 여전히 완전 자동 추출이 보장되지 않음.
  - 현재는 `--rootfs` 우회가 실전 대응 경로이며, 포맷 전용 extractor 체인 확장은 계속 필요.
- binary 분석은 심볼/문자열 기반 휴리스틱 중심이며, 디컴파일/CFG 기반 정밀 분석 통합은 미완.

## 다음 우선순위

1) 벤더 포맷 전용 extraction chain 확장 (QNAP/Synology/ASUS 계열 깊은 중첩 포맷)
2) 바이너리 심층 분석(checksec/r2/ghidra 연계) 결과를 findings/surfaces로 연결
3) (오케스트레이터 레이어) tribunal/judge + validator evidence를 통한 confirmed 승격 정책 E2E 강화
