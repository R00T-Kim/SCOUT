# SCOUT Docs Index

이 문서는 SCOUT 저장소의 "문서 시작점"입니다.

- [README (English)](../README.md)
- [README (한국어)](../README.ko.md)

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

## 5) 신규 기능 문서 (Phase 1-5 업그레이드)

- **SBOM/CVE**: `sbom.py` → CycloneDX 1.6, `cve_scan.py` → NVD API 2.0 CVE 매칭
- **보안 평가**: `cert_analysis.py` (X.509), `init_analysis.py` (부트 서비스), `fs_permissions.py` (퍼미션)
- **MCP 서버**: `mcp_server.py` — 12개 도구 stdio 서버, AI 에이전트 연동
- **LLM 드라이버**: `llm_driver.py` — Codex + Claude API + Ollama, `llm_cost.py` 비용 추적
- **Reachability**: `reachability.py` — CVE 도달성 BFS 분석
- **펌웨어 비교**: `firmware_diff.py` — 파일시스템/바이너리/config 3단계 diff
- **GDB 에뮬레이션**: `emulation_gdb.py` — 순수 stdlib GDB RSP 클라이언트
- **Ghidra 연동**: `ghidra_bridge.py` + `ghidra_analysis.py` — 선택적 디컴파일
- **퍼징**: `fuzz_target.py` + `fuzz_harness.py` + `fuzz_campaign.py` + `fuzz_triage.py` — AFL++ 파이프라인
- **리포트**: `report_export.py` — Markdown executive report 생성

## 6) 파이프라인 (42 stages)

```
tooling → extraction → structure → carving → firmware_profile → inventory
→ ghidra_analysis → sbom → cve_scan → reachability
→ endpoints → surfaces → web_ui → graph → attack_surface
→ functional_spec → threat_model → findings → llm_triage → llm_synthesis
→ attribution → emulation → dynamic_validation → fuzzing
→ exploit_gate → exploit_chain → exploit_autopoc → poc_validation → exploit_policy
```
