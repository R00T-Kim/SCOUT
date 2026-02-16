# SCOUT Framework Blueprint (Firmware Input -> Full Chain)

이 문서는 SCOUT의 전체 프레임워크 청사진입니다.

목표는 단일 기능이 아니라, **펌웨어 입력부터 confirmed(동적 증거 포함)까지** 이어지는 end-to-end 체인을 구성하는 것입니다.

## 핵심 원칙

- **증거 우선(Evidence-first)**: 모든 중요한 결과는 run_dir 아래의 파일(artifact)과 sha256로 고정되어야 함
- **결정론(Deterministic)**: LLM이 없어도 stage 산출물이 재현 가능해야 함 (`--no-llm`)
- **승격(confirmed)에는 동적 검증 증거가 필수**: static 분석만으로는 high-confidence여도 confirmed가 될 수 없음
- **Exploit-chain은 lab-gated**: 승인된 범위에서만 실행; 목적은 재현 가능한 검증 evidence 생성

## 구성요소

### AIEdge (executor)

- 입력: firmware 파일
- 출력: `aiedge-runs/<run_id>/` (evidence store)
- StageFactory 기반 stage는 `stages/<stage_name>/stage.json`을 남기고, 산출물은 `artifacts[]`에 sha256로 기록
- findings는 StageFactory stage가 아니라 `run_findings()` 통합 단계로 실행되며 `stages/findings/*.json` 산출물을 직접 생성

### Orchestrator (예: Terminator)

- 입력: AIEdge run_dir + 정책
- 역할:
  - 필요한 stage만 재실행(부분 실행)
  - tribunal/judge로 후보를 평가(비용/캐시 포함)
  - validator로 동적 증거 생성 및 confirmed 승격 정책을 enforce

## 데이터 흐름(요약)

```mermaid
flowchart TD
  F[Firmware Input] --> R[run_dir 생성]
  R --> tool[tooling]
  R --> ext[extraction]
  ext --> st[structure]
  st --> car[carving]
  car --> prof[firmware_profile]
  prof --> inv[inventory]
  inv --> surf[surfaces/endpoints/graph/attack_surface]
  surf --> find[findings]
  find --> judge[tribunal/judge (LLM-as-judge)]
  judge --> val[validator (dyn evidence)]
  val --> conf[confirmed]
  val --> hc[high_confidence_static]
```

## 산출물(Artifacts) 계약

- stage 재실행/연동 계약: `docs/aiedge_adapter_contract.md`
- 펌웨어 프로파일/인벤토리 v1 규격: `docs/aiedge_firmware_artifacts_v1.md`
