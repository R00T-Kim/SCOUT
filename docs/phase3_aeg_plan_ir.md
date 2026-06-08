# SCOUT Phase 3 AEG Plan IR Readiness — 2026-06-08 KST

- 기준 버전: `scout-firmware 3.0.0rc1` / `v3.0.0-rc1`
- 기준 main commit: `1955ac3185a168111d5995560728f89cba1fdfc7` (PR #16 merge 후 Phase 3 시작점)
- Phase 3 artifact: `docs/pov/phase3_aeg_readiness.json`
- Artifact schema: `scout-phase3-aeg-readiness-v1`
- Phase 3 contract: `scout-aeg-phase3-plan-ir-contract-v1`

## 목적

Phase 3의 목적은 AutoPoC를 단순 template fallback 단계에서 **Plan IR 기반 primitive proof generator**로 승격하는 것이다. 이 문서는 2026-06-08 KST 기준으로 Phase 3 완료 여부를 증명하는 repo-local 산출물과 gate를 요약한다.

## 완료 gate

| Gate | 2026-06-08 KST 결과 | 증거 |
| --- | --- | --- |
| Plan IR input contract | Pass | AutoPoC attempt마다 `scope`, `target_profile`, `primitive`, `preconditions`, `execution`, `verification`, `cleanup`, `gate`, `backend_plan`을 포함한다. |
| Candidate selection | Pass | `priority + Plan IR presence + proof feasibility + family diversity` 정책으로 top-N이 같은 family에 collapse되지 않게 했다. |
| Reliability variants | Pass | runner와 Plan IR 모두 `baseline`, `cold_start`, `service_restart`, `reboot` variant를 기록한다. |
| Backend redundancy map | Pass | Plan IR `backend_plan`이 `service_harness`, `qemu_user`, `full_system_emulation`, `hardware_in_loop`을 명시한다. |
| Failure taxonomy | Pass | `runner_nonpass`를 `payload`, `precondition`, `harness`, `false_hypothesis`, `environment`로 분류하고 summary coverage를 기록한다. |

## 구현 산출물

- `src/aiedge/exploit_autopoc.py`
  - Phase 3 Plan IR contract 생성/정규화
  - family-diverse candidate selection
  - proof feasibility score
  - backend redundancy map
  - failure taxonomy와 summary coverage
- `exploit_runner.py`
  - `--reliability-variants` CLI 추가
  - attempt/evidence bundle에 reliability variant 기록
  - Plan IR transition evidence에 reliability variant 연결
- `src/aiedge/phase3_readiness.py`
  - Phase 3 완료 gate를 repo-local probe로 검증
- `scripts/build_phase3_aeg_readiness.py`
  - `docs/pov/phase3_aeg_readiness.json` 생성
- `tests/test_exploit_autopoc_stage.py`, `tests/test_exploit_runner.py`
  - Plan IR/taxonomy/selection/reliability variant regression test

## 현재 artifact verdict

`docs/pov/phase3_aeg_readiness.json`의 현재 verdict는 다음과 같다.

| 항목 | 값 |
| --- | --- |
| `schema_version` | `scout-phase3-aeg-readiness-v1` |
| `phase3_contract_version` | `scout-aeg-phase3-plan-ir-contract-v1` |
| `phase3_ready` | `true` |
| `verdict` | `phase3-complete` |
| `artifact_date` | `2026-06-08 KST` |
| `package_version` | `3.0.0rc1` |

## 남은 주의점

Phase 3 gate는 AutoPoC/runner의 contract와 evidence taxonomy를 완성했다. 다만 실제 broad pass-rate KPI는 더 많은 real firmware pair가 필요하므로, Phase 1 scale-out과 Phase 4 corpus expansion이 계속되어야 한다. 즉 2026-06-08 KST의 완료 주장은 **Phase 3 contract/readiness 완료**이지, 모든 firmware family에서 높은 exploit success rate를 보장한다는 뜻은 아니다.
