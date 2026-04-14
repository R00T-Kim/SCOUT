# Stage Contracts

SCOUT의 stage contract는 두 층으로 나뉜다.

1. **generic stage manifest contract**
   - 모든 registered stage는 `stages/<stage>/stage.json`을 가진다.
   - validator는 `stage_name`, `stage_identity`, `stage_key`, `attempt`, `status`,
     `inputs`, `artifacts`, `duration_s` 같은 공통 불변식을 검사한다.
2. **artifact-specific lightweight contract**
   - 대표 JSON artifact에 대해 top-level shape를 확인한다.
   - 예: `inventory.json`, `firmware_profile.json`, `sbom.json`,
     `cve_matches.json`, `taint_results.json`, `verified_alerts.json`,
     `triaged_findings.json`, `findings.json`, `communication_graph.json`

## CLI

```bash
python3 scripts/validate_stage_outputs.py --run-dir aiedge-runs/<run_id>
```

- 성공: exit `0`, `[OK] <run_dir>`
- 실패: exit `2`, `[FAIL] <run_dir>` + 위반 목록

## 범위

현재 validator는:

- registered stage의 `stage.json`
- stage manifest가 참조하는 artifact path 존재 여부
- direct child JSON artifact의 최소 shape

를 검증한다.

현재 validator가 **일부러 느슨하게 두는 것**:

- deep nested optional field 전체 스키마
- large non-JSON artifact 내용 검증 (`.dot`, `.mmd`, `.cypher`, `.csv`, `.log`)
- auxiliary non-stage 디렉토리 (`stages/llm/` 같은 로그 보조 디렉토리)

## 테스트

- `tests/test_stage_contracts.py`
- 기존 세부 contract test:
  - `tests/test_firmware_artifact_contracts.py`
  - `tests/test_e2e_report_contracts.py`
  - `tests/test_schema.py`

## CI

`.github/workflows/ci.yml`의 `stage-contracts` job이:

1. `tests/test_stage_contracts.py`
2. tiny sample run 생성
3. `python3 scripts/validate_stage_outputs.py --run-dir <run_dir>`

를 실행한다.

즉, 이 validator는 세부 unit contract를 대체하는 게 아니라
**run-dir 전체를 훑는 lightweight guardrail** 역할이다.
