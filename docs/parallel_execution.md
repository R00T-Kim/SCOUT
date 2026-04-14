# Parallel Execution Provenance

SCOUT는 `--experimental-parallel [N]`가 켜진 경우 DAG level-wise 병렬 실행을 사용한다.

## Manifest provenance

모든 run은 `manifest.json`에 실행 provenance를 남긴다.

```json
{
  "execution_mode": "sequential",
  "max_workers": 1
}
```

병렬 실행이면:

```json
{
  "execution_mode": "parallel",
  "max_workers": 4
}
```

규칙:

- `execution_mode`는 `sequential` 또는 `parallel`
- `max_workers`는 양의 정수
- legacy run은 필드가 없을 수 있으나, 2C.5 이후 생성/재실행 run은 필드를 기록한다

## verified_chain provenance

`scripts/build_verified_chain.py`는 `manifest.json`에서 실행 provenance를 읽어
`verified_chain/verified_chain.json`의 `execution` 블록에 복사한다.

legacy manifest에서 provenance가 없으면 builder는 아래 기본값을 넣는다:

```json
{
  "execution": {
    "mode": "sequential",
    "max_workers": 1
  }
}
```

`scripts/verify_verified_chain.py`는:

- `execution`이 없으면 legacy contract로 간주하고 허용
- `execution`이 있으면
  - `mode in {"sequential", "parallel"}`
  - `max_workers >= 1`
  을 검증한다

## fail_fast semantics

현재 `run_stages_parallel()`은:

- stage DAG level 단위로 실행
- `fail_fast=False`면 같은 level의 peer는 계속 완료까지 실행
- `fail_fast=True`면 실패가 발생했을 때 아직 실행되지 않은 queued peer를 취소하려고 시도
- downstream dependent stage는 upstream 실패 시 `skipped`

관련 회귀 테스트:

- `tests/test_run_stages_parallel.py`

## 현재 의미

2C.5에서 추가한 execution provenance는:

- 병렬/순차 실행 결과 비교
- verifier/attestation에 execution context 포함
- 이후 `--experimental-parallel` 해제 조건 평가

를 위한 최소 기록 계층이다.
