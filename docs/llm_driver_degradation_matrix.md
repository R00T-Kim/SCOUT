# LLM Driver Degradation Matrix

이 문서는 SCOUT가 지원하는 4개 LLM 드라이버의 **system prompt 전달 방식**, **temperature 적용 방식**, **실패 표면**, **권장 사용처**를 정리한다. 목적은 "모든 드라이버가 동일하게 동작한다"고 과장하지 않고, 어떤 드라이버에서 어떤 열화(degradation)가 생길 수 있는지 문서화하는 것이다.

## 요약

| Driver | Prompt delivery | Temperature | 주요 강점 | 주요 제약 | 권장 용도 |
|---|---|---|---|---|---|
| Codex CLI | `system_prompt`를 user prompt 앞에 prepend | 사실상 비결정적, CLI 내부 정책 영향 | 기본 리더 경로, repo-local 사용 편의 | 네이티브 system 채널 아님 | 기본 개발/실험 |
| Claude API | API `system` 필드 사용 | API `temperature` 필드 사용 | 가장 명시적 계약, 재현성 문서화 쉬움 | API 키/쿼터 의존 | 발표용 재현 run, 정식 비교 |
| Claude Code CLI | `system_prompt`를 user prompt 앞에 prepend | 실질적으로 무시될 수 있음 | 로컬 interactive workflow 친화적 | 네이티브 system 채널 아님, quota/CLI 정책 영향 큼 | analyst-assisted triage |
| Ollama | HTTP body `system` 필드 사용 | `options.temperature` 사용 | 완전 로컬, air-gap 가능 | 모델 품질/컨텍스트 길이 편차 큼 | 오프라인 환경, 저비용 smoke |

## 계약 차이

### 1. System prompt 전달

- **Claude API / Ollama**
  - 드라이버가 `system` 필드를 **네이티브로 전달**한다.
  - 문서/재현성 설명이 가장 직관적이다.
- **Codex CLI / Claude Code CLI**
  - 드라이버가 `system_prompt`를 독립 채널로 보내지 않고,
    `"[System instructions] ... [User prompt] ..."` 형태로 **prepend**한다.
  - 따라서 동일 prompt라도 API 경로와 **완전히 동일한 해석을 보장하지 않는다**.

### 2. Temperature

- **Claude API**: `temperature`를 body에 직접 전달
- **Ollama**: `options.temperature`로 전달
- **Codex CLI / Claude Code CLI**: 드라이버 인터페이스는 값을 받지만, 실제 CLI 레이어에서 그대로 반영된다고 가정하면 안 된다.

## 실패 표면

SCOUT는 `classify_llm_failure()`로 아래 실패 버킷을 통일한다.

- `quota_exhausted`
- `timeout`
- `driver_unavailable`
- `driver_nonzero_exit`
- `driver_error`
- `skipped`

### 드라이버별 흔한 열화

#### Codex CLI
- CLI 응답 형식이 바뀌면 JSON parse recovery에 더 많이 의존할 수 있다.
- system prompt가 prepend 방식이라, 길이가 길수록 user prompt와의 경계가 흐려질 수 있다.

#### Claude API
- 쿼터/레이트리밋이 가장 직접적으로 surface 된다.
- 대신 실패 원인이 비교적 명확하다.

#### Claude Code CLI
- quota exhausted / nonzero exit / local CLI state 영향을 강하게 받는다.
- 실험 중에는 편하지만, 대규모 benchmark의 단일 진실 소스로 삼기엔 불안정할 수 있다.

#### Ollama
- 모델별 품질 편차가 크다.
- structured JSON adherence가 cloud API보다 약할 수 있다.
- 완전 로컬이라는 장점 때문에 smoke / offline lane에는 적합하다.

## 권장 사용 정책

### 발표/비교용 공식 수치
- **Claude API 우선**
- 이유: `system` / `temperature` / 실패 모드가 가장 설명 가능함

### 일상 개발/빠른 반복
- **Codex CLI 기본**
- 이유: repo-local workflow와 가장 잘 붙고 operator friction이 낮음

### analyst 보조 루프
- **Claude Code CLI 허용**
- 단, quota/exit failure를 항상 별도 기록하고, benchmark 정식 수치와 혼용하지 않는다.

### 오프라인/에어갭
- **Ollama**
- 단, 결과는 quality-sensitive benchmark보다 smoke / fallback lane로 해석한다.

## 문서 표현 규칙

이 문서 이후 README / status / results overview에서는 다음을 지킨다.

- "all drivers are equivalent" 같은 표현 금지
- Codex/Claude Code CLI는 **prepend-based system prompt delivery**라고 명시
- pair-eval / ROC 같은 reviewer-facing 숫자는 가능하면 **하나의 driver lane**으로 고정
- driver가 다르면 결과 비교 시 **driver 차이 자체를 변수**로 인정
