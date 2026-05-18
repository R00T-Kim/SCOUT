# SCOUT Handoff: v2.8.0 — Exploit Pattern RAG & Universal Chaining

## 1. 개요 (Overview)
본 문서는 SCOUT v2.7.3에서 v2.8.0으로의 메이저 업데이트 내역을 정리한다. 핵심 변경 사항은 **Exploit Pattern RAG (Retrieval-Augmented Generation)** 시스템의 도입으로, SCOUT이 과거의 공격 패턴을 학습하고 이를 현재 타겟의 채널(Channels)과 상태(States)에 맞게 자율적으로 적응(Adaptation)시켜 고품질의 다단계 PoC를 생성할 수 있는 지능형 레이어를 구축했다.

## 2. 주요 성과 (Key Accomplishments)

### 2.1. ER605 1-Day 분석 및 자동화 성공
*   **Target**: TP-Link ER605 (v2.2.2) `cmxddnsd`.
*   **Vulnerability**: Web API -> UCI Config -> Daemon -> `popen`으로 이어지는 Config-to-Sink 커맨드 인젝션.
*   **Result**: Universal Chaining 아키텍처를 통해 `Login -> Config Write -> Trigger -> Verify` 절차를 가진 PoC 자동 생성 및 검증 완료.

### 2.2. Exploit Pattern RAG (MVP+) 구현
*   **Knowledge Base**: `data/exploit_references/`에 구조화된 지식 저장소 구축 (JSON 메타데이터 + 추론 Markdown + PoC 샘플).
*   **Scoring Retriever**: 후보의 패밀리, 유입 채널(Web/Config/IPC), Sink 종류, 트리거 모델을 종합 스코어링하여 최적의 패턴을 매칭하는 엔진 구현.
*   **Adaptation Engine**: LLM에게 참조 코드를 단순 복사하지 않고 "현재 타겟에 어떻게 적용할 것인지"에 대한 **Adaptation Plan** 작성을 강제하여 할루시네이션 억제.
*   **Contamination Guard**: 참조 패턴의 타겟 특정 아티팩트(IP, 엔드포인트 등)가 생성된 PoC로 유출되는 것을 감지하고 차단하는 검증 로직 탑재.

### 2.3. Zero-Dependency & CI 최적화
*   **Mandate**: 외부 라이브러리(`PyYAML` 등) 의존성을 완전히 제거하고 순수 Python 표준 라이브러리(stdlib)만 사용하도록 복구.
*   **CI Compliance**: 린트(Ruff) 및 타입 체크(Pyright) 실패 항목을 해결하고, `no_llm` 모드에서의 런타임 안정성 확보.

### 2.4. 사용자 중심 문서화 개편
*   **README**: 기술 나열 방식에서 벗어나 "할 수 있는 일", "SCOUT의 장점" 위주로 개편.
*   **UX**: 영문/국문 README 상단에 언어 전환 링크 배치 및 릴리즈 노트 최신화.

## 3. 상세 구현 설계 (Technical Implementation)

### 3.1. RAG 저장소 구조
```text
data/exploit_references/patterns/
  └── config_derived_cmd_injection/
      ├── exploit.json   # 채널, Sink, 트리거 메타데이터
      ├── pattern.md     # 공격 원리 및 상태 전이 이론
      └── poc_sample.py  # (참조용) 고품질 PoC 구현체
```

### 3.2. 스코어링 로직
*   Family Match: +30
*   Entry Channel Match: +20
*   Bridge Channel Match: +20
*   Sink Type/API Match: +20
*   Trigger Model Match: +15

## 4. 향후 과제 (Future Roadmap)

1.  **지식 베이스 확장**: `PoC-in-GitHub` 데이터를 분류하여 Path Traversal, Memory Corruption 등 다양한 유형의 패턴 카드 대량 확충.
2.  **의미론적 검색 (Semantic RAG)**: 패턴 수가 늘어남에 따라 단순 키워드 매칭에서 Embedding 기반의 벡터 검색으로 전환.
3.  **실패 학습 루프 (Failure Learning)**: Runner 실행 실패 로그를 분석하여 특정 타겟에 부적합한 패턴의 스코어를 자동으로 낮추는 피드백 시스템 구축.
4.  **PoC 자동 정규화**: 외부 PoC 코드를 SCOUT 패턴 규격(`exploit.json`)으로 자동 변환해주는 파이프라인 구축.

## 5. 현재 상태 및 체크리스트
- [x] Exploit Pattern RAG 인프라 구축
- [x] Scoring Retriever 엔진 구현
- [x] Contamination Guard 및 Prompt Sanitization 적용
- [x] v2.8.0 정식 태그 및 GitHub Release 발행
- [x] CI (Lint, Typecheck, Test) 통과 확인

---
**Author**: SCOUT Dev Team (Gemini CLI)
**Date**: 2026-05-18
**Version**: v2.8.0
