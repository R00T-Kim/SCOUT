# SCOUT: Surface Candidate Outline & Unified Triage
**Agent 기반 IoT 펌웨어 취약점 후보 자동 생성 시스템**
*(Agent-based Vulnerability Candidate Generation for IoT Firmware)*

SCOUT는 IoT 펌웨어의 공격면(Attack Surface)을 정찰하고, 증거(Evidence)를 기반으로 실제로 검증해볼 가치가 있는 취약점 후보(Vulnerability Candidate)를 자동으로 생성하는 시스템입니다.

기존의 취약점 탐지 도구들이 단순한 패턴 매칭이나 과도한 오탐(False Positive)을 보여주는 것과 달리, SCOUT는 **Agent(LLM)**를 활용하여 정적·동적·코드 분석 결과를 종합하고 분석가의 판단을 보조하는 "이유 있는 후보 리스트"를 제공합니다.

## 🚀 Key Features

*   **Multi-Tool Integration**: EMBA, Firmwalker (정적), FirmAE (동적), Ghidra (코드) 등 검증된 오픈소스 도구 활용
*   **Fact-Based Reasoning**: 도구의 출력 결과에서 '사실(Fact)'과 '증거(Evidence)'만을 추출하여 판단의 근거로 사용
*   **Agent Synthesis**: LLM Agent가 수집된 정보를 바탕으로 취약점 후보를 추론하고, 검증 우선순위와 재현 가이드(Reproduction Steps)를 제시
*   **Reproducible Candidates**: 막연한 의심이 아닌, 공격면 앵커(Anchor)와 증거가 명시된 검증 가능한 후보 리스트 생성

## 🏗 Architecture

SCOUT는 다음과 같은 파이프라인으로 구성됩니다.

1.  **Collect**: `collect/` - 타겟 펌웨어에 대해 EMBA, FirmAE, Ghidra 등을 실행하여 원본 로그 수집
2.  **Normalize**: `normalize/` - 각 도구의 로그를 표준화된 JSON 스키마(`static_facts`, `dynamic_facts`, `code_signals`)로 변환
3.  **Synthesis (Agent)**: `agent/` - LLM Agent가 정규화된 데이터를 분석하여 취약점 가설 수립 및 통합
4.  **Validate**: `validate/` - 생성된 후보 리스트의 스키마 및 근거(Evidence) 충족 여부 검증
5.  **Report**: `report/` - 최종 `vuln_candidates.json` 및 가독성 높은 리포트 생성

## 📂 Project Structure

```bash
scout/
├── collect/       # 외부 도구 실행 및 로그 수집 스크립트
├── normalize/     # 로그 파싱 및 표준화 모듈
├── agent/         # LLM 프롬프트 및 추론 로직
├── validate/      # 데이터 검증 및 룰 기반 필터링
├── report/        # 리포트 생성 모듈
├── samples/       # 테스트용 샘플 데이터
├── utils/         # 공통 유틸리티 및 스키마 정의 (schemas.py)
└── main.py        # 파이프라인 오케스트레이션
```

## 🛠 Prerequisites

*   Python 3.8+
*   Docker (for FirmAE/EMBA)
*   Ghidra (headless mode support)
*   OpenAI API Key (or compatible LLM API)
