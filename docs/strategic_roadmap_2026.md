# SCOUT 전략 로드맵 2026-2028

> 작성일: 2026-04-12 | 기반: 학술 논문 30+편, 경쟁 도구 12개, 규제 동향 5개 축, 코드베이스 심층 분석

---

## Executive Summary

SCOUT는 42-stage 결정론적 증거 패키징(deterministic evidence packaging), 해시 앵커링 증거 체인, adversarial LLM debate(99.3% LLM 판정 기준 FPR 감소, Tier 2 v2.3.0 baseline)로 **펌웨어 증거 엔진** 분야에서 독보적 위치를 점유한다. 그러나 **precision 35-41%**, **68% LLM parse failure**, **순차 파이프라인 병목**이라는 3가지 핵심 과제가 다음 단계 도약을 가로막고 있다.

이 보고서는 4개 병렬 연구 스트림(학술 논문, 업계 동향, LLM 프론티어, 코드 갭 분석)과 Theori Xint 심층 분석을 종합하여, SCOUT의 **3-Phase 전략 로드맵**을 제안한다.

### 핵심 결론

1. **가장 빠른 ROI**: LLM structured output + system prompt 도입 (2-3일 작업, parse failure 68%→<10%)
2. **가장 큰 전략적 기회**: EU CRA 2026/09 보고 의무 시작 전 "EU CRA Annex I 호환 펌웨어 감사 출력" 포지셔닝
3. **가장 위협적인 경쟁자**: Theori Xint (multi-agent 오케스트레이션, DARPA AIxCC 3위) + FirmAgent (precision 91%, NDSS 2026)
4. **가장 유망한 기술**: LATTE Code Slicing (taint 정확도 즉시 향상) + Multi-Agent exploit chain (VulnSage 패턴)
5. **근본적 돌파구**: 동적 검증 경로 완성 (extraction → emulation → dynamic confirmation)

---

## Part 1: 경쟁 환경 — SCOUT는 어디에 서 있는가

### 1.1 직접 경쟁 도구 매트릭스

| 도구 | 유형 | Precision | 규모 | LLM 활용 | 강점 | 약점 |
|------|------|-----------|------|----------|------|------|
| **SCOUT** | 오픈소스 증거 엔진 | 35-41% | 1,123 FW | Advocate/Critic debate | 42-stage pipeline, SARIF+VEX+SLSA, 증거 체인 | Precision, parse failure, 순차 실행 |
| **Xint Code** (Theori) | 상용 SAST | ~80% (FP 20%) | 94만줄 PostgreSQL | Multi-agent 오케스트레이션 | Zero-day 발견(PostgreSQL, Redis), AIxCC 3위 | 펌웨어 비특화, 가격 미공개 |
| **FirmAgent** | 학술 도구 | **91%** | 14 FW | 퍼징+LLM 2단계 | 높은 precision, 17 CVE | 소규모 검증, 재현성 불명 |
| **FIRMHIVE** | 학술 도구 | 71% | 1,802 취약점 | Tree-of-Agents 재귀 | 넓은 탐색, 16x 깊은 추론 | FP 높음, Karonte 데이터셋 한정 |
| **EMBA v2.0** | 오픈소스 스캐너 | N/A | 1,074 FW | GPT (기본) | 95% 에뮬레이션, 커뮤니티 3.4k stars | Shell 기반, 증거 체인 없음 |
| **Finite State** | 상용 플랫폼 | N/A | 엔터프라이즈 | Reachability | $62.5M 펀딩, 포트폴리오 관리 | 심층 분석 부족, SaaS 종속 |
| **Eclypsium** | 상용 플랫폼 | N/A | 엔터프라이즈 | AI 바이너리 분석 | $94.2M 펀딩, 1,200만+ 해시 DB | 엔터프라이즈 IT 집중 |

### 1.2 Theori Xint — 가장 참고할 만한 모델

Xint는 SCOUT와 직접 경쟁하지는 않지만(소스코드/웹 중심 vs 펌웨어 바이너리), **아키텍처 패턴이 가장 선진적**이다:

**Xint의 핵심 아키텍처 교훈:**

| Xint 패턴 | 상세 | SCOUT 적용 가능성 |
|-----------|------|-------------------|
| **Multi-agent 오케스트레이션 엔진** | 독자적 AI 에이전트 오케스트레이션으로 다수 LLM을 병렬 배치 | SCOUT의 adversarial_triage를 전체 파이프라인으로 확장 |
| **전문화된 sub-agent as tools** | PovProducerAgent, SourceQuestionAgent, DiffAnalyzerAgent 등 | 각 분석 도메인별 전문 에이전트 분리 |
| **인덱싱된 코드 DB 기반 도구** | clang AST, Joern, Tree-sitter 인덱싱 → 전용 API (read_definition, find_references) | Ghidra P-code/AST를 인덱싱하여 LLM 도구로 노출 |
| **제약 기반 프롬프트** | "Rules over hints" — 금지 규칙이 가이드보다 효과적 | adversarial_triage/taint 프롬프트에 금지 규칙 추가 |
| **비용 인식 에스컬레이션** | VulnClassifier ($0.004) → VulnAnalyzer ($0.50) → 상위 20%만 심층 분석 | SCOUT의 haiku→sonnet→opus 라우팅 패턴과 동일 철학 |
| **병렬 모델 경쟁** | PoC 생성 시 Claude Sonnet, Claude 4, o3를 동시 실행, 먼저 성공한 것 채택 | poc_refinement에서 다중 모델 병렬 생성 |
| **Tool forcing** | `tool_choice=required`로 소형 모델의 일관적 도구 사용 보장 | haiku 호출 시 structured output 강제 |
| **Terminate tool 패턴** | 전용 종료 함수로 구조화된 최종 출력 보장 | JSON 응답 파싱 실패(68%) 해결의 핵심 |

**RoboDuck(AIxCC CRS) 교훈:**

- Infer 정적 분석의 **99.9% FP rate** → LLM 기반 2단계 필터링으로 극복
- Log probability 기반 confidence scoring (바이너리 yes/no 대신 0-1 연속값)
- 단일 async Python 프로세스에서 수천 개 태스크 오케스트레이션
- "대부분의 실패는 핵심 방법론이 아닌 보조 코드(빌드, 패키징)에서 발생"

### 1.3 SCOUT만의 전략적 모트(Moat)

경쟁 분석 결과, SCOUT만이 보유한 고유 강점:

1. **결정론적 증거 무결성**: SHA-256 해시 앵커링 + confidence caps + SLSA L2. CRA/FDA 감사에서 "감사 통과 가능한 증거"를 생성하는 **유일한 오픈소스 도구**
2. **E2E 파이프라인 깊이**: 추출→정적→동적→exploit chain까지 42단계는 경쟁자 중 최대 깊이
3. **Zero-dependency 배포**: 에어갭 환경(국방, 의료, 산업제어)에서의 배포 용이성
4. **Multi-backend LLM**: Codex/Claude/Ollama 4개 드라이버 — 벤더 종속 없음
5. **MCP 서버**: AI 에이전트 에코시스템에 대한 선제적 대응

---

## Part 2: 기술 트렌드 — 학술 최전선에서 배울 것

### 2.1 세 가지 메가 트렌드

**트렌드 1: Multi-Agent 시스템의 부상**

| 시스템 | 학회 | 에이전트 구성 | 성과 |
|--------|------|--------------|------|
| VulnSage | ICPC 2026 | Analyzer, Generator, Validator, Reflector + Supervisor | 146개 zero-day, EXPLOADE.js 대비 34.64% 향상 |
| Argus | arXiv 2026 | 공급망 분석 + RAG + ReAct multi-agent | 7개 프로젝트(10만LOC+)에서 zero-day |
| CVE-Genie | 2025 | 리소스 수집 → 환경 재구성 → 검증 | 841개 CVE 중 428개(51%) 자동 재현, $2.77/CVE |
| PentestAgent | AsiaCCS 2025 | RAG + multi-agent 침투 테스트 | 자동 정보수집/분석/익스플로잇 |
| Xint/RoboDuck | AIxCC 2024 | VulnClassifier → VulnAnalyzer → PovProducer → DynamicDebug | DARPA AIxCC 3위 |

→ **SCOUT 시사점**: 현재 adversarial_triage의 Advocate/Critic 2-agent 패턴을 전체 exploit chain으로 확장. VulnSage의 Analyzer/Generator/Validator/Reflector 4-agent 패턴이 SCOUT의 `chain_construction → exploit_autopoc → poc_validation` 경로에 직접 매핑됨.

**트렌드 2: Code Slicing + Structured Output = 정확도 점프**

| 기법 | 도구 | 효과 |
|------|------|------|
| Code Slicing Prompt Sequence | LATTE (TOSEM 2025) | 37개 신규 버그, 10 CVE, Emtaint/Arbiter 전 항목 우위 |
| Structured Output (tool_use) | Xint RoboDuck, Aardvark | Terminate tool 패턴으로 JSON 파싱 실패 제거 |
| Chain-of-Thought + few-shot | VulBinLLM (2025) | CWE-78 recall 100%, precision 84.67% |
| Log probability scoring | RoboDuck | $0.001/report로 0-1 confidence 연속값 생성 |

→ **SCOUT 시사점**: 68% parse failure의 근본 원인은 structured output 미사용. `llm_driver.py:329-333`에 system prompt + tool_use + temperature=0 추가만으로 즉시 해결 가능. LATTE의 Code Slicing은 `taint_propagation.py`의 프롬프트 구성에 직접 적용.

**트렌드 3: AI-Guided Dynamic Verification의 실증**

| 시스템 | 성과 | 기법 |
|--------|------|------|
| Google Big Sleep | SQLite zero-day (실제 CVE) | Gemini 1.5 + 코드 탐색 + 샌드박스 실행 |
| Google OSS-Fuzz AI | 26개 취약점, CVE-2024-9143 (OpenSSL 20년) | LLM 퍼즈 하네스 자동 생성, 37만줄 커버리지 |
| HouseFuzz | 177개 취약점 (156 zero-day) | 서비스 인식 multi-process 퍼징 |
| OpenAI Aardvark | 792 critical, 10,561 high severity, 10 CVE | GPT-5 기반 자율 보안 에이전트 |

→ **SCOUT 시사점**: 정적 분석만으로는 precision 35-41%의 천장을 돌파 불가. 동적 검증 경로 완성이 근본 해결책. HouseFuzz의 서비스 인식 퍼징 + OSS-Fuzz AI의 LLM 하네스 생성이 SCOUT의 fuzzing 스테이지를 혁신할 핵심 기술.

### 2.2 Taint 분석 — SCOUT 핵심 경쟁 영역의 진화

| 도구 | 연도 | 바이너리당 시간 | 0-day | 핵심 기법 |
|------|------|----------------|-------|-----------|
| Karonte | 2020 | ~6시간 | 46 TP | 다중 바이너리 심볼릭 |
| SaTC | 2021 | ~6.5시간 | 683 TP | 프론트엔드 소스 추출 |
| EmTaint | 2023 | <4시간 | 1,518 TP | On-demand alias |
| **LARA** | **2024** | - | **245 0-day, 162 CVE** | **URI/키 시맨틱 소스 식별** |
| **Mango** | **2024** | **8분** | 56 신규 | **정수/문자열 도메인 DFA** |
| SinkTaint | 2025 | - | 21 고위험 | 역추적 + 제약 분석 |
| **LATTE** | **2025** | - | **37 신규, 10 CVE** | **LLM Code Slicing** |
| **SCOUT** | **2026** | - | - | **P-code SSA + LLM debate** |

→ **우선 도입**: LARA의 URI/키 시맨틱 소스 식별(`enhanced_source.py` 강화) + LATTE의 Code Slicing(`taint_propagation.py` 프롬프트 재구성) + Mango 참고 스케일링

### 2.3 LLM 디컴파일 & 바이너리 분석

| 모델/도구 | 핵심 | SCOUT 적용 |
|-----------|------|-----------|
| LLM4Decompile V2 (9B) | Ghidra 의사코드 리파인먼트, re-executability 0.65 | Ollama 드라이버로 통합, ghidra_analysis 후처리 |
| BinaryAI (Tencent) | 바이너리-소스 함수 매칭, precision 85.84% | sbom/cve_scan SCA 정확도 향상 |
| VulBinLLM | Memory management agent + CoT, CWE-78 recall 100% | taint_propagation 보완 |
| GhidrAssistMCP | MCP 프로토콜 기반 Ghidra AI 통합 | SCOUT MCP ↔ GhidraMCP 양방향 |
| SK2Decompile | 2-phase: skeleton → skin, 난독화 바이너리 대응 | 향후 난독화 펌웨어 분석 |

---

## Part 3: 규제 환경 — SCOUT에게 유리한 바람

### 3.1 규제 타임라인 — 2026-2028 핵심 마일스톤

```
2026 ──────────────────────────────────────────────────── 2028
  │                                                         │
  ├─ 2026.09: EU CRA 취약점/인시던트 보고 의무 시작           │
  │                                                         │
  ├─ 2026.09: ETSI EN 303 645 시행 (소비자 IoT)             │
  │                                                         │
  ├─ 2027.12: EU CRA 전체 적용 (SBOM 포함, CE 마킹 필수)     │
  │           벌금: 최대 €15M 또는 매출 2.5%                  │
  │                                                         │
  ├─ 2028.01: UN R155 모든 차종 적용 (자동차 사이버보안)       │
  │                                                         │
  └─ FDA: Section 524B — 의료기기 SBOM + SAST 의무           │
```

### 3.2 SCOUT의 규제 대응 준비도

| 규제 요구사항 | SCOUT 현재 상태 | 격차 |
|--------------|----------------|------|
| SBOM (CycloneDX) | ✅ CycloneDX 1.6 + VEX | SPDX 미지원 |
| 취약점 보고 | ✅ SARIF 2.1.0 | CSAF/OpenVEX 미지원 |
| 증거 무결성 | ✅ SHA-256 + SLSA L2 | — (선도) |
| Reachability | ✅ BFS 기반 도달성 | EPSS 미통합 |
| SAST 문서화 | ✅ TUI + 웹 뷰어 | 규제별 맞춤 보고서 부재 |
| CI/CD 통합 | ⚠️ CLI + SARIF | GitHub Action 부재 |
| SaaS/클라우드 | ❌ 온프레미스만 | 클라우드 서비스 미구현 |

→ **기회**: 2026.09 CRA 보고 의무 시작 전 5개월 — "EU CRA Annex I 호환 펌웨어 감사 출력" 포지셔닝의 최적 시기. SCOUT의 SARIF+CycloneDX+SLSA 출력은 이미 CRA 기술 요건과 호환.

---

## Part 4: 코드베이스 내부 — 지금 고쳐야 할 것

### 4.1 Critical Issues (즉시 해결)

**[C1] LLM 68% Parse Failure — 2-3일 수정**

```
현재: llm_driver.py:329-333
  "messages": [{"role": "user", "content": prompt}]
  → temperature 미설정 (기본 1.0), system prompt 부재, text 기반 JSON 요청

수정:
  1. system prompt 분리 (role: "system")
  2. temperature: 0 (JSON 출력에 필수)
  3. tool_use / Terminate tool 패턴으로 구조화 출력 강제
  4. few-shot 예시 2-3개 추가 (adversarial_triage, taint_propagation)
  
기대 효과: parse failure 68% → <10%, 추가 repair 호출 제거
```

**[C2] Sink 심볼 11개로 제한 — 반나절 수정**

```
현재: taint_propagation.py:40-52
  _SINK_SYMBOLS = {system, popen, execve, ...} — 11개

누락: memcpy, memmove, snprintf, strncpy, printf, syslog, dlopen,
      realpath, sprintf (format string), sscanf

수정: 싱크 확장 + format string 탐지 패턴 추가
기대 효과: 탐지 커버리지 즉시 확대
```

### 4.2 High-Priority Technical Debt

**[H1] run.py 4,476줄 God Object**
- 98회 normalize 보일러플레이트, stage_registry와 중복 팩토리
- → stage_executor.py, report_assembler.py, handoff_writer.py로 분리

**[H2] 순차 파이프라인 — DAG 병렬화**
- `stage.py:128-139`의 for-loop → 독립 스테이지(sbom‖endpoints, graph‖threat_model) 병렬
- 선언적 의존성 그래프 + `concurrent.futures`
- → 분석 시간 40-60% 단축

**[H3] 32개 모듈(34%) 테스트 부재**
- Critical: taint_propagation(1,010줄), adversarial_triage, semantic_classifier
- High: chain_constructor(1,130줄), ghidra_analysis(1,095줄), sarif_export, cve_scan(1,233줄)
- → LLM mock fixture 프레임워크 + 우선 모듈 테스트

**[H4] LLM 비용 강제 누락**
- llm_cost.py의 check_budget()을 taint/adversarial/semantic 스테이지에서 미호출
- → 예산 초과 시 조기 중단 메커니즘 추가

---

## Part 5: 전략 로드맵 — 3 Phases

### Phase 1: "Quick Wins" (2026 Q2-Q3, v2.5-v2.6)

**목표**: parse failure 해결, precision 50%+ 도달, CRA 포지셔닝

| # | 작업 | 노력 | 영향 | 근거 |
|---|------|------|------|------|
| 1.1 | **LLM structured output 도입** | 2-3일 | CRITICAL | Xint Terminate tool 패턴, 68%→<10% |
| 1.2 | **System prompt + temperature=0** | 1일 | HIGH | 전체 LLM 호출 품질 향상 |
| 1.3 | **Few-shot + CoT 프롬프트** | 2일 | HIGH | VulBinLLM CWE-78 recall 100% |
| 1.4 | **Sink 심볼 확장** (11→25+) | 반나절 | MEDIUM | format string, memcpy 등 |
| 1.5 | **LATTE Code Slicing** 도입 | 1주 | HIGH | taint 정확도 점프, 10 CVE 실증 |
| 1.6 | **LARA URI/키 시맨틱 소스 식별** | 1주 | HIGH | 소스 커버리지 확대, 245 0-day |
| 1.7 | **EPSS 스코어 통합** | 2일 | MEDIUM | CVE 우선순위 정확도 향상 |
| 1.8 | **GitHub Action 패키지** | 3일 | MEDIUM | CI/CD 통합, CRA 대응 |
| 1.9 | **CRA Annex I 호환성 매핑 문서** | 2일 | HIGH | 마케팅/포지셔닝 |

**Phase 1 KPI**: adversarial_triage parse failure <10%, Tier 1 precision 50%+, GitHub Action 배포

### Phase 2: "Architecture Leap" (2026 Q4 - 2027 Q2, v3.0)

**목표**: multi-agent 전환, DAG 병렬화, 동적 검증 강화, precision 70%+

| # | 작업 | 노력 | 영향 | 근거 |
|---|------|------|------|------|
| 2.1 | **DAG 기반 파이프라인 병렬화** | 2주 | HIGH | 분석 시간 40-60% 단축 |
| 2.2 | **run.py 분해** | 1주 | HIGH | stage_executor/report_assembler/handoff_writer |
| 2.3 | **Multi-agent exploit chain** | 3주 | CRITICAL | VulnSage Analyzer/Generator/Validator/Reflector |
| 2.4 | **LLM 퍼즈 하네스 자동 생성** | 2주 | HIGH | OSS-Fuzz AI: 37만줄 커버리지 |
| 2.5 | **서비스 인식 퍼징** | 3주 | HIGH | HouseFuzz: 177개 취약점, 156 zero-day |
| 2.6 | **Vul-RAG 지식 베이스** | 2주 | MEDIUM | CVE/CWE 시맨틱 매칭, 16-24% 향상 |
| 2.7 | **LLM4Decompile 통합** | 1주 | MEDIUM | Ollama 드라이버, 디컴파일 품질 40%+ |
| 2.8 | **GhidrAssistMCP 연동** | 1주 | MEDIUM | SCOUT MCP ↔ Ghidra MCP 양방향 |
| 2.9 | **32개 모듈 테스트 추가** | 2주 | HIGH | LLM mock fixture 포함 |
| 2.10 | **SPDX SBOM + CSAF** 출력 | 4일 | MEDIUM | 규제 포맷 완전성 |

**Phase 2 KPI**: 분석 시간 50% 단축, precision 70%+, exploit chain 자동 생성률 2x

### Phase 3: "Platform Evolution" (2027 Q3 - 2028, v4.0)

**목표**: SaaS화, 자율 에이전트, 학술 벤치마크 리더십

| # | 작업 | 노력 | 영향 | 근거 |
|---|------|------|------|------|
| 3.1 | **Big Sleep 스타일 자율 에이전트** | 2개월 | CRITICAL | Terminator에 에이전틱 루프 |
| 3.2 | **SCOUT Cloud API** | 2개월 | HIGH | REST API + 웹 대시보드, SaaS |
| 3.3 | **포트폴리오 관리** | 1개월 | HIGH | 다수 펌웨어 버전 추적, 추이 시각화 |
| 3.4 | **CVE-Bench 스타일 자동 평가** | 3주 | MEDIUM | exploit 성공 자동 판정 |
| 3.5 | **BinaryAI SCA 통합** | 2주 | MEDIUM | 바이너리-소스 매칭 SBOM 정확도 |
| 3.6 | **LFwC 10,913개 코퍼스 벤치마크** | 1개월 | HIGH | 학술 재현성 표준 |
| 3.7 | **산업별 보고서** (FDA/CRA/ISO 21434) | 3주 | MEDIUM | 규제 맞춤 |
| 3.8 | **Greenhouse Tier 1.5** | 3주 | MEDIUM | single-service 리호스팅, 퍼징 2x |
| 3.9 | **증분 분석(Incremental)** | 2주 | MEDIUM | 연속 펌웨어 분석 시간 80% 단축 |
| 3.10 | **Foundation Model 파일럿** | 3개월 | HIGH | 펌웨어 바이너리 전용 사전학습 |

**Phase 3 KPI**: SaaS 런칭, 자율 zero-day 발견, precision 85%+, NDSS/USENIX 논문 게재

---

## Part 6: 포지셔닝 전략 — 무엇이 되어야 하는가

### 6.1 경쟁 포지셔닝 맵

```
                    Deep Analysis (심층)
                         │
                         │
          SCOUT v3.0 ────┤──── Xint Code
          (펌웨어)       │     (소스코드/웹)
                         │
                    FirmAgent ── FIRMHIVE
                    (학술)      (학술)
                         │
  ─────────────────────── ┼ ──────────────────────
  Narrow Scope            │              Wide Scope
  (단일 분석)             │           (포트폴리오)
                         │
          EMBA ──────────┤──── Finite State
          (스캐너)       │     (플랫폼)
                         │
                    Eclypsium ── Microsoft
                    (인프라)     (Azure)
                         │
                    Shallow Analysis (표면)
```

### 6.2 SCOUT의 최적 포지션

**"Deep Analysis × Wide Scope" 사분면으로 이동**

현재 SCOUT는 "Deep × Narrow" — 단일 펌웨어의 심층 분석. 
Phase 2-3을 통해 포트폴리오 관리 + SaaS를 추가하면 "Deep × Wide"로 이동하여, 
Finite State(Shallow × Wide)와 Xint(Deep × Narrow, 소스코드)의 공백을 차지.

### 6.3 상용화 경로

| 단계 | 시기 | 모델 | 타겟 |
|------|------|------|------|
| **Phase 1** | 2026 하반기 | 오픈소스 + 컨설팅 | CRA Annex I 호환 감사 출력 수요 |
| **Phase 2** | 2027 | Open Core (엔터프라이즈 확장) | OEM/의료기기/자동차 |
| **Phase 3** | 2028 | SaaS API + 라이선스 | 중소 제조사, 보안 컨설팅 |

---

## Part 7: 위험 요소 및 대응

| 위험 | 확률 | 영향 | 대응 |
|------|------|------|------|
| FirmAgent가 대규모 검증 후 공개 | 중 | 높음 | Precision 개선 가속, 차별화(증거 체인) 강조 |
| EU CRA SBOM 포맷이 SPDX 전용으로 결정 | 낮음 | 높음 | SPDX 출력 우선 추가 (Phase 1에 포함 검토) |
| LLM 비용 급등 | 낮음 | 중 | Ollama 로컬 모델 fallback 이미 보유 |
| Extraction 병목 미해결 | 높음 | 극심 | Pandawan 통합 + vendor_decrypt 확장 |
| 핵심 개발자 병목 | 높음 | 높음 | 테스트 커버리지 확보, 문서화, 코드 분해 |

---

## Appendix A: 핵심 참고 논문

| 논문 | 학회 | 핵심 기여 | SCOUT 관련성 |
|------|------|-----------|-------------|
| Operation Mango | USENIX Security 2024 | 8분/바이너리 DFA taint | 스케일링 참고 |
| LARA | USENIX Security 2024 | URI/키 시맨틱 소스 식별 | enhanced_source 강화 |
| LATTE | ACM TOSEM 2025 | LLM Code Slicing taint | taint_propagation 핵심 |
| HouseFuzz | IEEE S&P 2025 | 서비스 인식 multi-process 퍼징 | fuzzing 혁신 |
| PwnGPT | ACL 2025 | 분석-생성-검증 AEG | exploit_autopoc 패턴 |
| VulnSage | ICPC 2026 | Multi-agent exploit | chain_construction 확장 |
| Argus | arXiv 2026 | RAG+ReAct multi-agent SAST | 전체 아키텍처 참고 |
| VulBinLLM | arXiv 2025 | CoT + Memory Agent | 프롬프트 강화 |
| Vul-RAG | ACM TOSEM 2025 | CVE 시맨틱 RAG | cve_scan 보강 |
| LLM4Decompile V2 | 2024 | Ghidra 디컴파일 리파인먼트 | ghidra_analysis 후처리 |
| BinaryAI | ICSE 2024 | 바이너리-소스 SCA | sbom precision |
| FirmAgent | NDSS 2026 | 퍼징+LLM 2단계, 91% precision | 직접 경쟁 참고 |
| FIRMHIVE | arXiv 2025 | Tree-of-Agents 재귀 | multi-agent 패턴 |
| Mens Sana | NDSS 2025 | 10,913 펌웨어 코퍼스 | 벤치마크 표준 |
| SinkTaint | IEEE TDSC 2025 | 역추적+제약 분석 | fp_verification 강화 |

## Appendix B: 핵심 경쟁사 펀딩/규모

| 회사 | 총 펀딩 | 최근 라운드 | 직원 |
|------|---------|------------|------|
| Finite State | $62.5M | 4라운드 | ~100 |
| Eclypsium | $94.2M | 2026.03 $25M | ~150 |
| Binarly | $14.1M | 2024.03 $10.5M Seed | ~30 |
| Theori | 비공개 | 비공개 | ~80 |

## Appendix C: Xint/RoboDuck 아키텍처 상세

**RoboDuck Bug Detection Pipeline:**
```
Static Analysis (Infer) ─┬─→ Vulnerability Scoring ($0.001/report)
                         │     └── log probability → 0-1 score
LLM-Based Analysis ─────┘
  ├── Single function mode
  └── Large code mode (관련 코드 번들링)
                         ↓
              Agent-Based Analysis ($0.50/report)
                ├── 상위 20%만 심층 분석
                └── Code exploration tools 장착
                         ↓
              PoC Generation
                ├── Claude Sonnet 3.5 ─┐
                ├── Claude 4 ──────────┤→ 병렬 실행, 먼저 성공한 것 채택
                └── OpenAI o3 ─────────┘
                         ↓
              Patch Generation (coding agents + sequence alignment)
```

**Xint Code 3-Stage Process:**
```
1. Attack Surface Exploration → 자율적 진입점/위협 경계 매핑
2. Deep Code Analysis → 의미론적 코드 추론 (패턴 매칭이 아님)
3. Impact Assessment → 익스플로잇 가능성 + 비즈니스 영향 평가
```

---

*본 문서는 SCOUT 프로젝트의 내부 전략 참고용으로 작성되었습니다.*
*데이터 수집일: 2026-04-12 | 연구 범위: 학술 논문 30+편, 웹 검색 50+ 쿼리*
