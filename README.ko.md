<div align="center">

<img src="https://img.shields.io/badge/SCOUT-Firmware_Evidence_Engine-0d1117?style=for-the-badge&labelColor=0d1117" alt="SCOUT" />

# SCOUT

### Deterministic Firmware Security Analysis Pipeline

**펌웨어 하나 넣으면, SARIF findings + CycloneDX SBOM+VEX + 해시 기반 증거 체인이 나옵니다 -- 명령어 하나로.**

*Ghidra P-code taint 분석, adversarial LLM 토론, pip 의존성 제로로 펌웨어 취약점을 자동 탐지합니다.*

<br />

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=for-the-badge)](LICENSE)
[![Stages](https://img.shields.io/badge/Pipeline-42_Stages-blueviolet?style=for-the-badge)]()
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero_(stdlib)-orange?style=for-the-badge)]()
[![Version](https://img.shields.io/badge/Version-2.5.0-red?style=for-the-badge)]()

[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-blue?style=for-the-badge&logo=github)]()
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX_1.6+VEX-brightgreen?style=for-the-badge)]()
[![SLSA](https://img.shields.io/badge/SLSA-Level_2-purple?style=for-the-badge)]()

<br />

<table>
<tr>
<td align="center"><strong>1,123</strong><br/><sub>펌웨어 분석 완료<br/>(Tier 1)</sub></td>
<td align="center"><strong>99.2%</strong><br/><sub>분석 성공률</sub></td>
<td align="center"><strong>13,893</strong><br/><sub>CVE 매칭</sub></td>
<td align="center"><strong>99.3%</strong><br/><sub>FPR 감소율<br/>(Tier 2 LLM)</sub></td>
<td align="center"><strong>≈ 0%</strong><br/><sub>False Negative<br/>Rate</sub></td>
</tr>
</table>

[English](README.md) | [한국어 (이 파일)](README.ko.md)

</div>

---

## 왜 SCOUT인가?

> **모든 finding에 해시 기반 증거 체인이 있습니다.**
> 파일 경로, 바이트 오프셋, SHA-256 해시, 근거 없이는 finding을 생성하지 않습니다. 펌웨어 블롭에서 최종 판정까지 추적 가능.

> **3-tier 신뢰도 상한 + Ghidra P-code 검증 -- 정직한 점수.**
> SYMBOL_COOCCURRENCE 0.40, STATIC_CODE_VERIFIED 0.55, PCODE_VERIFIED 0.75. `confirmed` 승격에는 동적 검증이 필요합니다. 점수를 부풀리지 않습니다.

> **SARIF + CycloneDX VEX + SLSA -- 표준 포맷.**
> GitHub Code Scanning, VS Code, CI/CD 즉시 연동.

---

## 작동 방식

```
  firmware.bin  ──>  42단계 파이프라인  ──>  SARIF findings       ──>  웹 뷰어
                     (Ghidra 자동 감지)     CycloneDX SBOM+VEX       TUI 대시보드
                     (CVE 자동 매칭)        증거 체인                  GitHub/VS Code
                     (LLM 선택적)           SLSA 인증서               AI 에이전트 MCP
```

```bash
# 전체 분석
./scout analyze firmware.bin

# 정적 분석만 (LLM 없음, $0)
./scout analyze firmware.bin --no-llm

# 사전 추출된 rootfs
./scout analyze firmware.img --rootfs /path/to/rootfs

# 웹 뷰어
./scout serve aiedge-runs/<run_id> --port 8080

# TUI 대시보드
./scout ti                    # 인터랙티브 (최신 실행)
./scout tw                    # 워치 모드 (자동 갱신)

# AI 에이전트용 MCP 서버
./scout mcp --project-id aiedge-runs/<run_id>
```

---

## 비교

| 기능 | SCOUT | FirmAgent | EMBA | FACT | FirmAE |
|:-----|:-----:|:---------:|:----:|:----:|:------:|
| 분석 규모 (테스트 펌웨어) | 1,123 | 14 | -- | -- | 1,124 |
| SBOM (CycloneDX 1.6+VEX) | O | X | O | X | X |
| SARIF 2.1.0 내보내기 | O | X | X | X | X |
| 해시 기반 증거 체인 | O | X | X | X | X |
| SLSA L2 프로비넌스 | O | X | X | X | X |
| Known CVE 시그니처 매칭 | O (2,528 CVEs, 시그니처 25개) | X | X | X | X |
| 신뢰도 상한 (정직한 점수) | O | X | X | X | X |
| Ghidra 통합 (자동 감지) | O | IDA Pro | O | X | X |
| AFL++ 퍼징 파이프라인 | O | O | X | X | X |
| 크로스 바이너리 IPC 체인 | O (5종) | X | X | X | X |
| 테인트 전파 (LLM) | O | O (DeepSeek) | X | X | X |
| 적대적 FP 제거 | O | X | X | X | X |
| MCP 서버 (AI 에이전트) | O | X | X | X | X |
| 웹 리포트 뷰어 | O | X | O | O | X |
| pip 의존성 없음 | O | X | X | X | X |

---

## 주요 기능

| | 기능 | 설명 |
|---|------|------|
| :package: | **SBOM & CVE** | CycloneDX 1.6 (40+ 시그니처) + NVD CVE 스캔 + 2,528 로컬 CVE DB + 25 Known CVE 시그니처 (8개 신규 벤더) |
| :mag: | **바이너리 분석** | ELF hardening (NX/PIE/RELRO/Canary) + `.dynstr` 감지 + FORTIFY_SOURCE + Ghidra 디컴파일 |
| :dart: | **공격 표면** | Source-to-sink 추적, 웹 서버 자동 감지, 크로스 바이너리 IPC 체인 (5종) |
| :brain: | **테인트 분석** | HTTP-aware 프로시저 간 테인트 + call chain 시각화; 웹 서버 우선 분석 |
| :shield: | **보안 평가** | X.509 인증서 스캔, 부트 서비스 감사, 파일시스템 권한, 자격 증명 매핑 |
| :test_tube: | **퍼징** *(선택)* | AFL++ CMPLOG, persistent mode, NVRAM faker, 하니스 생성, crash triage |
| :bug: | **에뮬레이션** | 4-tier (FirmAE / Pandawan+FirmSolo / QEMU user-mode / rootfs 검사) + GDB 원격 디버깅 |
| :robot: | **MCP 서버** | Model Context Protocol 12개 도구 (Claude Code/Desktop 연동) |
| :bar_chart: | **웹 뷰어** | Glassmorphism 대시보드 (KPI 바, IPC 맵, 리스크 히트맵) |
| :link: | **증거 체인** | SHA-256 앵커 아티팩트, 2-tier 신뢰도 상한 (0.40/0.55), 5단계 exploit 승격 |
| :scroll: | **SARIF & SLSA** | SARIF 2.1.0 findings + SLSA Level 2 in-toto 인증 |
| :chart_with_upwards_trend: | **벤치마킹** | FirmAE 데이터셋 지원, analyst-readiness 점수화, verifier 기반 archive bundle, TP/FP 분석 스크립트 |
| :key: | **벤더 복호화** | D-Link SHRS AES-128-CBC 자동 복호화; Shannon entropy 암호화 탐지 (>7.9) |

---

## 파이프라인 (42단계)

```
펌웨어 --> 언패킹 --> 프로파일 --> 인벤토리 --> Ghidra --> 시맨틱 분류
    --> SBOM --> CVE 스캔 --> 도달성 --> 엔드포인트 --> 서피스
    --> 강화 소스 --> C-Source 식별 --> 테인트 전파
    --> FP 검증 --> 적대적 트리아지
    --> 그래프 --> 공격 표면 --> Findings
    --> LLM 트리아지 --> LLM 합성 --> 에뮬레이션 --> [퍼징]
    --> PoC 개선 --> 체인 구성 --> 익스플로잇 체인 --> PoC --> 검증
```

Ghidra는 자동 감지되어 기본 활성화됩니다. `[대괄호]` 스테이지는 선택적 외부 도구 필요 (AFL++/Docker).

<details>
<summary><strong>v2.0 신규 스테이지 (8개)</strong></summary>

| 스테이지 | 모듈 | 목적 | LLM | 비용 |
|---------|------|------|-----|------|
| `enhanced_source` | `enhanced_source.py` | 웹 서버 자동 감지 + INPUT_APIS 스캔 (21개 API) | 아니오 | $0 |
| `semantic_classification` | `semantic_classifier.py` | 3단계 함수 분류기 (정적, haiku, sonnet) | 예 | 낮음 |
| `taint_propagation` | `taint_propagation.py` | HTTP-aware 프로시저 간 테인트 + call chain | 예 | 중간 |
| `fp_verification` | `fp_verification.py` | 3패턴 FP 제거 (sanitizer/비전파/시스템파일) | 아니오 | $0 |
| `adversarial_triage` | `adversarial_triage.py` | Advocate/Critic LLM 토론 기반 FPR 감소 | 예 | 중간 |
| `poc_refinement` | `poc_refinement.py` | 퍼징 시드 기반 반복 PoC 생성 (최대 5회) | 예 | 중간 |
| `chain_construction` | `chain_constructor.py` | 동일 바이너리 + 크로스 바이너리 IPC 익스플로잇 체인 | 아니오 | $0 |
| `csource_identification` | `csource_identification.py` | 정적 센티널 + QEMU 기반 HTTP 입력 소스 식별 | 아니오 | $0 |

</details>

<details>
<summary><strong>v2.5.0 신규 기능 (2026-04-13)</strong></summary>

| 기능 | 모듈 | 설명 |
|------|------|------|
| 중앙 시스템 프롬프트 | `llm_prompts.py` (신규) | 7개 역할별 시스템 프롬프트(ADVOCATE/CRITIC/TAINT/CLASSIFIER/REPAIR/SYNTHESIS) + temperature 상수 |
| LLMDriver Protocol 확장 | `llm_driver.py` | 4개 드라이버(Codex/Claude API/Claude Code/Ollama)에 `system_prompt` + `temperature` 파라미터 추가 |
| 5-stage JSON 파서 | `llm_driver.py` | preamble 제거 → fence → raw → brace-counting → common error fix; `required_keys` 스키마 검증 |
| Sink 심볼 28개로 확장 | `taint_propagation.py` | `_SINK_SYMBOLS` 11→28 (memcpy, memmove, strcat, strncpy, gets, vsprintf, printf 계열, scanf 계열, dlopen, realpath) |
| Format string 탐지 | `taint_propagation.py` | `_FORMAT_STRING_SINKS` + `_is_format_string_variable()` — 변수 기반 format string 탐지 |
| EPSS 스코어 통합 | `cve_scan.py` | FIRST.org API 배치 조회, per-run + cross-run 캐시, EPSS 백분위 기반 신뢰도 조정 |
| LLM 실패 관찰성 분리 | `llm_driver.py` + 스테이지 | `parse_failures` vs `llm_call_failures` 분리 집계, quota_exhausted 명시적 탐지 |
| GitHub Action | `.github/actions/scout-scan/` | CI/CD 통합용 composite action, GitHub Security 탭 SARIF 업로드 |
| CRA 준수 매핑 | `docs/cra_compliance_mapping.md` | EU Cyber Resilience Act Annex I 12개 필수 요구사항을 SCOUT 출력에 매핑 |
| 전략 로드맵 | `docs/strategic_roadmap_2026.md` | 30+ 학술 논문, 경쟁 도구 분석(Theori Xint, FirmAgent, EU CRA) 기반 3-Phase 계획 |

**v2.5.0 검증 (Netgear R7000, codex 드라이버, 2026-04-13):**

| 지표 | v2.5 이전 (1211 런) | v2.5.0 (1320 런) |
|---|---|---|
| `adversarial_triage` parse_failures | **100/100** | **0/100** |
| `adversarial_triage` parsed_ok | 0/100 | 100/100 |
| `fp_verification` unverified | 97/100 | 0/100 |
| `fp_verification` true_positives | 1 | 57 |
| `fp_verification` false_positives | 2 | 43 |
| `cve_scan` EPSS enriched | 0/23 | 23/23 |

- adversarial debate: 100건 검토 → 99건 downgraded (FP) + 1건 maintained (TP)
- 런: `aiedge-runs/2026-04-12_1320_sha256-b28bf08e9d2c`
- v2.5 이전 실패는 Claude CLI 쿼터 초과가 원인. v2.5.0에서 `quota_exhausted` 명시 분류로 실제 parse failure와 구분 가능

**핵심 버그 수정:**
- CVE scan signature-only 경로의 조기 `return` 제거 — enrichment / finding candidate 생성 누락 해결
- CVE scan backport 신뢰도 보정이 match별 component metadata 사용 (이전: 마지막 루프 변수 leak)
- semantic classifier 배치 50→15 축소로 긴 컨텍스트의 JSON 스키마 손실 방지

</details>

<details>
<summary><strong>v2.2.0 신규 기능</strong></summary>

| 기능 | 모듈 | 설명 |
|------|------|------|
| D-Link SHRS 복호화 | `vendor_decrypt.py` | SHRS 매직 자동 감지, AES-128-CBC 복호화 후 extraction |
| binwalk v3 호환 | `extraction.py` | 런타임 버전 감지, v3에서 제거된 `-d` 플래그 자동 처리 |
| Shannon entropy 탐지 | `extraction.py` | extraction 전 entropy 분석, >7.9는 암호화 의심으로 플래그 |
| CVE 시그니처 25개 | `cve_scan.py` | 13→25개 확장, 신규 벤더 8개 (Hikvision, QNAP, MikroTik, Ubiquiti, Tenda, Synology, Belkin, TRENDnet) + path_traversal 유형 |
| 정적 FP 룰 3개 | `fp_verification.py` | constant-sink gate, non-network binary gate, sanitizer detection |
| 2-tier 신뢰도 상한 | `confidence_caps.py` | SYMBOL_COOCCURRENCE_CAP=0.40, STATIC_CODE_VERIFIED_CAP=0.55 |
| Pandawan/FirmSolo Tier 1.5 | `emulation.py` | Docker 통합 Tier 1.5 에뮬레이션, KCRE 커널 복구 |
| Analyst-Readiness Benchmarking | `benchmark_eval.py` + `benchmark_firmae.sh` | archived bundle verifier pass, actionable candidate, analyst-ready 상태를 함께 측정 |
| LLM Trace Capture | `llm_driver.py` | stage별 `llm_trace/*.json`에 prompt/output/attempt 메타데이터 기록 |

**v2.2.0 벤치마크 (Tier 1 frozen baseline):**

- `1,123`개 펌웨어 / `8`개 벤더
- `1,110` success / `4` partial / `9` failed
- 분석 가능 비율 (`success + partial`): `99.2%`
- `3,523` findings / `13,893` CVE 매칭
- extraction ok / partial: `1110 / 4`
- inventory sufficient / insufficient: `1104 / 10`
- emulation 후처리(`report.json`) 기준 `used_tier=tier1`은 `1102`, `used_tier=tier2`는 `12`였으며, 이는 **stage-level path success이지 서비스 기동이 확인된 full-system success를 의미하지는 않습니다**

**v2.3.0 벤치마크 (Tier 2 LLM — adversarial triage):**

- `36` 펌웨어 / `9` 벤더 (ASUS, D-Link, Linksys, Netgear, OpenWrt, QNAP, Tenda, TP-Link, TRENDnet)
- `2,430` findings를 Advocate/Critic LLM 토론으로 검증 (GPT-5.3-Codex)
- `99.3%` 파싱 성공률
- `2,412` downgraded (FP 제거) / `18` maintained (실제 취약점)
- **FPR 감소율: 99.3%** | **False negative rate: ≈ 0%**
- 유지된 findings: command injection 5건 (gets→system/popen), buffer overflow 8건, unsafe API 7건

참고 문서:

- [`docs/tier1_rebenchmark_frozen_baseline.md`](docs/tier1_rebenchmark_frozen_baseline.md)
- [`docs/tier1_rebenchmark_final_analysis.md`](docs/tier1_rebenchmark_final_analysis.md)
- [`CHANGELOG.md`](CHANGELOG.md)

</details>

---

## 아키텍처

```
+--------------------------------------------------------------------+
|                       SCOUT (증거 생산 엔진)                        |
|                                                                    |
|  펌웨어 --> 언패킹 --> 프로파일 --> 인벤토리 --> SBOM --> CVE        |
|                         |            |            |      |         |
|                      Ghidra     바이너리 감사  40+ 시그    NVD+     |
|                      자동 감지   NX/PIE/etc              로컬 DB    |
|                                                                    |
|  --> 테인트 --> FP 필터 --> 공격 표면 --> Findings                  |
|     (HTTP-aware)  (3-패턴)   (IPC 체인)    (SARIF 2.1.0)           |
|                                                                    |
|  --> 에뮬레이션 --> [퍼징] --> 익스플로잇 체인 --> PoC --> 검증       |
|                                                                    |
|  42단계 . SHA-256 매니페스트 . 2-tier 신뢰도 상한 (0.40/0.55)        |
|  출력: SARIF + CycloneDX VEX + SLSA L2 + Markdown 보고서            |
+--------------------------------------------------------------------+
|                    핸드오프 (firmware_handoff.json)                 |
+--------------------------------------------------------------------+
|                     Terminator (오케스트레이터)                     |
|  LLM 심판 --> 동적 검증 --> Verified Chain                          |
+--------------------------------------------------------------------+
```

| 계층 | 역할 | 결정적? |
|:-----|:-----|:------:|
| **SCOUT** | 증거 생산 (42단계) | 예 |
| **핸드오프** | 엔진-오케스트레이터 JSON 계약 | 예 |
| **Terminator** | LLM 심판, 동적 검증, 익스플로잇 개발 | 아니오 (감사 가능) |

---

## 익스플로잇 승격 정책

| 등급 | 요구사항 | 배치 |
|:-----|:---------|:-----|
| `dismissed` | Critic 반박 강함 또는 신뢰도 < 0.5 | 부록만 |
| `candidate` | 신뢰도 0.5-0.8, 증거 존재하나 체인 불완전 | 보고서 (표시) |
| `high_confidence_static` | 신뢰도 >= 0.8, 강한 정적 증거, 동적 없음 | 보고서 (강조) |
| `confirmed` | 신뢰도 >= 0.8 AND 동적 검증 아티팩트 1+ | 보고서 (상단) |
| `verified_chain` | confirmed AND 샌드박스 PoC 3회 재현 | 익스플로잇 보고서 |

---

<details>
<summary><strong>CLI 레퍼런스</strong></summary>

| 명령어 | 설명 |
|--------|------|
| `./scout analyze <firmware>` | 전체 42단계 분석 파이프라인 |
| `./scout analyze <firmware> --quiet` | 진행 상황 출력 억제 (CI/스크립트 환경) |
| `./scout analyze-8mb <firmware>` | 8MB 정규형 트랙 분석 |
| `./scout stages <run_dir> --stages X,Y` | 특정 스테이지 재실행 |
| `./scout serve <run_dir>` | 웹 리포트 뷰어 |
| `./scout mcp [--project-id <id>]` | MCP stdio 서버 |
| `./scout tui <run_dir>` | TUI 대시보드 |
| `./scout ti` | TUI 인터랙티브 (최신 실행) |
| `./scout tw` | TUI 워치 모드 (자동 갱신) |
| `./scout to` | TUI 원샷 (최신 실행) |
| `./scout t` | TUI 기본 (최신 실행) |
| `./scout corpus-validate` | 코퍼스 매니페스트 검증 |
| `./scout quality-metrics` | 품질 메트릭 계산 |
| `./scout quality-gate` | 품질 임계값 확인 |
| `./scout release-quality-gate` | 통합 릴리즈 게이트 |

**종료 코드:** `0` 성공, `10` 부분 성공, `20` 치명적 오류, `30` 정책 위반

</details>

<details>
<summary><strong>벤치마킹</strong></summary>

```bash
# FirmAE 데이터셋 벤치마크 (현재 frozen baseline 기준 usable 펌웨어 1,123개)
./scripts/benchmark_firmae.sh --parallel 8 --time-budget 1800 --cleanup

# 옵션
--dataset-dir DIR       # 펌웨어 디렉토리 (기본: aiedge-inputs/firmae-benchmark)
--results-dir DIR       # 결과 출력 디렉토리
--file-list PATH        # 줄바꿈 기준 고정 펌웨어 리스트
--parallel N            # 동시 작업 수 (기본: 4)
--time-budget S         # 펌웨어당 시간 (기본: 600초)
--stages STAGES         # 특정 스테이지 (기본: 전체 파이프라인)
--max-images N          # 이미지 제한 (0 = 전체)
--llm                   # LLM 단계 활성화
--8mb                   # 8MB 트랙 사용
--full                  # 동적 스테이지 포함
--cleanup               # verifier 친화적인 run replica를 results/archives/ 아래 보존한 뒤 원본 run_dir 삭제
--dry-run               # 실행 없이 파일 목록만

# 기존 benchmark-results를 analyst-readiness 기준으로 재평가
python3 scripts/reevaluate_benchmark_results.py \
  --results-dir benchmark-results/<run>

# legacy bundle을 normalize한 뒤 일부 stage만 재실행 (archive fidelity 디버깅용)
python3 scripts/rerun_benchmark_stages.py \
  --results-dir benchmark-results/<legacy-run> \
  --out-dir benchmark-results/<rerun-out> \
  --stages attribution,graph,attack_surface \
  --no-llm

# 벤치마크 후 분석
PYTHONPATH=src python3 scripts/cve_rematch.py \
  --results-dir benchmark-results/firmae-YYYYMMDD_HHMM \
  --nvd-dir data/nvd-cache \
  --csv-out cve_matches.csv

PYTHONPATH=src python3 scripts/analyze_findings.py \
  --results-dir benchmark-results/firmae-YYYYMMDD_HHMM \
  --output analysis_report.json

# FirmAE 데이터셋 설정
./scripts/unpack_firmae_dataset.sh [ZIP_FILE]

# Tier 1 frozen baseline 문서
# - docs/tier1_rebenchmark_frozen_baseline.md
# - docs/tier1_rebenchmark_final_analysis.md
```

**현재 benchmark 계약**

- archived benchmark bundle은 이제 **flattened JSON 묶음이 아니라 run replica 전체**를 보존하는 것을 표준으로 삼습니다.
- benchmark 품질은 두 층으로 봅니다.
  - **analysis rate** = 파이프라인 완료율 (`success + partial`)
  - **analyst-ready rate** = archived bundle이 analyst/verifier 점검을 통과하고 evidence navigation이 가능한 상태
- `benchmark-results/legacy/tier2-llm-v2`는 **legacy snapshot**입니다. 역사적 참고/재평가용으로만 남기고, 새 analyst-readiness 기준의 공식 baseline으로 쓰지 않습니다.
- 새 contract는 fresh single-sample run (`benchmark-results/tier2-single-fidelity`)에서 archived bundle 기준 digest/report verifier 통과로 확인했습니다.

**현재 LLM 품질 동작**

- `llm_triage` 모델 라우팅: `<=10 haiku`, `11-50 sonnet`, `>50 또는 chain-backed opus`
- `haiku` 호출이 nonzero exit이면 `sonnet`으로 fallback합니다.
- `llm_triage`, `semantic_classification`, `adversarial_triage`, `fp_verification`은 `stages/<stage>/llm_trace/*.json`를 남깁니다.
- parse failure는 가능하면 repair하고, 아니면 조용히 성공 처리하지 않고 fail-closed `partial/degraded`로 남깁니다.

</details>

<details>
<summary><strong>환경 변수</strong></summary>

### 코어

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_LLM_DRIVER` | `codex` | LLM 제공자: `codex` / `claude` / `claude-code` / `ollama` |
| `ANTHROPIC_API_KEY` | -- | Claude 드라이버 API 키 (`claude-code`는 불필요) |
| `AIEDGE_OLLAMA_URL` | `http://localhost:11434` | Ollama 서버 URL |
| `AIEDGE_LLM_BUDGET_USD` | -- | LLM 비용 예산 한도 |
| `AIEDGE_PRIV_RUNNER` | -- | 동적 스테이지 특권 명령 접두사 |

### Ghidra

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_GHIDRA_HOME` | 자동 감지 | Ghidra 설치 경로; `/opt/ghidra_*`, `/usr/local/ghidra*` 탐색 |
| `AIEDGE_GHIDRA_MAX_BINARIES` | `20` | 분석할 최대 바이너리 수 |
| `AIEDGE_GHIDRA_TIMEOUT_S` | `300` | 바이너리당 분석 타임아웃 |

### SBOM & CVE

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_NVD_API_KEY` | -- | NVD API 키 (선택, 속도 제한 개선) |
| `AIEDGE_NVD_CACHE_DIR` | -- | 크로스 실행 NVD 응답 캐시 |
| `AIEDGE_SBOM_MAX_COMPONENTS` | `500` | 최대 SBOM 컴포넌트 |
| `AIEDGE_CVE_SCAN_MAX_COMPONENTS` | `50` | CVE 스캔 최대 컴포넌트 |

### 퍼징 & 에뮬레이션

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_AFLPP_IMAGE` | `aflplusplus/aflplusplus` | AFL++ Docker 이미지 |
| `AIEDGE_FUZZ_BUDGET_S` | `3600` | 퍼징 시간 예산 (초) |
| `AIEDGE_FUZZ_MAX_TARGETS` | `5` | 최대 퍼징 대상 |
| `AIEDGE_EMULATION_IMAGE` | `scout-emulation:latest` | 에뮬레이션 Docker 이미지 |
| `AIEDGE_FIRMAE_ROOT` | `/opt/FirmAE` | FirmAE 설치 경로 |

### 품질 게이트

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_QG_PRECISION_MIN` | `0.9` | 최소 정밀도 임계값 |
| `AIEDGE_QG_RECALL_MIN` | `0.6` | 최소 재현율 임계값 |
| `AIEDGE_QG_FPR_MAX` | `0.1` | 최대 거짓 양성률 |

</details>

<details>
<summary><strong>실행 디렉토리 구조</strong></summary>

```
aiedge-runs/<run_id>/
├── manifest.json
├── firmware_handoff.json
├── provenance.intoto.jsonl           # SLSA L2 인증서
├── input/firmware.bin
├── stages/
│   ├── extraction/                   # 추출된 파일시스템
│   ├── inventory/
│   │   └── binary_analysis.json      # 바이너리별 hardening + 심볼
│   ├── enhanced_source/
│   │   └── sources.json              # HTTP 입력 소스 + 웹 서버 감지
│   ├── sbom/
│   │   ├── sbom.json                 # CycloneDX 1.6
│   │   └── vex.json                  # VEX 악용 가능성
│   ├── cve_scan/
│   │   └── cve_matches.json          # NVD + Known 시그니처 매칭
│   ├── taint_propagation/
│   │   └── taint_results.json        # 테인트 경로 + call chain
│   ├── ghidra_analysis/              # 디컴파일 함수 (선택)
│   ├── chain_construction/
│   │   └── chains.json               # 동일/크로스 바이너리 IPC 체인
│   ├── findings/
│   │   ├── findings.json             # 전체 findings
│   │   ├── pattern_scan.json         # 정적 패턴 매칭
│   │   ├── sarif.json                # SARIF 2.1.0 내보내기
│   │   └── stage.json                # SHA-256 매니페스트
│   └── ...                           # 총 42개 스테이지 디렉토리
└── report/
    ├── viewer.html                   # 웹 대시보드
    ├── report.json
    ├── analyst_digest.json
    └── executive_report.md
```

</details>

<details>
<summary><strong>검증 스크립트</strong></summary>

```bash
# 증거 체인 무결성
python3 scripts/verify_analyst_digest.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_verified_chain.py --run-dir aiedge-runs/<run_id>

# 보고서 스키마 준수
python3 scripts/verify_aiedge_final_report.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_aiedge_analyst_report.py --run-dir aiedge-runs/<run_id>

# 보안 불변성
python3 scripts/verify_run_dir_evidence_only.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_network_isolation.py --run-dir aiedge-runs/<run_id>

# 품질 게이트
./scout release-quality-gate aiedge-runs/<run_id>
```

</details>

---

## 문서

| 문서 | 목적 |
|:-----|:-----|
| [Blueprint](docs/blueprint.md) | 파이프라인 아키텍처와 설계 근거 |
| [Status](docs/status.md) | 현재 구현 상태 |
| [Artifact Schema](docs/aiedge_firmware_artifacts_v1.md) | 프로파일링 + 인벤토리 계약 |
| [Adapter Contract](docs/aiedge_adapter_contract.md) | Terminator-SCOUT 핸드오프 프로토콜 |
| [Report Contract](docs/aiedge_report_contract.md) | 보고서 구조와 거버넌스 |
| [Analyst Digest](docs/analyst_digest_contract.md) | 다이제스트 스키마와 판정 |
| [Verified Chain](docs/verified_chain_contract.md) | 증거 요구사항 |
| [Duplicate Gate](docs/aiedge_duplicate_gate_contract.md) | 크로스 실행 중복 제거 |
| [Known CVE Ground Truth](docs/known_cve_ground_truth.md) | CVE 검증 데이터셋 |
| [Upgrade Plan v2](docs/upgrade_plan_v2.md) | v2.0 업그레이드 계획 |
| [LLM Roadmap](docs/roadmap_llm_agent_integration.md) | LLM 통합 전략 |

---

## 보안 & 윤리

> **인가된 환경에서만 사용하세요.**

SCOUT은 계약된 보안 감사, 취약점 연구 (책임 있는 공개), CTF/훈련 환경에서의 사용을 위해 설계되었습니다. 동적 검증은 네트워크 격리 샌드박스에서 실행됩니다. 무기화된 페이로드는 포함되어 있지 않습니다.

---

## 기여

1. **읽기** [Blueprint](docs/blueprint.md) 아키텍처 컨텍스트
2. **실행** `pytest -q` -- 모든 테스트 통과
3. **린트** `ruff check src/` -- 위반 없음
4. **준수** Stage 프로토콜 (`src/aiedge/stage.py`)
5. **pip 의존성 없음** -- stdlib only

---

## 라이선스

Apache 2.0

---

<div align="center">

<sub>보안 연구 커뮤니티를 위해 만들어졌습니다. 비인가 접근 금지.</sub>

<br />

<a href="https://github.com/R00T-Kim/SCOUT">github.com/R00T-Kim/SCOUT</a>

</div>
