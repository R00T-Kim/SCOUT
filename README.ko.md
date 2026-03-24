<div align="center">

<img src="https://img.shields.io/badge/SCOUT-Firmware_Evidence_Engine-0d1117?style=for-the-badge&labelColor=0d1117" alt="SCOUT" />

# SCOUT

### Firmware-to-Exploit Evidence Engine

**펌웨어 하나 넣으면, SARIF findings + CycloneDX SBOM+VEX + 해시 기반 증거 체인이 나옵니다.**

<br />

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Stages](https://img.shields.io/badge/Pipeline-34_Stages-blueviolet?style=for-the-badge)]()
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero_(stdlib)-orange?style=for-the-badge)]()

[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-blue?style=for-the-badge&logo=github)]()
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX_1.6+VEX-brightgreen?style=for-the-badge)]()
[![SLSA](https://img.shields.io/badge/SLSA-Level_2-purple?style=for-the-badge)]()

[English](README.md) | [한국어 (이 파일)](README.ko.md)

</div>

---

## 왜 SCOUT인가?

> **모든 finding에 해시 기반 증거 체인이 붙습니다.**
>
> 파일 경로, 바이트 오프셋, SHA-256 해시, 근거 없이는 finding을 생성하지 않습니다. 아티팩트는 펌웨어 입력부터 최종 판정까지 변조 불가능하고 추적 가능합니다. 블랙박스 점수 없음.

> **정적 분석 결과는 0.60 상한 -- 부풀리지 않습니다.**
>
> 동적으로 검증되지 않은 취약점의 confidence는 하드캡됩니다. `confirmed` 승격에는 최소 1개의 동적 검증 아티팩트가 필요합니다. 정직한 confidence가 높은 숫자보다 낫습니다.

> **SARIF + CycloneDX VEX + SLSA -- 또 다른 커스텀 포맷이 아닌 업계 표준.**
>
> Findings는 SARIF 2.1.0으로 내보내져 GitHub Code Scanning과 VS Code에서 바로 사용 가능합니다. SBOM은 CycloneDX 1.6 + VEX(Vulnerability Exploitability eXchange)로 출력됩니다. 분석 아티팩트에는 SLSA Level 2 in-toto attestation이 붙습니다.

---

## 최신 업데이트

| 기능 | 설명 |
|:-----|:-----|
| **SARIF 2.1.0 Export** | GitHub Code Scanning, VS Code SARIF Viewer, CI/CD 연동용 표준 findings 출력 |
| **CycloneDX VEX** | SBOM에 취약점 악용 가능성 상태(exploitable / affected / not_affected) 내장 |
| **정밀 .dynstr 탐지** | ELF 동적 임포트 테이블 파싱으로 바이트 스캔 대체; FORTIFY_SOURCE 커버리지 감지 |
| **40+ SBOM 시그니처** | wolfSSL, mbedTLS, GoAhead, miniUPnPd, SQLite, U-Boot 등 30개 이상 추가 (기존 8개) |
| **Ghidra Headless 스크립트** | 4개 분석 스크립트: `decompile_all`, `xref_graph`, `dataflow_trace`, `string_refs` |
| **AFL++ 성능 최적화** | CMPLOG, persistent mode, NVRAM faker, multi-instance, `AFL_ENTRYPOINT` 지원 |
| **Reachability-Aware CVE** | BFS 네트워크 도달성 분석 기반 CVE confidence 자동 조정 |
| **SLSA L2 Provenance** | 분석 아티팩트용 in-toto attestation, cosign 서명 가능 |
| **벤치마크 러너** | Corpus 기반 precision / recall / FPR 품질 측정 |
| **Quality Gate 오버라이드** | CI/CD 파이프라인용 환경변수 기반 품질 임계값 설정 |

---

## 작동 방식

```
  1. 입력             2. 분석                 3. 수집                  4. 검토
  ─────────          ──────────              ──────────               ────────
  firmware.bin  -->  34단계 파이프라인  -->  SARIF findings      -->  웹 뷰어
                     자동 실행               CycloneDX SBOM+VEX      VS Code (SARIF)
                                             증거 체인                GitHub Code Scanning
                                             SLSA attestation         TUI 대시보드
```

**Step 1** -- 펌웨어 바이너리(또는 사전 추출된 rootfs)를 SCOUT에 지정합니다.

**Step 2** -- 34단계 파이프라인이 자동 실행: 압축 해제, 프로파일링, 바이너리 분석, SBOM 생성, CVE 스캔, 도달성 분석, 보안 평가, 공격면 매핑, 익스플로잇 체인 구성, Ghidra 디컴파일(선택), AFL++ 퍼징(선택).

**Step 3** -- 구조화된 run 디렉토리에 결과 출력: SARIF 2.1.0 findings, CycloneDX 1.6 SBOM + VEX, 해시 기반 증거 체인, SLSA L2 provenance attestation, 임원용 Markdown 보고서.

**Step 4** -- 내장 웹 뷰어에서 결과 확인, VS Code나 GitHub Code Scanning에 SARIF 임포트, MCP 서버로 Claude Code/Desktop에서 아티팩트 조회, TUI 대시보드로 검토.

---

## 빠른 시작

```bash
# 전체 분석 (모든 기능 기본 활성화)
./scout analyze firmware.bin

# 결정론적 분석 (LLM 미사용)
./scout analyze firmware.bin --no-llm

# 사전 추출 rootfs (약한 압축 해제 우회)
./scout analyze firmware.img --rootfs /path/to/extracted/rootfs

# 분석 전용 프로필 (익스플로잇 체인 미실행)
./scout analyze firmware.bin --profile analysis --no-llm

# CI/CD용 SARIF export
./scout analyze firmware.bin --no-llm
# -> aiedge-runs/<run_id>/stages/findings/sarif.json

# AI 에이전트용 MCP 서버
./scout mcp --project-id aiedge-runs/<run_id>

# 웹 뷰어
./scout serve aiedge-runs/<run_id> --port 8080
```

---

## 경쟁 도구 비교

| 기능 | SCOUT | EMBA | FACT | FirmAE |
|:-----|:-----:|:----:|:----:|:------:|
| SBOM (CycloneDX 1.6) | Yes + VEX | Yes | No | No |
| SARIF 2.1.0 Export | Yes | No | No | No |
| 해시 기반 증거 체인 | Yes | No | No | No |
| SLSA L2 Provenance | Yes | No | No | No |
| Reachability-Aware CVE | Yes | No | No | No |
| Confidence Caps (정직한 스코어링) | Yes | No | No | No |
| Ghidra Headless 연동 | Yes | Yes | No | No |
| AFL++ 퍼징 파이프라인 | Yes | No | No | No |
| 3-Tier 에뮬레이션 | Yes | Partial | No | Yes |
| MCP 서버 (AI 에이전트 연동) | Yes | No | No | No |
| LLM 트리아지 + 합성 | Yes | No | No | No |
| 웹 리포트 뷰어 | Yes | Yes | Yes | No |
| pip 의존성 제로 | Yes | No | No | No |

---

## 주요 기능

| | 기능 | 설명 |
|---|------|------|
| :package: | **SBOM & CVE** | CycloneDX 1.6 SBOM (40+ 시그니처) + NVD API 2.0 CVE 스캔 + VEX + 도달성 기반 confidence |
| :mag: | **바이너리 분석** | ELF 하드닝 감사 (NX/PIE/RELRO/Canary) + 정밀 `.dynstr` 심볼 탐지 + FORTIFY_SOURCE + Ghidra 헤드리스 디컴파일(선택) |
| :dart: | **공격면 분석** | Source-to-sink 추적, IPC 감지 (5종), 자격증명 자동 매핑 |
| :shield: | **보안 평가** | X.509 인증서 스캔, 부트 서비스 감사, 파일시스템 권한 검사 |
| :test_tube: | **퍼징** *(선택)* | AFL++ 파이프라인 + CMPLOG, persistent mode, NVRAM faker, 바이너리 스코어링, 하네스 생성, 크래시 트리아지 — Docker + AFL++ 이미지 필요 |
| :bug: | **에뮬레이션** | 3-Tier (FirmAE / QEMU user-mode / rootfs 검사) + GDB 원격 디버깅 |
| :robot: | **MCP 서버** | Model Context Protocol로 12개 도구 노출 -- Claude Code/Desktop 연동 |
| :brain: | **LLM 드라이버** | Codex CLI + Claude API + Ollama -- 비용 추적 및 예산 제한 |
| :bar_chart: | **웹 뷰어** | 글래스모피즘 대시보드 -- KPI 바, IPC 맵, 리스크 히트맵, 그래프 시각화 |
| :link: | **증거 체인** | 해시 기반 아티팩트, 신뢰도 상한, 익스플로잇 티어링, verified chain 게이팅 |
| :scroll: | **SARIF Export** | SARIF 2.1.0 findings -- GitHub Code Scanning, VS Code SARIF Viewer, CI/CD |
| :lock: | **SLSA Provenance** | Level 2 in-toto attestation, cosign 서명 가능 |
| :clipboard: | **임원 보고서** | 상위 위험, SBOM/CVE 테이블, 공격면 포함 Markdown 보고서 자동 생성 |
| :arrows_counterclockwise: | **펌웨어 비교** | 두 분석 런 비교 -- 파일시스템, 하드닝, 설정 보안 변경사항 |
| :chart_with_upwards_trend: | **벤치마크 러너** | Corpus 기반 precision/recall/FPR 품질 측정 |

---

## 파이프라인 (34단계)

```
Firmware --> Unpack --> Profile --> Inventory --> [Ghidra] --> SBOM --> CVE Scan
    --> Reachability --> Security Assessment --> Endpoints --> Surfaces --> Graph
    --> Attack Surface --> Findings --> LLM Triage --> LLM Synthesis
    --> Emulation (3-tier) --> [Fuzzing] --> Exploit Chain --> PoC --> Verification
```

`[괄호]` 안의 스테이지는 선택적 외부 도구(Ghidra, AFL++/Docker)가 필요합니다.

---

## 아키텍처

```
+------------------------------------------------------------------+
|                      SCOUT (증거 엔진)                              |
|                                                                    |
|  Firmware --> Unpack --> Profile --> Inventory --> SBOM --> CVE     |
|                                      (+ 하드닝)    (NVD 2.0)      |
|                                                         |          |
|  --> 보안 평가 --> Surfaces --> 도달성 분석 --> Findings            |
|      (cert/init/fs-perm)          (BFS 그래프)                     |
|                                                                    |
|  --> [Ghidra] --> LLM 트리아지 --> LLM 합성                        |
|  --> 에뮬레이션 --> [퍼징] --> 익스플로잇 --> PoC --> 검증          |
|                                                                    |
|  34단계 . stage.json 매니페스트 . SHA-256 해시 아티팩트             |
|  출력: SARIF 2.1.0 + CycloneDX 1.6+VEX + SLSA L2 provenance      |
+------------------------------------------------------------------+
|                   Handoff (firmware_handoff.json)                   |
+------------------------------------------------------------------+
|                    Terminator (오케스트레이터)                       |
|  Tribunal --> Validator --> Exploit Dev --> Verified Chain          |
|  (LLM 심판)   (에뮬레이션)   (lab-gated)    (동적 증거)            |
+------------------------------------------------------------------+
```

| 레이어 | 역할 | 결정론적? |
|:-------|:-----|:---------:|
| **SCOUT** | 증거 생성 (추출, 프로파일링, 인벤토리, 공격면, findings) | Yes |
| **Handoff** | 엔진과 오케스트레이터 간 JSON 계약 | Yes |
| **Terminator** | LLM 심판, 동적 검증, 익스플로잇 개발, 리포트 승격 | No (감사 가능) |

---

## 익스플로잇 승격 정책

**철칙: 동적 증거 없이는 Confirmed 없음.**

| 레벨 | 요구 사항 | 표시 위치 |
|:-----|:----------|:----------|
| `dismissed` | Critic 반박 강함 또는 confidence < 0.5 | 부록만 |
| `candidate` | Confidence 0.5-0.8, 증거 존재하나 체인 불완전 | 리포트 (플래그) |
| `high_confidence_static` | Confidence >= 0.8, 정적 증거 강함, 동적 검증 없음 | 리포트 (강조) |
| `confirmed` | Confidence >= 0.8 AND 동적 검증 아티팩트 >= 1개 | 리포트 (상단) |
| `verified_chain` | Confirmed AND 샌드박스에서 PoC 3회 재현, 완전한 체인 | 익스플로잇 리포트 |

---

<details>
<summary><strong>CLI 레퍼런스</strong></summary>

| 명령어 | 설명 |
|--------|------|
| `./scout analyze <firmware>` | 전체 펌웨어 분석 파이프라인 |
| `./scout analyze-8mb <firmware>` | 8MB 트런케이션 트랙 |
| `./scout stages <run_dir>` | 기존 런에서 특정 스테이지 재실행 |
| `./scout diff <old_run> <new_run>` | 두 분석 런 비교 |
| `./scout mcp --project-id <id>` | MCP stdio 서버 시작 |
| `./scout serve <run_dir>` | 웹 리포트 뷰어 실행 |
| `./scout tui <run_dir>` | 터미널 UI 대시보드 |
| `./scout ti` | TUI 인터랙티브 모드 (최근 런) |
| `./scout tw <run_dir> -t 2` | TUI watch 모드 (자동 갱신) |
| `./scout corpus-validate <run_dir>` | 코퍼스 매니페스트 검증 |
| `./scout quality-metrics <run_dir>` | 품질 메트릭 계산 |
| `./scout quality-gate <run_dir>` | 품질 임계값 확인 |
| `./scout release-quality-gate <run_dir>` | 통합 릴리스 게이트 |

**종료 코드:** `0` 성공, `10` 부분 성공, `20` 치명적 오류, `30` 정책 위반

</details>

<details>
<summary><strong>환경 변수</strong></summary>

### 코어

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_LLM_DRIVER` | `codex` | LLM 제공자: `codex` / `claude` / `ollama` |
| `ANTHROPIC_API_KEY` | -- | Claude 드라이버 API 키 |
| `AIEDGE_OLLAMA_URL` | `http://localhost:11434` | Ollama 서버 URL |
| `AIEDGE_LLM_BUDGET_USD` | -- | LLM 비용 예산 한도 |
| `AIEDGE_PRIV_RUNNER` | -- | 동적 단계용 권한 명령 접두사 |
| `AIEDGE_FEEDBACK_DIR` | `aiedge-feedback` | Terminator 피드백 디렉토리 |

### SBOM & CVE

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_NVD_API_KEY` | -- | NVD API 키 (선택, 속도 제한 완화) |
| `AIEDGE_NVD_CACHE_DIR` | `aiedge-nvd-cache` | 크로스런 NVD 응답 캐시 |
| `AIEDGE_SBOM_MAX_COMPONENTS` | `500` | 최대 SBOM 컴포넌트 수 |
| `AIEDGE_CVE_SCAN_MAX_COMPONENTS` | `50` | CVE 스캔 대상 최대 컴포넌트 수 |
| `AIEDGE_CVE_SCAN_TIMEOUT_S` | `30` | NVD API 요청당 타임아웃 |

### Ghidra

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_GHIDRA_HOME` | -- | Ghidra 설치 경로 |
| `AIEDGE_GHIDRA_MAX_BINARIES` | `20` | 분석 대상 최대 바이너리 수 |
| `AIEDGE_GHIDRA_TIMEOUT_S` | `300` | 바이너리당 분석 타임아웃 |

### 퍼징 (AFL++)

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_AFLPP_IMAGE` | `aflplusplus/aflplusplus` | AFL++ Docker 이미지 |
| `AIEDGE_FUZZ_BUDGET_S` | `3600` | 퍼징 시간 예산 (초) |
| `AIEDGE_FUZZ_MAX_TARGETS` | `5` | 최대 퍼징 대상 바이너리 수 |

### 에뮬레이션

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_EMULATION_IMAGE` | `scout-emulation:latest` | Tier 1 Docker 이미지 |
| `AIEDGE_FIRMAE_ROOT` | `/opt/FirmAE` | FirmAE 설치 경로 |
| `AIEDGE_QEMU_GDB_PORT` | `1234` | QEMU GDB 원격 포트 |

### Quality Gate 오버라이드

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_QG_PRECISION_MIN` | `0.9` | 최소 precision 임계값 |
| `AIEDGE_QG_RECALL_MIN` | `0.6` | 최소 recall 임계값 |
| `AIEDGE_QG_FPR_MAX` | `0.1` | 최대 false positive rate |
| `AIEDGE_QG_ABSTAIN_MAX` | `0.25` | 최대 abstain rate |

</details>

<details>
<summary><strong>실행 디렉토리 구조</strong></summary>

```
aiedge-runs/<run_id>/
├── manifest.json
├── firmware_handoff.json
├── provenance.intoto.jsonl          # SLSA L2 attestation
├── input/firmware.bin
├── stages/
│   ├── tooling/
│   ├── extraction/
│   ├── firmware_profile/
│   ├── inventory/
│   │   └── binary_analysis.json     # 바이너리별 하드닝 데이터
│   ├── sbom/
│   │   ├── sbom.json                # CycloneDX 1.6 + CPE 인덱스
│   │   └── vex.json                 # VEX 악용 가능성 주석
│   ├── cve_scan/
│   │   └── cve_scan.json            # NVD API CVE 매칭 결과
│   ├── reachability/
│   │   └── reachability.json        # BFS 도달성 분류
│   ├── surfaces/
│   │   └── source_sink_graph.json
│   ├── ghidra_analysis/             # 선택사항
│   ├── findings/
│   │   ├── pattern_scan.json
│   │   ├── credential_mapping.json
│   │   ├── chains.json
│   │   └── sarif.json               # SARIF 2.1.0 export
│   ├── fuzzing/                     # 선택사항
│   │   └── fuzz_results.json
│   └── graph/
│       └── communication_graph.json
└── report/
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

# 리포트 스키마 준수
python3 scripts/verify_aiedge_final_report.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_aiedge_analyst_report.py --run-dir aiedge-runs/<run_id>

# 보안 불변 조건
python3 scripts/verify_run_dir_evidence_only.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_network_isolation.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_exploit_meaningfulness.py --run-dir aiedge-runs/<run_id>

# SLSA provenance 검증
cosign verify-attestation --type slsaprovenance \
  aiedge-runs/<run_id>/provenance.intoto.jsonl

# 품질 게이트
./scout quality-gate aiedge-runs/<run_id>
./scout release-quality-gate aiedge-runs/<run_id>
```

</details>

---

## 문서

| 문서 | 목적 |
|:-----|:-----|
| [Blueprint](docs/blueprint.md) | 전체 파이프라인 아키텍처 및 설계 근거 |
| [Status](docs/status.md) | 현재 구현 상태 |
| [Determinism Policy](docs/determinism_policy.md) | 결정론적 파이프라인 완화 정책 |
| [Quality SLO](docs/quality_slo.md) | 품질 게이트 임계값 및 SLO |
| [아티팩트 스키마](docs/aiedge_firmware_artifacts_v1.md) | 프로파일링 + 인벤토리 아티팩트 계약 |
| [어댑터 계약](docs/aiedge_adapter_contract.md) | Terminator-SCOUT 핸드오프 프로토콜 |
| [리포트 계약](docs/aiedge_report_contract.md) | 리포트 구조 및 거버넌스 규칙 |
| [Analyst Digest](docs/analyst_digest_contract.md) | 다이제스트 스키마 및 판정 의미론 |
| [Verified Chain](docs/verified_chain_contract.md) | verified chain 증거 요구사항 |
| [Duplicate Gate](docs/aiedge_duplicate_gate_contract.md) | 크로스런 중복 억제 규칙 |
| [Runbook](docs/runbook.md) | digest-first 검토 운영 흐름 |

---

## 보안 및 윤리

> **승인된 환경에서만 사용하십시오.**

SCOUT는 적절한 승인 하에 통제된 환경에서 사용해야 합니다:

- **계약 기반 보안 감사** -- 벤더 협의가 완료된 펌웨어 보안 평가
- **취약점 연구** -- 협조적 공개 타임라인을 갖춘 책임 있는 공개
- **CTF 및 훈련** -- 실험실 환경의 지정된 대상

동적 검증은 네트워크 격리된 샌드박스 컨테이너에서 실행됩니다. 익스플로잇 프로필과 실험실 증명은 기본 활성화됩니다. Weaponized payload는 포함되지 않습니다.

---

## 기여하기

기여를 환영합니다. Pull Request 제출 전:

1. **읽기** [Blueprint](docs/blueprint.md)에서 아키텍처 맥락 파악
2. **실행** `pytest -q` -- 모든 테스트 통과 필수
3. **확인** `pyright src/` -- 타입 에러 0개
4. **준수** 기존 stage 프로토콜 (`src/aiedge/stage.py`의 `Stage` 참조)
5. **pip 의존성 제로** -- 코어 모듈은 stdlib만 사용

새 파이프라인 스테이지 추가는 `CLAUDE.md`의 "Adding a New Pipeline Stage" 섹션을 참조하세요.

---

## 라이선스

MIT

---

<div align="center">

<sub>보안 연구 커뮤니티를 위해 만들어졌습니다. 비인가 접근에 사용하지 마세요.</sub>

<br />

<a href="https://github.com/R00T-Kim/SCOUT">github.com/R00T-Kim/SCOUT</a>

</div>
