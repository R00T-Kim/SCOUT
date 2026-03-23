<div align="center">

# SCOUT (AIEdge)

### Firmware-to-Exploit Evidence Engine

**펌웨어 바이너리에서 검증 가능한 취약점 체인(Exploit Chain)까지**
해시 기반 증거로 추적 가능한 단계형 분석 엔진

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

---

**언어:** [English README.md](README.md), 한국어 (이 파일)

*해시 기반 증거 아티팩트를 생성하는 결정론적 펌웨어 분석 엔진 — 압축 해제부터 취약점 발견, 풀체인 익스플로잇 검증까지.*

</div>

---

## 한 줄 요약

SCOUT는 펌웨어 분석 결과를 "가능한 취약점 목록"에서 멈추지 않고,
`static 분석 증거 → 동적 검증 증거 → exploit PoC → verified_chain`까지의 **증거 체인**으로 연결하려고 설계된 도구입니다.

---

## 철학

**모든 익스플로잇은 증거에서 시작됩니다. SCOUT는 증거 체인을 생성합니다.**

대부분의 펌웨어 분석 도구는 "잠재적 취약점 목록"에서 멈춥니다. SCOUT는 다른 전제를 가지고 설계되었습니다: 최종 목표는 **검증 가능하고 재현 가능한 익스플로잇 체인**이며, 모든 단계는 그 목표를 향해 존재합니다.

```
펌웨어 → 구조 분석 → 공격면 → 취약점 → 익스플로잇 원시 → PoC → 검증된 체인
```

SCOUT는 추측하지 않습니다. 각 단계는 `run_dir`에 **해시 기반 아티팩트**를 생성하며, 추적 가능한 증거 없이는 어떤 주장도 진행되지 않습니다. 엔진은 기본적으로 결정론적입니다 — LLM 판단과 동적 검증은 오케스트레이터(Terminator)가 감사 추적과 함께 그 위에 레이어링하며, 증거 체인 자체에 내장되지 않습니다.

---

## 핵심 원칙

- **증거 우선(Evidence-first)**
  모든 주장(탐지/후보/확인)은 run_dir의 파일 경로, 오프셋, 해시, 증거 파일로 추적 가능합니다.
- **결정론적 증거 생성 + 비결정론적 판단 분리**
  정적 분석은 재현 가능하게 동작하고, LLM 판단은 별도 레이어(Orchestrator)에서 감사 로그와 함께 수행됩니다.
- **Fail-closed 거버넌스**
  결과는 완전하지 않더라도 저장은 하되, **확인(confirmed/verified)** 판정은 게이트에서 엄격하게 제한합니다.
- **Full-Chain 또는 Nothing**
  후보 제시에 그치지 않고, 취약점 후보 → 익스플로잇 원시 → PoC → 검증 가능한 체인으로 진행 상태를 명시합니다.

---

## 기술 스택 및 핵심 제약

- **Pure Python 3.10+** — pip 의존성 없음 (표준 라이브러리만 사용)
- **외부 도구는 런타임 선택사항** — binwalk, QEMU, FirmAE, Docker, Ghidra, AFL++ 모두 없어도 graceful skip
- **환경 변수 기반 설정** — 설정 파일 없음, 모든 파라미터를 env var로 제어
- **종료 코드:** 0 = 성공, 10 = 부분 성공, 20 = 치명적 오류, 30 = 정책 위반

---

## 최근 동기화 포인트

- **SBOM & CVE 스캔** — 새 `sbom` 스테이지가 펌웨어 인벤토리에서 CycloneDX 1.6 SBOM 생성 (opkg/dpkg 패키지 DB, 바이너리 버전 문자열, SO 라이브러리 버전, 커널 버전). 새 `cve_scan` 스테이지가 NVD API 2.0에 CPE 매칭으로 쿼리. Critical/High CVE에 대한 finding 후보 자동 생성. `AIEDGE_NVD_API_KEY`, `AIEDGE_NVD_CACHE_DIR`로 설정.
- **보안 평가 모듈** — 새 `cert_analysis.py` (X.509 인증서 스캔: 만료, 약한 키/서명, 자체 서명, 개인 키 노출), `init_analysis.py` (부트 서비스 감사: SysV, systemd, BusyBox inittab, OpenWrt procd; telnet/FTP/UPnP/SNMP 플래그), `fs_permissions.py` (world-writable 파일, SUID/SGID, 민감 파일 권한 감사).
- **MCP 서버** — 새 `mcp` 서브커맨드가 Model Context Protocol (JSON-RPC 2.0 over stdio)으로 12개 SCOUT 도구 노출. MCP 호환 AI 에이전트(Claude Code, Claude Desktop 등)가 펌웨어 분석을 직접 구동 가능. 사용법: `./scout mcp --project-id <run_id>`, `claude mcp add scout -- ./scout mcp --project-id <id>`.
- **LLM 드라이버 확장** — `ClaudeAPIDriver` (직접 Claude API, `urllib.request`, `ANTHROPIC_API_KEY`)와 `OllamaDriver` (로컬 LLM 서버, `AIEDGE_OLLAMA_URL`). `AIEDGE_LLM_DRIVER=codex|claude|ollama`로 선택. `llm_cost.py`로 비용 추적, `AIEDGE_LLM_BUDGET_USD`로 예산 제한.
- **CVE 도달성 분석** — 새 `reachability` 스테이지가 CVE 매칭 컴포넌트가 실제로 공격면에서 도달 가능한지 통신 그래프의 BFS로 판별. 분류: `directly_reachable` (≤2 홉), `potentially_reachable` (3+), `unreachable`.
- **펌웨어 비교** — 새 `firmware_diff.py`가 두 분석 런을 비교: 파일시스템 diff (추가/삭제/수정/권한), 바이너리 하드닝 diff (NX/PIE/RELRO 변화), config 보안 diff (보안 키워드 하이라이트 포함 통합 diff). CLI: `./scout diff <old_run> <new_run>`.
- **GDB 에뮬레이션 지원** — 새 `emulation_gdb.py`가 순수 stdlib GDB Remote Serial Protocol 클라이언트 제공. QEMU `-g` 스텁에 연결해 레지스터 읽기, 메모리 검사, 브레이크포인트, 백트레이스.
- **Ghidra 헤드리스 연동** — 새 `ghidra_bridge.py` + `ghidra_analysis.py` 스테이지. 선택적 Ghidra 디컴파일, 크로스레퍼런스, 데이터플로우 추적 (실제 함수 분석으로 source→sink). 분석 바이너리의 SHA-256 캐시. 런타임 선택사항 (Ghidra 미설치 시 graceful skip).
- **AFL++ 퍼징 파이프라인** — 새 `fuzz_target.py` (바이너리 점수 0-100), `fuzz_harness.py` (딕셔너리/시드/하네스 생성), `fuzz_campaign.py` (AFL++ Docker, QEMU 모드), `fuzz_triage.py` (크래시 익스플로잇 가능성 분류). 런타임 선택사항 (Docker/AFL++ 미설치 시 graceful skip).
- **Executive 리포트 생성** — 새 `report_export.py`가 파이프라인 요약, 상위 위험, SBOM/CVE 테이블, 공격면, 자격증명 findings를 포함한 Markdown 임원 보고서 생성.
- **웹 뷰어 UX 개선** — 단일 창 네비게이션 (사이드바 클릭으로 하나의 패널만 표시), 고정 KPI 요약 바 (Critical/High CVE 수, 컴포넌트, 엔드포인트), SBOM/CVE Scan/Reachability/보안 평가 신규 패널. 가독성을 위한 텍스트 대비 개선. 패널 전환 시 그래프 재렌더링.
- **파이프라인 확장** — 29 → 34개 등록 스테이지: `ghidra_analysis`, `sbom`, `cve_scan`, `reachability`, `fuzzing` 추가.
- **IPC 감지 파이프라인** — 펌웨어 rootfs에서 Unix socket, D-Bus 서비스, 공유 메모리, named pipe 감지. ELF 바이너리 `.rodata`/`.dynstr` IPC 심볼 스캔 (socket, bind, dbus_*, shm_open, fork, execve). 새로운 `ipc_channel` 그래프 노드와 IPC 엣지 5종 (`ipc_unix_socket`, `ipc_dbus`, `ipc_shm`, `ipc_pipe`, `ipc_exec_chain`). IPC 리스크 스코어링.
- **Source→Sink 경로 추적** — `surfaces` 스테이지에서 `source_sink_graph.json` 생성. 네트워크 엔드포인트 → 서비스 컴포넌트 → exec sink 바이너리(system, popen, execve) 경로 매핑. "외부 입력이 어디서 위험한 함수에 도달하는가?" 분석 가능.
- **Credential 자동 매핑** — `findings` 스테이지에서 `credential_mapping.json` 생성. SSH 키, 비밀번호 해시, API 토큰, 기본 자격증명을 auth 서피스(SSH, web, OS)에 매핑. 위험도 분류(high/medium/low).
- **Verifier reason code 개선** — `dynamic_validation`에서 `isolation_verified`/`boot_verified`/`pcap_captured` 생성, `poc_validation`에서 `repro_3_of_3` 생성. findings가 `VERIFIED` 판정 상태에 도달하는 경로 활성화.
- **인터랙티브 웹 뷰어** — 글래스모피즘 다크 테마, 순수 JS force-directed 그래프 (외부 의존성 없음). 새 패널: IPC Map, Source→Sink Paths, Credential Map, Risk Heatmap.
- **바이너리 하드닝 분석** — 순수 Python ELF 파서로 NX, PIE, RELRO, Stack Canary, Stripped 상태를 바이너리별로 수집.
- **3-Tier 에뮬레이션** — Tier 1: FirmAE 시스템 에뮬레이션(Docker 컨테이너), Tier 2: QEMU user-mode 서비스 프로빙, Tier 3: rootfs 검사(Alpine Docker fallback).
- **LLM Provider 추상화** — `llm_driver.py`의 `LLMDriver` Protocol과 `CodexCLIDriver`. `AIEDGE_LLM_DRIVER` env var로 provider 선택, `ModelTier` ("haiku"|"sonnet"|"opus") 지원.
- **취약점 유형별 PoC 템플릿** — `poc_templates.py` 레지스트리: `cmd_injection`, `path_traversal`, `auth_bypass`, `info_disclosure` 4종 + `tcp_banner` fallback.
- **LLM 보조 트리아지 스테이지** (`llm_triage`) — findings → llm_synthesis 사이에 실행. 모델 티어 자동 선택: <10 후보 → haiku, 10–50 → sonnet, >50 → opus.
- **Terminator 양방향 피드백 루프** — `terminator_feedback.py`가 `firmware_handoff.json`에 `feedback_request` 섹션 추가.
- `analyze` / `analyze-8mb`에 `--rootfs <DIR>` 지원. 다층 패킹 펌웨어에서 추출 실패 시, 수동/사전 추출 rootfs를 바로 주입.

---

## 아키텍처 요약

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         SCOUT (증거 엔진)                                │
│                                                                          │
│  펌웨어 ──► 압축해제 ──► 프로파일 ──► 인벤토리 ──► SBOM ──► CVE 스캔   │
│                                         (+ 하드닝)    (NVD API 2.0)     │
│                                                             │            │
│  ──► 보안 평가 ──► 공격면 ──► 도달성 분석 ──► Findings                  │
│      (cert/init/fs-perm)             (BFS 그래프)                        │
│                                                                          │
│  ──► Ghidra 분석 ──► LLM 트리아지 ──► LLM 합성                          │
│      (선택사항)                                                           │
│                                                                          │
│  ──► 에뮬레이션(3-Tier) ──► 퍼징(AFL++) ──► 익스플로잇                  │
│                              (선택사항)                                  │
│                                                                          │
│  StageFactory 스테이지: stage.json (sha256 매니페스트)                   │
│  Findings 단계: run_findings()가 구조화된 아티팩트 생성                  │
│               모든 경로 run-relative, 모든 해시 기록                    │
│               34개 등록 스테이지 (29개에서 확장)                         │
│                                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│                    Handoff (JSON 계약)                                   │
├──────────────────────────────────────────────────────────────────────────┤
│                   Terminator (오케스트레이터)                             │
│                                                                          │
│  Tribunal ──► Validator ──► Exploit Dev ──► Verified Chain               │
│  (LLM 심판)   (에뮬레이션)   (lab-gated)    (동적 증거 있을 때만 확인)  │
└──────────────────────────────────────────────────────────────────────────┘
```

각 단계는 `aiedge-runs/<ts>_sha256-.../` 아래에 증거를 남깁니다.

**관심사 분리:**

| 레이어 | 역할 | 결정론적? |
|:-------|:-----|:---------:|
| **SCOUT** | 증거 생성 (추출, 프로파일링, 인벤토리, 공격면, findings) | 예 |
| **Handoff** | 엔진과 오케스트레이터 간 JSON 계약 (`firmware_handoff.json`) | 예 |
| **Terminator** | LLM 심판, 동적 검증, 익스플로잇 개발, 리포트 승격 | 아니오 (감사 가능) |

---

## 빠른 시작 (CLI)

### 기본 분석

```bash
cd /path/to/SCOUT
./scout analyze firmware.bin \
  --ack-authorization --no-llm \
  --case-id my-analysis \
  --stages tooling,extraction,structure,carving,firmware_profile,inventory

# 추출이 약한 타깃(다층 포맷)에서는 사전 추출 rootfs를 직접 주입
./scout analyze firmware.img \
  --ack-authorization --no-llm \
  --case-id my-analysis \
  --rootfs /path/to/extracted/rootfs
```

### 전체 프로필 (exploit 모드)

```bash
./scout analyze firmware.bin \
  --ack-authorization \
  --case-id my-analysis \
  --profile exploit \
  --exploit-flag lab \
  --exploit-scope lab-only \
  --exploit-attestation authorized
```

### 기존 분석 재실행 / 특정 스테이지만 수행

```bash
./scout stages aiedge-runs/<run_id> \
  --stages llm_synthesis,dynamic_validation,exploit_autopoc \
  --time-budget-s 900
```

### MCP 서버 (AI 에이전트 연동)

```bash
# MCP stdio 서버 시작
./scout mcp --project-id aiedge-runs/<run_id>

# Claude Code에서 등록
claude mcp add scout -- ./scout mcp --project-id <id>
```

### 환경 변수

```bash
# LLM 설정
export AIEDGE_LLM_DRIVER=codex              # LLM provider: codex | claude | ollama
export ANTHROPIC_API_KEY=sk-ant-...         # ClaudeAPIDriver 사용 시
export AIEDGE_OLLAMA_URL=http://localhost:11434  # OllamaDriver 사용 시
export AIEDGE_LLM_BUDGET_USD=5.00           # LLM 비용 예산 한도

# LLM 타임아웃
export AIEDGE_LLM_CHAIN_TIMEOUT_S=180
export AIEDGE_LLM_CHAIN_MAX_ATTEMPTS=5
export AIEDGE_AUTOPOC_LLM_TIMEOUT_S=180
export AIEDGE_AUTOPOC_LLM_MAX_ATTEMPTS=4

# SBOM & CVE 스캔
export AIEDGE_NVD_API_KEY=<nvd-api-key>     # NVD API 키 (없어도 동작, 속도 제한 완화)
export AIEDGE_NVD_CACHE_DIR=aiedge-nvd-cache  # 크로스런 NVD 응답 캐시
export AIEDGE_SBOM_MAX_COMPONENTS=500       # 최대 SBOM 컴포넌트 수
export AIEDGE_CVE_SCAN_MAX_COMPONENTS=50    # CVE 스캔 대상 최대 컴포넌트 수
export AIEDGE_CVE_SCAN_TIMEOUT_S=30         # NVD API 요청당 타임아웃

# Ghidra 연동
export AIEDGE_GHIDRA_HOME=/opt/ghidra       # Ghidra 설치 경로
export AIEDGE_GHIDRA_MAX_BINARIES=20        # 분석 바이너리 최대 수
export AIEDGE_GHIDRA_TIMEOUT_S=300          # Ghidra 분석 타임아웃

# AFL++ 퍼징
export AIEDGE_AFLPP_IMAGE=aflplusplus/aflplusplus  # AFL++ Docker 이미지
export AIEDGE_FUZZ_BUDGET_S=3600            # 퍼징 예산 (초)
export AIEDGE_FUZZ_MAX_TARGETS=5            # 최대 퍼징 대상 바이너리 수

# MCP 서버
export AIEDGE_MCP_MAX_OUTPUT_KB=512         # MCP 응답 최대 크기
export AIEDGE_QEMU_GDB_PORT=1234           # QEMU GDB 원격 포트

# 에뮬레이션
export AIEDGE_EMULATION_IMAGE=scout-emulation:latest  # Tier 1 Docker 이미지
export AIEDGE_FIRMAE_ROOT=/opt/FirmAE       # FirmAE 경로

# Terminator 연동
export AIEDGE_FEEDBACK_DIR=aiedge-feedback  # Terminator 피드백 디렉토리

# 포트 스캔
export AIEDGE_PORTSCAN_TOP_K=1000
export AIEDGE_PORTSCAN_START=1
export AIEDGE_PORTSCAN_END=65535
export AIEDGE_PORTSCAN_WORKERS=128
export AIEDGE_PORTSCAN_BUDGET_S=120
export AIEDGE_PORTSCAN_FULL_RANGE=0  # 1: 전체 포트 범위 스캔

# 권한 없는 환경에서 동적 단계 실행
export AIEDGE_PRIV_RUNNER='./scripts/priv-run'
```

---

## 결과 검증 (권장)

```bash
python3 scripts/verify_analyst_digest.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_aiedge_analyst_report.py --run-dir aiedge-runs/<run_id>

python3 scripts/verify_run_dir_evidence_only.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_network_isolation.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_exploit_meaningfulness.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_verified_chain.py --run-dir aiedge-runs/<run_id>
```

네 개의 verifier 모두 통과 + digest 무결성 확인이 기본 운영 기준입니다.

---

## 품질 게이트 및 릴리스 게이트

```bash
./scout corpus-validate aiedge-runs/<run_id>       # 코퍼스 매니페스트 검증
./scout quality-metrics aiedge-runs/<run_id>        # 품질 메트릭 계산
./scout quality-gate aiedge-runs/<run_id>           # 품질 임계값 확인
./scout release-quality-gate aiedge-runs/<run_id>  # 통합 릴리스 게이트 (CLI)
scripts/release_gate.sh --run-dir aiedge-runs/<run_id>  # 통합 릴리스 게이트 (쉘)
```

---

## 터미널 UI / 뷰어

```bash
./scout tui aiedge-runs/<run_id>            # one-shot (기본)
./scout tw aiedge-runs/<run_id> -t 2 -n 20  # watch 모드
./scout ti aiedge-runs/<run_id>             # interactive
./scout to aiedge-runs/<run_id>             # once 모드
./scout serve aiedge-runs/<run_id>          # 웹 뷰어
```

인터랙티브 키:

- 이동: `j/k`, `↑/↓`, `g/G`
- 패널: `c`(후보), `t`(위협), `m`(런타임 모델), `a`(자산/프로토콜)
- 갱신: `r`, 종료: `q`

---

## run_dir 핵심 구조

```text
aiedge-runs/<run_id>/
├─ manifest.json
├─ firmware_handoff.json
├─ input/firmware.bin
├─ stages/
│  ├─ tooling/
│  ├─ extraction/
│  ├─ structure/
│  ├─ carving/
│  ├─ firmware_profile/
│  ├─ inventory/
│  │  └─ binary_analysis.json  (+ 바이너리별 하드닝 데이터)
│  ├─ sbom/
│  │  └─ sbom.json             (CycloneDX 1.6 SBOM + CPE 인덱스)
│  ├─ cve_scan/
│  │  └─ cve_scan.json         (NVD API 2.0 CVE 매칭 결과)
│  ├─ reachability/
│  │  └─ reachability.json     (BFS 도달성 분류)
│  ├─ surfaces/
│  │  └─ source_sink_graph.json
│  ├─ web_ui/
│  │  └─ web_ui.json
│  ├─ ghidra_analysis/
│  │  └─ ghidra_analysis.json  (디컴파일 + 크로스레퍼런스, 선택사항)
│  ├─ findings/
│  │  ├─ pattern_scan.json
│  │  ├─ credential_mapping.json
│  │  └─ chains.json
│  ├─ llm_triage/
│  │  └─ triage.json
│  ├─ dynamic_validation/
│  ├─ exploit_autopoc/
│  ├─ fuzzing/
│  │  └─ fuzz_results.json     (AFL++ 크래시 + 트리아지, 선택사항)
│  └─ graph/
│     └─ communication_graph.json
└─ report/
   ├─ report.json
   ├─ analyst_overview.json
   ├─ analyst_digest.json / .md
   └─ executive_report.md      (report_export.py 생성)
```

---

## 익스플로잇 승격 정책

**철칙: 증거 없이는 Confirmed 없음.**

| 레벨 | 요구 사항 | 표시 위치 |
|:-----|:----------|:----------|
| `dismissed` | Critic 반박 강함 또는 신뢰도 < 0.5 | 부록만 |
| `candidate` | 신뢰도 0.5–0.8, 증거 존재하나 체인 불완전 | 리포트 (플래그) |
| `high_confidence_static` | 신뢰도 ≥ 0.8, 정적 증거 강함, 동적 검증 미사용 | 리포트 (강조) |
| `confirmed` | 신뢰도 ≥ 0.8 AND 동적 검증 아티팩트 ≥1개 | 리포트 (상단) |
| `verified_chain` | Confirmed AND 샌드박스에서 PoC 3회 재현, 완전한 체인 | 익스플로잇 리포트 |

---

## 계약 문서 (Contracts)

| 문서 | 목적 |
|:-----|:-----|
| `docs/blueprint.md` | 전체 파이프라인 아키텍처와 설계 근거 |
| `docs/status.md` | 현재 구현 상태 — 단일 소스 오브 트루스 |
| `docs/aiedge_firmware_artifacts_v1.md` | 프로파일링 + 인벤토리 아티팩트 스키마 계약 |
| `docs/aiedge_adapter_contract.md` | Terminator↔SCOUT 핸드오프 프로토콜 |
| `docs/aiedge_report_contract.md` | 리포트 구조와 거버넌스 규칙 |
| `docs/analyst_digest_contract.md` | 정규 `report/analyst_digest.json` 스키마와 판정 의미론 |
| `docs/verified_chain_contract.md` | verified_chain 증거 요구사항 |
| `docs/aiedge_duplicate_gate_contract.md` | 크로스런 중복 억제 규칙 |
| `docs/runbook.md` | digest-first 검토 + verified-chain 증명 게이트를 위한 운영 흐름 |
| `docs/aiedge_8mb_track_runbook.md` | 8MB 트런케이션 트랙 운영 가이드 |
| `docs/analyst_viewer_cockpit_mapping.md` | 뷰어 패널-아티팩트 매핑 |

---

## 보안 및 윤리

> **승인된 환경에서만 사용**

SCOUT는 아래 목적의 통제된 환경에서 사용해야 합니다.

- **사전 승인된 보안 점검** — 벤더 협의가 완료된 계약 기반 펌웨어 보안 감사
- **취약점 연구** — 협조적 공개 타임라인을 갖춘 책임감 있는 공개
- **CTF 및 교육 환경** — 지정된 대상에 대한 연습 및 훈련

**기본 보안 제약:**

- 동적 검증은 외부 네트워크 없는 샌드박스 컨테이너에서 실행
- PoC 실행은 명시적인 `--ack-authorization` 및 실험실 환경 확인 조건에서만
- weaponized payload 미포함; `poc_skeletons/`는 안전한 PoC 뼈대만 포함
- 모든 LLM 판단 및 익스플로잇 생성 단계에 대한 완전한 감사 추적
- `confirmed` 상태는 동적 증거 없이는 불가 — 예외 없음

---

## 원문 / 추가 정보

- English README: `README.md`

---

MIT License
