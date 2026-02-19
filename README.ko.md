# SCOUT (AIEdge)

<div align="center">

### Firmware-to-Exploit Evidence Engine

**펌웨어 바이너리에서 검증 가능한 취약점 체인(Exploit Chain)까지**  
해시 기반 증거로 추적 가능한 단계형 분석 엔진

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

</div>

---

## 한 줄 요약

SCOUT는 펌웨어 분석 결과를 "가능한 취약점 목록"에서 멈추지 않고,
`static 분석 증거 → 동적 검증 증거 → exploit PoC → verified_chain`까지의 **증거 체인**으로 연결하려고 설계된 도구입니다.

---

## 핵심 원칙

- **증거 우선( Evidence-first )**  
  모든 주장(탐지/후보/확인)은 run_dir의 파일 경로, 오프셋, 해시, 증거 파일로 추적 가능합니다.
- **결정론적 증거 생성 + 비결정론적 판단 분리**  
  정적 분석은 재현 가능하게 동작하고, LLM 판단은 별도 레이어(Orchestrator)에서 감사 로그와 함께 수행됩니다.
- **Fail-closed 거버넌스**  
  결과는 완전하지 않더라도 저장은 하되, **확인(confirmed/verified)** 판정은 게이트에서 엄격하게 제한합니다.
- **Full-Chain 또는 Nothing**  
  후보 제시에 그치지 않고, 취약점 후보 → 익스플로잇 원시 → PoC → 검증 가능한 체인으로 진행 상태를 명시합니다.

---

## 최근 동기화 포인트

- `./scout` 래퍼가 우선 사용되며, 긴 `PYTHONPATH=... python3 -m aiedge` 호출은 보조 수단입니다.
- `dynamic_validation`과 `exploit_autopoc`가 **증거 번들(evidence bundle)**을 통해 연결되어, 실시간으로 D/E/V 우선순위 판독이 가능해졌습니다.
- 런타임 통신 모델이 별도 stage로 산출됩니다.  
  - `stages/graph/communication_graph.json`
  - `stages/graph/communication_matrix.json` / `.csv`
  - Neo4j용 `communication_graph.cypher`, `communication_graph.queries.cypher`
- TUI/뷰어에 위협·런타임·자산 패널이 추가되어 한 화면에서 흐름을 볼 수 있습니다.
- `AIEDGE_PRIV_RUNNER`는 상대 경로를 지원하며, `run_dir` 포함 다수 위치에서 안전하게 해석됩니다.

---

## 아키텍처 요약

```
펌웨어
  ├─ 추출/프로파일링
  ├─ 인벤토리(파일/바이너리)
  ├─ 공격면 매핑(네트워크/서비스/프로토콜/엔트리포인트)
  ├─ 취약점 패턴 + 체인 후보
  ├─ 동적 검증(부팅/포트/서비스/트래픽)
  ├─ PoC/자동 공격체인 시도(실행 기반 증거)
  └─ verified_chain report 생성
```

각 단계는 `aiedge-runs/<ts>_sha256-.../` 아래에 증거를 남깁니다.

---

## 빠른 시작 (CLI)

### 기본 분석

```bash
cd /path/to/SCOUT
./scout analyze firmware.bin \
  --ack-authorization --no-llm \
  --case-id my-analysis \
  --stages tooling,extraction,structure,carving,firmware_profile,inventory
```

### 전체 프로필(권장: exploit 모드)

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

환경변수(필요 시):

```bash
export AIEDGE_LLM_CHAIN_TIMEOUT_S=180
export AIEDGE_LLM_CHAIN_MAX_ATTEMPTS=5
export AIEDGE_AUTOPOC_LLM_TIMEOUT_S=180
export AIEDGE_AUTOPOC_LLM_MAX_ATTEMPTS=4

export AIEDGE_PORTSCAN_TOP_K=1000    # 힌트/우선 포트 + top-k 스캔 개수
export AIEDGE_PORTSCAN_START=1
export AIEDGE_PORTSCAN_END=65535
export AIEDGE_PORTSCAN_WORKERS=128
export AIEDGE_PORTSCAN_BUDGET_S=120
export AIEDGE_PORTSCAN_FULL_RANGE=0  # 1: 전체 포트 범위 스캔, 0(기본): top-k 중심 우선 스캔

# 전체 범위 스캔이 필요한 경우:
# export AIEDGE_PORTSCAN_FULL_RANGE=1
```

### no-new-privileges 환경에서 동적 단계 실행

```bash
export AIEDGE_PRIV_RUNNER='./scripts/priv-run'
./scout stages aiedge-runs/<run_id> --stages dynamic_validation,exploit_autopoc
```

---

## 결과 검증(권장)

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

## 터미널 UI / 뷰어

```bash
./scout tui aiedge-runs/<run_id>            # one-shot (기본)
./scout tw aiedge-runs/<run_id> -t 2 -n 20   # watch 모드
./scout ti aiedge-runs/<run_id>              # interactive
./scout to aiedge-runs/<run_id>              # once 모드
./scout serve aiedge-runs/<run_id>            # 웹 뷰어
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
├─ input/firmware.bin
├─ stages/
│  ├─ extraction/
│  ├─ firmware_profile/
│  ├─ inventory/
│  ├─ surfaces/
│  ├─ findings/
│  ├─ dynamic_validation/
│  ├─ exploit_autopoc/
│  └─ graph/
└─ report/
   ├─ report.json
   ├─ analyst_overview.json
   └─ analyst_digest.json / .md
```

---

## 계약 문서(Contracts)

현재 문서들과 스키마는 `docs/` 폴더에서 관리합니다.

- `docs/status.md`: 현재 구현 상태
- `docs/runbook.md`: 운영 절차/검증 플로우
- `docs/aiedge_firmware_artifacts_v1.md`: 산출물 스키마
- `docs/aiedge_report_contract.md`: 최종 리포트 계약
- `docs/analyst_digest_contract.md`: digest 스키마
- `docs/analyst_viewer_cockpit_mapping.md`: 뷰어/카드 매핑
- `docs/verified_chain_contract.md`: verified_chain 계약
- `docs/codex_first_agent_policy.md`: LLM/Codex 실행 정책

---

## 보안 및 윤리

SCOUT는 아래 목적의 통제된 환경에서 사용해야 합니다.

- 사전 승인된 보안 점검(벤더 협의)
- 연구/랩 환경에서의 재현성 높은 취약점 분석
- CTF 및 교육 환경

다음은 기본 보안 제약입니다.

- 외부 네트워크 비활성에서의 동적 검증 권장
- PoC 실행은 실험실 승인/범위 제어 조건에서만 수행
- weaponized payload 미포함; 기본 템플릿은 안전한 PoC 뼈대
- 최종 **confirmed/verified** 판단은 동적 증거 없이는 불가

---

## 원문/추가 정보

- English README: `README.md`
- 본 문서 한글판입니다. 영어판이 더 자세한 내용이나 최신 변경이 우선입니다.

---

MIT License
