<div align="center">

<img src="https://img.shields.io/badge/SCOUT-Firmware_Evidence_Engine-0d1117?style=for-the-badge&labelColor=0d1117" alt="SCOUT" />

# SCOUT

### Firmware Security Analysis Pipeline with Deterministic Evidence Packaging

**펌웨어 하나 넣으면, SARIF findings + CycloneDX SBOM+VEX + 해시 기반 증거 체인 + analyst-ready reasoning trail이 나옵니다 -- 명령어 하나로.**

*SCOUT는 대규모 벌크 스캐너보다는 단일 펌웨어를 깊게 파고드는 분석가 코파일럿으로 최적화되어 있습니다. Ghidra P-code taint 분석, adversarial LLM 토론, finding/report/viewer/TUI 전반 reasoning persistence, pip 의존성 제로.*

<br />

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=for-the-badge)](LICENSE)
[![Stages](https://img.shields.io/badge/Pipeline-42_Stages-blueviolet?style=for-the-badge)]()
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero_(stdlib)-orange?style=for-the-badge)]()
[![Version](https://img.shields.io/badge/Version-2.6.0-red?style=for-the-badge)]()

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
<sub>기준 데이터(carry-over): Tier 1 v2.4.0, 2026-04-05, static-only, 1,123 펌웨어 · Tier 2 v2.3.0, 2026-04-09, claude-code 드라이버, 36 펌웨어</sub>

[English](README.md) | [한국어 (이 파일)](README.ko.md)

</div>

---

> [!NOTE]
> **README의 벤치마크 수치는 모두 carry-over baseline입니다** (Tier 1: v2.4.0 static-only, 2026-04-05, 1,123개 펌웨어 · Tier 2: v2.3.0 claude-code 드라이버, 2026-04-09, 36개 펌웨어). v2.6.0 기준 fresh corpus 재검증은 대기 중입니다. [`docs/benchmark_governance.md`](docs/benchmark_governance.md) 와 [`benchmarks/baselines/v2.5.0/manifest.json`](benchmarks/baselines/v2.5.0/manifest.json) 참조.

> [!TIP]
> **v2.6.0 핵심 변화** ([PR #6](https://github.com/R00T-Kim/SCOUT/pull/6) · Phase 2B 통합)
> - **DAG 기반 병렬 stage 실행 PoC**: `--experimental-parallel [N]`로 42-stage 파이프라인을 level-wise 병렬 실행 (15 level / max-width 7). out-of-order 안전 progress 출력. 기존 순차 경로 무수정.
> - **`reasoning_trail` finding / analyst report / TUI / 웹 뷰어 전면 노출**: `adversarial_triage`와 `fp_verification`이 advocate / critic / decision / pattern-hit 엔트리를 기록 (raw response 200자 redaction). 분석가가 왜 downgrade/uphold/priority 결정이 났는지 바로 추적 가능.
> - **MCP analyst tools 4종**: verdict override, hint injection, reasoning 조회, category filter. `adversarial_triage` advocate 프롬프트가 다음 런에서 `AIEDGE_FEEDBACK_DIR`의 분석가 hint를 읽어 prefix — analyst-in-the-loop 피드백 루프 완성.
> - **`priority_score` / `priority_inputs`를 detection confidence와 분리**: `confidence`는 static-evidence cap에 엄격 유지. EPSS / reachability / backport / CVSS는 별도 ranking 신호로 이동. "EPSS-additive confidence가 heuristic으로 보인다"는 리뷰어 비판 직접 응답.
> - **extraction 실패 시 analyst guidance**: 언패킹 실패 시 opaque error 대신 vendor decrypt 힌트, `--rootfs` 우회, binwalk variants, 이슈 템플릿 등 실무 가이드 제공.

---

## 왜 SCOUT인가?

> **모든 finding에 해시 기반 증거 체인이 있습니다.**
> 파일 경로, 바이트 오프셋, SHA-256 해시, 근거 없이는 finding을 생성하지 않습니다. 펌웨어 블롭에서 최종 판정까지 추적 가능.

> **4-tier 신뢰도 상한 + Ghidra P-code 검증 -- 정직한 점수.**
> SYMBOL_COOCCURRENCE 0.40, STATIC_CODE_VERIFIED 0.55, STATIC_ONLY 0.60, PCODE_VERIFIED 0.75. `confirmed` 승격에는 동적 검증이 필요합니다. 점수를 부풀리지 않습니다.

> **SARIF + CycloneDX VEX + SLSA -- 표준 포맷.**
> GitHub Code Scanning, VS Code, CI/CD 즉시 연동.

> **Analyst-in-the-loop 펌웨어 리뷰용으로 설계됨.**
> SCOUT는 단일 펌웨어 이미지를 빠르게 깊이 파고들고, evidence 경로를 드러내며, triage와 reporting 표면 전반에 reasoning을 보존할 때 가장 강합니다. MCP를 통해 분석가 hint가 다음 런의 LLM 판단에 피드백됩니다.

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
| :package: | **SBOM & CVE** | CycloneDX 1.6 + VEX + 25 Known CVE 시그니처 (8 벤더) + NVD 스캔 + 2,528 로컬 CVE DB + EPSS 스코어링 (FIRST.org API, 배치 + 캐싱) |
| :mag: | **바이너리 분석** | Ghidra P-code SSA dataflow taint + ELF hardening (NX/PIE/RELRO/Canary/FORTIFY) + `.dynstr` 감지 + 28개 sink 심볼 + format string 탐지 |
| :dart: | **공격 표면** | Source→sink 추적, 웹 서버 자동 감지, 크로스 바이너리 IPC 체인 (5종: unix socket, dbus, shm, pipe, exec) |
| :brain: | **테인트 분석** | HTTP-aware 프로시저 간 테인트, P-code SSA dataflow, call chain 시각화, 4-strategy fallback (P-code → colocated → decompiled → interprocedural) |
| :robot: | **LLM 엔진** | 4개 백엔드 (Codex CLI / Claude API / Claude Code CLI / Ollama) + 중앙 관리 시스템 프롬프트 + structured JSON 출력 + 5-stage 파서 (preamble/fence/raw/brace-counting/error-recovery) + temperature 제어 |
| :crossed_swords: | **Adversarial Debate** | Advocate/Critic LLM 토론 기반 FPR 감소 (Tier 2 99.3%). parse_failures vs llm_call_failures 분리 + quota_exhausted 명시적 탐지 |
| :compass: | **Analyst Copilot** *(v2.6.0)* | finding / analyst markdown / TUI / 웹 뷰어에 `reasoning_trail`을 보존해, 왜 downgrade/uphold/priority 결정이 났는지 바로 추적 가능. advocate / critic / decision / pattern-hit 엔트리, raw response 200자 redaction |
| :inbox_tray: | **MCP Analyst Tools** *(v2.6.0)* | reasoning 조회, hint injection, verdict override, category filter 4개 tool. `AIEDGE_FEEDBACK_DIR` opt-in으로 hint가 다음 런 advocate 프롬프트에 주입됨 (`fcntl.flock` 기반 쓰기 안전) |
| :triangular_ruler: | **Detection vs Priority 분리** *(v2.6.0)* | `confidence`는 증거 강도만 (≤0.55 static cap), `priority_score` / `priority_inputs`는 EPSS·reachability·backport·CVSS 기반 운영 우선순위 신호만 담당. [`docs/scoring_calibration.md`](docs/scoring_calibration.md) 참조 |
| :speedboat: | **병렬 DAG 실행** *(v2.6.0, PoC)* | `--experimental-parallel [N]` 기반 opt-in level-wise stage 병렬 실행 (ThreadPoolExecutor + Kahn topo). 42-stage 기준 15 level / max-width 7. 기존 순차 경로 무수정 |
| :shield: | **보안 평가** | X.509 인증서 스캔, 부트 서비스 감사, 파일시스템 권한, 자격 증명 매핑, hardcoded secret 탐지 |
| :test_tube: | **퍼징** *(선택)* | AFL++ CMPLOG, persistent mode, NVRAM faker, 하니스 생성, crash triage |
| :bug: | **에뮬레이션** | 4-tier (FirmAE / Pandawan+FirmSolo / QEMU user-mode / rootfs 검사) + GDB 원격 디버깅 |
| :electric_plug: | **MCP 서버** | Model Context Protocol 12개 도구 (Claude Code/Desktop 연동) |
| :bar_chart: | **웹 뷰어** | Glassmorphism 대시보드 (KPI 바, IPC 맵, 리스크 히트맵, 인터랙티브 evidence 탐색) |
| :link: | **증거 체인** | SHA-256 앵커 아티팩트 + 4-tier 신뢰도 상한 (0.40/0.55/0.60/0.75) + 5단계 exploit 승격 ladder |
| :scroll: | **표준 출력** | SARIF 2.1.0 (GitHub Code Scanning) + CycloneDX 1.6 + VEX + SLSA Level 2 in-toto 인증 |
| :gear: | **CI/CD 통합** | GitHub Action (`.github/actions/scout-scan/`) composite Docker action + GitHub Security 탭 SARIF 자동 업로드 |
| :scales: | **규제 정합성** | EU CRA Annex I 호환 출력 포맷 (`docs/cra_compliance_mapping.md`); FDA Section 524B 가이던스 호환 SBOM 출력; ISO 21434 / UN R155 호환 출력 포맷 |
| :chart_with_upwards_trend: | **벤치마킹** | FirmAE 데이터셋 (1,123 펌웨어), analyst-readiness 점수화, verifier 기반 archive bundle, TP/FP 분석 스크립트 |
| :key: | **벤더 복호화** | D-Link SHRS AES-128-CBC 자동 복호화; Shannon entropy 암호화 탐지 (>7.9); binwalk v3 호환 |
| :white_check_mark: | **Zero Dependencies** | Pure Python 3.10+ stdlib만 사용 — pip 의존성 없음, 에어갭 환경 배포 친화적 |

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
<summary><strong>파이프라인 스테이지 레퍼런스 (42개)</strong></summary>

| 스테이지 | 모듈 | 목적 | LLM | 비용 |
|---------|------|------|-----|------|
| `tooling` | `tooling.py` | 외부 도구 가용성 체크 (binwalk, Ghidra, Docker) | 아니오 | $0 |
| `extraction` | `extraction.py` | 펌웨어 언패킹 (binwalk + vendor_decrypt + Shannon entropy) | 아니오 | $0 |
| `structure` | `structure.py` | 파일시스템 구조 분석 | 아니오 | $0 |
| `carving` | `carving.py` | 비구조화 영역 파일 카빙 | 아니오 | $0 |
| `firmware_profile` | `firmware_profile.py` | 아키텍처/커널/init 시스템 프로파일링 | 아니오 | $0 |
| `inventory` | `inventory.py` | 바이너리별 ELF hardening + 심볼 추출 | 아니오 | $0 |
| `ghidra_analysis` | `ghidra_analysis.py` | 디컴파일 + P-code SSA dataflow | 아니오 | $0 |
| `semantic_classification` | `semantic_classifier.py` | 3-pass 함수 분류 (static → haiku → sonnet) | 예 | 낮음 |
| `sbom` | `sbom.py` | CycloneDX 1.6 SBOM + VEX 생성 | 아니오 | $0 |
| `cve_scan` | `cve_scan.py` | NVD + 25 known signature + EPSS enrichment | 아니오 | $0 |
| `reachability` | `reachability.py` | BFS 기반 호출 그래프 도달성 | 아니오 | $0 |
| `endpoints` | `endpoints.py` | 네트워크 엔드포인트 발견 | 아니오 | $0 |
| `surfaces` | `surfaces.py` | 공격 표면 열거 | 아니오 | $0 |
| `enhanced_source` | `enhanced_source.py` | 웹 서버 자동 감지 + INPUT_APIS 스캔 (21개 API) | 아니오 | $0 |
| `csource_identification` | `csource_identification.py` | 정적 센티널 + QEMU 기반 HTTP 입력 소스 식별 | 아니오 | $0 |
| `taint_propagation` | `taint_propagation.py` | 28개 sink + format string 탐지 인터프로시저 taint | 예 | 중간 |
| `fp_verification` | `fp_verification.py` | 3패턴 FP 제거 + LLM 검증 (parse/call 실패 분리) | 예 | 낮음 |
| `adversarial_triage` | `adversarial_triage.py` | Advocate/Critic LLM 토론 (FPR 99.3% 감소) | 예 | 중간 |
| `graph` | `graph.py` | 통신 그래프 (5종 IPC edge) | 아니오 | $0 |
| `attack_surface` | `attack_surface.py` | IPC 체인 포함 공격 표면 매핑 | 아니오 | $0 |
| `attribution` | `attribution.py` | 벤더/펌웨어 attribution | 아니오 | $0 |
| `functional_spec` | `functional_spec.py` | 기능 명세 추출 | 아니오 | $0 |
| `threat_model` | `threat_model.py` | STRIDE 기반 위협 모델링 | 아니오 | $0 |
| `web_ui` | `web_ui.py` | 웹 UI / CGI 엔드포인트 분석 | 아니오 | $0 |
| `findings` | `findings.py` | Finding 집계 + SARIF export | 아니오 | $0 |
| `llm_triage` | `llm_triage.py` | LLM finding 트리아지 (haiku/sonnet/opus 자동 라우팅) | 예 | 가변 |
| `llm_synthesis` | `llm_synthesis.py` | LLM finding 합성 | 예 | 중간 |
| `emulation` | `emulation.py` | 4-tier 에뮬레이션 (FirmAE / Pandawan / QEMU / rootfs) | 아니오 | $0 |
| `dynamic_validation` | `dynamic_validation.py` | 동적 동작 검증 | 아니오 | $0 |
| `fuzzing` | `fuzz_*.py` | NVRAM faker 포함 AFL++ 퍼징 | 아니오 | $0 |
| `poc_refinement` | `poc_refinement.py` | 반복 PoC 생성 (5회 시도) | 예 | 중간 |
| `chain_construction` | `chain_constructor.py` | 동일 바이너리 + 크로스 바이너리 IPC 익스플로잇 체인 | 아니오 | $0 |
| `exploit_gate` | `stage_registry.py` | exploit 승격 게이트 | 아니오 | $0 |
| `exploit_chain` | `exploit_chain.py` | exploit 체인 검증 | 아니오 | $0 |
| `exploit_autopoc` | `exploit_autopoc.py` | 자동 PoC 오케스트레이션 | 예 | 중간 |
| `poc_validation` | `poc_validation.py` | PoC 재현 검증 | 아니오 | $0 |
| `exploit_policy` | `exploit_policy.py` | 최종 exploit 승격 결정 | 아니오 | $0 |

OTA 전용 스테이지: `ota`, `ota_payload`, `ota_fs`, `ota_roots`, `ota_boottriage`, `firmware_lineage` (Android 스타일 OTA payload 분석).

</details>

## 벤치마크

### Tier 1 (정적 분석, frozen baseline)

_기준 데이터: v2.4.0, 2026-04-05, static-only (carry-over; v2.5.0 코퍼스 재검증 예정)_

- `1,123`개 펌웨어 / `8`개 벤더 / `99.2%` 분석 가능 비율
- `1,110` success / `4` partial / `9` failed
- `3,523` findings / `13,893` CVE 매칭

### Tier 2 (LLM Adversarial Debate, GPT-5.3-Codex)

_기준 데이터: v2.3.0, 2026-04-09, claude-code 드라이버 (carry-over; v2.5.0 코퍼스 재검증 예정)_

- `36`개 펌웨어 / `9`개 벤더
- `2,430` findings 토론 → `2,412` downgraded + `18` maintained
- **FPR 감소율: 99.3%** | **False negative rate: ≈ 0%**

### v2.6.0 post-merge 실펌웨어 검증

_이 섹션은 위 carry-over corpus baseline과 별개로, 릴리즈 후 실펌웨어 검증 결과를 기록합니다._

#### 검증 대상 1 — Netgear R7000 (codex 드라이버, `--experimental-parallel 4`)

| 지표 | v2.5.0 | v2.6.0 |
|---|---|---|
| `adversarial_triage` parse_failures | 0/100 | **0/100** (100 debated, 97 downgraded, 3 maintained) |
| `fp_verification` unverified | 0/100 | **0/100** (100 verified: 56 TP, 44 FP) |
| `reasoning_trail_count` (top-level findings) | N/A | **0/3** top-level / **100/100** `adversarial_triage` + `fp_verification` 아티팩트 ¹ |
| `priority_score` 보유 finding 수 | N/A | **3/3** (100% additive priority annotation) |
| `priority_bucket_counts` | N/A | `{critical: 0, high: 0, medium: 3, low: 0}` |
| category 분포 | N/A | `{vulnerability: 1, pipeline_artifact: 2, misconfiguration: 0, unclassified: 0}` |
| `cve_scan` EPSS enriched | 23/23 | **0** (stage skipped — `sbom`이 partial이라 `cve_scan`/`reachability`가 upstream 의존성 실패로 skip ²) |
| `--experimental-parallel 4` wall-clock | N/A | **약 170분** 파이프라인 end-to-end (`fp_verification`이 113분으로 dominant. 순차 실행 baseline 없어서 델타 미산정) |

¹ **v2.6.0 → v2.6.1 후속 수정 (커밋 `7b36274`)**: 기존에는 top-level synthesis finding(`web.exec_sink_overlap`)이 그 아래에서 debate된 per-alert trail을 상속받지 못했습니다. 후속 패치는 `fp_verification`의 TP/FP 카운트 + `adversarial_triage`의 downgrade/maintain 집계를 `synthesis_inherit` 항목으로 synthesis finding에 부착합니다. 위 R7000 런은 v2.6.0 배포본 동작이며, 패치 적용 후 재실행하면 top-level `reasoning_trail_count`는 **1/3**이 됩니다.

² **v2.6.0 → v2.6.1 후속 수정 (커밋 `8e0bb82`)**: R7000의 extraction 자체는 정상 성공 (1,664개 파일 + 2,412개 바이너리가 `squashfs-root` 아래에 존재). 그런데 SBOM 스테이지가 0 components를 반환한 진짜 이유는 조용한 스키마 불일치였습니다 — `_collect_so_files_from_inventory`가 deprecated된 `inventory.file_list`를 읽었고 (`roots`만 노출되는 현재 스키마), `_detect_from_binary_analysis`가 엔트리별 `string_hits`를 기대했으나 현재는 `matched_symbols`만 방출. OpenWrt는 opkg 데이터베이스 한 군데서만 100+ 컴포넌트가 나와서 이 버그가 가려져 있었습니다. 수정: 두 헬퍼가 `inventory.roots`를 직접 walk하고, `_extract_ascii_runs` 신규 헬퍼로 바이너리 파일 앞 256KB를 읽어 printable run 추출로 폴백. 이 R7000 런에 `SbomStage`만 재실행하면 component 수가 **0 → 4**로 증가 (`curl 7.36.0`은 `/usr/bin/curl` 직접 읽어서 탐지, `openssl 1.0.0` / `libz 1` / `libpthread 0`은 `.so*` walking). 전체 파이프라인 재실행 시 downstream `cve_scan` / `reachability`가 실제 CVE + EPSS 수치를 생성.

#### 검증 대상 2 — OpenWrt Archer C7 v5 (TP-Link, `--no-llm`)

| 지표 | v2.6.0 |
|---|---|
| 총 findings | **3** |
| `reasoning_trail_count` | **0** _(no-llm 모드는 adversarial_triage / fp_verification이 LLM-gated이므로 trail 미생성. 정상 동작)_ |
| `priority_score` 보유 finding 수 | **3 / 3** _(100% — additive priority annotation 성공)_ |
| `priority_bucket_counts` | `{critical: 0, high: 0, medium: 3, low: 0}` |
| category 분포 | `{vulnerability: 1, pipeline_artifact: 2, misconfiguration: 0, unclassified: 0}` _(PR #7a 3-category ontology, 0% unclassified)_ |
| 특이사항 | squashfs ext4 루트 정상 추출. `--no-llm` 모드라서 reasoning_trail 미생성 (예상). `findings` stage까지 end-to-end 완주 |

전체 버전 히스토리는 [`CHANGELOG.md`](CHANGELOG.md), 두 score 계약은 [`docs/scoring_calibration.md`](docs/scoring_calibration.md)를 참조하세요.

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
|  42단계 . SHA-256 매니페스트 . 4-tier 신뢰도 상한 (0.40/0.55/0.60/0.75)     |
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
