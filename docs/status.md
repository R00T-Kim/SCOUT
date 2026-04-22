# Status

이 문서는 "현재 구현 상태"를 솔직하게 기록합니다.

## Phase 2A run.py 분해 현황

Phase 2A run.py decomposition: 4,476 → 4,140 lines (normalize/stage_executor/report_assembler/handoff_writer 추출 완료). 나머지 분해는 후속 작업.

## 현재 구현됨

- SCOUT CLI: `./scout analyze`, `./scout stages` (래퍼 권장)
- 동일 기능은 `python3 -m aiedge analyze`, `python3 -m aiedge stages`로 직접 실행 가능
- **Benchmark fidelity layer** (`benchmark_eval.py`): archived bundle 기준 metric 수집, manifest legacy/canonical field 호환 해석, analyst-readiness 판정
- **Benchmark triage scripts**: `scripts/reevaluate_benchmark_results.py`(기존 benchmark 재평가), `scripts/rerun_benchmark_stages.py`(legacy bundle normalize + stage subset rerun)
- **Fresh fidelity validation**: 새 archive contract는 `benchmark-results/tier2-single-fidelity` single-sample run에서 digest/report verifier 동시 통과로 확인됨
- Stage evidence store(run_dir): StageFactory stage는 `stages/<name>/stage.json` 기반 artifact hashing을 사용하고, findings는 `run_findings()`가 `stages/findings/*.json`을 직접 생성
- `analyze`/`analyze-8mb`에 `--rootfs <DIR>` 지원 (사전 추출 rootfs 직접 ingest)
- `firmware_profile` stage:
  - `stages/firmware_profile/stage.json`과 `stages/firmware_profile/firmware_profile.json` 생성이 확인됨
  - ELF 교차검증(`arch_guess`, `elf_hints`)으로 OS/arch 오탐 완화
- Inventory stage는 "죽지 않고" `inventory.json`/`string_hits.json`/`binary_analysis.json`을 남김
- extraction/inventory 품질 게이트(coverage threshold) 반영:
  - sparse 결과는 `quality.status=insufficient`로 표시되고 `partial`로 강등될 수 있음
- `firmware_handoff.json` 자동 생성 (analyze + stages)
- TUI/뷰어 진입 가이드는 `./scout tui` 단축키(`ti/tw/to`) 및 `./scout serve`를 기준으로 정렬되어 최신 상태입니다.
- SquashFS 재귀 추출: BFS 큐 기반, 깊이 제한 4, 오프셋 기반 매직 스캔(벤더 래퍼 대응). 이중/다중 SquashFS 자동 추출 가능.
- 심링크 containment: 추출된 심링크가 `run_dir` 밖으로 resolve되면 rootfs 후보에서 제외. `_rel_to_run_dir`, `_probe_is_dir`, `_probe_exists`, `_resolve_or_record`, `is_dir_safe`, `is_file_safe` 모두 적용.
- `_BINARY_BRIDGE_TOKENS` 탐지 카테고리: `sprintf`/`snprintf`/`strcat`/`strcpy` 등이 `system`/`popen` exec 싱크 근처에 있으면 커맨드 인젝션 브릿지로 플래그. inventory 교차검증(`bridge_sink_cooccurrence`) 포함.
- `web_ui` 스테이지: HTML/JS 보안 패턴 스캐너. `stages/web_ui/web_ui.json` 산출. JS 9개 패턴 + HTML 4개 패턴 + API 스펙 파일 탐지.
- LLM Provider 추상화: `llm_driver.py` (LLMDriver Protocol, CodexCLIDriver, `resolve_driver()`). 3개 호출사이트(llm_synthesis, exploit_autopoc, llm_codex) 통합. `AIEDGE_LLM_DRIVER` env var로 provider 선택, ModelTier ("haiku"|"sonnet"|"opus") 지원.
- **LLM trace capture** (`llm_driver.py`): `stages/<stage>/llm_trace/*.json`에 prompt/output/attempt/usage 메타데이터 기록
- 바이너리 하드닝: 순수 Python ELF 파서로 NX/PIE/RELRO/Canary/Stripped 수집. inventory `binary_analysis.json`에 `hardening_summary` 포함. findings 점수에 하드닝 기반 보정 적용 (fully hardened: x0.7, no protection: x1.15).
- 3-Tier 에뮬레이션: FirmAE Docker 이미지(Tier 1) + QEMU user-mode 서비스 프로빙(Tier 2, lighttpd/busybox/dnsmasq/sshd) + rootfs 검사 fallback(Tier 3). `docker/scout-emulation/` Dockerfile 포함. `AIEDGE_EMULATION_IMAGE`, `AIEDGE_FIRMAE_ROOT` env var.
- 엔디안 인식 아키텍처 감지: MIPS/ARM 빅/리틀엔디안 정확 구분 (`mips_be`, `mips_le`, `arm_be`, `arm_le`).
- 취약점 유형별 PoC 템플릿: `poc_templates.py` 레지스트리 4종 (cmd_injection, path_traversal, auth_bypass, info_disclosure) + tcp_banner fallback. `poc_skeletons/` 디렉토리에 standalone PoC 파일.
- exploit_runner 실제 PCAP 캡처: tcpdump 가용 시 실제 패킷 캡처 (기존 placeholder fallback 유지).
- PoC 재현성 검증: `poc_validation`에서 readback_hash 일관성 확인으로 재현성 보장.
- LLM 트리아지 스테이지: findings → `llm_triage` → llm_synthesis 순서로 실행. 모델 티어 자동 선택 (`<=10`: haiku, `11-50`: sonnet, `>50` 또는 chain-backed: opus). 하드닝/attack_surface 보안 컨텍스트 포함 프롬프트. `haiku` nonzero exit 시 `sonnet` fallback, parse repair pass, `--no-llm`에서 graceful skip.
- `adversarial_triage` / `fp_verification`: parse failure를 조용히 무시하지 않고 repair 시도 후 fail-closed `partial`/`unverified`로 반영
- `attribution`: extraction stage manifest 자체보다 inventory roots 실제 존재 여부를 우선 사용하여 degraded 오탐 완화
- `graph`: runtime communication graph가 비어도 `fallback_reference_graph`와 blocked reason code를 남겨 empty vs explained-blocked를 구분
- Terminator 양방향 피드백 루프: `terminator_feedback.py`가 `firmware_handoff.json`에 `feedback_request` 섹션 추가. Terminator 판정(confirmed boost, false_positive suppress)이 `duplicate_gate`에 반영. `AIEDGE_FEEDBACK_DIR` env var.
- IPC 감지 파이프라인: Unix socket, D-Bus, SHM, named pipe 감지. ELF `.rodata`/`.dynstr` IPC 심볼 추출. `ipc_channel` 그래프 노드 + IPC 엣지 5종 (`ipc_unix_socket`, `ipc_dbus`, `ipc_shm`, `ipc_pipe`, `ipc_exec_chain`). IPC 리스크 스코어링.
- Source→Sink 경로 추적: `stages/surfaces/source_sink_graph.json` 생성. 네트워크 엔드포인트 → 서비스 컴포넌트 → exec sink 바이너리 경로 매핑.
- Credential 자동 매핑: `stages/findings/credential_mapping.json` 생성. SSH 키, 비밀번호 해시, API 토큰 → auth surface 매핑. 위험도 분류(high/medium/low).
- Verifier reason code 개선: `dynamic_validation`에서 `isolation_verified`/`boot_verified` 생성, `poc_validation`에서 `repro_3_of_3` 생성. VERIFIED 판정 경로 활성화.
- 인터랙티브 웹 뷰어: 글래스모피즘 다크 테마, 순수 JS force-directed 그래프, IPC Map/Source→Sink/Credential Map 패널. 파이프라인 진행률 바, 접이식 카드, 다크/라이트 토글.
- **SBOM 생성** (`sbom.py`): CycloneDX 1.6 포맷 SBOM 자동 생성. opkg/dpkg 패키지 DB, 바이너리 버전 문자열, SO 라이브러리 버전, 커널 버전에서 컴포넌트 탐지. CPE 2.3 식별자 자동 구성. `stages/sbom/sbom.json`, `stages/sbom/cpe_index.json` 산출.
- **CVE 스캐닝** (`cve_scan.py`): NVD API 2.0 CVE 매칭. Rate-limited (API key 유/무에 따라 10/50 req/min). SHA-256 기반 캐시 (per-run + cross-run `AIEDGE_NVD_CACHE_DIR`). Critical/High CVE → finding 후보 자동 생성. `AIEDGE_NVD_API_KEY` env var.
- **X.509 인증서 분석** (`cert_analysis.py`): PEM/DER 인증서 스캔. 만료, 약한 키(<2048 RSA), 약한 서명(SHA-1, MD5), 자체서명, 개인키 노출 감지.
- **Init 서비스 감사** (`init_analysis.py`): SysV, systemd, BusyBox inittab, OpenWrt procd, xinetd/inetd 파싱. telnet(HIGH), FTP/TFTP(MEDIUM), UPnP/SNMP(MEDIUM) 위험 서비스 플래그.
- **파일 퍼미션 감사** (`fs_permissions.py`): world-writable, SUID/SGID, 민감 파일(shadow, 개인키) 과도한 권한 감지.
- **MCP 서버** (`mcp_server.py`): JSON-RPC 2.0 over stdio, 12개 도구 노출. `./scout mcp --project-id <run_id>`. Claude Code/Desktop 등 MCP 호환 AI 에이전트에서 SCOUT 구동 가능.
- **LLM 드라이버 확장**: `ClaudeAPIDriver` (Claude API 직접 호출, `ANTHROPIC_API_KEY`) + `OllamaDriver` (로컬 LLM, `AIEDGE_OLLAMA_URL`). `AIEDGE_LLM_DRIVER=codex|claude|ollama`. 비용 추적 (`llm_cost.py`, `AIEDGE_LLM_BUDGET_USD`).
- **CVE Reachability 분석** (`reachability.py`): communication graph BFS로 공격 표면에서 CVE 컴포넌트까지 도달성 판정. directly_reachable(≤2 hop), potentially_reachable(3+), unreachable.
- **펌웨어 비교** (`firmware_diff.py`): 두 run 간 파일시스템 diff(추가/삭제/수정/퍼미션), 바이너리 hardening diff, config 보안 diff.
- **GDB RSP 클라이언트** (`emulation_gdb.py`): 순수 stdlib GDB Remote Serial Protocol 클라이언트. QEMU `-g` stub에 연결하여 레지스터/메모리 읽기, 브레이크포인트, 백트레이스.
- **Ghidra headless 연동** (`ghidra_bridge.py`, `ghidra_analysis.py`): 선택적 Ghidra 디컴파일/xref/데이터플로우 분석. SHA-256 캐시. 미설치 시 graceful skip. `AIEDGE_GHIDRA_HOME`, `AIEDGE_GHIDRA_MAX_BINARIES`.
- **AFL++ 퍼징 파이프라인**: `fuzz_target.py`(스코어링 0-100), `fuzz_harness.py`(딕셔너리/시드/하네스), `fuzz_campaign.py`(AFL++ Docker QEMU mode), `fuzz_triage.py`(크래시 분류/exploitability). 미설치 시 graceful skip. `AIEDGE_AFLPP_IMAGE`, `AIEDGE_FUZZ_BUDGET_S`.
- **SARIF 2.1.0 Export** (`sarif_export.py`): Findings를 OASIS SARIF 2.1.0 포맷으로 자동 변환. GitHub Code Scanning, VS Code SARIF Viewer 호환. `stages/findings/sarif.json` 산출. 파이프라인 완료 시 자동 생성.
- **SLSA L2 Provenance** (`provenance.py`): in-toto v0.1 attestation 자동 생성. firmware_handoff, analyst_digest, verified_chain을 subject로 포함. `provenance.intoto.jsonl` 산출. 파이프라인 완료 시 자동 생성.
- **Executive Report 생성** (`report_export.py`): Markdown executive report 자동 생성. 파이프라인 요약, 상위 리스크, SBOM/CVE 테이블, 공격 표면, 크레덴셜 findings. 파이프라인 완료 시 `report/executive_report.md` 자동 생성.
- **웹 뷰어 UX 대폭 개선**: 싱글 패널 뷰(사이드바 클릭 → 해당 패널만 표시), KPI 바(Critical/High/Components/CVEs/Endpoints 상시 표시), SBOM/CVE/Reachability/Security Assessment 4개 패널 추가, 페이지네이션(SBOM 30/page, CVE 20/page), 그래프 Python 사전 레이아웃(150 노드 균형 선택, 호버 시 연결 정보 표시), viewer.html 1.5MB→567KB 경량화.
- **공유 유틸리티** (`path_safety.py`): `assert_under_dir`, `rel_to_run_dir`, `sha256_file`, `sha256_text` 공유 모듈.
- 파이프라인 29 → 34개 스테이지 (v2.1): `ghidra_analysis`, `sbom`, `cve_scan`, `reachability`, `fuzzing` 추가.
- 파이프라인 34 → 42개 스테이지 (v2.2): `enhanced_source`, `semantic_classification`, `taint_propagation`, `fp_verification`, `adversarial_triage`, `poc_refinement`, `chain_construction` 추가.

## v2.6.0 업그레이드 (2026-04-13, Phase 2B)

전략 로드맵 Phase 2B 완료. 성능 (DAG 병렬화), analyst copilot UX (reasoning trail / MCP override), confidence calibration 3축 구현. 6개 atomic commit으로 단일 세션 병렬 실행 후 [PR #6](https://github.com/R00T-Kim/SCOUT/pull/6)로 rebase merge.

### DAG 병렬화 PoC _(PR #10)_
- **`stage_dag.py`** (신규): 42개 stage 수동 dependency dict (`STAGE_DEPS`) + Kahn `topo_levels()` 결정론적 알파벳 정렬 + `validate_deps()` 경고 집계. `findings` 제외 (integrated step), `exploit_gate` 포함 (inline factory). 현재 42-stage 기준 15 level / max-width 7
- **`run_stages_parallel()`** in `stage.py`: ThreadPoolExecutor level-wise submit, skip-on-failed-dep semantics, `fail_fast=True/False` 모드. `run_stages()` 무수정
- **`--experimental-parallel [N]`** CLI 플래그 (`analyze` + `stages` subparser), 기본 4 workers
- **ProgressTracker out-of-order 모드**: 내부 `_completion_counter`로 parallel 완료 순서 렌더링

### Reasoning trail 전면 도입 _(PR #11 + PR #13)_
- **`reasoning_trail.py`** (신규): `ReasoningEntry` dataclass (stage/step/verdict/rationale/delta/timestamp/llm_model/raw_response_excerpt). `raw_response_excerpt` 200-char cap은 `__post_init__`에서 강제 (call site가 우회 불가)
- **adversarial_triage.py**: debate loop에서 advocate/critic/decision 엔트리 기록 (기존 `triage_outcome` 유지)
- **fp_verification.py**: sanitizer/non-propagating/sysfile 패턴 hit + LLM `<pattern>_detected` / `llm_verdict` 기록 (기존 `fp_verdict` / `fp_rationale` 유지)
- **findings.py**: additive `reasoning_trail` 필드 (PR #7a 패턴, schema bump 없음) + `reasoning_trail_count` summary
- **SARIF export**: `properties.scout_reasoning_trail` 노출
- **Viewer 3개 surface**: 임베디드 HTML 뷰어 collapsible `<details>` + 애널리스트 markdown numbered subsection + TUI `render_finding_detail_with_trail()` (AIEDGE_TUI_ASCII 호환)

### MCP analyst tools _(PR #12)_
- **4개 신규 도구**: `scout_get_finding_reasoning` (trail 조회), `scout_inject_hint` (분석가 hint 추가), `scout_override_verdict` (verdict 강제), `scout_filter_by_category` (category 필터)
- **`terminator_feedback.py` 확장**: `add_analyst_hint` / `get_analyst_hints` / `set_verdict_override`. `fcntl.flock` 쓰기 안전, `assert_under_dir` 경로 강제, 기존 `verdicts` 리스트 스키마 보존
- **Analyst hint 루프**: `adversarial_triage._build_analyst_hint_prefix()`가 `AIEDGE_FEEDBACK_DIR`의 hint를 advocate 프롬프트에 priority-정렬 prefix. opt-in 기본 무동작

### Detection vs Priority 분리 _(PR #15)_
- **`scoring.py`** (신규): `PriorityInputs` frozen dataclass + `compute_priority_score()` (weights: detection 50% / EPSS 25% / reach 15% / CVSS 10%, backport -0.20) + `priority_bucket()` (critical/high/medium/low)
- **`cve_scan.py:1140-1170`** 리팩토링: `confidence`는 `STATIC_CODE_VERIFIED_CAP=0.55`에서 엄격 유지. EPSS / reachability / backport / CVSS는 `priority_score`로 이동. `_REACHABILITY_MULTIPLIERS`, `_EPSS_BOOST_*`, `_epss_confidence_adjustment()` 고아 internal 삭제
- **`findings.py`**: additive `priority_score` + `priority_inputs` + `priority_bucket_counts` (CVE finding은 cve_scan에서 선주입, 나머지는 `confidence` 기반 default)
- **`sarif_export.py`**: `scout_priority_score` + `scout_priority_inputs` properties bag 추가
- **`quality_metrics.py`**: `count_findings_by_priority` + `PRIORITY_BUCKET_LABELS` (기존 per-confidence helper 유지)
- **`docs/scoring_calibration.md`** (신규): 두 score 계약 + before/after 예시
- **리뷰어 비판 직접 응답**: "EPSS-additive confidence가 ranking heuristic으로 보인다"

### Extraction 실패 analyst guidance _(PR #14)_
- **`_build_extraction_guidance()`** in `extraction.py`: 4개 early-return 실패 경로 (firmware missing, invalid rootfs, no binwalk, timeout) + 성공 외 경로 모두에 entropy / vendor_decrypt / `--rootfs` / binwalk variants / 이슈 템플릿 가이드 주입
- **`_emit_extraction_guidance()`** in `run.py`: stderr 출력 (quiet 모드 존중) + run dir 로그
- **`docs/runbook.md#extraction-failure`** 섹션 (symptoms/causes/remediation 표)

### 검증
| 지표 | v2.5.0 | v2.6.0 |
|------|--------|--------|
| pytest | 865 | **1027** (+162) |
| pyright errors | 0 | **0** (baseline 유지) |
| ruff | clean | **clean** |
| CI checks | 5/5 green | **5/5 green** |

**신규 테스트 분포**: reasoning_trail 20 / extraction_guidance 18 / mcp_analyst_tools 33 / stage_dag 14 / run_stages_parallel 14 / scoring 19 / reasoning_trail_viewer 44

**R7000 smoke (PR #15)**: 3 findings, 모두 `priority_score` + `priority_inputs` 보유, `cve_confidence_above_0.55_cap = 0` (detection cap 엄격 적용 확인), `priority_bucket_counts = {critical: 0, high: 0, medium: 3, low: 0}`

### 설계 불변식 유지
- `findings.py` additive only (PR #7a 패턴: `category`, `reasoning_trail`, `priority_score`, `priority_inputs`). **Report schema version bump 없음**. 7 downstream consumer 무수정
- Sequential `run_stages()` bit-identical
- `StageContext` frozen 유지 (thread-safe sharing)
- `assert_under_dir()` 모든 file write 경로
- v2.5.0의 LLM driver contract (system_prompt / temperature / 5-stage parser) 그대로
- 200-char `raw_response_excerpt` cap은 `__post_init__`에서 강제

### v2.6.1 close-out (2026-04-17)

R7000 post-merge 실펌웨어 검증 도중 발견된 2개 shipped 버그를 post-release로 수정. 둘 다 additive-only, schema bump 없음, 기존 consumer 무수정.

**버그 #1 — synthesis 레벨 reasoning_trail 상속 누락** (commit `7b36274`):
- top-level synthesis finding `web.exec_sink_overlap`이 자기 밑에서 debate된 per-alert trail을 상속받지 못했음
- `findings.json`에서 `reasoning_trail_count: 0/3` (top-level), 그러나 `stages/adversarial_triage/triaged_findings.json`에는 100/100 trail 존재
- 수정: `_inherit_synthesis_reasoning_trail()` 헬퍼 — matched downstream evidence lineage를 읽어 top-level synthesis finding에 `reasoning_trail`을 상속. run-relative binary path를 우선 매칭하고, 불일치 시 binary SHA-256을 보조 사용. `findings/synthesis_match` summary entry + 대표 downstream evidence의 deterministic top-K trail 샘플을 부착하며, 매칭 불가 시 기존 aggregate `synthesis_inherit` fallback 유지
- 테스트: `TestSynthesisReasoningTrailInheritance` 5 cases

**버그 #2 — SBOM inventory 스키마 불일치** (commit `8e0bb82`):
- `_collect_so_files_from_inventory`가 pre-v2.x `inventory.file_list` 키를 읽음 (현재 스키마는 `roots` + `entries` int만 노출)
- `_detect_from_binary_analysis`가 엔트리당 `string_hits` 리스트를 기대 (현재 스키마는 `matched_symbols`만 노출)
- 결과: vendor 스톡 펌웨어에서 sbom 0 components. OpenWrt는 opkg status 한 군데로 100+ components가 나와서 버그가 가려져 있었음
- 수정:
  - `_collect_so_files_from_inventory(inventory, run_dir)` → `inventory.roots`를 직접 walk해서 `.so*` glob
  - `_detect_from_binary_analysis(..., run_dir=)` → 엔트리에 `string_hits`가 없으면 `_extract_ascii_runs` (zero-dep `strings` 대체)로 바이너리 앞 256KB 읽어 printable run 추출 후 기존 `_BINARY_PATTERNS` 정규식 적용
  - `binary_analysis.json` 리더가 현재 `hits` 키 + legacy `binaries`/`entries` 모두 인식
  - pre-v2.x `file_list` / `string_hits` 경로는 legacy fallback으로 유지
- 검증: R7000 run에 `SbomStage`만 재실행 → **0 → 4 components** (`curl 7.36.0` 바이너리 직접 읽기, `openssl 1.0.0` / `libz 1` / `libpthread 0` so_filename walking)
- 테스트: `tests/test_sbom_schema_fix.py` 14 cases (`_extract_ascii_runs` 4 / so_files 5 / binary_analysis 4 / SbomStage integration 1)

**전체 회귀 (두 수정 누적)**:
| 지표 | v2.6.0 shipped | post-release |
|------|----------------|-------------|
| pytest | 1027 | **1047** (+20: synthesis 5 + sbom 14 + 기타 1) |
| pyright | 0 errors | **0** |
| ruff | clean | **clean** |
| check_doc_consistency | 0 violations | **0** |

**태그**: 위 후속 수정과 2C.3~2C.6 foundation hardening은 **v2.6.1**로 roll-up 완료.

### post-v2.6.1 fuzzing stage 수정 (2026-04-19)

v2.6.1 이후 외부 기여(@NightStalkers-160th) PR 2건을 머지. 둘 다 AFL++ fuzzing stage 경계의 실제 운영 실패를 좁은 범위로 수정. CHANGELOG는 `[Unreleased] Fixed`에 보관, 다음 point release에서 roll-up 예정.

**PR #7 — Docker fuzzing 산출물 ownership 수정** (merge `c919390`):
- 증상: AFL++ Docker 컨테이너가 root 소유로 `stages/fuzzing/*/afl_output/default/` 생성 → SCOUT `_collect_stats`가 `fuzzer_stats`를 읽을 때 `PermissionError: [Errno 13]` 발생 → fuzzing stage `failed`
- 수정: docker_cmd에 `--user $(os.getuid()):$(os.getgid())` 추가 (2줄 diff)
- 검증: OpenWrt Archer C7 v5 run (`2026-04-13_1014_sha256-bf9eeb5af38a`) — 이전에 정확히 이 에러로 `failed` 상태였던 run을 재실행, `default/` 소유자가 root:root → rootk1m:rootk1m으로 변경되며 PermissionError 소멸

**PR #8 — AFL++ 0-execution campaign을 partial로 정직 보고** (merge `4e7ee05`):
- 증상: AFL++가 fork server handshake 실패 / QEMU arch mismatch / docker non-zero exit 등으로 target을 한 번도 실행 못 해도 `fuzzing: ok`로 보고됨
- 수정:
  - `_append_campaign_execution_limitations(limitations, docker_rc, docker_err, stats)` — docker exit code / forkserver handshake / arch mismatch / zero-exec 4가지 실패 신호를 limitation 문자열로 기록
  - `_campaign_completed(result)` — `stats.execs_done > 0`일 때만 `True` 반환. `targets_completed` 카운터는 이 게이트 통과분만 증가
  - 한 파일에서 helper 분리 + 2개 호출지점 수정
- 테스트: `tests/test_fuzz_campaign.py` 4 cases (no-exec / arch mismatch / campaign_completed gate / stage-level partial status)
- 검증: 같은 OpenWrt Archer C7 v5 run에서 AFL++가 `Fork server handshake failed`로 abort 한 MIPS-32 dnsmasq target — `limitations = [docker_exit_1, forkserver_handshake_failed, no_fuzzer_executions]` 3개 모두 기록됨, `targets_attempted=1 / targets_completed=0`, stage status = **`partial`**

**회귀**:
| 지표 | v2.6.1 | post-merge |
|------|--------|-----------|
| pytest | 1047 | **1051+** (+4 fuzz_campaign) |
| pyright | 0 errors | **0** |
| ruff | clean | **clean** |
| check_doc_consistency | 0 violations | **0** |

**실펌웨어 증거**: `aiedge-runs/2026-04-13_1014_sha256-bf9eeb5af38a/stages/fuzzing/`에서 pre-/post-merge 쌍 유지 (status `failed`→`partial`, limitations `[PermissionError]`→`[docker_exit_1, forkserver_handshake_failed, no_fuzzer_executions]`).

## v2.5.0 업그레이드 (2026-04-13)

전략 로드맵 Phase 1 구현. 학술 논문 30+편, 경쟁 도구 12개(Theori Xint, FirmAgent, FIRMHIVE 등), Theori Xint 심층 분석 기반.

### LLM 구조 개선
- **`llm_prompts.py`** (신규): `STRUCTURED_JSON_SYSTEM` 등 7개 system prompt + temperature 상수 중앙 관리
- **LLMDriver Protocol 확장**: `system_prompt`, `temperature` 파라미터 추가. 4개 드라이버(Codex/Claude API/Claude Code/Ollama) 모두 지원
- **5-stage JSON 파서**: preamble 제거 → fence 추출 → raw → brace-counting → common error fix. `required_keys` 스키마 검증
- **adversarial_triage / taint_propagation / semantic_classifier**: 모든 LLM 호출에 system_prompt + temperature 적용
- **semantic_classifier 배치 축소**: 50 → 15개 함수/배치

### Sink 커버리지 확대
- **`_SINK_SYMBOLS`**: 11 → 28개 (memcpy, strcat, printf, syslog, scanf, dlopen 등)
- **`_FORMAT_STRING_SINKS`** + `_is_format_string_variable()`: variable-controlled format string 탐지

### EPSS 통합
- **cve_scan.py**: FIRST.org EPSS API 배치 조회, per-run + cross-run 캐시
- 신뢰도 조정: EPSS ≥ 0.10 → +0.10, ≥ 0.01 → +0.05, < 0.001 → -0.05

### 버그 수정
- **CVE scan signature-only 경로**: 조기 return 제거, 공통 후처리 파이프라인 사용
- **CVE scan `comp` 변수 버그**: match별 component_metadata 보존, leaked 루프 변수 참조 제거
- **LLM 실패 분류**: parse_failures vs llm_call_failures 분리 집계 (adversarial_triage, fp_verification)

### CI/CD & 문서
- **GitHub Action**: `.github/actions/scout-scan/` (composite, SARIF + Security 탭 업로드)
- **CRA 매핑**: `docs/compliance_mapping/cra_annex_i.md` (EU CRA Annex I 12개 요구사항)
- **전략 로드맵**: `docs/strategic_roadmap_2026.md` (3-Phase plan)

### R7000 검증 (2026-04-13)

| 지표 | v2.4.1 (이전) | v2.5.0 (현재) |
|------|---------------|---------------|
| adversarial_triage parse_failures | 100/100 | **0/100** |
| fp_verification unverified | 97/100 | **0/100** |
| fp_verification true_positives | 1 | **57** |
| cve_scan EPSS enriched | 0/23 | **23/23** |

- 런: `aiedge-runs/2026-04-12_1320_sha256-b28bf08e9d2c` (codex 드라이버, R7000 31MB)
- adversarial debate: 100 debated → 99 downgraded(FP) + 1 maintained(TP)

## v2.4.1 패치 (2026-04-11)

- **Confidence 보정**: `decompiled_colocated` 0.60→0.45 (high-risk 0.50). Terminator 피드백: symbol co-occurrence와 증거 수준 동일.
- **addr_diff 제거**: P-code taint에서 주소 근접 매칭 → callee name 매칭으로 변경. 컴파일러 최적화에 robust.
- **Interprocedural taint (Strategy 4)**: xref call graph 기반 cross-function source→sink 탐지. 1-hop 제한.
- **검증**: RT-AX88U에서 `fread→vsprintf` interprocedural trace 1건 신규 발견.

## v2.4.0 업그레이드 (2026-04-11)

- **Ghidra P-code taint 분석**: `pcode_taint.py` — 3-strategy (P-code SSA dataflow → P-code colocated → decompiled body). 함수 수준 source→sink 검증.
- **4-tier confidence caps**: `PCODE_VERIFIED_CAP = 0.75` 추가로 4-tier 완성. SYMBOL_COOCCURRENCE(0.40) < STATIC_CODE_VERIFIED(0.55) < STATIC_ONLY(0.60) < PCODE_VERIFIED(0.75).
- **소스 룰 확장**: SQL injection, format string, path traversal, SSRF 4개 패밀리 + 9개 regex 패턴.
- **CGI 핸들러 탐지**: Ghidra string_refs에서 `do_*_cgi` 함수명 추출 → source endpoint 등록.
- **INPUT_APIS 확장**: `cJSON_Parse`, `json_tokener_parse`, `xmlParseMemory` 추가.
- **SBOM 백포트 감지**: opkg 패치 리비전 파싱, CVE 매칭 시 confidence -0.30.
- **Handoff 스키마**: `firmware_handoff.json`에 adversarial triage 스키마 레퍼런스 추가.
- **검증**: ASUS RT-AX88U 재분석 — 5건 신규 decompiled_colocated traces, confidence 0.40→0.60 (+50%).

## v2.3.0 업그레이드 (2026-04-11)

- **Adversarial triage 병렬화**: `ThreadPoolExecutor` 기반 finding 단위 병렬 실행 (6h→50min). `AIEDGE_ADV_PARALLEL` env var (기본 8).
- **Codex 모델 설정**: `AIEDGE_CODEX_MODEL` env var 추가 (기본 `gpt-5.3-codex`).
- **ClaudeCodeCLIDriver**: Claude Code CLI OAuth 세션 기반 LLM 드라이버 추가.
- **실시간 CLI 진행률**: `ProgressTracker` 모듈로 파이프라인 스테이지별 진행 표시.
- **benchmark_eval.py**: analyst readiness 평가, bundle verifier, metrics 수집.
- **TUI 리브랜딩**: AIEdge → SCOUT, 색상 cyan → magenta, viewer indigo/purple 팔레트.
- **Apache 2.0 라이선스**: MIT에서 전환.
- **LLM JSON 파싱 통합**: `parse_json_from_llm_output()` 3-stage fallback으로 7개 중복 구현 대체.
- **Tier 2 LLM 벤치마크**: 36 firmware, 2430 findings debated, 99.3% LLM-adjudicated FPR reduction, 18 maintained true findings.
- 파이프라인 41 → 42 stages: `csource_identification` 추가.

## v2.0 업그레이드 (2026-03-27)

### 신규 스테이지 (34 → 41)
- **`enhanced_source`** (`enhanced_source.py`): `.dynstr` INPUT_APIS 스캔 (14개 API). LLM 미사용, 비용 $0.
- **`semantic_classification`** (`semantic_classifier.py`): 3-pass 함수 분류기 (static → haiku → sonnet). 보안 관련 함수 자동 분류.
- **`taint_propagation`** (`taint_propagation.py`): LLM 기반 inter-procedural taint 분석. 함수 레벨 캐시로 중복 호출 방지.
- **`fp_verification`** (`fp_verification.py`): 3-패턴 FP 제거 (sanitizer/non-propagating/sysfile). LLM 미사용, 비용 $0.
- **`adversarial_triage`** (`adversarial_triage.py`): Advocate/Critic LLM 토론을 통한 FPR 감소.
- **`poc_refinement`** (`poc_refinement.py`): 퍼징 시드 기반 반복적 PoC 생성 (최대 5회 시도).
- **`chain_construction`** (`chain_constructor.py`): 익스플로잇 체인 조립 (same-binary + IPC cross-binary).

### CLI 모듈화
- **`__main__.py` 분리**: ~4,500줄 → 7개 모듈 (~660줄 진입점).
  - `cli_common.py`: 공유 유틸리티, 상수, 헬퍼 함수
  - `cli_serve.py`: `serve` 서브커맨드 (웹 리포트 뷰어)
  - `cli_tui_data.py`: TUI 데이터 로딩 및 처리
  - `cli_tui_render.py`: TUI 렌더링 및 표시 로직
  - `cli_tui.py`: TUI 서브커맨드 오케스트레이션
  - `cli_parser.py`: 인자 파서 구축 (`_build_parser()`)

### 신규 스크립트
- **`scripts/benchmark_firmae.sh`**: SCOUT vs FirmAE 벤치마크 비교 실행.
- **`scripts/benchmark_firmae.sh` archive contract 변경**: `--cleanup`가 flattened JSON snapshot이 아니라 verifier-friendly run replica archive를 보존한 뒤 원본 run_dir 삭제
- **`scripts/unpack_firmae_dataset.sh`**: FirmAE 데이터셋 분류 및 언패커.

### 신규 문서
- **`docs/upgrade_plan_v2.md`**: v2.0 전체 업그레이드 계획 및 부록.
- **`docs/roadmap_llm_agent_integration.md`**: LLM 통합 로드맵 및 전략.

## 이전 개선 (2026-03 초)

### Phase 1: 버그 수정
- **Exploit stage import 격리** (`run.py`): 5개 exploit stage를 단일 try/except에서 개별 try/except ImportError 블록으로 분리. 각 stage 실패가 독립적으로 limitation에 기록됨. GhidraAnalysisStage() 직접 호출 버그 수정 (make_ghidra_analysis_stage factory 사용).
- **Duplicate gate 파일 잠금** (`duplicate_gate.py`): read-modify-write 사이클에 `fcntl.flock()` advisory lock 추가. 동시 실행 시 데이터 손실 방지.
- **LLM driver 미인식 이름 경고** (`llm_driver.py`): `AIEDGE_LLM_DRIVER`에 미인식 값이 설정될 경우 stderr 경고 출력.

### Phase 2: 증거 체인 무결성
- **Findings stage SHA-256 매니페스트** (`run.py`): `_write_findings_manifest()`가 `stages/findings/stage.json`에 SHA-256 해시 포함 매니페스트 생성. Handoff 번들에서 하드코딩된 `"status": "ok"` 제거.
- **Firmware handoff 유효성 검증** (`schema.py` + `run.py`): `validate_handoff()`가 `firmware_handoff.json` 기록 전 필수 키를 검증.
- **파이프라인 후 실패 기록** (`run.py`): SARIF, executive report, SLSA provenance 실패가 limitation으로 기록됨 (기존: 무시). SLSA 실패 시 `gate_passed=False` 설정.

### Phase 3: 리포트 중복 제거
- **`_finalize_report()` 헬퍼 추출** (`run.py`): 예산 소진/정상 종료 경로 간 ~35줄 중복 제거.
- **Extraction schema 통일** (`run.py`): 3개 extraction summary 코드 경로가 동일한 12-key 스키마 생성.

### Phase 4: CI/CD
- **GitHub Actions CI** (`.github/workflows/ci.yml`): pytest (Python 3.10-3.12), ruff lint, pyright typecheck 자동화.
- **Ruff linting 설정** (`pyproject.toml`) + **Pyright standard mode** (`pyrightconfig.json`).

### Phase 5: 레지스트리 정리
- **firmware_lineage, fuzzing stage**: 기존에 등록만 되고 인스턴스화되지 않던 stage를 전체 파이프라인에 포함.

## Known Issues (중요)

- **Legacy Tier 2 archive는 현재 contract의 공식 baseline이 아님**: `benchmark-results/legacy/tier2-llm-v2`는 historical reference용이며, archived bundle verifier 기준으로는 incomplete/misaligned evidence가 남아 있음
- old Tier 2 bundle을 normalize + static rerun하면 digest verifier는 상당 부분 회복되지만, 일부 `report` verifier 실패는 **이미 archive에 포함되지 않은 extraction evidence refs** 때문에 코드만으로 복구되지 않음
- fresh full Tier 2 rerun 전까지 analyst-ready aggregate 수치는 single-sample fidelity 검증 외에는 확정 수치로 간주하면 안 됨

- 샌드박스/호스트 정책에 따라 `serve --once`가 포트 바인딩 권한 문제로 실패할 수 있음 (`Operation not permitted`).
- 다층 벤더 포맷은 재귀 SquashFS로 많이 개선되었으나, 암호화된 포맷이나 특수 커스텀 헤더는 여전히 수동 추출 필요.
  - 현재는 `--rootfs` 우회가 보완 경로이며, 포맷 전용 extractor 체인 확장은 계속 필요.
- 바이너리 보안 속성(NX/PIE/RELRO/Canary)이 순수 Python `.dynstr` 파싱으로 수집되며 findings 점수에 반영. FORTIFY_SOURCE 탐지 포함. 디컴파일/CFG 기반 정밀 분석은 Ghidra 연동으로 보완.
- **Ghidra 분석**: `run.py` 자동 실행에 optional로 포함 (Ghidra 미설치 시 graceful skip). `--stages ghidra_analysis`로도 수동 실행 가능.
- **AFL++ 퍼징**: 전체 파이프라인에 포함됨 (Docker + AFL++ 미설치 시 graceful skip). `--stages fuzzing`으로도 수동 실행 가능.
- Reachability에서 CVE 컴포넌트명과 graph 노드 ID 형식 불일치(`curl` vs `component:curl`)로 일부 `no_graph_data` 발생. 매칭 로직 개선 필요.

## 다음 우선순위

> [!important] **Phase 2C/2D/3 실행 계획**은 gnosis wiki에 통합 관리됩니다: [`gnosis/wiki/projects/scout-phase-2c-2d-plan.md`](https://github.com/R00T-Kim/gnosis/blob/main/wiki/projects/scout-phase-2c-2d-plan.md). 세션이 바뀌거나 담당자가 교체돼도 동일 품질의 결과가 나오도록 SSOT 표, dependency DAG, operator checklist, 각 작업 항목의 entry/exit criteria, 검증 명령, 롤백 계획이 전부 거기에 있습니다. 아래 "다음 우선순위" 목록은 **Phase 2C 착수 전의 레거시 백로그**이며, 계획 문서의 Phase 2C 작업이 이들을 흡수/재배치합니다.

**Phase 2C 요약** (6-8주, foundation hardening):
- 2C.1 SBOM 재측정 파일럿 5 펌웨어 (3일) — 근거 보고서: `docs/sbom_schema_fix_impact.md` (`4/6` 샘플 변화, 결론: **2C.6 전체 재측정 필수**)
- 2C.2 Synthesis inherit finding-level 재작성 (matched downstream lineage / deterministic top-K / aggregate fallback, 3일)
- 2C.3 `finding.evidence_tier` 필드 rollout (1주) — branch 구현 기준 additive taxonomy landed: `evidence_tier` + `tier_counts`, SARIF `scout_evidence_tier`, MCP tier filter (`docs/evidence_tier_contract.md`)
- 2C.4 Stage contract tests 42 스테이지 (2-3주) — lightweight validator landed and smoke-verified on representative firmware; `scripts/validate_stage_outputs.py` + `src/aiedge/stage_contracts.py` + `tests/test_stage_contracts.py` + `docs/stage_contracts.md`
- 2C.5 병렬 실행 hardening + wall-clock 실측 (1주) — execution provenance landed and verified via `manifest.execution_mode/max_workers`, `verified_chain.execution`, and legacy-compatible verifier checks; `docs/parallel_execution.md`
- 2C.6 1,123 펌웨어 corpus 전체 재측정 (1-2주) — **완료**. 최종 baseline refresh는 `docs/carry_over_benchmark_v2.6.md` 및 `benchmark-results/2c6-fresh-full-final/aggregate.json`에 기록: **success 1110 / partial 4 / fatal 9**. archive-only rerun은 invalid로 폐기했고, fresh rerun 4파동(v2/resume/r3/r4)을 합쳐 best-view corpus를 재구성함
- 2C.7 Docs/marketing 규율 + v2.6.1 태그 (1주) — **완료**. Tier 1 fresh baseline, confidence semantic break, LLM driver degradation, analyst copilot 3분리, release/governance 문구를 정리하고 `v2.6.1` 태그/릴리즈를 발행함

> 2C.6 fresh corpus refresh는 **1123-target 기준 1110 success / 4 partial / 9 fatal**로 마감됐다. 성공 run은 `extraction=ok` / `inventory=sufficient`가 1110건 전부 일치하고, nonzero findings는 1110/1110, nonzero CVE는 1089/1110이다. 다만 이 rerun은 여전히 baseline refresh이지, 곧바로 "가치가 증명됐다"는 뜻은 아니다. review-facing 숫자는 extraction success / inventory sufficiency / SBOM delta / pair-labeled recall-FP / tier ROC를 분리해서 읽어야 하고, reviewer-facing precision/recall/ROC는 pair-labeled eval lane에서 별도로 확정한다.

> Reviewer eval lane local-7 완료: 7 local pairs / 14 runs, **recall 0.142857 / false-positive rate 0.142857** (`benchmark-results/pair-eval/pair_eval_summary.json`). R7000은 target CVE를 vulnerable/patched 모두에서 유지했고, 나머지 6쌍은 vulnerable miss + patched clean으로 나왔다.

**2C.7 이후 권장 실행 순서** (Pivot 2026-04-19 반영):

> [!important] **Direction Pivot 2026-04-19**: reviewer eval lane 분석 (recall 0.142857 / degenerate ROC / dedicated rerun 정체) + SCOUT 정체성 갈림길 검토 결과, **Phase 2D 직진 보류 + Phase 2C+ (detection 보강 4-6주) insert + 갈래 A (Compliance/Audit) 1순위 재포지셔닝**이 채택되었습니다. 본격 SSOT 재배치는 gnosis 계획 문서를 참조하세요.

1. **[B-2] E2E demo 확정** — `docs/r7000_e2e_demo.md`를 실측 artifact 기준으로 마감하고 reviewer walkthrough를 고정
2. **[D] results overview 마감** — corpus baseline, pair eval, calibration, E2E demo를 한 문서에서 cross-link하고 reviewer 공유용 요약본으로 고정
3. **Phase 2C+ 진입** — 5개 detection 보강 항목 (4-6주)
4. **Phase 3'.1 (산업별 보고서) 즉시 시작** — Phase 2C+와 완전 병렬, EU CRA 2026/09 보고 의무 5개월 timing
5. **Phase 2D 진입 Exit Gate 통과 후 Phase 2D' 착수** (capability layer, scope 좁힘)

**Phase 2C+ 요약** (4-6주, detection 보강 — Pivot 2026-04-19 insert):
- 2C+.1 LATTE Code Slicing (`taint_propagation.py`) — **landed PR #9** (opt-in via `AIEDGE_LATTE_SLICING=1`)
- 2C+.2 LARA URI/키 시맨틱 소스 식별 (`enhanced_source.py`) — **landed PR #9**; follow-up `ascii_strings` wire-through 적용됨 (`CHANGELOG [Unreleased] Fixed`)
- 2C+.3 Sink 28→50+ 확장 + format string variable 검출 강화 — **landed PR #9**
- 2C+.4 Vendor 포맷별 extraction chain 확장 (5종) — pending (유일한 미완)
- 2C+.5 finding diversity gate + dedicated rerun timeout 진단 — **landed PR #9**

권장 실행 순서: 2C+.5 (측정 도구 먼저) → 2C+.3 (sink) → 2C+.1 (LATTE) → 2C+.2 (LARA) → 2C+.4 (vendor extraction)

**Phase 2D 진입 Exit Gate** (5개 임계값 모두 통과 시 진입):
- pair eval recall ≥ 0.40 (summary-reuse baseline 0.142857 / 1차 측정 Codex 6h LATTE-off + LARA misconnected 14/14 = 0.142857)
- evidence_tier ≥ 2개 tier nonzero TP (현재 `symbol_only`만)
- finding diversity index < 0.5 (summary-reuse baseline 1.0 / 1차 측정 1.0, 공식 `PAIR_EVAL_DIVERSITY` gate FAIL)
- dedicated reviewer rerun: 1개 driver(claude 또는 codex) success — **통과 (Codex 6h LATTE-off 14/14 완주, 2026-04-19 ~ 2026-04-20)**
- pair corpus size ≥ 10 (현재 7, 2C+.4로 확장 예정)

**Exit Gate 1차 측정 (Codex baseline, 2026-04-19→20)**: 11h 1min wall-clock, 14/14 rows success, avg 93min/run. 공식 `scripts/release_gate.sh` 결과 `RELEASE_GOVERNANCE=FAIL` (`PAIR_EVAL_DIVERSITY` + `QUALITY_POLICY` + `CONTRACT_FINAL` 3개 sub-gate FAIL). 이 run은 `AIEDGE_LATTE_SLICING` 미설정 + 2C+.2 LARA `ascii_strings` 단락 상태였으므로 2C+ 핵심 detection 축이 비활성.

**Exit Gate 2차 측정 공식 봉인 (Codex LATTE-on, 2026-04-20)**: `benchmark-results/pair-eval-dedicated-local7-codex-6h-r2-latte-on/` 14/14 완주 (13:33 KST, 12h 45min wall-clock). `AIEDGE_LATTE_SLICING=1` + LARA `ascii_strings` follow-up fix 모두 반영된 상태. 결과:
- `scripts/score_pair_corpus.py --pairs benchmarks/pair-eval/pairs.json` → `{"pairs": 7, "recall": 0.142857, "fpr": 0.142857}` — summary-reuse baseline과 소수점 이하까지 **완전 동일**
- `pair_eval_findings.csv` 14개 row 전부 `aiedge.findings.web.exec_sink_overlap` 단일 ID (`finding_diversity_index = 1.000`)
- `scripts/release_gate.sh` → `RELEASE_GOVERNANCE=FAIL` (PAIR_EVAL_DIVERSITY / QUALITY_POLICY / CONTRACT_FINAL sub-gate FAIL)

**Phase 2D' Entry Gate 5개 scorecard 최종**:
- Gate 1 recall ≥ 0.40 → 0.143 **FAIL**
- Gate 2 tier variation ≥ 2 nonzero TP tiers → 1 **FAIL**
- Gate 3 finding diversity < 0.5 → 1.000 **FAIL**
- Gate 4 dedicated rerun ≥ 1/N success → 14/14 **PASS**
- Gate 5 pair corpus size ≥ 10 → 7 **FAIL**

**시나리오 C 공식 봉인**: Pivot 2026-04-19의 "변동 없음 → 2C+ 전략 재검토" 시나리오 채택 확정. Option D (Phase 2D' deferred, 갈래 A 올인)로 로드맵 이동. 근본 원인은 `findings.py`의 primary-finding 선택이 synthesis-stage 합성 finding (`web.exec_sink_overlap`) 하나만 선택한다는 점 — LARA source 확장(0→21-86 hits/run)과 LATTE slicing은 evidence를 풍부하게 만들지만 finding ID 다양성에는 기여하지 못함. 이 전체 분석은 `docs/v2.7.0_release_plan.md` + `wiki/projects/scout-direction-pivot-2026-04.md` + `wiki/projects/scout-cra-audit-saas-scope.md`에 기록됨. Claude LATTE-on lane은 Claude Pro/Max 플랜의 5h rolling usage quota 소진(`"You've hit your limit · resets 5am (Asia/Seoul)"`)으로 `llm_call_failures=100/100` 발생 후 폐기 (driver-level noise, 재측정 결과와 무관).

**v2.7.0 tag 발행 조건 충족**: 공식 scorecard가 release note에 인용 가능한 상태. 후속 v2.7.1은 2C+.4 vendor extraction chain 확장 (DIR-859 / RT-AC68U / WRT1900ACS / DIR-878 + 1종 → corpus 7→10+) + 3'.1 B-5 release tag로 bundle 예정.

**v2.7.1 post-release update (2026-04-22, Phase 2C+.4 corpus expansion + B-5 release tag)**: v2.7.1 released 2026-04-22 — Phase 2C+.4 vendor extraction 5종 완결 (DIR-859 / DIR-878 / RT-AC68U / WRT1900AC v2 / EA6700) + Phase 3'.1 step B-5 release tag packaging. 공식 release note: [GitHub](https://github.com/R00T-Kim/SCOUT/releases/tag/v2.7.1) / 측정 이력: `docs/v2.7.1_release_plan.md`. 12-pair `--no-llm` FINAL 측정 (WRT1900AC v2 ok 전환 후) 결과:

- Gate 1 Recall: 0.1429 → **0.1667** (+17% rel) — 여전히 FAIL (임계 0.40 미달)
- Gate 2 Tier variation: 1 (`symbol_only`만) — FAIL 유지 (1차 측정에서 WRT partial의 `analysis_incomplete`가 `unknown` tier 채움으로 일시 PASS 보였으나 2400s rerun 후 TP 소멸, baseline 회귀)
- Gate 3 Finding diversity: 1.000 → **0.917** — FAIL (24 row 중 22 `web.exec_sink_overlap` + 2 `analysis_incomplete` from DIR-878 partial)
- Gate 4 Dedicated rerun: 14/14 + **12/12 `--no-llm`** — PASS 유지
- Gate 5 Corpus size: 7 → **12** — ❌ → ✅ **PASS** (manifest 등록만으로 통과)

**FINAL scorecard: 5/5 중 2/5 PASS** (Gate 4 + Gate 5). v2.7.0의 1/5 → v2.7.1 2/5, +1 순증가는 Corpus에서 옴. 공식 수치는 `benchmark-results/pair-eval-12pair-mixed/` 및 `docs/v2.7.1_release_plan.md`. **교훈**: partial extraction artifact가 Gate 2 수치를 왜곡할 수 있음 — ok 측정이 figure of record. Pivot Option D (갈래 A 1순위, 갈래 B external)는 변경 없음 — v2.7.1은 시나리오 C의 정량적 정련이지 re-pivot 아님. Gate 1/2/3의 구조적 한계 (`findings.py` single-synthesis-finding selection)는 외부 detection-engine 트랙 유지.

**Phase 2D' 요약** (4-6주, capability layer — scope 좁힘):
- 2D.1 reasoning_trail + MCP 실전 루프 검증
- 2D.2 Multi-agent exploit chain
- 2D.4a Vul-RAG (CVE 시맨틱 매칭만)
- ~~2D.3 LLM 퍼즈 하네스 자동 생성~~ → external track
- ~~2D.4b LLM4Decompile / GhidraMCP~~ → external track

**Phase 3' 요약** (재배치 2026-04-19, 갈래 A 우선):
- **3'.1 산업별 보고서 (FDA Section 524B / EU CRA Annex I / ISO 21434 / UN R155)** — **승격 1순위**, Phase 2C.7만 의존, 즉시 착수 가능
- 3'.2 CRA-compatible audit SaaS (전 SCOUT Cloud API, scope 좁힘)
- 3'.3 LFwC 10,913 벤치마크
- 3'.4 펌웨어 portfolio 관리
- 3'.5 CVE-Bench 자동 평가
- ~~3.1 Big Sleep 자율 에이전트~~ → external track
- ~~3.6 Foundation Model 파일럿~~ → external track

---

**레거시 백로그** (Phase 2C 작업에 흡수/재배치됨):

1) 새 benchmark contract로 Tier 2 full fresh rerun 수행 (legacy snapshot과 분리된 공식 analyst-readiness baseline 생성)
2) report verifier의 remaining dangling `evidence_refs` assembly 경로 정리
3) Reachability 컴포넌트-노드 ID 매칭 로직 개선 (CPE 이름 → graph 노드 ID 정규화)
4) 벤더 포맷 전용 extraction chain 확장 (QNAP/Synology/ASUS 계열 깊은 중첩 포맷)
5) Ghidra dataflow 결과를 source-sink 그래프와 findings confidence에 통합
6) ~~퍼징 크래시를 exploit_autopoc PoC seed로 자동 연계~~ -- v2.0 `poc_refinement` 스테이지로 해결
7) Public benchmark corpus 확장 (현재 seed fixture → 실제 공개 펌웨어 corpus)
8) 남은 `_assert_under_dir()` 로컬 복사본을 `path_safety.py` import로 통합 (26파일)
9) Semantic classification 결과를 taint propagation 초기 seed로 활용하는 피드백 루프 강화
10) Adversarial triage 라운드 수/모델 티어 자동 조정 (finding 수 기반)
