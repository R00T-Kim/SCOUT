# Status

이 문서는 "현재 구현 상태"를 솔직하게 기록합니다.

## 현재 구현됨

- AIEdge CLI: `./scout analyze`, `./scout stages` (래퍼 권장)
- 동일 기능은 `python3 -m aiedge analyze`, `python3 -m aiedge stages`로 직접 실행 가능
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
- 바이너리 하드닝: 순수 Python ELF 파서로 NX/PIE/RELRO/Canary/Stripped 수집. inventory `binary_analysis.json`에 `hardening_summary` 포함. findings 점수에 하드닝 기반 보정 적용 (fully hardened: x0.7, no protection: x1.15).
- 3-Tier 에뮬레이션: FirmAE Docker 이미지(Tier 1) + QEMU user-mode 서비스 프로빙(Tier 2, lighttpd/busybox/dnsmasq/sshd) + rootfs 검사 fallback(Tier 3). `docker/scout-emulation/` Dockerfile 포함. `AIEDGE_EMULATION_IMAGE`, `AIEDGE_FIRMAE_ROOT` env var.
- 엔디안 인식 아키텍처 감지: MIPS/ARM 빅/리틀엔디안 정확 구분 (`mips_be`, `mips_le`, `arm_be`, `arm_le`).
- 취약점 유형별 PoC 템플릿: `poc_templates.py` 레지스트리 4종 (cmd_injection, path_traversal, auth_bypass, info_disclosure) + tcp_banner fallback. `poc_skeletons/` 디렉토리에 standalone PoC 파일.
- exploit_runner 실제 PCAP 캡처: tcpdump 가용 시 실제 패킷 캡처 (기존 placeholder fallback 유지).
- PoC 재현성 검증: `poc_validation`에서 readback_hash 일관성 확인으로 재현성 보장.
- LLM 트리아지 스테이지: findings → `llm_triage` → llm_synthesis 순서로 실행. 모델 티어 자동 선택 (<10: haiku, 10-50: sonnet, >50: opus). 하드닝/attack_surface 보안 컨텍스트 포함 프롬프트. `--no-llm`에서 graceful skip.
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
- **Executive Report 생성** (`report_export.py`): Markdown executive report 자동 생성. 파이프라인 요약, 상위 리스크, SBOM/CVE 테이블, 공격 표면, 크레덴셜 findings.
- **웹 뷰어 UX 대폭 개선**: 싱글 패널 뷰(사이드바 클릭 → 해당 패널만 표시), KPI 바(Critical/High/Components/CVEs/Endpoints 상시 표시), SBOM/CVE/Reachability/Security Assessment 4개 패널 추가, 페이지네이션(SBOM 30/page, CVE 20/page), 그래프 Python 사전 레이아웃(150 노드 균형 선택, 호버 시 연결 정보 표시), viewer.html 1.5MB→567KB 경량화.
- **공유 유틸리티** (`path_safety.py`): `assert_under_dir`, `rel_to_run_dir`, `sha256_file`, `sha256_text` 공유 모듈.
- 파이프라인 29 → 34 stages: `ghidra_analysis`, `sbom`, `cve_scan`, `reachability`, `fuzzing` 추가.

## Known Issues (중요)

- 샌드박스/호스트 정책에 따라 `serve --once`가 포트 바인딩 권한 문제로 실패할 수 있음 (`Operation not permitted`).
- 다층 벤더 포맷은 재귀 SquashFS로 많이 개선되었으나, 암호화된 포맷이나 특수 커스텀 헤더는 여전히 수동 추출 필요.
  - 현재는 `--rootfs` 우회가 보완 경로이며, 포맷 전용 extractor 체인 확장은 계속 필요.
- 바이너리 보안 속성(NX/PIE/RELRO/Canary)이 순수 Python `.dynstr` 파싱으로 수집되며 findings 점수에 반영. FORTIFY_SOURCE 탐지 포함. 디컴파일/CFG 기반 정밀 분석은 Ghidra 연동으로 보완.
- **Ghidra 분석**: `run.py` 자동 실행에 optional로 포함 (Ghidra 미설치 시 graceful skip). `--stages ghidra_analysis`로도 수동 실행 가능.
- **AFL++ 퍼징**: 기본 파이프라인에 포함되지 않음 (선택 기능). `--stages fuzzing`으로 수동 실행. Docker + AFL++ 이미지 필요.
- Reachability에서 CVE 컴포넌트명과 graph 노드 ID 형식 불일치(`curl` vs `component:curl`)로 일부 `no_graph_data` 발생. 매칭 로직 개선 필요.

## 다음 우선순위

1) Reachability 컴포넌트-노드 ID 매칭 로직 개선 (CPE 이름 → graph 노드 ID 정규화)
2) 벤더 포맷 전용 extraction chain 확장 (QNAP/Synology/ASUS 계열 깊은 중첩 포맷)
3) FirmAE 호환 펌웨어 커버리지 확대 (Tier 1 에뮬레이션 성공률 향상)
4) Ghidra dataflow 결과를 source-sink 그래프와 findings confidence에 통합
5) 퍼징 크래시를 exploit_autopoc PoC seed로 자동 연계
6) Public benchmark corpus 확장 (현재 seed fixture → 실제 공개 펌웨어 corpus)
