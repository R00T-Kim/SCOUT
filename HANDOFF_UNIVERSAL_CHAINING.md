# SCOUT: Universal Exploit-Chain Orchestration (Handoff Document)

## 1. 개요 (Overview)
본 문서는 SCOUT의 취약점 체이닝 아키텍처를 단일 프로세스/네트워크 소켓 중심에서 **범용적 상태 기반 오케스트레이션(Universal Exploit-Chain Orchestration)** 구조로 진화시키기 위한 설계, 구현 이력 및 가이드를 담고 있다.

단순히 "익스플로잇을 자동 생성한다"는 모호한 목표 대신, **Web API -> Config -> IPC -> Daemon -> Sink**로 이어지는 복잡한 데이터 흐름과 상태 전이를 모델링하여 실제 동작 가능한 PoC 스켈레톤을 생성하는 데 목적을 둔다.

## 2. 작업 타임라인 및 이력 (Implementation Timeline)

### 2026-05-18: ER605 1-day 분석에서 범용 아키텍처 도출까지

1.  **[Research] TP-Link ER605 CMXDDNS 패치 분석**
    *   v2.2.2와 v2.2.4 사이의 `cmxddnsd` 바이너리 패치 디프(Patch Diff)를 통해 `interface` 설정값이 `sprintf`를 거쳐 `popen`으로 흐르는 Command Injection 취약점 식별.
    *   Web/API를 통해 설정된 값이 파일 시스템(UCI Config)을 거쳐 데몬의 Sink까지 도달하는 **Config-to-Sink Chaining** 구조 확인.

2.  **[Act] SCOUT 정적 탐지 로직 1차 추가 (Trial & Error)**
    *   `src/aiedge/exploitability_dossier.py`에 `cmxddnsd` 전용 탐지 룰을 하드코딩하여 추가.
    *   **문제점 발견**: 특정 데몬명에 의존하는 방식은 확장성이 떨어지며, "범용 탐지기"로서의 SCOUT 철학에 맞지 않음을 확인.

3.  **[Refactor] 탐지 로직 일반화 (Generalization)**
    *   특정 데몬명을 제거하고, 모든 바이너리를 대상으로 **[Config API] + [String Builder] + [Command Sink]**가 공존하는 패턴을 찾는 범용 스캐너(`_config_derived_command_injection_candidates`)로 개편.

4.  **[Validate] 실제 펌웨어 대상 E2E 테스트 수행**
    *   대상: `ER605 v2.2.2 (Build 20231017)` 펌웨어 바이너리.
    *   결과: SCOUT이 `cmxddnsd` 뿐만 아니라 동일한 패턴을 가진 `cloud-brd` 데몬까지 후보군으로 자동 검출 성공. (`exploitability_dossier.json`에 기록됨)

5.  **[Analysis] PoC 자동 생성 단계의 한계 식별**
    *   `exploit_autopoc` 실행 결과, 정적 단서는 찾았으나 LLM이 다단계(Multi-step) 상태 전이(로그인 -> 설정 -> 트리거) 코드를 짜지 못하고 단일 패킷 공격만 시도하다 실패하는 현상 관측.
    *   **결론**: 단순 룰 추가가 아닌, 아키텍처 레벨의 **Universal Chaining** 설계 필요성 도출.

## 3. 핵심 설계 철학 (Core Philosophy)
*   **From Connectivity to Capability**: 단순히 두 컴포넌트가 연결되어 있음을 아는 것을 넘어, 해당 채널을 통해 공격자가 어떤 **Capability**를 가지는지 모델링한다.
*   **Exploit Plan IR**: LLM이 곧바로 Python 코드를 짜게 하지 않고, 중간 단계인 **Exploit Plan IR(Intermediate Representation)**을 생성하여 논리적 단계(States/Transitions)를 먼저 검증한다.
*   **Channel-Awareness**: IoT/Firmware 특유의 데이터 채널(UCI Config, NVRAM, Init Scripts, Temp Files)을 1급 객체(First-class object)로 취급한다.

## 4. 상세 아키텍처 (Detailed Architecture)

### 4.1 범용 채널 모델 (Universal Channel Model)
단순한 `ChannelType`을 넘어, 익스플로잇에 필요한 5가지 핵심 속성을 포함한다.
1. **Channel**: 경로 (WebAPI, Config, IPC, File, DeviceNode, etc.)
2. **Capability**: 공격자 권한 (Writable, Readable, Persistent, etc.)
3. **Transform**: 데이터 변형 (Encoding, Sanitization, Escaping)
4. **Trigger**: Sink 도달 조건 (Daemon Restart, Config Reload, Boot, Signal)
5. **Verifier**: 성공 확인 지표 (Side-effect, Log, File Creation, Callback)

### 4.2 Exploit Plan IR (Intermediate Representation)
LLM이 생성해야 할 중간 논리 구조:
*   **Goal**: 최종 목표 (e.g., `trigger_command_injection`)
*   **States**: 공격 진행 상태 (`Unauthenticated` -> `Authenticated` -> `PayloadInjected` -> `Triggered`)
*   **Transitions**: 상태 전이를 위한 구체적 액션 (Action, Channel, Pre/Post-conditions)

## 5. 구현 로드맵 (Roadmap)
1.  **Phase 1 (Engine)**: `chain_constructor.py` 리팩토링. 엣지에 `activation`, `trigger`, `capability` 필드 추가.
2.  **Phase 2 (Planner)**: `exploit_autopoc.py`에 Plan IR 생성 단계 및 12종 이상의 IoT 채널 인식 로직 주입.
3.  **Phase 3 (Runner)**: `exploit_runner.py` 고도화. 세션 유지, 지연 트리거 처리, 사이드 이펙트 기반 Verifier 라이브러리 구축.

## 6. 발견된 문제점 및 교훈 (Lessons Learned)
*   **Hardcoding vs Generalization**: 특정 버그에 매몰되기보다 패턴을 추상화했을 때 더 많은 잠재적 취약점(`cloud-brd` 등)을 발견할 수 있었음.
*   **Prompt Constraints의 한계**: LLM에게 코드 스타일로만 상태머신을 강제하면 논리적 오류가 잦음. 반드시 구조화된 IR(JSON 등)을 먼저 생성하게 하고 이를 코드로 낮추는(Lowering) 방식이 안정적임.
*   **Invisible Channels**: IoT 기기에서는 네트워크 응답에 나타나지 않는 '파일 시스템'이나 '환경 변수'가 가장 강력한 익스플로잇 채널임을 망각해서는 안 됨.

---
**최종 업데이트**: 2026-05-18
**작성자**: SCOUT AI Agent & Senior Analyst

## 7. 2026-05-18 Follow-up Implementation Notes

Universal Chaining was advanced from prompt-only guidance to artifact-backed Plan IR propagation.

### Implemented

1. **Channel model formalization**
   * `src/aiedge/chain_constructor.py` now defines `Channel`, `WebAPIChannel`, `ConfigChannel`, and `IPCChannel` dataclasses.
   * Cross-binary graph/shared-string/NVRAM chains now emit `channels[]` with `capability`, `transform`, `trigger`, `verifier`, and evidence hints.

2. **Config-to-sink candidates became channel-aware**
   * `src/aiedge/exploitability_dossier.py` generic config-derived command injection candidates now include a `config` channel.
   * Candidate IDs include a stable relpath hash to avoid daemon-name collisions.
   * Dossier decision logs and chain hypotheses preserve `channels[]` for downstream stages.

3. **Exploit Plan IR propagation**
   * `src/aiedge/exploit_state_machine.py` now emits `plan_ir` (`exploit-plan-ir-v1`) containing `goal`, `states`, `transitions`, and `channels`.
   * `autopoc_seed` carries `plan_ir` and `channels` so AutoPoC has a structured lowering target.

4. **AutoPoC lowering context**
   * `src/aiedge/exploit_autopoc.py` now loads and renders `identified_channels_json` and `exploit_plan_ir_json` into candidate prompt context.
   * `src/aiedge/poc_templates.py` includes a deterministic `config_state_machine` template for `config_derived_injection`/`generic_config_parser` candidates. It remains non-weaponized and only reports success on bounded marker readback.

### Verification

* `PYTHONPATH=src python3 -m py_compile ...` for touched implementation and test files.
* Targeted regression: `PYTHONPATH=src pytest -q tests/test_chain_constructor_channels.py tests/test_exploitability_dossier_stage.py tests/test_exploit_dag_stages.py tests/test_exploit_autopoc_stage.py tests/test_poc_validation_stage.py` → 30 passed.
* Full regression: `PYTHONPATH=src pytest -q` → passed.

### Remaining Work

* Add richer channel extraction from concrete HTTP route tables and UCI schema files, not only shared strings/binary substrings.
* Extend runner evidence bundles with per-transition results (`transition_id`, `status`, `readback_hash`).
* Run ER605 v2.2.2 artifact E2E to confirm `Web/API -> Config -> cmxddnsd/cloud-brd -> sink` candidates lower into useful lab skeletons.

## 8. 2026-05-18 Completion Notes

The follow-up pass completed the remaining Universal Chaining execution loop and updated the knowledge base.

### Additional implementation

1. **AutoPoC Plan IR fallback and candidate hygiene**
   * `exploit_autopoc` now synthesizes a safe `exploit-plan-ir-v1` when a dossier candidate has `channels[]` but was selected before its state-machine twin.
   * Duplicate candidates now merge downstream `channels`/`plan_ir` where possible.
   * Candidate selection now keeps one candidate per `chain_id` so generated plugins and evidence bundles do not overwrite each other.

2. **Runner transition evidence**
   * `exploit_runner.py` now records `transition_evidence[]` derived from each plugin's `_PLAN_IR`.
   * Evidence rows include `attempt`, `transition_id`, `action`, `channel_type`, `target`, `verifier`, `status`, `proof_evidence_ref`, and `readback_hash_present`.

3. **Goal-mode state**
   * Codex goals were enabled in `~/.codex/config.toml` (`[features] goals = true`) and the active SCOUT goal was persisted under `.omx/state/active-goal-universal-chaining.json`.

### E2E result: ER605 run artifact

Run directory: `aiedge-runs/2026-05-17_1347_sha256-db84e89cd312-1`

Executed subset:
`chain_construction -> exploitability_dossier -> protocol_model -> exploit_state_machine -> exploit_autopoc -> poc_validation`

Observed result:
* `chain_construction`: ok, 50 same-binary chains.
* `exploitability_dossier`: ok, 51 candidates, 40 surfaces, top score 62.0.
* `exploit_state_machine`: ok, 50 machines with Plan IR/channel propagation.
* `exploit_autopoc`: partial as expected without a live target marker echo; selected 3 distinct chains and generated deterministic templates.
* `poc_validation`: ok; policy gate remained lab-only/authorized/non-weaponized.
* Evidence bundles for `chain_001`, `chain_003`, and `chain_020` now contain 12 `transition_evidence` rows each (4 transitions x 3 repro attempts).

### Verification

* Targeted: `PYTHONPATH=src pytest -q tests/test_exploit_autopoc_stage.py tests/test_exploit_runner.py tests/test_exploit_dag_stages.py` -> passed (25 tests).
* Full: `PYTHONPATH=src pytest -q` -> passed.
* Gnosis docs were linted/synced/built with strict MkDocs after update.

### Remaining non-blocking extensions

* Improve route-aware Web/API channel extraction from concrete web handler tables.
* Add richer UCI/NVRAM schema parsing to name config fields more precisely.
* Add lab harness support for explicit config reload/readback endpoints so `planned_or_unproven` transition rows can be upgraded to observed proof rows.

## 9. 2026-05-18 Generalized Deep-Chain Quality Pass

The Out of Bounds ER605 article is now treated as a process benchmark, not as a product/protocol feature request. The reusable target is: discover deep chains where attacker influence crosses non-obvious boundaries such as outbound client responses, config state, IPC, parser fields, daemon reloads, and leak-before-control stages.

### Correction after v2.7.3 first pass

The first quality pass overfit the naming and docs to ER605/Comexe/DDNS. This follow-up re-centers the code on generic outbound response-parser chains. ER605 remains a fixture/example for quality evaluation only.

### Generalized model

1. **Outbound response-chain detection**
   * `exploitability_dossier.py` detects `outbound_response_parser_chain:*` candidates from upstream-service markers, response fields, parser sinks, and client-ish binaries.
   * New generic families: `outbound_protocol_response_parser`, `stateful_response_parser`, `lab_service_emulation_required`, `info_leak_chain_candidate`, `bounded_protocol_probe`.
   * New generic channels: `lab_network_redirection`, `protocol_response`, `parser_field`, `leak_before_control_boundary`.

2. **Protocol-aware Plan IR**
   * `exploit_state_machine.py` lowers these candidates to `classify_outbound_response_chain_quality`.
   * Plan actions include `emulate_protocol_channel`, `stage_bounded_field_probe`, and `validate_leak_before_control_boundary`.

3. **Non-weaponized quality template**
   * `poc_templates.py` adds an `outbound_protocol_response` deterministic template.
   * The generated plugin is exploit-first but lab-bounded: it sends only short benign proof packets to the configured lab target and succeeds as `vulnerability_trigger` only with observed response/readback evidence.
   * It does not generate overlong fields, ROP, command payloads, crypto/key recovery, or spoofing infrastructure.

4. **Selection hygiene**
   * `exploit_autopoc.py` avoids duplicate candidate IDs across dossier/state-machine sources, in addition to duplicate chain IDs.

### Quality verdict

* Previous quality: good triage, but too instance-specific after the first ER605 quality pass.
* Current quality: medium-high for generic safe reproduction planning and analyst handoff.
* Remaining dynamic gap: isolated lab harnesses and parser verifiers are needed to upgrade blueprint transitions into observed evidence.

See `docs/er605_poc_quality.md` for the detailed process-based quality review.
