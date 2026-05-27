# SCOUT Controlled Weaponization Layer

## Summary

SCOUT의 기본 전제는 **허가된 펌웨어 보안 연구, 제품보안, 내부 레드팀, 고객 승인 랩 환경**이다. 이 문서는 그 전제를 명시하고, SCOUT의 AEG-first 방향을 PoV에서 끝내지 않고 **controlled weaponization**까지 확장하기 위한 제품/아키텍처 구상을 기록한다.

여기서 weaponization은 무차별 공격, persistence, lateral movement, stealth, live 인터넷 대상 공격을 의미하지 않는다. SCOUT에서 허용되는 의미는 다음이다.

> Controlled weaponization = 허가된 범위에서 exploit primitive를 대상 조건에 맞게 안정적으로 실행하고, 비파괴적 또는 bounded 방식으로 효과를 증명하며, 실패 시 안전하게 중단하고, evidence/cleanup/control-pair 결과를 남기는 패키징.

이 문서는 실행 가능한 payload 절차나 공격 레시피가 아니라, SCOUT이 어떤 gate와 산출물로 weaponization-ready 상태를 판정해야 하는지 정의한다.

## Operating assumption

SCOUT의 exploit/AEG lane은 다음 상황을 기본 가정한다.

- 분석 대상 펌웨어, 랩 장비, 고객 장비, 또는 hardware-in-loop target에 대해 명시적 권한이 있다.
- 실행 범위는 engagement, lab subnet, registered device, firmware hash, run directory로 제한된다.
- exploit proof는 `exploit_gate.scope=lab-only` 또는 동등한 승인 scope와 `exploit_gate.attestation=authorized`가 있어야 신뢰된다.
- 공개 저장소에는 working weaponized payload를 두지 않는다. 실제 exploit logic은 private package/plugin/vault에서 관리한다.
- 공개 문서와 산출물은 hash-anchored evidence, primitive proof, reproducibility, cleanup, fail-closed control 결과를 남긴다.

이 전제는 안전장치를 제거한다는 뜻이 아니다. 오히려 weaponization 단계에서는 scope guard와 promotion gate를 더 강하게 적용한다.

## Current SCOUT position

SCOUT v3.0.0-rc1의 AEG 강점은 다음에 있다.

1. 펌웨어 추출, inventory, SBOM, script/binary surface 수집.
2. Web/API, CGI, shell script, IPC, config, daemon, binary sink를 chain 후보로 재구성.
3. Exploit Pattern RAG를 raw public PoC 복사가 아니라 curated pattern card로 사용.
4. `exploit_autopoc`, `poc_validation`, `verified_chain`, FP/FPR evidence를 통해 lab PoV를 gate.
5. real known-vulnerable/patched firmware pair로 fail-closed 증거를 남김.

현재 한계는 exploit synthesis와 operational weaponization의 마지막 구간이다.

- target-specific adaptation은 아직 private plugin/analyst 역량에 많이 의존한다.
- reliability engineering, cold-boot 재현, cleanup, operator workflow는 별도 layer가 필요하다.
- memory-corruption 계열의 crash-to-control, heap shaping, ROP/JOP 자동화는 SCOUT core의 1차 강점이 아니다.

따라서 SCOUT core는 **exploitability + lab PoV evidence engine**으로 유지하고, weaponization은 별도 gated layer로 추가한다.

## Proposed extension: SCOUT-W

SCOUT-W는 SCOUT 위에 올라가는 **Controlled Weaponization Extension**이다.

```text
SCOUT Core
  firmware analysis
  evidence graph
  exploitability dossier
  exploit chain ranking
  Exploit Pattern RAG
  AutoPoC / PoV
        ↓
Exploit Plan IR Builder
        ↓
SCOUT-W Controlled Weaponization Layer
  scope guard
  target profiler
  precondition solver
  primitive adapter
  delivery orchestrator
  reliability harness
  cleanup manager
  evidence recorder
        ↓
Private Exploit Package Vault
        ↓
Execution Backend
  synthetic service
  user-mode harness
  service/container harness
  full-system emulation
  hardware-in-loop lab
  authorized customer target
        ↓
Promotion Gate
        ↓
Report / Operator Console
```

## Exploit Plan IR

Weaponization은 raw request/payload 문자열을 먼저 생성하는 문제가 아니다. SCOUT은 먼저 evidence-backed Plan IR을 만들어야 한다.

```yaml
schema: scout-exploit-plan-ir-v1
plan_id: scout-chain-001
scope:
  allowed_targets:
    - registered_lab_device
    - engagement_allowlist
  forbidden:
    - unknown_firmware
    - unscoped_internet_target

target_profile:
  firmware_sha256: required
  vendor_family: observed
  architecture: observed
  service: observed
  auth_state: observed_or_required
  hardening: observed

primitive:
  type: auth_bypass | arbitrary_read | constrained_write | config_state_write | command_effect_marker | controlled_crash | state_transition
  destructive: false
  expected_effect: bounded_marker_or_state_change

preconditions:
  - firmware_hash_matches
  - service_or_ipc_present
  - relevant_handler_reachable
  - verifier_channel_available
  - control_pair_available_or_exception_approved

execution:
  mode: lab_or_authorized_scope_only
  timeout_seconds: bounded
  retry_policy: conservative
  state_reset: required

verification:
  repro_required: 3
  evidence_types:
    - response_marker
    - state_diff
    - process_trace
    - pcap_hash
    - log_marker

cleanup:
  restore_config: true
  remove_marker: true
  reboot_policy: explicit_only

gate:
  require_isolation: true
  require_fail_closed_control: true
  require_cleanup_evidence: true
  require_redaction: true
```

LLM/AutoPoC는 이 IR의 빈칸을 firmware evidence로 채우는 보조자여야 한다. payload 상상이나 raw public PoC 복사는 금지한다.

## Core modules

### 1. Scope Guard

실행 전 범위를 검증한다.

- engagement ID 또는 run authorization metadata 확인
- target allowlist, lab subnet, registered device, firmware hash binding 확인
- public internet target 또는 unknown firmware 차단
- `profile=exploit`, authorized attestation, scope metadata 없으면 실행 중단

### 2. Target Profiler

weaponized package가 지원 가능한 대상인지 비파괴적으로 확인한다.

- firmware hash/version/build family
- architecture and service family
- reachable management surface
- authentication/session requirement
- required config/state preconditions
- patched/control relation when available

### 3. Precondition Solver

SCOUT finding을 실행 가능/불가 상태로 분류한다.

Allowed decisions:

- `RUN`
- `SKIP_UNSUPPORTED_VERSION`
- `NEEDS_AUTH`
- `NEEDS_STATE_SETUP`
- `NEEDS_CONTROL_PAIR`
- `BLOCKED_SCOPE`
- `BLOCKED_UNSAFE_EFFECT`

### 4. Primitive Adapter

SCOUT-W의 기본 proof 단위는 shell 획득이 아니라 bounded primitive다.

| Primitive | Preferred proof style |
| --- | --- |
| `auth_bypass` | bounded access to an authorized lab marker resource |
| `arbitrary_read` | read a lab marker/synthetic secret only |
| `constrained_write` | write temporary marker then clean up |
| `config_state_write` | temporary config key/state diff then restore |
| `command_effect_marker` | non-destructive marker effect |
| `controlled_crash` | lab process crash with restart/recovery evidence |
| `state_transition` | before/after state transition evidence |

Shell-level proof is high-risk and should be a separate, explicit promotion class, not the default proof type.

### 5. Delivery Orchestrator

Many firmware exploit chains are multi-step. The orchestrator coordinates authorized setup, trigger, verification, cleanup, and control comparison from Plan IR without exposing raw exploit recipes in public docs.

Required outputs:

- stage order actually executed
- precondition decision trace
- verifier observations
- retry/failure classification
- cleanup result
- control/patched result

### 6. Reliability Harness

Weaponization-ready means repeated, recoverable, and explainable.

Minimum promotion evidence:

- same target repro: at least 3/3
- cold/reinitialized target repro: at least 2/2 when backend supports reset
- patched/control: fail-closed
- cleanup: verified or manual recovery documented
- evidence: redacted and hash-anchored
- FP status: no high/critical FP verdict for the promoted claim

### 7. Evidence Recorder

Every run records a ledger.

Required ledger fields:

- firmware SHA-256
- run id and run directory
- chain id and pattern id
- Plan IR hash
- private package/plugin hash
- target profile hash
- execution backend
- verifier artifact hashes
- pcap/log hashes when present
- cleanup result
- vulnerable/control result
- promotion level

## Implemented gate: `weaponization-readiness`

SCOUT now includes **metadata/evidence-only** Plan IR, preflight, and readiness
commands for this layer:

```bash
./scout weaponization-plan aiedge-runs/<run_id> \
  --package-manifest /secure/private/package.manifest.json \
  --out aiedge-runs/<run_id>/weaponization_plan.json

./scout weaponization-preflight aiedge-runs/<run_id> \
  --plan aiedge-runs/<run_id>/weaponization_plan.json \
  --package-manifest /secure/private/package.manifest.json \
  --out aiedge-runs/<run_id>/weaponization_preflight.json
```

`weaponization-plan` lowers SCOUT evidence and optional private package metadata
into `scout-weaponization-plan-ir-v1`. `weaponization-preflight` then blocks the
private execution lane unless scope, authorization, exact firmware binding,
chain/pattern binding, safe primitive type, declared preconditions,
unknown-target denial, and cleanup requirements are satisfied.

The final readiness gate is:

```bash
./scout weaponization-readiness aiedge-runs/<run_id> \
  --package-manifest /secure/private/package.manifest.json \
  --out aiedge-runs/<run_id>/controlled_weaponization_readiness.json
```

The command does not import, load, or execute private exploit source. It fails
closed unless all of the following are true:

- the completed run passes `aeg-e2e-gate`;
- the run manifest is `profile=exploit` with authorized attestation and bounded scope;
- the package is pinned by SHA-256 and bound to the exact firmware SHA-256;
- the package binds to a SCOUT `chain_id` and curated `pattern_id`;
- the declared primitive is a controlled verifier primitive;
- destructive, persistent, and lateral-movement capabilities are explicitly false;
- scope-token, authorization, target-profile-match, and unknown-target denial policies are enabled;
- preconditions, target profile, cleanup strategy, cleanup verification, and evidence ledger entries are present;
- vulnerable/control fail-closed proof is present unless the operator explicitly uses `--allow-missing-control-pair`.

Passing this gate promotes the package to `L6_CONTROLLED_WEAPONIZATION_PACKAGE`.
Failing gates remain below L6 and explain the missing evidence in JSON.

SCOUT also provides a gated execution wrapper for the private step:

```bash
./scout weaponization-execute aiedge-runs/<run_id> \
  --exploit-dir /secure/private/exploits \
  --plan aiedge-runs/<run_id>/weaponization_plan.json \
  --preflight aiedge-runs/<run_id>/weaponization_preflight.json \
  --readiness aiedge-runs/<run_id>/controlled_weaponization_readiness.json \
  --cleanup-log /secure/private/cleanup.log \
  --approval /secure/private/engagement_approval.json \
  --out-ledger aiedge-runs/<run_id>/weaponization_ledger.json
```

`weaponization-execute` refuses to invoke the private runner unless the Plan IR
schema is valid, preflight passed, readiness promoted to L6, and the requested
chain matches the Plan IR binding. It delegates to the existing private
`exploit_runner.py` contract and then writes the same ledger described below;
it does not contain or generate exploit payload logic.

If a private package has already run inside the authorized scope, SCOUT can
record a separate execution ledger:

```bash
./scout weaponization-ledger aiedge-runs/<run_id> \
  --plan aiedge-runs/<run_id>/weaponization_plan.json \
  --preflight aiedge-runs/<run_id>/weaponization_preflight.json \
  --readiness aiedge-runs/<run_id>/controlled_weaponization_readiness.json \
  --execution-evidence aiedge-runs/<run_id>/exploits/chain_<id>/evidence_bundle.json \
  --cleanup-log /secure/private/cleanup.log \
  --approval /secure/private/engagement_approval.json \
  --out aiedge-runs/<run_id>/weaponization_ledger.json
```

`weaponization-ledger` is also metadata/evidence-only. It hashes the Plan IR,
preflight decision, readiness report, `exploit-evidence-v1` bundle(s), cleanup
proof, and optional `scout-engagement-approval-v1` manifest. A passing ledger
without approval is `L6_EXECUTION_LEDGER_READY`; with valid engagement approval
it becomes `L7_ENGAGEMENT_APPROVED_PACKAGE`. Exit `38` blocks promotion when
reproducibility, cleanup, scope/preflight, readiness, or approval evidence is
missing or contradictory.

## Private Exploit Package format

SCOUT-W packages live outside the public repository. Public SCOUT may define the manifest contract, not the payload.

Before a private package can be used by SCOUT-W, its manifest should pass the
standalone package lint and be registered in a metadata-only vault:

```bash
./scout weaponization-package lint \
  --package-manifest /secure/private/package.manifest.json \
  --out /secure/private/package.lint.json

./scout weaponization-package register \
  --registry /secure/private/package_vault.json \
  --package-manifest /secure/private/package.manifest.json

./scout weaponization-package verify \
  --registry /secure/private/package_vault.json \
  --package-hash <package_sha256> \
  --firmware-sha256 <firmware_sha256> \
  --pattern-id <pattern_id> \
  --chain-id <chain_id>
```

The vault is an allowlist of reviewed package hashes and scope metadata. It does
not store exploit source. `weaponization-execute --vault-registry ...` blocks
private runner invocation unless the package hash is registered for the Plan IR
firmware, pattern, and chain binding.

```json
{
  "schema_version": "scout-private-exploit-package-v1",
  "package": {
    "id": "vendor-family-or-chain-id",
    "version": "1.0.0",
    "classification": "controlled-authorized-exploit",
    "hash_sha256": "<private-package-or-plugin-sha256>"
  },
  "binding": {
    "scout_chain_id": "required",
    "pattern_id": "required",
    "supported_firmware_sha256": ["<firmware-sha256>"],
    "supported_arch": ["arm", "mips"]
  },
  "target_profile": {
    "firmware_sha256": "<firmware-sha256>",
    "architecture": "mips",
    "service": "http"
  },
  "preconditions": ["service reachable", "lab marker provisioned"],
  "capability": {
    "primitive": "arbitrary_read",
    "destructive": false,
    "persistence": false,
    "lateral_movement": false,
    "cleanup_required": true
  },
  "execution_policy": {
    "require_scope_token": true,
    "require_authorized_attestation": true,
    "require_target_profile_match": true,
    "require_control_pair_for_promotion": true,
    "deny_unknown_targets": true
  },
  "cleanup": {
    "required": true,
    "strategy": "restore transient config and remove lab marker",
    "verification": "cleanup_log"
  },
  "promotion": {
    "control_pair_validated": true
  },
  "evidence": {
    "required": ["target_profile", "verifier_log", "cleanup_log", "plan_ir_hash", "package_hash"],
    "artifacts": {
      "target_profile": "sha256:<target-profile-hash>",
      "verifier_log": "sha256:<verifier-log-hash>",
      "cleanup_log": "sha256:<cleanup-log-hash>",
      "plan_ir_hash": "sha256:<plan-ir-hash>",
      "package_hash": "sha256:<private-package-or-plugin-sha256>"
    }
  }
}
```

## Promotion levels

SCOUT should never collapse all evidence into a single “exploitable” label.

| Level | Meaning |
| --- | --- |
| `L0_FINDING_ONLY` | Static finding or heuristic signal only |
| `L1_STATIC_REACHABLE` | Static source-to-sink or graph reachability evidence |
| `L2_DYNAMIC_REACHABLE` | Runtime/harness reachability observed |
| `L3_PRIMITIVE_OBSERVED` | Bounded exploit primitive observed once |
| `L4_REPRODUCIBLE_POV` | Primitive proof is reproducible |
| `L5_CONTROL_PAIR_VALIDATED` | Vulnerable passes and patched/control fails closed |
| `L6_CONTROLLED_WEAPONIZATION_PACKAGE` | Private package is scoped, repeatable, cleanup-aware, and ledgered |
| `L7_ENGAGEMENT_APPROVED_PACKAGE` | Package is approved for a specific authorized engagement scope |

Current SCOUT core primarily targets L0-L5. SCOUT-W owns L6-L7.

## Design priorities

1. **Pair-first AEG**: real known-vulnerable/patched pair evidence is the strongest promotion path.
2. **Graph-native Plan IR**: exploit generation should be state-transition planning over evidence, not blind payload generation.
3. **Primitive-centered proof**: prove bounded primitives before considering stronger effects.
4. **Private package vault**: keep exploit logic private, signed, hash-bound, and test-gated.
5. **Multi-backend execution**: do not depend on one emulation stack. Support user-mode harness, service harness, full-system emulation, and hardware-in-loop.
6. **Reliability before reach**: repeated authorized lab success beats broad but unverified exploit claims.
7. **Operator-visible gates**: every blocked condition should explain what evidence is missing.

## Non-goals

- No public weaponized payload corpus.
- No automatic cloning/execution of public PoC repositories.
- No persistence, stealth, lateral movement, or post-exploitation framework.
- No unknown-target or internet-scale execution mode.
- No promotion from static confidence alone.

## Product interpretation

SCOUT should be described as:

> Firmware exploit discovery → evidence-backed PoV → controlled weaponization package → authorized red-team/product-security execution ledger.

This keeps the AEG-first identity honest: exploit remains the end goal in authorized work, but every step is scoped, reproducible, fail-closed, and audit-ready.
