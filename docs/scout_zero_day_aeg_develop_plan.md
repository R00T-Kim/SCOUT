# SCOUT Zero-day Research / AEG Develop Plan

작성일: 2026-06-07 KST
대상 repo: SCOUT (`pyproject.toml` 기준 `scout-firmware 3.0.0rc1` / README 표기 `v3.0.0-rc1`, 현재 `stage_registry` 기준 50 stages)
작성 목적: 현재 SCOUT repo와 실제 E2E 분석 데이터를 근거로, **Zero-day Research** 관점과 **Automated Exploit Generation(AEG)** 관점의 장점/단점 각 5개를 도출하고, 장점 극대화·단점 보완을 위한 통합 개발 계획을 제시한다.

## 분석 기준 버전 / 일자

| 항목 | 값 |
| --- | --- |
| 분석 작성일 | 2026-06-07 KST |
| 현재 repo commit | `a7891f0` (`2026-06-01T11:43:22+09:00`, `Merge PR #14: Harden exploit intel contracts`) |
| 제품/패키지 버전 | `scout-firmware 3.0.0rc1` (`v3.0.0-rc1`) |
| 현재 stage registry | 50 stages (`2026-06-07` 현재 코드로 확인) |
| 최신 방향 결정 기준 | gc-tree docs: `domain/scout-firmware-to-exploit-deterministic-engine`, `repos/scout-repo-firmware-to-exploit`, `domain/aeg-automated-exploit-generation` |
| 최신 방향 결정 일자 | 2026-05-20 이후 기준: AEG 1순위, Compliance/Audit/CRA 보조 |
| repo status 기준 문서 | `docs/status.md`의 `v3.0.0-rc1 현재 기준 (2026-05-27, AEG + controlled weaponization 방향)` |
| 현재 코드 재검증일 | 2026-06-07 KST |
| Fresh synthetic E2E 실행일 | 2026-06-07, run artifact `created_at=2026-06-07T14:14:58~59Z` |
| R7000 real pair 원본 run 일자 | 2026-05-20 (`2026-05-20_2222`, `2026-05-20_2150`) |
| R7000 real pair 현재 코드 재검증일 | 2026-06-07 KST |

## 0. 해석 기준과 안전 경계

SCOUT의 최신 방향은 gc-tree 기준 문서와 현재 repo 상태를 우선한다.

- SCOUT은 **AEG-first deterministic firmware-to-exploit evidence engine**이다.
- Compliance/Audit/CRA 산출물은 1차 제품이 아니라 AEG evidence를 신뢰·납품·감사 가능하게 만드는 보조 레이어다.
- PoC-in-GitHub 등 공개 PoC 원천은 raw exploit code 복사/실행이 아니라 **metadata-only seed → curated exploit pattern card** 경로로만 사용한다.
- 본 계획의 AEG/weaponization 표현은 허가된 랩·제품보안·내부 레드팀 범위의 PoV/controlled package를 의미한다. 공개 repo에 working weaponized payload, persistence, stealth, lateral movement, live internet target execution을 두지 않는다.

사용자가 지적한 “예전 버전 산출물일 수 있음”을 반영해 evidence 등급을 다음처럼 나눈다.

| 등급 | 의미 | 이번 분석에서의 사용 방식 |
| --- | --- | --- |
| S0 | 현재 코드로 이번 세션에서 새로 실행한 fresh evidence | synthetic AEG pair 3종 결과를 1차 회귀 근거로 사용 |
| S1 | 과거 run artifact이지만 현재 코드의 gate로 재검증됨 | R7000 real known-vulnerable/patched pair를 핵심 real-firmware 근거로 사용 |
| S2 | checked-in 문서/JSON이 현재 코드 재검증 없이 존재 | 방향성/설계/보조 근거로만 사용 |
| S3 | 문서가 참조하지만 현재 워크트리에 없거나 stale 가능성이 높은 결과 | 결론의 핵심 수치로 사용하지 않음 |

모든 핵심 evidence는 아래 표에서 **버전 / 원본 일자 / 재검증 일자**를 함께 기록한다. 이 세 값이 없으면 release-facing 주장에는 사용하지 않는다.

## 1. Repo 분석 요약

### 1.1 현재 구현 축

현재 SCOUT는 단일 스캐너가 아니라 firmware-to-exploit evidence pipeline이다. 현재 코드 기준 stage registry는 50개 stage를 포함한다.

핵심 구현 축:

1. **Firmware ingestion / extraction / inventory**
   - carving, extraction, inventory, firmware_profile, firmware_lineage, structure, sbom, cve_scan.
2. **Attack-surface and source-to-sink evidence**
   - endpoints, attack_surface, surfaces, enhanced_source, taint_propagation, graph, reachability, script_analysis, web_ui.
3. **Exploitability reconstruction**
   - findings, chain_construction, exploitability_dossier, exploit_state_machine, exploit_chain, primitive_verifier.
4. **AEG / PoV validation**
   - exploit_intel, exploit_rag, exploit_autopoc, poc_validation, verified_chain, aeg_e2e_gate, aeg_readiness, real_firmware_pair_gate.
5. **Quality / governance**
   - fp_verification, adversarial_triage, quality_metrics, evidence tiers, confidence caps, report export, SLSA/SARIF/SBOM, controlled weaponization docs.

### 1.2 현재 방향과 stale 문서 구분

- 최신 gc-tree 문서와 `docs/status.md`는 SCOUT의 1순위를 AEG로 둔다.
- `docs/strategic_roadmap_2026.md` 초반에는 과거 pivot으로 “Compliance/Audit 1순위”가 남아 있다. 이는 최신 gc-tree 기준과 충돌하므로 현재 제품 우선순위 근거로 쓰지 않는다.
- 일부 문서가 참조하는 `benchmark-results/2c6-fresh-full-final/aggregate.json`, `benchmark-results/pair-eval-12pair-mixed/*`는 현재 워크트리에 없었다. 따라서 이 문서의 최종 수치 근거에서는 제외하고, “과거 benchmark context”로만 취급한다.

## 2. 실제 E2E 분석 데이터와 신뢰도

### 2.1 S0: 이번 세션 fresh synthetic AEG E2E

현재 코드(`scout-firmware 3.0.0rc1`, commit `a7891f0`)로 `scripts/run_aeg_synthetic_pair.py`를 세 패턴에 대해 2026-06-07에 새로 실행했다.

| Pattern | 실행 버전/일자 | Fresh evidence path | Vulnerable side | Patched/control side | 판정 |
| --- | --- | --- | --- | --- | --- |
| `memory_stateful_probe` | `3.0.0rc1` / 2026-06-07 / artifact `created_at=2026-06-07T14:14:58~59Z` | `/tmp/scout-aeg-current-memory/synthetic_aeg_pair_summary.json` | gate pass, `verified_chain.state=pass`, `isolation_verified`, `repro_3_of_3` | gate fail-closed, `poc_repro_failed` | pass |
| `cgi_param_cmd_injection` | `3.0.0rc1` / 2026-06-07 / artifact `created_at=2026-06-07T14:14:58~59Z` | `/tmp/scout-aeg-current-cgi/synthetic_aeg_pair_summary.json` | gate pass, `verified_chain.state=pass`, `isolation_verified`, `repro_3_of_3` | gate fail-closed, `poc_repro_failed` | pass |
| `config_derived_cmd_injection` | `3.0.0rc1` / 2026-06-07 / artifact `created_at=2026-06-07T14:14:58~59Z` | `/tmp/scout-aeg-current-config/synthetic_aeg_pair_summary.json` | gate pass, `verified_chain.state=pass`, `isolation_verified`, `repro_3_of_3` | gate fail-closed, `poc_repro_failed` | pass |

해석:

- 현재 코드의 AEG gate는 lab vulnerable/control separation을 재현한다.
- 세 결과 모두 loopback-only synthetic lab service를 사용하고 raw public PoC execution을 하지 않는다.
- 단, synthetic pair는 real firmware complexity를 대체하지 않는다. real firmware release claim에는 S1/S0 수준의 real pair evidence가 추가로 필요하다.

### 2.2 S1: 현재 코드로 재검증한 R7000 real firmware pair

기존 checked-in run artifact를 현재 코드(`scout-firmware 3.0.0rc1`, commit `a7891f0`)의 gate로 2026-06-07에 재검증했다. 원본 run 일자는 2026-05-20이다.

| 항목 | Vulnerable | Patched/control |
| --- | --- | --- |
| Pair | Netgear R7000 / CVE-2017-5521 | Netgear R7000 / patched version |
| 원본 run 일자 | 2026-05-20T22:22:27Z | 2026-05-20T21:50:19Z |
| 현재 코드 재검증 일자/버전 | 2026-06-07 / `scout-firmware 3.0.0rc1` / commit `a7891f0` | 2026-06-07 / `scout-firmware 3.0.0rc1` / commit `a7891f0` |
| Run dir | `aiedge-runs/2026-05-20_2222_sha256-c025ce21eabc` | `aiedge-runs/2026-05-20_2150_sha256-6309264efce0` |
| Firmware SHA-256 | `c025ce21eabc4908caa9a4932f373174450df99662c66f388790e316b326cbc0` | `6309264efce04ae651adb34bf7697089b273ebc6100ba2e78b0c1bf10e89281e` |
| `./scout aeg-e2e-gate` | pass | fail |
| AutoPoC runner | `runner_pass=1` | `runner_pass=0` |
| PoC validation | `status=ok`, `repro_3_of_3` | `status=ok`, no reproducibility reason code |
| Verified chain | `state=pass`, `isolation_verified`, `repro_3_of_3` | `state=fail`, `poc_repro_failed` |
| FPR evidence | `fpr=0.0 <= 0.1` | `fpr=0.0 <= 0.1` |
| High/critical FP evidence | `high_or_critical_fp_count=0` | `high_or_critical_fp_count=0` |
| Pair gate | `promotable_real_firmware_pair=true` | control fails dynamic proof checks as expected |

현재 코드로 2026-06-07에 재실행한 integrated readiness도 통과했다.

| Check | 결과 |
| --- | --- |
| 실행 버전/일자 | `scout-firmware 3.0.0rc1`, commit `a7891f0`, 2026-06-07 |
| `./scout aeg-readiness --out /tmp/scout_aeg_platform_readiness_current.json` | `verdict=platform-ready`, `ready=true` |
| Curated pattern cards | 4 |
| Pattern cards with pair evidence | 4/4 |
| Synthetic pair validated | 3 |
| Real firmware pair validated | 1 |
| Stable artifact binding | `docs/pov/netgear-r7000-cve-2017-5521_real_pair.json` promotable |
| SHA binding | pass |
| Vulnerable/pass vs patched/dynamic-fail-closed separation | pass |

### 2.3 S1/S2: Real run artifact detail

R7000 vulnerable run의 현재 산출물은 다음과 같다. 원본 run 일자는 2026-05-20이고, 아래 요약은 2026-06-07 현재 코드로 artifact를 재검토한 값이다.

| 지표 | 값 |
| --- | --- |
| 원본 run 일자 | 2026-05-20T22:22:27Z |
| 요약 검토 버전/일자 | `scout-firmware 3.0.0rc1`, commit `a7891f0`, 2026-06-07 |
| Profile | `exploit` |
| Stage files | 49 stage artifacts present |
| Stage status | ok 30 / partial 12 / failed 0 / skipped 7 |
| Findings | 4 |
| Exploit candidates | 3 (`medium=1`, `low=2`) |
| Chain construction | 10,337 total chains (`same_binary=10084`, `cross_binary_ipc=253`) |
| Exploitability dossier | 25 candidates, 20 chain hypotheses, top score 82.0 |
| AutoPoC | status partial, attempted 3, runner_pass 1, runner_nonpass 2 |
| FP verification | eligible_checked 541, false_positives 0 |
| Attack surface | endpoints 626, attack_surface_items 80 |

R7000 patched/control run. 원본 run 일자는 2026-05-20이고, 아래 요약은 2026-06-07 현재 코드로 artifact를 재검토한 값이다.

| 지표 | 값 |
| --- | --- |
| 원본 run 일자 | 2026-05-20T21:50:19Z |
| 요약 검토 버전/일자 | `scout-firmware 3.0.0rc1`, commit `a7891f0`, 2026-06-07 |
| Stage status | ok 31 / partial 11 / failed 0 / skipped 7 |
| Findings | 4 |
| Exploit candidates | 3 |
| Chain construction | 4,201 total chains |
| AutoPoC | status partial, attempted 3, runner_pass 0 |
| FP verification | eligible_checked 236, false_positives 0 |
| Attack surface | endpoints 734, attack_surface_items 80 |

ER605-style manual/analysis run (`aiedge-runs/2026-05-19_1409_sha256-225e1d209771`)은 많은 수동 분석 artifact와 E2E stage output을 포함하지만, 현재 목적에서는 S2 보조 근거로만 둔다. 원본 run 일자는 2026-05-19이고, 현재 코드로 AEG 성공 gate를 재통과한 증거는 없다.

| 지표 | 값 |
| --- | --- |
| 원본 run 일자 | 2026-05-19T14:09:48Z |
| 요약 검토 버전/일자 | `scout-firmware 3.0.0rc1`, commit `a7891f0`, 2026-06-07 |
| Stage status | ok 34 / partial 11 / failed 0 / skipped 4 |
| Findings | 3 |
| Chain construction | 50 chains, `llm_generated=2` |
| Exploitability dossier | 133 candidates, 20 chain hypotheses, top score 73.0 |
| AutoPoC | status partial, attempted 3, runner_pass 0 |
| FP verification | eligible_checked 51, false_positives 6 |
| Attack surface | endpoints 2009 |

해석:

- R7000 pair는 현재 코드로 재검증된 real firmware AEG floor다.
- ER605 run은 분석 폭과 수동 chain evidence의 가치를 보여주지만, 현재 AEG 성공 증거로 쓰기에는 runner pass가 없다.
- real run의 `dynamic_validation`이 여전히 partial인 점, AutoPoC가 partial/template fallback에 의존하는 점은 핵심 개선 대상이다.

## 3. Zero-day Research 관점

여기서 Zero-day Research는 “이미 CVE로 알려진 취약점의 단순 재현”이 아니라, 펌웨어 증거에서 아직 명명·분류되지 않은 취약 가능성을 발견·검증·축소하는 연구 과정을 뜻한다.

### 3.1 장점 5개

1. **결정론적 evidence pipeline이 zero-day 후보의 재현성과 감사성을 높인다.**
   - 현재 50-stage pipeline은 firmware hash, stage artifact, finding, chain, report를 run directory에 고정한다.
   - Zero-day 후보가 “LLM이 그럴듯하게 말한 것”으로 끝나지 않고 extraction/inventory/source/sink/chain/evidence refs로 추적된다.

2. **Binary + shell/script + endpoint + graph + taint의 hybrid coverage가 firmware 특화 attack surface를 넓게 잡는다.**
   - R7000 vulnerable run에서 endpoints 626, attack_surface_items 80, chain 10,337개가 생성됐다.
   - ER605 보조 run은 endpoints 2009, dossier candidates 133개를 보여준다.
   - 이는 웹 CGI, config, IPC, daemon, script-driven surface가 섞인 firmware zero-day 탐색에 유리하다.

3. **Pair/differential evidence 모델이 zero-day 연구의 false lead를 줄이는 구조를 이미 갖고 있다.**
   - R7000 pair는 vulnerable pass / patched dynamic fail-closed를 현재 코드로 재검증했다.
   - 같은 구조를 unknown issue에 적용하면 “취약 후보가 버전 차이와 연결되는지”를 검증하는 연구 프로토콜로 확장할 수 있다.

4. **Exploit Pattern RAG가 raw PoC 복사가 아니라 exploit family/channel/precondition 추상화로 작동한다.**
   - Pattern cards는 `family`, `entry_channel`, `bridge_channel`, `trigger_model`, `sink`, `forbidden_reuse`, `validation_evidence`를 가진다.
   - Zero-day 연구에서는 공개 PoC를 복사하지 않고, 알려진 exploit shape를 firmware-local evidence에 맞춰 hypothesis로 변환할 수 있다.

5. **LLM/analyst explainability surface가 human-in-the-loop zero-day triage에 적합하다.**
   - reasoning trail, adversarial triage, FP verification, confidence cap, priority score 분리가 있다.
   - 이는 zero-day 후보를 “탐지 수량”이 아니라 evidence quality와 analyst 검토 가능성 기준으로 다룰 수 있게 한다.

### 3.2 단점 5개

1. **현재 real firmware 검증 floor는 known CVE pair 1개에 집중되어 있어 zero-day claim에는 부족하다.**
   - 실재 firmware에서 현재 코드로 재검증된 promotable pair는 R7000 CVE-2017-5521 1개다.
   - 이는 AEG gate의 건전성을 보이지만, unknown zero-day 발견 능력 자체를 입증하지는 않는다.

2. **동적 검증과 emulation 계층이 아직 partial인 run이 많다.**
   - R7000 vulnerable run은 stage failed는 없지만 partial 12 / skipped 7이고 `dynamic_validation`도 partial이다.
   - Zero-day 연구에서는 static hypothesis만으로는 오탐/미검증 후보가 누적되므로 dynamic reachability 강화가 필요하다.

3. **Finding diversity와 candidate collapse 문제가 연구 생산성을 제한할 수 있다.**
   - 과거 문서는 pair-eval에서 single synthesis finding으로 diversity gate가 실패했다고 기록한다.
   - 현재 R7000도 chain은 10,337개지만 exploit candidates는 3개로 압축된다. 압축 자체는 필요하지만, 다양한 root cause/family를 잃을 위험이 있다.

4. **Benchmark freshness와 result registry가 불완전하다.**
   - 문서가 참조하는 일부 aggregate/pair-eval 결과 파일이 현재 워크트리에 없다.
   - Zero-day 연구는 최신 코드·최신 corpus·동일 조건 재현성이 핵심이므로, stale artifact가 섞이면 판단을 흐린다.

5. **현재 RAG/pattern corpus가 작아 zero-day hypothesis diversity가 제한된다.**
   - Curated pattern cards는 4개이며, real firmware pair evidence가 있는 card는 1개다.
   - memory corruption, parser state machine, auth/session logic, update/OTA path, IPC boundary 등 다양한 zero-day family를 커버하려면 corpus 확대가 필요하다.

## 4. Automated Exploit Generation 관점

여기서 AEG는 허가된 랩 범위에서 firmware evidence를 바탕으로 lab-bounded PoV/PoC를 생성·검증하고, false-positive와 control-pair를 통과한 산출물만 controlled promotion으로 연결하는 흐름을 뜻한다.

### 4.1 장점 5개

1. **현재 AEG gate가 vulnerable/pass와 patched/control fail-closed를 실제로 분리한다.**
   - R7000 vulnerable run은 AutoPoC runner pass, `repro_3_of_3`, `verified_chain pass`, FPR 0.0을 통과했다.
   - patched/control은 runner, reproducibility, verified-chain 동적 proof 3개에서 fail-closed했다.

2. **현재 코드의 fresh synthetic pair 3종이 AEG regression floor를 제공한다.**
   - `memory_stateful_probe`, `cgi_param_cmd_injection`, `config_derived_cmd_injection` 모두 현재 세션에서 vulnerable pass / control fail-closed를 재현했다.
   - CI-safe loopback lab service라서 빠른 회귀 테스트에 적합하다.

3. **Exploit Pattern RAG와 exploit_intel이 AEG seed를 안전하게 확장한다.**
   - PoC-in-GitHub/NVD/vuln-list-update는 metadata-only seed로만 쓰고 raw public PoC clone/execute/prompt injection을 금지한다.
   - 이는 AEG 품질과 안전 경계를 동시에 지키는 핵심 구조다.

4. **AutoPoC가 chain/dossier 기반 후보를 실제 runner와 PoC validation으로 낮추는 제품 경로를 이미 갖고 있다.**
   - R7000 vulnerable run은 dossier candidates 25개, chain-backed AutoPoC candidates 22개, selected 3개, runner_pass 1개를 만들었다.
   - 단순 report가 아니라 “후보 → bundle → runner → reproducibility → verified_chain” 경로가 존재한다.

5. **Controlled weaponization 설계가 AEG 이후 단계를 제품화 가능한 promotion level로 정의한다.**
   - `L0_FINDING_ONLY`부터 `L7_ENGAGEMENT_APPROVED_PACKAGE`까지 단계가 있고, SCOUT core는 L0-L5, SCOUT-W는 L6-L7을 담당한다.
   - private package vault, scope guard, target profile binding, cleanup, approval ledger가 명확한 비공개/허가형 제품 경계다.

### 4.2 단점 5개

1. **AutoPoC는 현재 real firmware에서 partial이고 성공률이 낮다.**
   - R7000 vulnerable run도 attempted 3 중 runner_pass 1, runner_nonpass 2이며 stage status는 partial이다.
   - patched/control의 fail-closed는 좋지만, vulnerable side의 pass rate와 candidate selection reliability를 높여야 한다.

2. **Pattern corpus가 AEG 일반화에 충분히 크지 않다.**
   - 현재 curated cards는 4개, real firmware pair validated는 1개다.
   - broad AEG claim에는 최소 10~20개 firmware-relevant pattern family와 여러 real pair가 필요하다.

3. **현재 AEG는 lab PoV 중심이며 L6/L7 controlled package는 설계가 구현을 앞선다.**
   - README/docs에는 weaponization-plan/preflight/readiness/ledger 흐름이 있지만, 실제 private package reliability, cleanup, hardware-in-loop 운영 증거는 제한적이다.
   - 내부 레드팀 제품으로 쓰려면 operator workflow와 execution ledger가 더 강해야 한다.

4. **FPR 0.0은 필요조건이지 충분조건이 아니다.**
   - R7000 run의 FP verification은 false positive 0을 보이지만, 이것이 모든 후보의 true exploitability recall을 뜻하지는 않는다.
   - AEG 품질은 FPR뿐 아니라 vulnerable recall, primitive reproducibility, control-pair separation, diversity로 함께 봐야 한다.

5. **동적 backend 다양성과 deep exploit primitive coverage가 부족하다.**
   - 현재 synthetic 3종과 R7000 auth-bypass floor는 강하지만, memory corruption의 crash-to-control, parser state bugs, OTA/update path, multi-process IPC exploitability는 real pair evidence가 약하다.
   - emulation/fuzzing/Ghidra-dependent stages가 partial/skipped인 경우가 있어 backend redundancy가 필요하다.

## 5. 통합 Develop 계획

목표는 “Zero-day Research 후보 발굴력”과 “AEG lab proof 성공률”을 분리하지 않고 하나의 evidence-led 개발 루프로 통합하는 것이다.

```text
Firmware corpus / pair corpus
  -> deterministic extraction + inventory
  -> source/sink/graph/dossier evidence
  -> novelty-aware zero-day hypothesis queue
  -> pattern-card / plan-IR grounded AEG generation
  -> dynamic runner + reproducibility + verified_chain
  -> vulnerable/control pair gate
  -> evidence ledger + controlled promotion
```

### Phase 0 — Evidence freshness and provenance hardening (1주)

목표: stale artifact 문제를 제거하고, 모든 AEG/zero-day 결론이 현재 코드·현재 데이터에서 온 것임을 증명한다.

작업:

1. `docs/pov/current_e2e_evidence_ledger.json` 추가.
   - git commit, pyproject version, stage count, command, generated_at, run_dir, input SHA, output SHA, verdict를 기록.
2. `scripts/verify_current_e2e_ledger.py` 추가.
   - `aeg-readiness`, R7000 pair gate, synthetic pair 3종 summary를 검증.
3. stale references audit.
   - 현재 워크트리에 없는 `benchmark-results/*` 참조는 `historical` 또는 `missing`으로 표시.
4. Docs sync rule.
   - README/results/status가 같은 evidence ledger를 인용하도록 정렬.

Exit gate:

- `./scout aeg-readiness` 재실행 결과가 ledger와 일치.
- synthetic 3종 fresh run이 ledger에 기록.
- R7000 real pair gate가 현재 코드로 재검증됨.
- 문서가 없는 benchmark artifact를 최신 수치처럼 주장하지 않음.

### Phase 1 — Pair-first benchmark floor 재구축 (2~3주)

목표: Zero-day/AEG 양쪽의 품질을 평가할 최소 real firmware benchmark floor를 만든다.

작업:

1. `benchmarks/pair-eval/pairs.json`의 12개 pair를 현재 코드로 재실행하거나, 비용이 크면 우선 5개 representative pair를 freeze.
2. 각 pair에 대해 extraction status, inventory sufficiency, top finding family, evidence tier, AutoPoC status, gate result를 기록.
3. pair-eval summary를 현재 워크트리에 생성.
   - recall, FPR, finding diversity, evidence tier variation, dynamic proof success rate.
4. R7000 외 real firmware pair evidence를 최소 3개로 확대.
5. patched/control fail-closed가 FPR-only가 아니라 동적 proof failure인지 확인.

KPI:

| Metric | 현재 | Phase 1 목표 |
| --- | --- | --- |
| real firmware pair validated | 1 | >= 3 |
| curated cards with real pair evidence | 1/4 | >= 3/4 |
| pair-eval summary freshness | 일부 참조 missing | current-code generated |
| broad pair recall | 현재 워크트리에서 미검증 | baseline 재측정 |
| FPR ceiling | R7000 0.0 | <= 0.10 유지 |

### Phase 2 — Zero-day hypothesis engine 강화 (3~5주)

목표: 알려진 CVE 재현을 넘어서 unknown 후보를 체계적으로 찾고, stale/noisy 후보를 줄인다.

작업:

1. **Novelty scorer** 추가.
   - known CVE signature, exact version-pair evidence, NVD/CPE match와 별도로 “unmatched source→sink chain”, “new endpoint/config key”, “changed handler in vulnerable lineage”를 점수화.
2. **Differential firmware analysis lane** 강화.
   - vulnerable/patched 또는 adjacent-version pair에서 changed binary/config/script와 finding/chain의 교집합을 우선순위화.
3. **Finding diversity repair**.
   - single synthesis finding으로 collapse되는 후보를 root cause/family/channel/sink 단위로 분리.
4. **Dynamic reachability first**.
   - static chain 후보는 L1로 유지하고, service/user-mode/full-system/hardware-in-loop 중 하나에서 L2 이상으로 승격된 후보만 zero-day shortlist에 남긴다.
5. **Analyst queue**.
   - unknown 후보는 “evidence gap”, “required dynamic proof”, “control candidate”를 명시한 dossier로 export.

KPI:

- shortlist 후보의 evidence tier가 최소 2종 이상으로 분산.
- top-N zero-day 후보에서 duplicate/root-cause collapse 비율 감소.
- dynamic reachability 없는 high-priority claim 금지.
- analyst가 재현해야 할 다음 실험이 dossier에 자동 기록.

### Phase 3 — AEG robustness and Plan IR 중심화 (3~5주)

목표: AutoPoC를 “template fallback partial”에서 “Plan IR 기반 primitive proof generator”로 전환한다.

작업:

1. Exploit Plan IR를 AutoPoC의 중심 입력으로 승격.
   - target_profile, preconditions, primitive type, verifier channel, cleanup requirement를 필수화.
2. Candidate selection 개선.
   - chain count가 폭증해도 top 3 selection이 family diversity와 proof feasibility를 보장하도록 scoring 보정.
3. Multi-run reliability harness.
   - `repro_3_of_3`뿐 아니라 cold-start/reboot/service-restart 변형에서 bounded proof를 반복.
4. Backend redundancy.
   - qemu-user, service harness, full-system emulation, hardware-in-loop 중 가능한 backend를 Plan IR에 매핑.
5. Failure taxonomy.
   - runner_nonpass를 payload 문제, precondition 문제, harness 문제, false hypothesis, environment 문제로 분류.

KPI:

| Metric | 현재 관찰 | Phase 3 목표 |
| --- | --- | --- |
| R7000 vulnerable AutoPoC | attempted 3 / runner_pass 1 / partial | selected 후보 pass rate >= 50% |
| runner failure taxonomy | nonpass count 중심 | reason-code taxonomy 100% |
| Plan IR coverage | docs/weaponization 중심 | AutoPoC input contract로 적용 |
| reproducibility | `repro_3_of_3` | reboot/service restart variants 추가 |

### Phase 4 — Exploit Pattern RAG corpus expansion (지속, 4~8주)

목표: 작은 4-card corpus를 firmware-relevant, validation-backed corpus로 확대한다.

작업:

1. Curated card 4개 → 20개.
   - auth bypass, command injection, config-derived injection, path traversal, info disclosure, parser state bug, IPC boundary, OTA/update path, memory corruption candidate.
2. 모든 card에 synthetic vulnerable/control evidence를 요구.
3. 최소 5개 card에 real firmware known-vulnerable/patched evidence를 요구.
4. Candidate importer는 metadata-only 정책 유지.
5. Contamination regression test 확대.
   - endpoint, credential, payload literal, target host, vendor magic constant 누출 금지.

KPI:

- curated cards >= 20.
- synthetic pair evidence 100%.
- real firmware pair evidence >= 5 cards.
- raw PoC contamination test 0 fail.
- pattern-card retrieval이 unsupported family에 대해 abstain/fail-closed.

### Phase 5 — Controlled weaponization readiness (4주+)

목표: AEG proof를 내부 레드팀 제품의 L6/L7 package readiness로 안전하게 승격한다.

작업:

1. Private package manifest contract 강화.
   - package hash, supported firmware SHA, primitive type, cleanup method, verifier channel, operator warning.
2. Scope guard hard fail.
   - unknown firmware, unscoped internet target, missing engagement approval, missing cleanup plan이면 실행 불가.
3. Cleanup manager와 execution ledger 구현 강화.
   - marker/state cleanup, reboot policy, evidence bundle hash, approval ledger.
4. Operator console/report.
   - blocked reason, missing precondition, allowed scope, expected bounded effect를 명확히 표시.
5. Public repo boundary 유지.
   - exploit logic은 private vault/plugin에서 관리하고 public artifact는 hash/evidence/contract만 기록.

KPI:

- L6 package readiness gate가 public test fixture에서 pass/fail 양쪽을 검증.
- cleanup evidence 없는 package는 promotion 불가.
- private package source 없이 hash/manifest만으로 readiness 검증 가능.

### Phase 6 — Continuous QA gates

매 PR 또는 release 전 다음을 기본 gate로 둔다.

1. `python3 scripts/run_aeg_synthetic_pair.py` 3 patterns.
2. `./scout aeg-readiness --out <tmp>`.
3. 최소 1개 real pair gate smoke: R7000 CVE-2017-5521.
4. `scripts/check_exploit_pattern_evidence.py --require-real-firmware-pair`.
5. `git diff --check` and targeted unit tests for changed modules.
6. Docs evidence ledger consistency check.

## 6. 우선순위 로드맵

기준 시작일은 2026-06-07이며, 기준 제품 버전은 `scout-firmware 3.0.0rc1` / `v3.0.0-rc1`이다. 실제 일정은 firmware 확보·emulation 비용에 따라 조정하되, 각 phase 산출물에는 생성일, 기준 commit, 기준 SCOUT 버전을 반드시 기록한다.

| 우선순위 | 기준 기간/일자 | 기준 버전 | 작업 묶음 | 이유 |
| --- | --- | --- | --- | --- |
| P0 | 2026-06-07 ~ 2026-06-14 | `3.0.0rc1` | Evidence ledger + stale artifact audit | 현재 결론의 신뢰도를 먼저 고정해야 함 |
| P1 | 2026-06-15 ~ 2026-07-05 | 2026-06-07 baseline `3.0.0rc1`; phase-start version+commit 재기록 | Pair benchmark floor 재구축 | Zero-day/AEG 모두 real-control 평가가 필요 |
| P2 | 2026-07-06 ~ 2026-08-09 | 2026-06-07 baseline `3.0.0rc1`; phase-start version+commit 재기록 | AutoPoC Plan IR + failure taxonomy | 현재 partial/nonpass를 actionable하게 줄임 |
| P3 | 2026-07-06 ~ 2026-08-09 | 2026-06-07 baseline `3.0.0rc1`; phase-start version+commit 재기록 | Zero-day novelty + diversity repair | known-CVE 재현에서 unknown 후보 연구로 확장 |
| P4 | 2026-08-10 ~ 2026-10-04 | 2026-06-07 baseline `3.0.0rc1`; phase-start version+commit 재기록 | Pattern corpus 20개 + real pair 5개 | AEG 일반화와 RAG 품질 개선 |
| P5 | 2026-10-05 이후 | 2026-06-07 baseline `3.0.0rc1`; phase-start version+commit 재기록 | SCOUT-W L6/L7 readiness | 내부 레드팀 제품화, 단 public payload 경계 유지 |


## 7. Phase별 승격 게이트 / 놓칠 수 있는 것 / 엣지 케이스 / 성능 극대화 업데이트

작성/반영일: 2026-06-07 KST
기준 버전: `scout-firmware 3.0.0rc1` / `v3.0.0-rc1`
기준 commit: `a7891f0` (`2026-06-01T11:43:22+09:00`)
성격: 위 보고서의 S0/S1/S2 evidence 모델을 유지하면서, 2026-06-07 현재 repo-local gate와 외부 firmware/AEG 연구를 반영한 실행 플랜 업데이트.

### 7.1 리서치 근거 요약

| 근거 | 버전/일자 | 이번 플랜에 반영한 점 |
| --- | --- | --- |
| `docs/aeg_e2e_validation.md` | repo current / 2026-06-07 검토 | AEG promotion은 AutoPoC runner, PoC reproducibility, verified chain, FPR ceiling, high/critical FP 부재를 모두 요구한다. |
| `src/aiedge/aeg_e2e_gate.py` | `3.0.0rc1`, commit `a7891f0` / 2026-06-07 검토 | `runner_pass >= 1`, `repro_3_of_3`, `isolation_verified`, `fpr <= 0.10`을 fail-closed gate로 고정한다. |
| `src/aiedge/real_firmware_pair_gate.py` | `3.0.0rc1`, commit `a7891f0` / 2026-06-07 검토 | real pair 승격은 firmware SHA binding, vulnerable pass, patched/control dynamic fail-closed를 동시에 요구한다. |
| `src/aiedge/aeg_readiness.py` | `3.0.0rc1`, commit `a7891f0` / 2026-06-07 검토 | 플랫폼 readiness는 pattern card evidence, synthetic pair, real pair floor, stable artifact binding을 요구한다. |
| `docs/controlled_weaponization_layer.md` | repo current / 2026-06-07 검토 | SCOUT core는 L0-L5, SCOUT-W는 L6-L7로 분리하고, scope/cleanup/private vault/ledger 없이는 승격하지 않는다. |
| Firmadyne README | GitHub current / 2026-06-07 검색 | firmware emulation은 extraction, arch, NVRAM, network inference, QEMU state에 민감하므로 pair gate에서 환경 실패와 취약점 실패를 분리해야 한다. URL: https://github.com/firmadyne/firmadyne |
| Greenhouse, USENIX Security 2023 | 2023-08 / 2026-06-07 검색 | single-service rehosting과 coverage-guided fuzzing은 full-system emulation 실패를 우회하는 성능/coverage 전략이다. URL: https://www.usenix.org/conference/usenixsecurity23/presentation/tay |
| Pandawan, USENIX Security 2024 | 2024-08 / 2026-06-07 검색 | user/kernel holistic rehosting과 FICD류의 initialization-completion 측정은 dynamic gate의 “환경 준비됨” 판단에 필요하다. URL: https://www.usenix.org/conference/usenixsecurity24/presentation/angelakopoulos |
| Operation Mango, USENIX Security 2024 | 2024-08 / 2026-06-07 검색 | all-binary taint-style analysis와 빠른 DFA 최적화는 source/sink miss와 성능 병목을 동시에 줄이는 방향이다. URL: https://www.usenix.org/conference/usenixsecurity24/presentation/gibbs |
| ChatAFL, NDSS 2024 | 2024 / 2026-06-07 검색 | protocol grammar/state extraction은 stateful firmware service 테스트에서 valid input과 state coverage를 높이는 전략이다. URL: https://www.ndss-symposium.org/ndss-paper/large-language-model-guided-protocol-fuzzing/ |
| Google OSS-Fuzz-Gen | GitHub current / 2026-06-07 검색 | 생성 산출물은 “생성 성공”이 아니라 compilability, crash, runtime coverage, line coverage diff로 평가해야 한다. URL: https://github.com/google/oss-fuzz-gen |
| LLM Agents one-day paper | arXiv v2, 2024-04-17 / 2026-06-07 검색 | CVE description이 있을 때와 없을 때 성능 차이가 크므로, zero-day claim은 one-day metadata leakage와 contamination을 반드시 배제해야 한다. URL: https://arxiv.org/abs/2404.08144 |
| ZeroDayBench | arXiv v1, 2026-03-02 / 2026-06-07 검색 | 최신 frontier agent도 unseen zero-day를 자동 해결하기 어렵다는 기준선을 두고, SCOUT는 “자동 주장”보다 증거/검증 gate 중심으로 설계해야 한다. URL: https://arxiv.org/abs/2603.02297 |

### 7.2 전체 승격 원칙

1. **Static-only 금지**: source/sink, taint, graph, LLM reasoning만으로 AEG/zero-day release claim에 승격하지 않는다. 최소 L2 dynamic reachability 또는 명시적 dynamic gap dossier가 필요하다.
2. **AEG promotion 5-check all-pass**: `autopoc_runner_pass`, `poc_validation_reproducible`, `verified_chain_pass`, `quality_fpr_ceiling`, `no_high_severity_fp_verified`가 모두 통과해야 한다.
3. **Real firmware pair 우선**: release-facing AEG claim은 vulnerable pass와 patched/control dynamic fail-closed가 같은 pair manifest와 SHA binding 아래에서 성립해야 한다.
4. **Zero-day novelty 분리**: known CVE 재현, one-day advisory 기반 exploitability, unknown zero-day 후보를 별도 레인으로 분리하고 서로 KPI를 섞지 않는다.
5. **Contamination fail-closed**: public PoC source는 metadata/pattern seed만 허용하며 raw exploit code, payload literal, target host, credential, endpoint literal이 산출물로 누출되면 승격을 중단한다.
6. **Version/date mandatory**: 각 phase 산출물은 생성일, 재검증일, SCOUT 버전, git commit, firmware SHA, source artifact path를 포함해야 한다.
7. **SCOUT-W boundary**: L6/L7 package는 public repo에 payload를 두지 않고 private vault hash/manifest/approval ledger만 public evidence로 남긴다.

### 7.3 Phase별 업데이트 플랜

| Phase | 기준 기간/버전 | 승격 게이트 | 놓칠 수 있는 것 | 엣지 케이스 | 성능 극대화 |
| --- | --- | --- | --- | --- | --- |
| P0 Evidence Ledger | 2026-06-07 ~ 2026-06-14 / `3.0.0rc1` | 모든 핵심 claim에 `date/version/commit/source_path/artifact_hash/evidence_tier` 존재, S0/S1/S2/S3 자동 분류, stale artifact는 release claim 제외 | `/tmp` fresh result 손실, 문서가 없는 benchmark를 최신 수치처럼 인용, UTC/KST 혼동, run 원본일과 재검증일 혼동 | symlink/relative path artifact, untracked report만 존재, 같은 firmware SHA의 복수 run, stage registry 변경 | artifact hash cache, ledger diff만 재검증, code/version 변경 없으면 heavy stage rerun 생략 |
| P1 Pair Benchmark Floor | 2026-06-15 ~ 2026-07-05 / 2026-06-07 baseline `3.0.0rc1`; phase-start version 재기록 | firmware SHA binding, vulnerable AEG gate pass, patched/control dynamic fail-closed, pair summary signed, 최소 real pair 3개 후 5개로 확장 | patched fail이 환경 실패인지 취약점 부재인지 구분 실패, extraction partial 누락, 같은 root cause 중복 집계, vendor URL drift | patched도 여전히 취약, firmware wrapper만 다르고 rootfs 동일, emulation boot success지만 service not ready, control artifact 누락 | extraction/inventory cache, pair 단위 병렬 실행, service-ready probe 먼저 수행, failed stage만 selective rerun |
| P2 Zero-day Hypothesis | 2026-07-06 ~ 2026-08-09 / 2026-06-07 baseline `3.0.0rc1`; phase-start version 재기록 | known-CVE/one-day 중복 배제, root-cause diversity gate, source→sink→precondition evidence, L2 dynamic reachability 또는 gap dossier, analyst review bundle | advisory/PoC metadata가 zero-day 후보에 섞임, unreachable source를 취약점으로 오판, sink co-occurrence를 dataflow로 오판 | generated config source, CGI/env indirect taint, BusyBox applet alias, endian/arch-specific parser behavior, firmware lineage fork | changed-file/endpoint prefilter, all-binary taint 후보 top-K, slicing 후 LLM 사용, family-diverse sampling, decompilation/taint cache |
| P3 AutoPoC Robustness | 2026-07-06 ~ 2026-08-09 / 2026-06-07 baseline `3.0.0rc1`; phase-start version 재기록 | Plan IR complete, preconditions solved, N-of-M attempt policy, runner reason-code taxonomy 100%, `repro_3_of_3`, isolation verified, cleanup status recorded | syntactically valid but wrong primitive, benign response를 runner pass로 오판, qemu/harness flake를 exploit fail로 오판, nonpass reason 미분류 | auth/session/csrf required, reboot 또는 cold-start 필요, nondeterministic service state, timeout vs blocked input 구분, cleanup side-effect | cheapest verifier first, Plan IR ranking, synthetic-before-real gating, multi-backend fallback, early abort on unsatisfied preconditions |
| P4 Pattern RAG Corpus | 2026-08-10 ~ 2026-10-04 / 2026-06-07 baseline `3.0.0rc1`; phase-start version 재기록 | card schema pass, `forbidden_reuse` pass, synthetic pair evidence 100%, real pair evidence >= 5 cards, unsupported family abstain, contamination tests 0 fail | metadata-only seed를 proof처럼 취급, target-specific literal leakage, weak family labels, R7000 overfit | one firmware에 multiple CVE, CPE/vendor false match, public PoC repo 내용 변경, NVD/vuln-list lag | metadata cache, batch importer, retrieval top-K 제한, family/channel 균형 sampling, card quality score로 rerank |
| P5 SCOUT-W L6/L7 Readiness | 2026-10-05 이후 / 2026-06-07 baseline `3.0.0rc1`; phase-start version 재기록 | L5 pass 후만 L6, private package manifest lint/register/verify, scope token, firmware binding, cleanup plan/evidence, reliability threshold, approval ledger | package hash는 맞지만 target precondition 불충족, cleanup evidence 누락, approval stale, private runner와 public verifier 불일치 | customer lab network 제약, hardware-in-loop flake, partial cleanup, controlled crash가 destructive effect로 변질 | dry-run/preflight 먼저, hardware reservation queue, reliability matrix, vault hash verification cache, package-level smoke tests |
| P6 Continuous QA | 매 PR/release / 2026-06-07 baseline `3.0.0rc1`; PR/release version+commit 기록 | synthetic 3-pattern pass, `aeg-readiness` pass, R7000 real-pair smoke, ledger consistency, docs date/version check, targeted tests pass | CI가 synthetic만 보고 real pair stale를 놓침, qemu/network 환경 의존 failure, docs/report drift, generated artifact 누락 | network disabled CI, firmware license로 artifact 미포함, ephemeral `/tmp`, long-running full pair timeout | tiered CI: fast synthetic / nightly real pair / weekly full pair, artifact cache, fail-fast diagnostics, expensive test quarantine |

### 7.4 Phase별 세부 액션

#### P0 — Evidence ledger hardening

- **게이트 구현**: `scripts/check_report_evidence.py`를 추가해 Markdown/JSON report에서 version/date/commit/path/SHA 누락을 fail 처리한다.
- **놓칠 수 있는 것 보완**: `aiedge-runs/*/manifest.json`의 original run date와 current revalidation date를 분리 기록한다.
- **엣지 케이스 보완**: `/tmp` artifact는 release 근거가 아니라 fresh regression 근거로만 쓰고, release 근거는 repo-persisted evidence path 또는 export bundle hash를 요구한다.
- **성능**: artifact hash는 file mtime+size+sha cache로 관리하고, code commit이 같으면 ledger lint만 재실행한다.
- **DoD**: 이 보고서와 신규 evidence ledger가 `2026-06-07`, `3.0.0rc1`, `a7891f0`를 포함하고 stale/S2/S3 claim을 release KPI에서 제외한다.

#### P1 — Pair benchmark floor 재구축

- **게이트 구현**: `real_firmware_pair_gate` 결과를 pair-level matrix로 모아 `pair_id`, `vuln_sha`, `patched_sha`, `vuln_gate`, `control_fail_reason`, `emulation_ready`를 저장한다.
- **놓칠 수 있는 것 보완**: patched/control fail이 `service_unreachable`이면 “취약점 부재”가 아니라 “환경 미검증”으로 분류한다.
- **엣지 케이스 보완**: 같은 rootfs SHA를 가진 vendor repack firmware는 중복 pair로 세지 않는다.
- **성능**: extraction/inventory/profile은 firmware SHA 단위 immutable cache로 두고, AEG/dynamic validation만 pair 변경 시 rerun한다.
- **DoD**: phase 시작일 기준 SCOUT version+commit으로 real firmware pair 3개 이상, 다음 milestone에서 5개 이상; 각 pair는 vulnerable pass + control dynamic fail-closed.

#### P2 — Zero-day hypothesis lane

- **게이트 구현**: `novelty_dossier.json`에 `known_cve_overlap`, `public_advisory_overlap`, `pattern_seed_used`, `lineage_delta`, `dynamic_reachability`를 기록한다.
- **놓칠 수 있는 것 보완**: CVE/advisory/NVD/vuln-list seed가 연결된 candidate는 “one-day/known-pattern”으로 분리하고 zero-day KPI에 넣지 않는다.
- **엣지 케이스 보완**: config-derived input, CGI environment, nvram getter, shell script variable expansion을 source taxonomy에 명시한다.
- **성능**: 모든 binary를 깊게 분석하기보다 Mango식 all-binary fast pass로 후보를 넓게 잡고, 상위 후보만 deep taint/LLM slicing으로 보낸다.
- **DoD**: zero-day 후보는 최소 3개 family/channel에서 나오고, “known-CVE 재현”과 “unknown hypothesis”가 dashboard에서 분리된다.

#### P3 — AutoPoC Plan IR / failure taxonomy

- **게이트 구현**: AutoPoC candidate마다 Plan IR 필수 필드(`scope`, `target_profile`, `primitive`, `preconditions`, `execution`, `verification`, `cleanup`, `gate`)를 요구한다.
- **놓칠 수 있는 것 보완**: runner fail은 `precondition_missing`, `service_not_ready`, `input_rejected`, `oracle_ambiguous`, `timeout`, `crash_nonisolated`, `cleanup_failed` 등 reason-code로 분류한다.
- **엣지 케이스 보완**: session/auth/csrf/reboot-dependent PoC는 precondition solver가 없으면 자동 실행하지 않고 “blocked-by-precondition”으로 남긴다.
- **성능**: Plan IR ranking으로 상위 N개만 runner에 올리고, oracle이 명확한 cheap verifier부터 실행한다.
- **DoD**: R7000 vulnerable에서 runner_pass 비율을 1/3에서 50% 이상으로 올리거나, nonpass 100%가 actionable reason-code를 가진다.

#### P4 — Exploit Pattern RAG corpus 확장

- **게이트 구현**: pattern card는 schema, synthetic pair, contamination, retrieval-abstain test를 통과해야 curated로 승격한다.
- **놓칠 수 있는 것 보완**: public PoC importer는 code body를 저장하지 않고 source URL/hash/license/description/CWE/CPE metadata만 보존한다.
- **엣지 케이스 보완**: card 하나가 여러 CVE/vendor를 묶을 경우 target-specific literal과 family-level abstraction을 분리한다.
- **성능**: retrieval은 broad top-K가 아니라 `family + entry_channel + sink + precondition` composite key로 좁힌다.
- **DoD**: curated card 20개, synthetic pair evidence 100%, real pair evidence 5개 이상, unsupported query abstain.

#### P5 — Controlled weaponization readiness

- **게이트 구현**: L6 package는 `L5_AEG_VERIFIED` evidence, private package hash, firmware SHA allowlist, scope token, cleanup plan/evidence, approval ledger를 모두 요구한다.
- **놓칠 수 있는 것 보완**: public verifier는 private payload를 몰라도 package hash/manifest/scope/cleanup proof를 검증할 수 있어야 한다.
- **엣지 케이스 보완**: hardware-in-loop에서 crash/reboot가 생기면 destructive capability로 오판되지 않게 bounded effect와 cleanup policy를 구분한다.
- **성능**: preflight/dry-run으로 실패 가능한 package를 먼저 걸러 hardware lab 시간을 보호한다.
- **DoD**: scoped private test fixture에서 pass/fail 양쪽이 검증되고, cleanup evidence 없는 package는 promotion 불가.

#### P6 — Continuous QA / release gate

- **게이트 구현**: PR gate는 synthetic 3-pattern + targeted tests, nightly는 real pair smoke, weekly는 full pair/corpus gate로 tier를 나눈다.
- **놓칠 수 있는 것 보완**: docs/report lint가 version/date/commit 누락과 stale evidence tier 누락을 fail 처리한다.
- **엣지 케이스 보완**: CI에서 firmware blob을 못 싣는 경우 SHA-bound external fixture manifest와 skip reason을 명시한다.
- **성능**: fast gate는 10~15분 안에 끝나도록 synthetic/ledger/targeted unit에 집중하고, qemu-heavy tests는 nightly/weekly로 이동한다.
- **DoD**: release 전 `aeg-readiness`, R7000 smoke, evidence ledger, pattern evidence check가 모두 green이며, 실패 시 어떤 phase gate가 막았는지 보고서가 자동 생성된다.

### 7.5 공통 성능 극대화 전략

1. **Immutable cache 경계**: firmware SHA, extractor version, stage code commit이 같으면 extraction/inventory/profile은 재사용하고 dynamic/AEG만 재실행한다.
2. **Service-ready first**: emulation 성공과 exploit 실패를 분리하기 위해 service-ready probe를 모든 dynamic gate 앞에 둔다.
3. **Fast-wide / deep-narrow**: all-binary fast taint·endpoint·surface pass로 넓게 후보를 잡고, deep taint/LLM/runner는 diversity-aware top-K에만 적용한다.
4. **Reason-code feedback loop**: AutoPoC nonpass reason을 candidate ranking과 precondition solver training data로 되돌린다.
5. **Pair-parallel but resource-aware**: pair는 병렬화하되 QEMU/TAP/network/hardware resource lock을 명시해 false flaky를 줄인다.
6. **Tiered CI**: PR에는 cheap deterministic gate, nightly에는 real-pair smoke, weekly/release에는 full corpus/pair benchmark를 둔다.
7. **Abstain as success path**: RAG/LLM이 unsupported family나 stale evidence를 만났을 때 hallucinated PoC를 내는 대신 abstain/fail-closed하면 품질 성능으로 인정한다.

### 7.6 업데이트된 우선순위

| 우선순위 | 변경 | 이유 |
| --- | --- | --- |
| 1 | P0 evidence ledger를 먼저 구현 | 사용자가 지적한 stale 산출물 리스크를 gate로 고정해야 이후 수치가 의미 있다. |
| 2 | P1 pair benchmark를 3개 real pair까지 우선 확장 | zero-day/AEG 모두 control-pair 없이는 release-facing claim이 약하다. |
| 3 | P3 AutoPoC Plan IR와 failure taxonomy를 P2와 병렬 진행 | current bottleneck은 candidate 수보다 runner pass/nonpass를 설명하고 개선하는 능력이다. |
| 4 | P2 zero-day novelty는 known-CVE/one-day 분리 dashboard부터 시작 | 외부 연구상 LLM agent 성능은 제공 context에 크게 의존하므로 contamination-free novelty 기준이 선행돼야 한다. |
| 5 | P4 pattern corpus는 card 수보다 evidence-backed diversity 우선 | 20개 card라도 synthetic/control/real pair evidence가 없으면 AEG 일반화 주장에 약하다. |
| 6 | P5 SCOUT-W는 L5 evidence가 안정화된 뒤 private package readiness로 제한 | 안전 경계와 제품 신뢰도를 위해 public payload 없는 manifest/hash/ledger 중심으로만 승격한다. |

## 8. Phase 1/2 진행 반영 — 2026-06-07 KST

기준 버전은 `scout-firmware 3.0.0rc1` / `v3.0.0-rc1`이며, 기준 main commit은 PR #15 merge commit `e5722e0`이다. 이 섹션은 Phase 0/1 readiness merge 이후 같은 보고서에 이어 붙인 실행 업데이트다.

### 8.1 Phase 1 실행 업데이트

신규 산출물:

- `src/aiedge/phase12_progress.py`
- `scripts/build_phase1_phase2_progress.py`
- `docs/pov/phase1_pair_matrix.json`
- `docs/phase1_phase2_progress.md`

`docs/pov/phase1_pair_matrix.json`은 `benchmarks/pair-eval/pairs.json`의 12개 pair를 다음 기준으로 재정렬한다.

- `vuln_sha`, `patched_sha`를 명시한다.
- local firmware file 존재 여부와 SHA match를 기록한다.
- real-pair report가 있으면 `control_fail_reason`과 `emulation_ready`를 기록한다.
- 같은 vulnerable/patched firmware SHA tuple은 `dedupe_key`로 묶어 scale target 중복 집계를 막는다.

현재 Phase 1 실행 결과:

| 항목 | 값 |
| --- | --- |
| pair corpus size | 12 |
| local firmware pair ready | 2 |
| promotable real pair | 1 |
| Phase 1 scale target | 3 |
| scale target met | false |
| next run queue | `dlink-dir859-cve-2019-17621` |

해석: Phase 1은 Phase 2 진입 최소 floor는 이미 통과했지만, scale target 3개는 아직 미충족이다. 이번 업데이트는 다음 pair를 추측이 아니라 local artifact/SHA 상태 기반 queue로 고정했다.

### 8.2 Phase 2 실행 업데이트

신규 산출물:

- `docs/pov/phase2_novelty_dossier.json`

`docs/pov/phase2_novelty_dossier.json`은 zero-day KPI에 known CVE, public advisory, pattern seed 기반 후보가 섞이지 않도록 다음 필드를 모든 candidate에 강제한다.

- `known_cve_overlap`
- `public_advisory_overlap`
- `pattern_seed_used`
- `lineage_delta`
- `dynamic_reachability`

현재 Phase 2 실행 결과:

| 항목 | 값 |
| --- | --- |
| candidate count | 12 |
| known/one-day count | 12 |
| unknown hypothesis count | 0 |
| zero-day KPI count | 0 |
| 3-family/channel unknown target | false |

해석: Phase 2는 unknown 후보를 과장해서 주장하지 않는다. 먼저 known-CVE/one-day/pattern-seeded 후보를 zero-day KPI에서 배제하는 dashboard와 gate를 만들었다. 다음 작업은 firmware lineage와 source→sink evidence에서 public advisory overlap이 없는 unknown candidate를 생성하고, dynamic reachability 또는 gap dossier로 승격하는 것이다.


## 9. Phase 3 완료 반영 — 2026-06-08 KST

기준 버전은 `scout-firmware 3.0.0rc1` / `v3.0.0-rc1`이며, Phase 3 시작 기준 main commit은 PR #16 merge commit `1955ac3185a168111d5995560728f89cba1fdfc7`이다. 이 섹션은 Phase 1/2 진행 반영 이후 같은 보고서에 이어 붙인 Phase 3 실행 업데이트다.

신규 산출물:

- `src/aiedge/phase3_readiness.py`
- `scripts/build_phase3_aeg_readiness.py`
- `docs/pov/phase3_aeg_readiness.json`
- `docs/phase3_aeg_plan_ir.md`

Phase 3 구현 반영:

- AutoPoC candidate마다 `scout-aeg-phase3-plan-ir-contract-v1` Plan IR를 생성/정규화한다.
- Plan IR 필수 필드는 `scope`, `target_profile`, `primitive`, `preconditions`, `execution`, `verification`, `cleanup`, `gate`, `backend_plan`이다.
- candidate selection은 `priority + Plan IR presence + proof feasibility + family diversity` 순으로 보정되어 top-N이 같은 family에 collapse되지 않는다.
- runner와 Plan IR 모두 `baseline`, `cold_start`, `service_restart`, `reboot` reliability variant를 기록한다.
- backend map은 `service_harness`, `qemu_user`, `full_system_emulation`, `hardware_in_loop`을 명시한다.
- runner nonpass는 `payload`, `precondition`, `harness`, `false_hypothesis`, `environment` taxonomy로 분류되고 summary coverage로 기록된다.

현재 Phase 3 readiness 결과:

| 항목 | 값 |
| --- | --- |
| artifact | `docs/pov/phase3_aeg_readiness.json` |
| schema | `scout-phase3-aeg-readiness-v1` |
| contract | `scout-aeg-phase3-plan-ir-contract-v1` |
| phase3_ready | `true` |
| verdict | `phase3-complete` |
| artifact date | `2026-06-08 KST` |

해석: Phase 3는 AutoPoC/runner contract 관점에서 완료되었다. 즉 Plan IR input contract, family-diverse selection, reliability variant evidence, backend redundancy map, nonpass failure taxonomy가 repo-local readiness artifact로 증명된다. 단, broad real-firmware pass-rate 일반화는 Phase 1 scale-out과 Phase 4 corpus expansion 이후 별도 측정해야 한다.

## 10. 결론

SCOUT의 현재 강점은 “많이 찾는다”보다 **증거를 남기고, gate를 통과한 exploitability만 승격한다**는 점이다. 현재 코드로 재검증한 R7000 real firmware pair와 fresh synthetic pair 3종은 AEG gate의 핵심 구조가 작동함을 보여준다.

그러나 Zero-day Research와 broad AEG 제품으로 주장하려면 현재의 1개 real pair, 4개 curated pattern, partial AutoPoC, stale benchmark references를 넘어서야 한다. 따라서 다음 개발은 새 기능 추가보다 먼저 **evidence freshness ledger → pair-first benchmark 재구축 → Plan IR 기반 AutoPoC 안정화 → zero-day novelty/diversity 강화 → pattern corpus 확장** 순서로 진행하는 것이 가장 안전하고 제품적인 경로다.
