# SCOUT Phase 1/2 진행 기록 — 2026-06-07 KST

- 기준 버전: `scout-firmware 3.0.0rc1` / `v3.0.0-rc1`
- 기준 main commit: `e5722e0` (PR #15 merge, Phase 0/1 readiness gate 반영)
- 작성일: 2026-06-07 KST

## Phase 1 — Pair matrix 확장

`docs/pov/phase1_pair_matrix.json`는 `benchmarks/pair-eval/pairs.json`의 12개 pair를 현재 local firmware artifact와 real-pair gate report 기준으로 재정렬한다.

핵심 필드:

- `vuln_sha`, `patched_sha`
- `local_firmware_ready`
- `control_fail_reason`
- `emulation_ready`
- `dedupe_key`, `duplicate_firmware_sha_pair`
- `counted_for_phase1_scale`

현재 결과:

- pair corpus size: 12
- local firmware pair ready: 2 (`netgear-r7000-cve-2017-5521`, `dlink-dir859-cve-2019-17621`)
- promotable real pair: 1 (`netgear-r7000-cve-2017-5521`)
- Phase 1 scale target 3개: 아직 미충족
- next queue: `dlink-dir859-cve-2019-17621`

해석: Phase 1은 PR #15에서 Phase 2 진입 최소 floor를 통과했고, 이번 단계에서 scale-out queue를 local artifact 상태 기반으로 명시했다.

## Phase 2 — Novelty dossier 시작

`docs/pov/phase2_novelty_dossier.json`는 zero-day KPI에 known CVE/one-day/public advisory/pattern seed가 섞이지 않도록 분리 gate를 시작한다.

모든 candidate는 다음 필드를 가져야 한다.

- `known_cve_overlap`
- `public_advisory_overlap`
- `pattern_seed_used`
- `lineage_delta`
- `dynamic_reachability`

현재 결과:

- candidate count: 12
- known/one-day count: 12
- unknown hypothesis count: 0
- zero-day KPI count: 0
- 3-family/channel unknown target: 아직 미충족(non-blocking 진행 target)

해석: Phase 2는 아직 unknown 후보를 주장하지 않는다. 대신 known CVE pair corpus를 zero-day KPI에서 배제하는 guardrail과 dashboard를 먼저 만들었다. 다음 단계는 firmware lineage/source→sink evidence에서 public advisory overlap이 없는 unknown candidate를 생성하는 것이다.
