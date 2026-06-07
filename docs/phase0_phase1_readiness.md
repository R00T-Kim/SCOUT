# SCOUT Phase 0/1 Readiness — Phase 2 Entry Gate

작성일: 2026-06-07 KST
기준 버전: `scout-firmware 3.0.0rc1` / `v3.0.0-rc1`
기준 commit: `a7891f0` (`2026-06-01T11:43:22+09:00`)

## 목적

Phase 0(Evidence Ledger / stale artifact audit)과 Phase 1(Pair Benchmark Floor)을 실제 검증 artifact로 고정해 Phase 2(Zero-day hypothesis lane)에 들어갈 수 있는 최소 상태를 만든다.

## 생성된 gate artifact

| Artifact | Schema | 결과 | 의미 |
| --- | --- | --- | --- |
| `docs/pov/phase0_report_evidence_audit.json` | `scout-report-evidence-audit-v1` | `passed=true` | 보고서에 필수 일자/버전/commit/evidence-tier/Phase0/Phase1 marker가 있음 |
| `docs/pov/netgear-r7000-cve-2017-5521_real_pair.json` | `real-firmware-pair-aeg-gate-v1` | `verdict=promotable` | R7000 vulnerable pass + patched/control dynamic fail-closed + SHA binding |
| `docs/pov/aeg_platform_readiness.json` | `aeg-platform-readiness-v1` | `verdict=platform-ready`, `ready=true` | curated pattern evidence, synthetic pair evidence, real-pair floor, stable artifact binding 통과 |
| `docs/pov/phase0_phase1_readiness.json` | `scout-phase0-phase1-readiness-v1` | `verdict=phase2-entry-ready` | Phase 0 ready + Phase 1 minimum real-pair floor 통과 |

## 현재 판정

- `phase2_entry_ready=true`
- `phase0.ready=true`
- `phase1.minimum_ready=true`
- `phase1.promotable_real_pair_count=1`
- `phase1.scale_target_met=false`

해석: Phase 2 진입에 필요한 최소 evidence floor는 충족했다. 다만 Phase 1의 scale target인 real firmware pair 3개는 아직 미달이므로, Phase 2와 병렬로 P1 scale-out을 계속 진행해야 한다.

## 검증 명령

```bash
python3 scripts/check_report_evidence.py \
  --out docs/pov/phase0_report_evidence_audit.json

./scout aeg-real-pair-gate \
  --pair-id netgear-r7000-cve-2017-5521 \
  --vulnerable-run-dir aiedge-runs/2026-05-20_2222_sha256-c025ce21eabc \
  --control-run-dir aiedge-runs/2026-05-20_2150_sha256-6309264efce0 \
  --pattern-id netgear_passwordrecovered_auth_bypass \
  --out docs/pov/netgear-r7000-cve-2017-5521_real_pair.json

./scout aeg-readiness \
  --out docs/pov/aeg_platform_readiness.json

python3 scripts/build_phase0_phase1_readiness.py \
  --out docs/pov/phase0_phase1_readiness.json
```

## Phase 2 진입 전제

Phase 2에서는 zero-day hypothesis와 known/one-day reproduction을 분리해야 한다. 현재 gate는 다음을 보장한다.

1. release-facing claim에 S2/S3 stale artifact를 쓰지 않는다.
2. AEG 최소 real-pair floor는 R7000 known-vulnerable/patched pair로 통과했다.
3. Phase 1 scale target은 별도 non-blocking 추적 항목으로 남겼다.
4. Phase 2 산출물은 `novelty_dossier.json`에 `known_cve_overlap`, `public_advisory_overlap`, `pattern_seed_used`, `lineage_delta`, `dynamic_reachability`를 기록해야 한다.
