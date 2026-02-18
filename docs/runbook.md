# Runbook

## 1) Analyze firmware and create run_dir

```bash
cd /home/rootk1m/SCOUT
PYTHONPATH=src python3 -m aiedge analyze /path/to/ER-e50.v3.0.1.bin \
  --case-id er-e50-v3.0.1-verified-chain \
  --ack-authorization \
  --profile exploit \
  --exploit-flag lab \
  --exploit-attestation authorized \
  --exploit-scope lab-only \
  --no-llm
```

The analyze command prints the generated run_dir path. Use that value as `<run_dir>` in all commands below.

### ER-e50 `analysis` profile note (verifier scope)

- ER-e50 `analysis` runs intentionally omit `manifest.track` in `manifest.json`.
- `python3 scripts/verify_aiedge_final_report.py --run-dir <run_dir>` is the canonical 8MB-only final verifier and will fail on ER-e50 `analysis` runs by design.
- ER-e50 `analysis` operator gates are:

```bash
python3 scripts/verify_analyst_digest.py --run-dir <run_dir>
python3 scripts/verify_aiedge_analyst_report.py --run-dir <run_dir>
```

## 2) Run dynamic validation stage (if not already included)

```bash
PYTHONPATH=src python3 -m aiedge stages <run_dir> \
  --stages dynamic_validation \
  --no-llm
```

## 3) Inject private exploit code and capture evidence-only artifacts

```bash
python3 exploit_runner.py \
  --run-dir <run_dir> \
  --exploit-dir /path/to/private/exploits \
  --chain-id ER-e50_v3.0.1:rce_cgi_injection \
  --repro 3
```

## 4) Assemble verified_chain contract

```bash
python3 scripts/build_verified_chain.py --run-dir <run_dir>
```

Expected output: `[OK] built verified_chain: ...` and file `<run_dir>/verified_chain/verified_chain.json`.

## 5) Verify analyst digest artifacts first (digest-first workflow)

```bash
test -f <run_dir>/report/analyst_digest.json
test -f <run_dir>/report/analyst_digest.md
python3 scripts/verify_analyst_digest.py --run-dir <run_dir>
```

Expected result: digest files exist and verifier returns `[OK]`.

## 6) Run all four verified-chain verifiers

```bash
python3 scripts/verify_run_dir_evidence_only.py --run-dir <run_dir>
python3 scripts/verify_network_isolation.py --run-dir <run_dir>
python3 scripts/verify_exploit_meaningfulness.py --run-dir <run_dir>
python3 scripts/verify_verified_chain.py --run-dir <run_dir>
```

All four commands must return `[OK]` for a fully verified run.

## 7) Digest-first operator flow

1. Open `report/analyst_digest.md` first for analyst-readable summary.
2. Confirm `exploitability_verdict.state` in `report/analyst_digest.json` is not used without verifier context.
3. Follow `finding_verdicts[].evidence_refs` and `finding_verdicts[].verifier_refs` to inspect exact proof artifacts.
4. Treat any non-`VERIFIED` state as fail-closed and action on `reason_codes` / `next_actions`.

Operator note: for `profile=exploit`, `report/report.json` `exploit_assessment.decision` and
`exploit_assessment.reason_codes` now mirror `report/analyst_digest.json`
`exploitability_verdict.state` / `reason_codes`; `exploit_assessment.stage_statuses` is context only.

`VERIFIED` is only meaningful when digest verification passes and all four verified-chain verifiers pass.

### Exploit candidate planning artifact (deterministic)

- Findings stage now writes `<run_dir>/stages/findings/exploit_candidates.json`
  (`schema_version: exploit-candidates-v1`).
- This is a planning/triage aid derived from deterministic pattern + chain findings; it is **not** verifier proof.
- Use `summary` (`candidate_count`, `high|medium|low`, `chain_backed`) first, then inspect each candidate `evidence_refs`.

Quick check:

```bash
python3 - <run_dir>/stages/findings/exploit_candidates.json <<'PY'
import json,sys
p=json.load(open(sys.argv[1], encoding="utf-8"))
print(p["schema_version"], p.get("summary", {}))
PY
```

## 8) Single-pane overview (additive, offline-safe)

- Recommended local serving flow (avoids `file://` fetch limitations):

```bash
PYTHONPATH=src python3 -m aiedge serve <run_dir>
```

- Open `<run_dir>/report/viewer.html` for the single-pane operator overview.
- The viewer consumes `<run_dir>/report/analyst_overview.json` (`schema_version="analyst_overview-v1"`), which is a derived additive payload for navigation/summary and does not replace contract artifacts.
- Offline behavior is supported via embedded bootstrap JSON in `viewer.html`; when opened via `file://`, browser fetch restrictions are surfaced in the in-page warning anchor `#file-warning` and the viewer falls back to embedded bootstrap data.
- Gate applicability caveats:
  - `manifest.profile=analysis` -> verified-chain gate is `not_applicable`.
  - `manifest.track.track_id=8mb` -> final 8MB report-contract gate is applicable.

### Cockpit card meanings (operator guidance)

- **Executive Verdict**: current digest verdict (`state`, `reason_codes`, `next_actions`); if digest data is missing/incomplete, treat as blocked/unknown (fail-closed).
- **Attack Surface Scale**: high-level counts (endpoints/surfaces/unknowns/non-promoted) to estimate analysis scope; these counts are context, not proof.
- **Exploit Candidate Map**: visual distribution of `high/medium/low` candidates from `stages/findings/exploit_candidates.json` plus top candidate paths, `attack_hypothesis`, `expected_impact`, and `next_step` guidance; use this to prioritize manual chain validation.
- **Verification Status**: gate applicability/presence indicators from overview payload; this card does not report authoritative verifier pass/fail.
- **Evidence Navigator**: run-relative shortcuts to digest/overview/report artifacts; use links to inspect evidence and verifier references quickly.

### Trust boundary and authoritative checks

- `viewer.html` is non-authoritative convenience UI only.
- Verifier scripts are authoritative for release/operator gates:

```bash
python3 scripts/verify_analyst_digest.py --run-dir <run_dir>
python3 scripts/verify_aiedge_analyst_report.py --run-dir <run_dir>
```

- Fail-closed rule: if cockpit cards disagree with verifier output, or required artifacts/verifier results are missing, treat the run as non-verified.

## 9) Notes for operators

- `--exploit-dir` is private input only; exploit source must not be copied into `run_dir`.
- Evidence files under `run_dir/exploits/` and `run_dir/verified_chain/` are policy-checked as evidence-only.
- `report/duplicate_gate.json` is triage metadata only; it does not suppress/remove items from top-level `report/report.json` `findings`.
- Dynamic validation requires non-interactive `sudo -n` for FirmAE/isolation captures (tight allowlist, no broad sudoers rules).

## 10) Codex-first execution policy check

- Policy reference: `docs/codex_first_agent_policy.md`.
- Before execution, confirm runtime metadata reports main model `gpt-5.3-codex` (or `openai/gpt-5.3-codex`).
- During execution, mark each subagent call as model-verified or `model_unverified`; if drift is detected, apply codex retry-first fallback procedure from the policy and log the event.
- Limitation reminder from policy: subagent model pinning is not enforceable in this toolchain, so model provenance for subagents can be unavailable and must be treated as `model_unverified`.
