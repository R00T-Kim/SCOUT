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

`VERIFIED` is only meaningful when digest verification passes and all four verified-chain verifiers pass.

## 8) Notes for operators

- `--exploit-dir` is private input only; exploit source must not be copied into `run_dir`.
- Evidence files under `run_dir/exploits/` and `run_dir/verified_chain/` are policy-checked as evidence-only.
- `report/duplicate_gate.json` is triage metadata only; it does not suppress/remove items from top-level `report/report.json` `findings`.
- Dynamic validation requires non-interactive `sudo -n` for FirmAE/isolation captures (tight allowlist, no broad sudoers rules).

## 9) Codex-first execution policy check

- Policy reference: `docs/codex_first_agent_policy.md`.
- Before execution, confirm runtime metadata reports main model `gpt-5.3-codex` (or `openai/gpt-5.3-codex`).
- During execution, mark each subagent call as model-verified or `model_unverified`; if drift is detected, apply codex retry-first fallback procedure from the policy and log the event.
- Limitation reminder from policy: subagent model pinning is not enforceable in this toolchain, so model provenance for subagents can be unavailable and must be treated as `model_unverified`.
