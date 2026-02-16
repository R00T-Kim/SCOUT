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

The analyze command prints the generated run_dir path. Use that value as `<RUN_DIR>` in all commands below.

## 2) Run dynamic validation stage (if not already included)

```bash
PYTHONPATH=src python3 -m aiedge stages <RUN_DIR> \
  --stages dynamic_validation \
  --no-llm
```

## 3) Inject private exploit code and capture evidence-only artifacts

```bash
python3 exploit_runner.py \
  --run-dir <RUN_DIR> \
  --exploit-dir /path/to/private/exploits \
  --chain-id ER-e50_v3.0.1:rce_cgi_injection \
  --repro 3
```

## 4) Assemble verified_chain contract

```bash
python3 scripts/build_verified_chain.py --run-dir <RUN_DIR>
```

Expected output: `[OK] built verified_chain: ...` and file `<RUN_DIR>/verified_chain/verified_chain.json`.

## 5) Run all four verified-chain verifiers

```bash
python3 scripts/verify_run_dir_evidence_only.py --run-dir <RUN_DIR>
python3 scripts/verify_network_isolation.py --run-dir <RUN_DIR>
python3 scripts/verify_exploit_meaningfulness.py --run-dir <RUN_DIR>
python3 scripts/verify_verified_chain.py --run-dir <RUN_DIR>
```

All four commands must return `[OK]` for a fully verified run.

## 6) Notes for operators

- `--exploit-dir` is private input only; exploit source must not be copied into `run_dir`.
- Evidence files under `run_dir/exploits/` and `run_dir/verified_chain/` are policy-checked as evidence-only.
- Dynamic validation requires non-interactive `sudo -n` for FirmAE/isolation captures (tight allowlist, no broad sudoers rules).
