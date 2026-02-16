# Runbook

## 1) AIEdge 실행

결정론적 실행(LLM off):

```bash
cd /home/rootk1m/SCOUT
PYTHONPATH=src python3 -m aiedge analyze /path/to/firmware.bin \
  --ack-authorization --no-llm \
  --case-id my-run \
  --stages tooling,extraction,structure,carving,firmware_profile,inventory
```

부분 재실행(기존 run_dir):

```bash
PYTHONPATH=src python3 -m aiedge stages /path/to/aiedge-runs/<run_id> \
  --ack-authorization --no-llm \
  --stages inventory
```

## 2) 계약/검증 스크립트

- `python3 scripts/verify_aiedge_analyst_report.py --run-dir <run_dir>`
- `python3 scripts/verify_aiedge_final_report.py --run-dir <run_dir>`

## 3) Terminator 연동(E2E)

- 문서: `docs/e2e_terminator_aiedge_stage_control.md`
- 스크립트:
  - `scripts/e2e_terminator_aiedge_stage_control.sh`
  - `scripts/e2e_terminator_aiedge_stage_control_interrupt.sh`
  - `scripts/e2e_terminator_aiedge_stage_control_preexisting_session.sh`
