# AIEdge 8MB Track Runbook

This runbook describes the canonical 8MB firmware track used for deterministic end-to-end analysis, lab-gated exploit workflow checks, and performance regression measurement.

## Canonical Input

- Canonical firmware snapshot:
  - `/home/rootk1m/SCOUT/aiedge-runs/2026-02-12_1633_sha256-387d97fd9251/input/firmware.bin`
  - sha256 prefix: `387d97fd9251`
  - size: `8388608`

## Analysis (8MB Track)

```bash
PYTHONPATH=/home/rootk1m/SCOUT/src \
python3 -m aiedge analyze-8mb \
  /home/rootk1m/SCOUT/aiedge-runs/2026-02-12_1633_sha256-387d97fd9251/input/firmware.bin \
  --case-id 8mb-analysis \
  --ack-authorization \
  --no-llm
```

- Output runs are written under the current working directory as `./aiedge-8mb-runs/<run-id>/`.
- A track marker is recorded in `manifest.json` under `track`.

## Tooling Coverage Notes

- Tooling metadata is written to `stages/tooling/tools.json` and each tool now includes a `required` boolean.
- Stage details report deterministic lists for `missing_required_tools` and `missing_optional_tools`.
- Missing optional tools do not invalidate a run; they only reduce analysis coverage for paths that rely on those tools.
- `ubidump` is optional in the 8MB track. If missing, UBI-oriented extraction paths are skipped while the canonical run remains valid.

To enable optional `ubidump` support in a lab-only environment (no secrets needed):

```bash
python3 -m pip install ubidump
```

- Re-run analysis after installation to populate `ubidump.available=true` in `stages/tooling/tools.json`.

## Exploit Profile (Lab-Gated)

Exploit profile requires explicit gate fields.

```bash
PYTHONPATH=/home/rootk1m/SCOUT/src \
python3 -m aiedge analyze-8mb \
  /home/rootk1m/SCOUT/aiedge-runs/2026-02-12_1633_sha256-387d97fd9251/input/firmware.bin \
  --case-id 8mb-exploit \
  --ack-authorization \
  --no-llm \
  --profile exploit \
  --exploit-flag flag \
  --exploit-attestation authorized \
  --exploit-scope lab-only \
  --stages exploit_gate,exploit_chain,exploit_policy
```

Notes:
- These stages are non-weaponized and designed to emit audit-ready artifacts.
- Evidence policy checks run under `exploit_policy`.

## Determinism (Replay Gate)

Run analysis twice under identical environment and compare bundles:

```bash
PYTHONPATH=/home/rootk1m/SCOUT/src \
python3 - <<'PY'
from pathlib import Path
from aiedge.determinism import assert_bundles_equal, collect_run_bundle

run1 = Path("<run-dir-1>")
run2 = Path("<run-dir-2>")
assert_bundles_equal(collect_run_bundle(run1), collect_run_bundle(run2))
print("OK")
PY
```

## Performance

Generate a machine-readable perf summary JSON:

```bash
RUNS=3 TIME_BUDGET_S=120 /home/rootk1m/SCOUT/scripts/perf_8mb_track.sh
```

## E2E Script

```bash
/home/rootk1m/SCOUT/scripts/e2e_aiedge_8mb_track.sh
```

- `WORK_DIR` defaults to a new temporary directory (`mktemp -d`). Override it by exporting `WORK_DIR` (for example: `WORK_DIR=/tmp/aiedge-8mb-e2e /home/rootk1m/SCOUT/scripts/e2e_aiedge_8mb_track.sh`).
- Expected outputs under `$WORK_DIR`:
  - `evidence_index.json`: top-level index of generated artifacts and flow run directories; the script prints `[OK] evidence index: <path>` when written.
  - `repro_bundle.json`: deterministic reproduction bundle (canonical firmware identity, replay commands, run dirs, bundle digests).
  - `perf.json`: machine-readable performance summary from `scripts/perf_8mb_track.sh`.
  - run directories: analysis and exploit run paths referenced in `evidence_index.json` under `flows.*.run_dirs`.

Isolation checks covered by this flow:
- Runtime negative test (`tests/test_emulation.py`) runs `docker run --network none --pull=never alpine:3.23 ...` and asserts DNS lookup fails with no non-loopback routes.
- E2E assertions verify emulation artifacts at `<run>/stages/emulation/stage.json` and `<run>/stages/emulation/emulation.log`.
- E2E fails if emulation evidence does not include `stages/emulation/emulation.log` or if the emulation log does not contain `--network none`.
- Exploit-gated validation failures print `stage.json` and `policy.json` paths for immediate policy-evidence triage.

## Final Report Verifier

Verify that a finalized run report satisfies completeness and canonical 8MB identity checks:

```bash
python3 /home/rootk1m/SCOUT/scripts/verify_aiedge_final_report.py --run-dir <run-dir>
```

- Success emits one line prefixed with `[OK]`.
- Contract violations emit one line prefixed with `[FAIL]` and exit non-zero.

## Production-Mode Preflight and Quality Gates

Use this sequence before operator handoff. It runs matrix E2E coverage, release governance gates, and audit package validation.

### Local (copy/paste)

```bash
set -euo pipefail
PYTHONPATH=src scripts/e2e_aiedge_matrix.sh
PYTHONPATH=src scripts/release_gate.sh --run-dir <run-dir>
python3 scripts/audit_package_validate.py --run-dir <run-dir>
```

### CI (copy/paste)

```bash
set -euo pipefail
export PYTHONPATH=src
scripts/e2e_aiedge_matrix.sh
scripts/release_gate.sh --run-dir "$RUN_DIR" --manifest benchmarks/corpus/manifest.json --metrics-out "$RUN_DIR/metrics.json" --quality-out "$RUN_DIR/quality_gate.json"
python3 scripts/audit_package_validate.py --run-dir "$RUN_DIR" > "$RUN_DIR/audit_summary.json"
```

### LLM-Primary Gate Inputs (copy/paste)

`scripts/release_gate.sh` always runs quality policy with `--llm-primary`. Use these commands when triaging or reproducing LLM gate behavior directly:

```bash
# Derive LLM verdict from report.llm.status (requires --report)
PYTHONPATH=src python3 -m aiedge release-quality-gate \
  --metrics <run-dir>/metrics.json \
  --report <run-dir>/report/report.json \
  --llm-primary \
  --out <run-dir>/quality_gate.json

# Override with deterministic fixture verdict payload
PYTHONPATH=src python3 -m aiedge release-quality-gate \
  --metrics <run-dir>/metrics.json \
  --report <run-dir>/report/report.json \
  --llm-primary \
  --llm-fixture <path-to-llm-fixture.json> \
  --out <run-dir>/quality_gate.json

# End-to-end release gate with fixture passthrough
PYTHONPATH=src scripts/release_gate.sh --run-dir <run-dir> --llm-fixture <path-to-llm-fixture.json>
```

## Failure Triage Flow

1. Run `PYTHONPATH=src scripts/release_gate.sh --run-dir <run-dir>` and identify first `[GATE][FAIL][TOKEN]` line.
2. If token is `CONTRACT_FINAL` or `CONTRACT_ANALYST`, run the matching verifier directly:
   - `python3 scripts/verify_aiedge_final_report.py --run-dir <run-dir>`
   - `python3 scripts/verify_aiedge_analyst_report.py --run-dir <run-dir>`
3. If token is `QUALITY_METRICS`, re-run `PYTHONPATH=src python3 -m aiedge quality-metrics --manifest benchmarks/corpus/manifest.json --out <run-dir>/metrics.json` and inspect missing/invalid metrics keys.
4. If token is `QUALITY_POLICY`, re-run `PYTHONPATH=src python3 -m aiedge release-quality-gate --metrics <run-dir>/metrics.json --report <run-dir>/report/report.json --out <run-dir>/quality_gate.json` and inspect `errors[]` in `quality_gate.json`.
   - `QUALITY_GATE_LLM_REQUIRED`: run included `--llm-primary` but no usable LLM gate payload; provide `--report <run-dir>/report/report.json` and ensure report includes `llm.status`, or pass `--llm-fixture <fixture.json>`.
   - `QUALITY_GATE_LLM_INVALID`: LLM gate verdict was present but not one of `{pass, fail}`; fix fixture/report payload and re-run.
   - `QUALITY_GATE_LLM_VERDICT_MISS`: LLM gate verdict is missing or resolved to fail; verify `report.llm.status == "ok"` (derived pass path) or provide a fixture with `{"verdict": "pass"}`.
5. If token is `EXPLOIT_TIER_POLICY`, inspect `<run-dir>/report/report.json` and `<run-dir>/stages/exploit_policy/policy.json` for tier errors and blocked/forbidden entries.
6. If token is `TAMPER_SUITE`, run `python3 -m pytest -q tests/test_tamper_suite.py` and remediate the first failing invariant.
7. Re-run `python3 scripts/audit_package_validate.py --run-dir <run-dir>`; do not hand off unless `"ok": true`.

## Audit Package Checklist (Machine-Checkable)

- `manifest.json`: must contain non-empty `ref_md_sha256` (`python3 scripts/audit_package_validate.py --run-dir <run-dir>`).
- `report/report.json`: must contain non-empty `overview.ref_md_sha256` and match `manifest.json` (`python3 scripts/audit_package_validate.py --run-dir <run-dir>`).
- `metrics.json`: must contain non-empty `corpus_id` (`python3 scripts/audit_package_validate.py --run-dir <run-dir>`).
- `quality_gate.json`: must contain `verdict` in `{pass, fail}` (`python3 scripts/audit_package_validate.py --run-dir <run-dir>`).
- Release governance artifacts must exist and be current (`PYTHONPATH=src scripts/release_gate.sh --run-dir <run-dir>` writes `metrics.json` and `quality_gate.json`).
