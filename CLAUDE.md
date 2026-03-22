# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SCOUT (AIEdge) is a deterministic firmware-to-exploit evidence engine. It takes firmware blobs as input and produces hash-anchored evidence artifacts through a 30-stage sequential pipeline — from unpacking through vulnerability discovery to exploit chain verification. SCOUT is the evidence-production layer; a separate orchestrator (Terminator) applies LLM judgment and dynamic validation on top via `firmware_handoff.json`.

**Key constraints:** Pure Python 3.10+ with zero pip dependencies (stdlib only). External tools (binwalk, QEMU, FirmAE, docker) are runtime-optional.

## Build, Test, and Run Commands

```bash
# CLI help
./scout --help

# Deterministic analysis (no LLM)
./scout analyze firmware.bin --ack-authorization --no-llm --case-id <id>

# With specific stages
./scout analyze firmware.bin --ack-authorization --no-llm --case-id <id> \
  --stages tooling,extraction,structure,carving,firmware_profile,inventory

# Pre-extracted rootfs bypass (when extraction is weak)
./scout analyze firmware.img --ack-authorization --no-llm --case-id <id> \
  --rootfs /path/to/extracted/rootfs

# 8MB canonical track (truncated input for quick profiling)
./scout analyze-8mb firmware.bin --ack-authorization --no-llm --case-id <id>

# Rerun specific stages on existing run
./scout stages aiedge-runs/<run_id> --no-llm --stages inventory

# Full exploit profile (requires authorization flags)
./scout analyze firmware.bin --ack-authorization --case-id <id> \
  --profile exploit --exploit-flag lab --exploit-attestation authorized --exploit-scope lab-only

# Run tests
pytest -q                                        # full suite
pytest -q tests/test_inventory.py                # single module
pytest -q tests/test_inventory.py::test_func     # single test

# Type checking (pyright configured via pyrightconfig.json)
pyright src/

# Quality and verification
./scout corpus-validate aiedge-runs/<run_id>              # corpus manifest validation
./scout quality-metrics aiedge-runs/<run_id>               # compute quality metrics
./scout quality-gate aiedge-runs/<run_id>                  # check quality thresholds
./scout release-quality-gate aiedge-runs/<run_id>          # unified release gate (CLI)
scripts/release_gate.sh --run-dir aiedge-runs/<run_id>     # unified release gate (shell)
python3 scripts/verify_analyst_digest.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_verified_chain.py --run-dir aiedge-runs/<run_id>

# TUI dashboard (./scout provides shortcut aliases)
./scout tui aiedge-runs/<run_id> --interactive   # interactive mode
./scout tw aiedge-runs/<run_id> -t 2             # live-refresh (watch)
./scout ti                                       # alias: tui -i (interactive, latest run)
./scout to                                       # alias: tui -m once
./scout t                                        # alias: tui (latest run)

# Serve report viewer
./scout serve aiedge-runs/<run_id>
```

**Exit codes:** 0 = success, 10 = partial success, 20 = fatal error, 30 = policy violation.

**Default time budget:** `--time-budget-s 3600` (1 hour). Stages receive a remaining-budget callback and should respect it.

## Architecture

### Stage Pipeline

Stages execute sequentially via `run_stages()` in `src/aiedge/stage.py`. Each stage implements the `Stage` Protocol (structural typing, not ABC):
- Property `name: str`
- Method `run(ctx: StageContext) -> StageOutcome`

Stages are registered as factory functions in `src/aiedge/stage_registry.py` (`_STAGE_FACTORIES` dict, 29 entries). Stage factories are instantiated by `run.py` which manages run directories, manifests, and report finalization.

**Execution order:** tooling → extraction → structure → carving → firmware_profile → inventory → endpoints → surfaces → web_ui → graph → attack_surface → functional_spec → threat_model → **findings** → **llm_triage** → llm_synthesis → attribution → dynamic_validation → emulation → exploit_gate → exploit_chain → exploit_autopoc → poc_validation → exploit_policy (plus OTA-specific stages: ota, ota_payload, ota_fs, ota_roots, ota_boottriage, firmware_lineage)

### Inter-Stage Communication

Stages have **no in-memory coupling**. Each stage reads JSON artifacts from predecessor directories in `run_dir/stages/<predecessor>/` and writes to `run_dir/stages/<own_name>/`. The `stage.json` file in each stage directory records status, timing, artifact paths with SHA-256 hashes, and limitations.

### Key Abstractions

| Type | Location | Purpose |
|------|----------|---------|
| `Stage` Protocol | `stage.py:59-63` | Interface all stages implement |
| `StageContext` | `stage.py:25-29` | Frozen dataclass: `run_dir`, `logs_dir`, `report_dir` |
| `StageOutcome` | `stage.py:33-36` | Result: `status` (ok/partial/failed/skipped), `details`, `limitations` |
| `StageFactory` | `stage_registry.py:36` | `Callable[[_RunInfoLike, str|None, Callable[[], float], bool], Stage]` |
| `RunReport` | `stage.py:53-56` | Aggregated result of all stages |
| `LLMDriver` Protocol | `llm_driver.py:30-47` | Unified LLM backend interface (`name`, `available()`, `execute()`) |
| `ModelTier` | `llm_driver.py:15` | `Literal["haiku", "sonnet", "opus"]` for LLM tier selection |

### Evidence & Governance Layers

- **Confidence caps** (`confidence_caps.py`): Static-only findings capped at 0.60 confidence
- **Exploit tiering** (`exploit_tiering.py`): suspected → strong_static → dynamic_repro → exploitability_assessed
- **Determinism** (`determinism.py`): Canonical JSON bundles ensure reproducible runs
- **Quality gates** (`quality_policy.py`, `quality_metrics.py`): Threshold checks and corpus-based evaluation
- **Schema validation** (`schema.py`): Report validation, version tracking, verdict semantics
- **Duplicate gate** (`duplicate_gate.py`): Cross-run duplicate suppression with Terminator feedback integration

### LLM Driver Abstraction

`llm_driver.py` provides an `LLMDriver` Protocol with `CodexCLIDriver` implementation. All LLM call sites (`llm_synthesis`, `exploit_autopoc`, `llm_codex`) use `resolve_driver()` to get the active backend. Select provider via `AIEDGE_LLM_DRIVER` env var. Supports `ModelTier` for automatic model selection. Stages gracefully skip LLM calls under `--no-llm`.

### Findings Stage — Special Pattern

The `findings` stage is **not** registered in `_STAGE_FACTORIES`. It runs as an integrated step via `run_findings(ctx)` called directly from `run.py` during full `analyze`/`analyze-8mb` execution, after all registered stages complete. It cannot be invoked standalone via `--stages findings`. Its output goes to `run_dir/stages/findings/*.json`.

### exploit_gate — Inline Stage

`exploit_gate` is registered in `_STAGE_FACTORIES` but has no dedicated module file. Its factory `_make_exploit_gate_stage` is defined inline in `stage_registry.py`.

### CLI Entry Point

`__main__.py` (4498 lines) contains all CLI subcommands, TUI rendering, and the report viewer. Subcommands: `analyze`, `analyze-8mb`, `stages`, `corpus-validate`, `quality-metrics`, `quality-gate`, `release-quality-gate`, `serve`, `tui`. Parser is built in `_build_parser()` (line 3367), dispatched in `main()` (line 3905). The `./scout` shell wrapper adds short aliases (`t`, `ti`, `tw`, `to`) and sets up `PYTHONPATH`.

### Path Safety

`_assert_under_dir()` enforces that artifact paths stay within the run directory. The canonical definition lives in `findings.py` (line 27-33); each stage module defines its own local copy. This appears across 23 stage modules (122 total call sites). Every file write in a stage must pass this check — it is a critical security invariant.

## Adding a New Pipeline Stage

1. Create `src/aiedge/your_stage.py` implementing the `Stage` protocol
2. Add a factory function in `stage_registry.py` and register in `_STAGE_FACTORIES`
3. Use `_assert_under_dir(ctx.run_dir, path)` for all file writes
4. Stage output goes to `run_dir/stages/your_stage/stage.json` + artifacts
5. The factory signature is `(run_info, case_id, remaining_budget_fn, no_llm) -> Stage`
6. Add tests in `tests/test_your_stage.py`

## Critical Coupling Points

- **`stage.py`** Protocol/dataclass changes affect all 30 stages
- **`schema.py`** validation changes affect report generation, quality gates, and all verification scripts
- **`run.py`** report finalization changes affect all verification scripts and handoff generation
- **`exploit_tiering.py`** tier definitions are imported by `schema.py`, `findings.py`, and exploit stages
- **`terminator_feedback.py`** bridges SCOUT↔Terminator bidirectional feedback; changes affect handoff contract
- Individual stage modules are well-isolated and safe to modify independently

## Environment Variables

Key configuration prefixes (no config files, environment-variable-driven):
- `AIEDGE_PORTSCAN_*` — port scanning parameters (TOP_K, START, END, WORKERS, BUDGET_S, FULL_RANGE)
- `AIEDGE_LLM_CHAIN_*` — LLM synthesis timeouts and retry limits
- `AIEDGE_AUTOPOC_LLM_*` — Auto-PoC LLM parameters
- `AIEDGE_PRIV_RUNNER` — privileged command prefix for dynamic validation
- `AIEDGE_ATTACK_SURFACE_MAX_*` — attack surface scan limits
- `AIEDGE_BINARY_STRINGS_BUDGET` — binary strings analysis budget
- `AIEDGE_DUPLICATE_*` — cross-run duplicate suppression
- `AIEDGE_TUI_ASCII` — force ASCII-only TUI rendering
- `AIEDGE_RUNS_DIRS` — custom run output directories
- `AIEDGE_LLM_DRIVER` — LLM provider selection (default: codex)
- `AIEDGE_EMULATION_IMAGE` — Docker image for Tier 1 FirmAE emulation (default: scout-emulation:latest)
- `AIEDGE_FIRMAE_ROOT` — FirmAE installation path (default: /opt/FirmAE)
- `AIEDGE_FEEDBACK_DIR` — Terminator feedback directory for bidirectional handoff

## Design Invariants

- **All artifact paths must be run-dir-relative.** Absolute paths in outputs are bugs. `_assert_under_dir()` enforces path traversal prevention.
- **Stages fail open, governance fails closed.** Individual stages return `partial` with whatever they could produce. Promotion gates (quality gate, release gate, verified chain) reject incomplete evidence.
- **No finding without evidence.** Every finding requires file path, offset, hash, and rationale.
- **`--ack-authorization` is mandatory** for every analysis. Exploit profile requires additional attestation flags.
- **Generated runtime artifacts** (`aiedge-runs/`, `aiedge-inputs/`, `aiedge-8mb-runs/`) are local outputs — never commit them.

## Documentation

| Document | Purpose |
|----------|---------|
| `docs/blueprint.md` | Full pipeline architecture and design rationale |
| `docs/status.md` | Current implementation status |
| `docs/aiedge_firmware_artifacts_v1.md` | Schema contracts for profiling + inventory |
| `docs/aiedge_adapter_contract.md` | Terminator↔SCOUT handoff protocol |
| `docs/aiedge_report_contract.md` | Report structure and governance rules |
| `docs/analyst_digest_contract.md` | Analyst digest schema and verdict semantics |
| `docs/verified_chain_contract.md` | Verified chain evidence requirements |
| `docs/aiedge_duplicate_gate_contract.md` | Cross-run duplicate suppression rules |
| `docs/runbook.md` | Operator flow for digest-first review |
