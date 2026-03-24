# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SCOUT (AIEdge) is a deterministic firmware-to-exploit evidence engine. It takes firmware blobs as input and produces hash-anchored evidence artifacts through a 34-stage sequential pipeline — from unpacking through vulnerability discovery to exploit chain verification. SCOUT is the evidence-production layer; a separate orchestrator (Terminator) applies LLM judgment and dynamic validation on top via `firmware_handoff.json`.

**Key constraints:** Pure Python 3.10+ with zero pip dependencies (stdlib only). External tools (binwalk, QEMU, FirmAE, docker) are runtime-optional.

## Build, Test, and Run Commands

```bash
# CLI help
./scout --help

# Full analysis (all features enabled by default)
./scout analyze firmware.bin

# Deterministic analysis (no LLM)
./scout analyze firmware.bin --no-llm

# With specific stages
./scout analyze firmware.bin --no-llm \
  --stages tooling,extraction,structure,carving,firmware_profile,inventory

# Pre-extracted rootfs bypass (when extraction is weak)
./scout analyze firmware.img --no-llm --rootfs /path/to/extracted/rootfs

# 8MB canonical track (truncated input for quick profiling)
./scout analyze-8mb firmware.bin --no-llm

# Rerun specific stages on existing run
./scout stages aiedge-runs/<run_id> --no-llm --stages inventory

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

# MCP server for AI agent integration
./scout mcp [--project-id <run_id>]
```

**Exit codes:** 0 = success, 10 = partial success, 20 = fatal error, 30 = policy violation.

**Default time budget:** `--time-budget-s 3600` (1 hour). Stages receive a remaining-budget callback and should respect it.

## Architecture

### Stage Pipeline

Stages execute sequentially via `run_stages()` in `src/aiedge/stage.py`. Each stage implements the `Stage` Protocol (structural typing, not ABC):
- Property `name: str`
- Method `run(ctx: StageContext) -> StageOutcome`

Stages are registered as factory functions in `src/aiedge/stage_registry.py` (`_STAGE_FACTORIES` dict, 34 entries). Stage factories are instantiated by `run.py` which manages run directories, manifests, and report finalization.

**Execution order:** tooling → extraction → structure → carving → firmware_profile → inventory → ghidra_analysis → sbom → cve_scan → reachability → endpoints → surfaces → web_ui → graph → attack_surface → functional_spec → threat_model → findings → llm_triage → llm_synthesis → attribution → dynamic_validation → emulation → fuzzing → exploit_gate → exploit_chain → exploit_autopoc → poc_validation → exploit_policy (plus OTA-specific stages: ota, ota_payload, ota_fs, ota_roots, ota_boottriage, firmware_lineage)

**IPC detection flow:** inventory → endpoints → surfaces → graph → attack_surface. ELF `.rodata`/`.dynstr` IPC symbol extraction occurs in inventory; `ipc_channel` graph nodes and 5 IPC edge types (`ipc_unix_socket`, `ipc_dbus`, `ipc_shm`, `ipc_pipe`, `ipc_exec_chain`) are emitted by graph stage.

### Inter-Stage Communication

Stages have **no in-memory coupling**. Each stage reads JSON artifacts from predecessor directories in `run_dir/stages/<predecessor>/` and writes to `run_dir/stages/<own_name>/`. The `stage.json` file in each stage directory records status, timing, artifact paths with SHA-256 hashes, and limitations.

### Key Abstractions

| Type | Location | Purpose |
|------|----------|---------|
| `Stage` Protocol | `stage.py:59-63` | Interface all stages implement |
| `StageContext` | `stage.py:25-29` | Frozen dataclass: `run_dir`, `logs_dir`, `report_dir` |
| `StageOutcome` | `stage.py:32-36` | Result: `status` (ok/partial/failed/skipped), `details`, `limitations` |
| `StageFactory` | `stage_registry.py:36` | `Callable[[_RunInfoLike, str|None, Callable[[], float], bool], Stage]` |
| `RunReport` | `stage.py:52-56` | Aggregated result of all stages |
| `LLMDriver` Protocol | `llm_driver.py` | Unified LLM backend interface (`name`, `available()`, `execute()`) |
| `ModelTier` | `llm_driver.py` | `Literal["haiku", "sonnet", "opus"]` for LLM tier selection |
| `AIEdgePolicyViolation` | `policy.py` | Security exception raised by `assert_under_dir()` and authorization checks |

### LLM Driver Abstraction

`llm_driver.py` provides an `LLMDriver` Protocol with three implementations:
- `CodexCLIDriver` — wraps `codex exec --ephemeral` (default)
- `ClaudeAPIDriver` — direct Claude API via `urllib.request` (`ANTHROPIC_API_KEY`)
- `OllamaDriver` — local Ollama HTTP API (`AIEDGE_OLLAMA_URL`)

Select via `AIEDGE_LLM_DRIVER=codex|claude|ollama`. All three support `ModelTier` (haiku/sonnet/opus) selection. All LLM call sites (`llm_synthesis`, `exploit_autopoc`, `llm_codex`) use `resolve_driver()` to get the active backend. Cost tracking via `llm_cost.py` with optional budget limit (`AIEDGE_LLM_BUDGET_USD`). Stages gracefully skip LLM calls under `--no-llm`.

### Evidence & Governance Layers

- **Confidence caps** (`confidence_caps.py`): Static-only findings capped at 0.60 confidence
- **Exploit tiering** (`exploit_tiering.py`): suspected → strong_static → dynamic_repro → exploitability_assessed
- **Determinism** (`determinism.py`): Canonical JSON bundles ensure reproducible runs
- **Quality gates** (`quality_policy.py`, `quality_metrics.py`): Threshold checks and corpus-based evaluation
- **Schema validation** (`schema.py`): Report validation, version tracking, verdict semantics
- **Duplicate gate** (`duplicate_gate.py`): Cross-run duplicate suppression with Terminator feedback integration

### Path Safety — Critical Security Invariant

`assert_under_dir()` in `path_safety.py` is the canonical implementation that enforces artifact paths stay within the run directory. Many stage modules still define a local `_assert_under_dir()` copy (26 files, ~130 call sites). New code should import from `path_safety.py`. Every file write in a stage must pass this check.

### Special Stage Patterns

- **`findings` stage**: NOT registered in `_STAGE_FACTORIES`. Runs as an integrated step via `run_findings(ctx)` called from `run.py` after all registered stages complete. Cannot be invoked standalone via `--stages findings`.
- **`exploit_gate` stage**: Registered in `_STAGE_FACTORIES` but has no dedicated module file. Its factory `_make_exploit_gate_stage` is defined inline in `stage_registry.py`.

### CLI Entry Point

`__main__.py` (~4500 lines) contains all CLI subcommands, TUI rendering, and the report viewer. Subcommands: `analyze`, `analyze-8mb`, `stages`, `corpus-validate`, `quality-metrics`, `quality-gate`, `release-quality-gate`, `serve`, `mcp`, `tui`. Parser is built in `_build_parser()` (line 3367), dispatched in `main()` (line 3921). The `./scout` shell wrapper adds short aliases (`t`, `ti`, `tw`, `to`) and sets up `PYTHONPATH`.

## Adding a New Pipeline Stage

1. Create `src/aiedge/your_stage.py` implementing the `Stage` protocol
2. Add a factory function in `stage_registry.py` and register in `_STAGE_FACTORIES`
3. Import and use `assert_under_dir` from `path_safety.py` for all file writes
4. Stage output goes to `run_dir/stages/your_stage/stage.json` + artifacts
5. The factory signature is `(run_info, case_id, remaining_budget_fn, no_llm) -> Stage`
6. Add tests in `tests/test_your_stage.py`

## Critical Coupling Points

- **`stage.py`** Protocol/dataclass changes affect all 34 registered stages
- **`schema.py`** validation changes affect report generation, quality gates, and all verification scripts
- **`run.py`** report finalization changes affect all verification scripts and handoff generation
- **`exploit_tiering.py`** tier definitions are imported by `schema.py`, `findings.py`, and exploit stages
- **`terminator_feedback.py`** bridges SCOUT↔Terminator bidirectional feedback; changes affect handoff contract
- **`reporting.py`** report generation logic imported by `run.py`; changes affect all output formats
- **`policy.py`** defines `AIEdgePolicyViolation` used by `assert_under_dir()` across 26 stage modules
- Individual stage modules are well-isolated and safe to modify independently

## Test Infrastructure

Configured via `pyproject.toml`: `testpaths = ["tests"]`, `pythonpath = ["src"]`, `addopts = "-q"`. No `conftest.py` — each test file is self-contained, creating its own temporary directories via `tmp_path`. 83 test files covering stage logic, schema contracts, CLI behavior, and E2E report validation.

**Verification scripts** in `scripts/` validate run outputs post-execution:
- `verify_analyst_digest.py` / `verify_verified_chain.py` — evidence chain integrity
- `verify_aiedge_final_report.py` / `verify_aiedge_analyst_report.py` — report schema compliance
- `verify_exploit_meaningfulness.py` — exploit artifact quality
- `verify_network_isolation.py` / `verify_run_dir_evidence_only.py` — security invariants
- `build_verified_chain.py` — constructs verified chain from run artifacts
- `release_gate.sh` — unified release quality gate (wraps CLI `release-quality-gate`)

**E2E scripts** in `scripts/`: `e2e_aiedge_matrix.sh` (full pipeline), `e2e_aiedge_8mb_track.sh` (truncated track), `e2e_er_e50_inventory_regression.sh` (regression).

## Environment Variables

All configuration is environment-variable-driven (no config files). Key variables:

| Variable | Purpose | Default |
|----------|---------|---------|
| `AIEDGE_LLM_DRIVER` | LLM provider: `codex`, `claude`, `ollama` | `codex` |
| `ANTHROPIC_API_KEY` | Claude API key (required for `claude` driver) | — |
| `AIEDGE_OLLAMA_URL` | Ollama server URL | `http://localhost:11434` |
| `AIEDGE_LLM_BUDGET_USD` | LLM cost budget limit per run | unlimited |
| `AIEDGE_NVD_API_KEY` | NVD API key for higher CVE scan rate limits | — |
| `AIEDGE_NVD_CACHE_DIR` | Cross-run NVD response cache directory | — |
| `AIEDGE_GHIDRA_HOME` | Ghidra installation path | PATH fallback |
| `AIEDGE_GHIDRA_MAX_BINARIES` | Max binaries for Ghidra analysis | `10` |
| `AIEDGE_GHIDRA_TIMEOUT_S` | Per-binary Ghidra timeout | `300` |
| `AIEDGE_AFLPP_IMAGE` | AFL++ Docker image | `aflplusplus/aflplusplus` |
| `AIEDGE_FUZZ_BUDGET_S` | Per-target fuzzing budget (seconds) | `300` |
| `AIEDGE_FUZZ_MAX_TARGETS` | Max fuzzing targets | `3` |
| `AIEDGE_EMULATION_IMAGE` | Docker image for FirmAE emulation | `scout-emulation:latest` |
| `AIEDGE_FIRMAE_ROOT` | FirmAE installation path | `/opt/FirmAE` |
| `AIEDGE_QEMU_GDB_PORT` | GDB stub port for emulation | `1234` |
| `AIEDGE_FEEDBACK_DIR` | Terminator feedback directory | — |
| `AIEDGE_MCP_MAX_OUTPUT_KB` | MCP tool output truncation limit | `30` |
| `AIEDGE_PRIV_RUNNER` | Privileged command prefix for dynamic validation | — |
| `AIEDGE_TUI_ASCII` | Force ASCII-only TUI rendering | — |
| `AIEDGE_RUNS_DIRS` | Custom run output directories | — |

Additional prefixes: `AIEDGE_PORTSCAN_*` (port scanning), `AIEDGE_LLM_CHAIN_*` (LLM synthesis), `AIEDGE_AUTOPOC_LLM_*` (auto-PoC), `AIEDGE_ATTACK_SURFACE_MAX_*` (scan limits), `AIEDGE_DUPLICATE_*` (dedup), `AIEDGE_SBOM_MAX_COMPONENTS` (default 500), `AIEDGE_CVE_SCAN_MAX_COMPONENTS` (default 50), `AIEDGE_CVE_SCAN_TIMEOUT_S` (default 30).

## Design Invariants

- **All artifact paths must be run-dir-relative.** Absolute paths in outputs are bugs. `assert_under_dir()` enforces path traversal prevention.
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
| `docs/aiedge_8mb_track_runbook.md` | 8MB truncated track operator guide |
| `docs/e2e_terminator_aiedge_stage_control.md` | Terminator↔SCOUT stage control integration |
| `docs/analyst_viewer_cockpit_mapping.md` | Viewer panel-to-artifact mapping |

### Runtime Artifact Schemas (generated per-run, not committed)

| Artifact | Location | Schema |
|----------|----------|--------|
| Source→sink graph | `stages/surfaces/source_sink_graph.json` | `source-sink-v1` |
| Credential mapping | `stages/findings/credential_mapping.json` | `credential-mapping-v1` |
| Communication graph | `stages/graph/communication_graph.json` | Per-run network topology |
| Firmware handoff | `firmware_handoff.json` | SCOUT→Terminator contract |
