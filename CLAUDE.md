# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SCOUT (AIEdge) is a deterministic firmware-to-exploit evidence engine. It takes firmware blobs as input and produces hash-anchored evidence artifacts through a 42-stage sequential pipeline — from unpacking through vulnerability discovery to exploit chain verification. SCOUT is the evidence-production layer; a separate orchestrator (Terminator) applies LLM judgment and dynamic validation on top via `firmware_handoff.json`.

**Key constraints:** Pure Python 3.10+ with zero pip dependencies (stdlib only). External tools (binwalk, QEMU, FirmAE, docker) are runtime-optional.

## Build, Test, and Run Commands

```bash
# CLI help
./scout --help

# Full analysis (all features enabled by default)
./scout analyze firmware.bin

# Suppress real-time progress output (CI/scripted use)
./scout analyze firmware.bin --quiet

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

# Linting (ruff configured via pyproject.toml)
ruff check src/

# Type checking (pyright configured via pyrightconfig.json)
pyright src/

# Quality and verification
./scout corpus-validate aiedge-runs/<run_id>
./scout quality-metrics aiedge-runs/<run_id>
./scout quality-gate aiedge-runs/<run_id>
./scout release-quality-gate aiedge-runs/<run_id>
scripts/release_gate.sh --run-dir aiedge-runs/<run_id>
python3 scripts/verify_analyst_digest.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_verified_chain.py --run-dir aiedge-runs/<run_id>

# TUI dashboard
./scout tui aiedge-runs/<run_id> --interactive   # interactive mode
./scout tw aiedge-runs/<run_id> -t 2             # live-refresh (watch)
./scout ti                                       # interactive, latest run
./scout to                                       # once mode
./scout t                                        # latest run

# Serve report viewer
./scout serve aiedge-runs/<run_id>

# MCP server for AI agent integration
./scout mcp [--project-id <run_id>]
```

**Exit codes:** 0 = success, 10 = partial success, 20 = fatal error, 30 = policy violation.

**Default time budget:** `--time-budget-s 3600` (1 hour).

## Architecture

### Stage Pipeline

Stages execute sequentially via `run_stages()` in `src/aiedge/stage.py`. Each stage implements the `Stage` Protocol (structural typing, not ABC) with `name: str` property and `run(ctx: StageContext) -> StageOutcome` method. Stages are registered as factory functions in `src/aiedge/stage_registry.py` (`_STAGE_FACTORIES` dict, 42 entries).

> Full execution order, v2.0 stage details, IPC flow, and special patterns: see `.claude/rules/pipeline-architecture.md`

### Inter-Stage Communication

Stages have **no in-memory coupling**. Each stage reads JSON artifacts from `run_dir/stages/<predecessor>/` and writes to `run_dir/stages/<own_name>/`. The `stage.json` file records status, timing, artifact paths with SHA-256 hashes, and limitations.

### Key Abstractions

| Type | Location | Purpose |
|------|----------|---------|
| `Stage` Protocol | `stage.py:59-63` | Interface all stages implement |
| `StageContext` | `stage.py:25-29` | Frozen dataclass: `run_dir`, `logs_dir`, `report_dir` |
| `StageOutcome` | `stage.py:32-36` | Result: `status`, `details`, `limitations` |
| `StageFactory` | `stage_registry.py:36` | `Callable[[_RunInfoLike, str\|None, Callable[[], float], bool], Stage]` |
| `LLMDriver` Protocol | `llm_driver.py` | Unified LLM backend interface |
| `ConfidenceCaps` | `confidence_caps.py` | 4 caps: SYMBOL_COOCCURRENCE=0.40, STATIC_CODE_VERIFIED=0.55, STATIC_ONLY=0.60, PCODE_VERIFIED=0.75 |
| `AIEdgePolicyViolation` | `policy.py` | Security exception for path traversal prevention |

> LLM drivers, evidence chain, and governance details: see `.claude/rules/evidence-governance.md`

## Adding a New Pipeline Stage

1. Create `src/aiedge/your_stage.py` implementing the `Stage` protocol
2. Add a factory function in `stage_registry.py` and register in `_STAGE_FACTORIES`
3. Import and use `assert_under_dir` from `path_safety.py` for all file writes
4. Stage output goes to `run_dir/stages/your_stage/stage.json` + artifacts
5. The factory signature is `(run_info, case_id, remaining_budget_fn, no_llm) -> Stage`
6. Add tests in `tests/test_your_stage.py`
7. In `run.py`, wrap each stage import in its own `try/except ImportError` block

## Design Invariants

- **All artifact paths must be run-dir-relative.** `assert_under_dir()` enforces path traversal prevention.
- **Stages fail open, governance fails closed.** Stages return `partial`; promotion gates reject incomplete evidence.
- **No finding without evidence.** Every finding requires file path, offset, hash, and rationale.
- **Handoff validation is mandatory.** `firmware_handoff.json` validated via `validate_handoff()` before write.
- **`--ack-authorization` is mandatory** for every analysis.
- **Generated runtime artifacts** (`aiedge-runs/`, `aiedge-inputs/`, `aiedge-8mb-runs/`) — never commit them.

## Detailed Reference

| Topic | Location |
|-------|----------|
| Pipeline execution order, v2.0 stages, IPC, CLI modules | `.claude/rules/pipeline-architecture.md` |
| Confidence caps, exploit tiering, LLM drivers, path safety | `.claude/rules/evidence-governance.md` |
| Critical coupling points, test infrastructure, scripts | `.claude/rules/coupling-test.md` |
| Environment variables, documentation index, artifact schemas | `.claude/rules/environment-config.md` |
