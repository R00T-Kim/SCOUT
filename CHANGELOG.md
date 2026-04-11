# Changelog

All notable changes to SCOUT are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [2.3.0] — 2026-04-11

### Added
- Adversarial triage parallelization via ThreadPoolExecutor (`AIEDGE_ADV_PARALLEL`, default 8) — 6h→50min per firmware
- `AIEDGE_CODEX_MODEL` env var for configurable Codex model (default: `gpt-5.3-codex`)
- `ClaudeCodeCLIDriver` for OAuth-based LLM calls via Claude Code CLI
- Real-time CLI progress display (`ProgressTracker` module)
- `benchmark_eval.py` — analyst readiness evaluation, bundle verifier, metrics collection
- `DESIGN.md` — visual design system documentation (indigo/purple palette, glassmorphism)
- Benchmark scripts: `rebenchmark_v2.sh`, `rerun_adv_triage_codex.sh`, `rerun_adv_triage_parallel.sh`
- Tier 2 LLM benchmark: 36 firmware, 2430 findings debated, 99.3% FPR reduction, 18 maintained true findings

### Changed
- TUI rebranded AIEdge → SCOUT, header color cyan → magenta
- Viewer color palette refreshed: indigo/purple theme, subtler glassmorphism
- Relicensed from MIT to Apache 2.0 (LICENSE, NOTICE, pyproject.toml, README)
- Default Codex model changed from `gpt-5.4` to `gpt-5.3-codex`
- Default model tier set to `sonnet` for `llm_triage`
- LLM JSON response parsing consolidated into shared `parse_json_from_llm_output()` 3-stage fallback
- `--quiet` flag added for CI/scripted pipeline runs

### Fixed
- pyright `ConvertibleToFloat` errors in `adversarial_triage`, `attribution`, `benchmark_eval`
- Unused `_ANSI_CYAN` import and external font URL in viewer
- 19 LLM pipeline bugs across taint/FP/adversarial/classifier stages
- ClaudeCodeCLIDriver: MCP/plugins disabled to prevent stuck processes
- Unused `re` imports removed after parse consolidation

## [2.2.0] — 2026-04-01

### Added
- D-Link SHRS AES-128-CBC automatic decryption (`vendor_decrypt.py`)
- binwalk v3 compatibility with entropy-based detection
- CVE signature expansion: 13 → 25 signatures, 8 new vendors
- Ghidra decompiled code + xref chain injection into `fp_verification`
- Static pre-filters run in `--no-llm` mode
- 3 new static FP reduction rules (sanitizer/non-propagating/sysfile)
- Tier 1 benchmark baseline frozen (`tier1_rebenchmark_frozen_baseline.md`)
- `rerun_benchmark_stages.py` and `reevaluate_benchmark_results.py` scripts

### Changed
- Pipeline reordered: `ghidra_analysis` before `taint_propagation`/`semantic_classification`
- Stage factory count updated to 42
- 2-tier confidence caps: `SYMBOL_COOCCURRENCE_CAP=0.40`, `STATIC_CODE_VERIFIED_CAP=0.55`
- `no_xref_path` demoted from FP verdict to confidence reduction

### Fixed
- PLT stub function skip in decompiled context for FP verification
- Pandawan integration path resolution
- Ghidra stage ordering bug (moved before semantic classification)

## [2.1.0] — 2026-03-31

### Added
- CVE detection precision: known signatures, web server auto-detection, Ghidra auto-detect
- NVD local database matching (2,239 CVEs bulk download + `cve_rematch`)
- CVE rematch + findings analysis scripts
- Pandawan/FirmSolo Tier 1.5 emulation fallback
- `csource_identification` stage: HTTP input source identification
- Cross-binary IPC chain construction (5 edge types)

### Changed
- README restructured with FirmAgent comparison
- Pipeline expanded to 41 stages

### Fixed
- `no_signals` false positive removed
- Tests updated for `no_signals` removal

## [2.0.0] — 2026-02-16

Initial open-source release. Deterministic firmware-to-exploit evidence engine with 34-stage pipeline, hash-anchored artifact chains, and zero pip dependencies.

### Key Features
- 34-stage sequential pipeline (tooling → extraction → exploit_policy)
- SBOM (CycloneDX 1.6 + VEX), SARIF 2.1.0 export
- Ghidra headless integration, AFL++ fuzzing, FirmAE emulation
- MCP server (12 tools) for AI agent integration
- Web report viewer with glassmorphic dashboard
- Quality gates, release gates, and verified evidence chains
