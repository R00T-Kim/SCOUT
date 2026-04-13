# Changelog

All notable changes to SCOUT are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [2.5.0] — 2026-04-13

### Added
- **`llm_prompts.py`** — Centralized system prompt module: `STRUCTURED_JSON_SYSTEM`, `ADVOCATE_SYSTEM`, `CRITIC_SYSTEM`, `TAINT_SYSTEM`, `CLASSIFIER_SYSTEM`, `REPAIR_SYSTEM`, `SYNTHESIS_SYSTEM` + temperature constants
- **LLMDriver Protocol**: `system_prompt: str = ""` and `temperature: float | None = None` parameters wired into all 4 drivers (CodexCLI, ClaudeAPI, ClaudeCodeCLI, Ollama)
- **EPSS scoring** in `cve_scan.py`: FIRST.org API integration with batched queries, per-run + cross-run cache, confidence adjustment based on EPSS percentile
- **Sink expansion** (`taint_propagation.py`): `_SINK_SYMBOLS` 11 → 28 entries (memcpy, memmove, strcat, strncpy, gets, vsprintf, printf, fprintf, syslog, vprintf, vfprintf, snprintf, scanf, sscanf, fscanf, dlopen, realpath)
- **Format string sink set**: `_FORMAT_STRING_SINKS` + `_is_format_string_variable()` helper for variable-controlled format string detection
- **GitHub Action**: `.github/actions/scout-scan/` composite action for CI/CD with SARIF upload to GitHub Security tab
- **CRA compatibility documentation**: `docs/cra_compliance_mapping.md` mapping all 12 EU Cyber Resilience Act Annex I requirements to SCOUT outputs (output formats compatible with CRA Annex I)
- **Strategic roadmap**: `docs/strategic_roadmap_2026.md` 3-Phase plan based on 30+ academic papers and competitive analysis (Theori Xint, FirmAgent, EU CRA)
- LLM failure observability: `parse_failures` vs `llm_call_failures` separation in `adversarial_triage.py` and `fp_verification.py`
- Common LLM failure classification helpers in `llm_driver.py` (`quota_exhausted`, `driver_unavailable`, `driver_nonzero_exit`)

### Fixed
- **`parse_json_from_llm_output()`** rewritten as 5-stage parser: preamble strip → fence extract → raw text → brace-counting object extraction → common error fix (trailing commas, single quotes). Optional `required_keys` schema validation
- **CVE scan signature-only path**: removed early `return` so signature-only matches go through the same enrichment/finding-candidate pipeline as NVD matches
- **CVE scan `comp` variable bug**: backport confidence adjustment now uses per-match component metadata instead of leaked outer loop variable (was incorrectly applying last component's metadata to all matches)
- **Semantic classifier batch size**: reduced from 50 → 15 functions per LLM call to prevent JSON schema loss in long contexts

### Changed
- All LLM-using stages now pass appropriate `system_prompt` and `temperature` (deterministic 0.0 for JSON tasks, analytical 0.3 for advocate/critic debate)
- `adversarial_triage.py`: advocate/critic prompts cleaned (persona moved to system prompt), few-shot examples added
- `fp_verification.py`: unverified outcomes now distinguish parse failures from driver call failures
- `taint_propagation.py`: `_NETWORK_INPUT_SYMBOLS` expanded with `read`, `fread`

### Verified
- **R7000 (Netgear, 31MB) end-to-end run** (codex driver, 2026-04-13):
  - `adversarial_triage`: debated=100, parsed_ok=100, **parse_failures=0**, llm_call_failures=0, downgraded=99, maintained=1
  - `fp_verification`: eligible=100, true_positives=57, false_positives=43, **unverified=0**, parse_failures=0, llm_call_failures=0
  - `cve_scan`: matches=23, **epss_enriched=23/23**
  - Run: `aiedge-runs/2026-04-12_1320_sha256-b28bf08e9d2c`
- Pre-v2.5 baseline (same firmware, 2026-04-12 1211 run): adversarial parse_failures=100/100, fp unverified=97/100, EPSS 0/23

## [2.4.1] — 2026-04-11

### Fixed
- `decompiled_colocated` confidence reduced 0.60→0.45 (0.50 for high-risk sinks) — Terminator feedback: evidence level same as symbol co-occurrence
- P-code taint `addr_diff > 16` replaced with callee name matching via `resolve_call_target()` — robust against compiler optimizations

### Added
- **Interprocedural taint** (Strategy 4): cross-function source→sink detection via xref call graph
  - `decompiled_interprocedural` method: caller has source + calls callee with sink → conf 0.55-0.60
  - 1-hop depth limit to control false positives
  - Verified: `fread→vsprintf` across `FUN_00012514→FUN_00011fe0` in RT-AX88U

### Changed
- `taint_propagation.py`: separate confidence caps per method (pcode_colocated 0.65, decompiled_colocated 0.50, decompiled_interprocedural 0.60)

## [2.4.0] — 2026-04-11

### Added
- **Ghidra P-code taint analysis** (`ghidra_scripts/pcode_taint.py`): 3-strategy dataflow tracing (P-code SSA → P-code colocated → decompiled body), replacing symbol co-occurrence
- `PCODE_VERIFIED_CAP = 0.75` — 4-tier confidence caps: SYMBOL_COOCCURRENCE (0.40) < STATIC_CODE_VERIFIED (0.55) < STATIC_ONLY (0.60) < PCODE_VERIFIED (0.75)
- 4 new source pattern rule families: `sql_injection`, `format_string`, `path_traversal`, `ssrf` (9 regex patterns across PHP/Python/C/shell)
- CGI handler detection in `surfaces.py`: extracts `do_*_cgi` function names from Ghidra string_refs as source endpoints
- `INPUT_APIS` expanded: `cJSON_Parse`, `json_tokener_parse`, `xmlParseMemory`
- SBOM backport detection: `_Component.patch_revision` field, opkg version revision parsing
- CVE scan backport filter: -0.30 confidence for opkg packages with patch revision
- `adversarial_triage` schema reference in `firmware_handoff.json` for downstream consumers (Terminator)
- pyghidra fallback now generates `pcode_taint.json` with decompiled body analysis

### Changed
- `taint_propagation.py`: P-code verified results prioritized over static inference; P-code-covered binaries skipped in static fallback
- `ghidra_bridge.py`: `pcode_taint.py` added to default script set
- Detection engine confidence: symbol co-occurrence findings now differentiated from function-level verified findings

### Verified
- ASUS RT-AX88U: 5 new `decompiled_colocated` traces (nvram_get→vsprintf conf 0.60, sanitizer detection working)
- Before/after: 10 static_inference → 10 static + 5 Ghidra-verified, confidence 0.40→0.60 (+50%)

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
- 4-tier confidence caps established: `SYMBOL_COOCCURRENCE_CAP=0.40`, `STATIC_CODE_VERIFIED_CAP=0.55`, `STATIC_ONLY_CAP=0.60`, `PCODE_VERIFIED_CAP=0.75`
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
- Pipeline expanded toward 42-stage final count

### Fixed
- `no_signals` false positive removed
- Tests updated for `no_signals` removal

## [2.0.0] — 2026-02-16

Initial open-source release. Firmware-to-exploit evidence engine with deterministic evidence packaging, hash-anchored artifact chains, and zero pip dependencies. (Pipeline has since grown to 42 stages.)

### Key Features
- 42-stage sequential pipeline (tooling → extraction → exploit_policy)
- SBOM (CycloneDX 1.6 + VEX), SARIF 2.1.0 export
- Ghidra headless integration, AFL++ fuzzing, FirmAE emulation
- MCP server (12 tools) for AI agent integration
- Web report viewer with glassmorphic dashboard
- Quality gates, release gates, and verified evidence chains
