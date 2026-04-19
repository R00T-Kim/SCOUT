# Changelog

All notable changes to SCOUT are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- **FDA Section 524B compatibility mapping (Phase 3'.1 step B-2)** (`docs/compliance_mapping/fda_section_524b.md`). Maps SCOUT outputs to the four §524B(b) statutory obligations (postmarket vulnerability monitoring plan, secure design/develop/maintain processes, postmarket updates/patches, SBOM) and to the September 2023 FDA premarket cybersecurity guidance content elements (security objectives, threat modelling, security risk management, cybersecurity testing, architecture views, SBOM, vulnerability management, labelling, postmarket plan). Coverage is documented per element with explicit "out of scope" callouts for sponsor-side QMS deliverables. Disclaimer reuses the directory-wide "compatible with" wording rule.
- **ISO/SAE 21434 compatibility mapping (Phase 3'.1 step B-3)** (`docs/compliance_mapping/iso_21434.md`). Maps SCOUT outputs to ISO/SAE 21434:2021 work products across clauses 8 (continual cybersecurity activities), 9 (concept), 10 (product development), 11 (cybersecurity validation), 13 (operations and maintenance), and 15 (TARA methods). Identifies which work products are tool-friendly (WP-08-01..04, WP-10-04, WP-10-05, WP-13-02) versus manufacturer-side narratives (WP-09-02, WP-10-01, WP-10-02, etc.).
- **UN R155 compatibility mapping (Phase 3'.1 step B-3)** (`docs/compliance_mapping/un_r155.md`). Maps SCOUT outputs to UN R155 §7.2 (CSMS) and §7.3 (vehicle-type approval) requirements, plus per-threat guidance for the 15 most-relevant Annex 5 threat categories (manipulation, replay, malware insertion, network-design vulnerabilities, etc.). Co-published with the ISO/SAE 21434 mapping per the standard / regulation pairing.

### Changed

- **CRA mapping relocated into `docs/compliance_mapping/`** (`docs/compliance_mapping/cra_annex_i.md`, was `docs/cra_compliance_mapping.md`). Phase 3'.1 step B-1 sets up a four-document compliance-mapping suite (CRA Annex I / FDA Section 524B / ISO 21434 / UN R155); the CRA file ships first as the canonical baseline format, with sibling placeholders cross-linked from its header. References updated in README.md, README.ko.md, docs/status.md, CHANGELOG.md, and scripts/check_doc_consistency.py. The disclaimer is tightened to spell out that the "compatible with" wording is mandatory throughout the directory — any "compliant with" / "compliance" / "ready" substitution is rejected by `check_doc_consistency.py`.

### Fixed

- **AFL++ Docker fuzzing artifact ownership** (`fuzz_campaign.py`, PR #7). The Docker container is now invoked with the host user's uid/gid (`--user $(id -u):$(id -g)`), so files written under `stages/fuzzing/*/afl_output/` remain readable by SCOUT after the container exits. Previously, `_collect_stats` would raise `PermissionError: [Errno 13] Permission denied: .../fuzzer_stats` on any run that entered the fuzzing stage because the directory was created as `drwx------ root:root`. Validated on the OpenWrt Archer C7 v5 run (`2026-04-13_1014_sha256-bf9eeb5af38a`), where the pre-existing `PermissionError` no longer reproduces and `afl_output/default/` is now owned by the invoking user.
- **Fuzzing stage status when AFL++ never executes the target** (`fuzz_campaign.py`, PR #8). Campaigns that abort before any target execution — for example on forkserver handshake failure, QEMU architecture mismatch, or non-zero Docker exit — are no longer reported as `ok`. New helpers `_append_campaign_execution_limitations()` and `_campaign_completed()` record explicit limitations (`docker_exit_N`, `forkserver_handshake_failed`, `target_arch_mismatch`, `no_fuzzer_executions`) and refuse to increment `targets_completed` unless `stats.execs_done > 0`, so the stage correctly resolves to `partial` with actionable signal. Validated on the OpenWrt Archer C7 v5 MIPS-32 dnsmasq target, where AFL++ aborted with `Fork server handshake failed` and the stage now emits `status=partial` with all three limitations plus `targets_completed=0 / targets_attempted=1`. _(4 new tests in `tests/test_fuzz_campaign.py`.)_

## [2.6.1] — 2026-04-17

Phase 2C close-out release. This point release rolls up the post-v2.6.0 foundation hardening work, publishes the fresh corpus refresh baseline, and documents the semantic / driver caveats that were previously implicit.

### Added

- **Fresh corpus refresh baseline** (`docs/carry_over_benchmark_v2.6.md`, `benchmark-results/2c6-fresh-full-final/aggregate.json`, `scripts/aggregate_corpus_metrics.py`). The 1,123-target refresh is now published as a best-view aggregate across the fresh rerun waves. Final outcome: **1110 success / 4 partial / 9 fatal**; successful runs are `extraction=ok 1110/1110`, `inventory=sufficient 1110/1110`, `nonzero findings 1110/1110`, `nonzero CVE 1089/1110`.
- **LLM driver degradation matrix** (`docs/llm_driver_degradation_matrix.md`). Documents the actual contract differences between Codex CLI, Claude API, Claude Code CLI, and Ollama, especially around system-prompt delivery and temperature handling.
- **Confidence semantic break note** (`docs/confidence_semantic_break_v2.6.md`). Makes the v2.5.x → v2.6+ shift explicit: `confidence` is now evidence-only; `priority_score` / `priority_inputs` carry ranking semantics.

### Changed

- **README / README.ko baseline messaging**. Tier 1 hero numbers now point at the fresh v2.6.1 corpus refresh, while Tier 2 remains explicitly carry-over until the pair-eval lane lands. The over-broad "False negative rate ≈ 0%" phrasing is replaced with a pending pair-eval note.
- **Analyst copilot wording**. Public docs now split the surface into `Explainability surface`, `Analyst-in-the-loop channel`, and `Autonomous reasoning (future)` instead of presenting all LLM-related behavior as one undifferentiated capability.
- **Release governance helper** (`scripts/release.sh`). The helper is upgraded from a README-only version bumper into a release close-out utility that can synchronize pyproject, README badges, and CHANGELOG headers in dry-run/apply modes.

### Fixed

- **Synthesis finding reasoning trail inheritance** (`findings.py`). Top-level synthesis findings such as `aiedge.findings.web.exec_sink_overlap` now inherit matched downstream evidence lineage instead of relying only on the stage-level aggregate summary. Matching prefers run-relative binary path, falls back to binary SHA-256, emits a `findings/synthesis_match` summary entry, and appends a deterministic top-K sample of representative downstream trail entries.
- **SBOM stage silent schema mismatch** (`sbom.py`). Vendor-stock firmware no longer silently returns 0 components because of stale `inventory.file_list` / `string_hits` assumptions. The stage now walks `inventory.roots` directly and falls back to direct binary reads via `_extract_ascii_runs`.
- **Relative `runs_root` handling in `create_run()`** (`run.py`). `runs_root` is resolved before path derivation so relative output roots still wire absolute firmware paths into extraction; regression coverage lives in `tests/test_create_run_relative_runs_root.py`.

### Verification

- `python3 -m py_compile scripts/aggregate_corpus_metrics.py`
- `python3 scripts/check_doc_consistency.py`
- fresh corpus aggregate regenerated from `benchmark-results/2c6-fresh-full-v2*` waves
- representative firmware smoke coverage retained from 2C.1–2C.5 (R7000 lineage / SBOM pilot / verified-chain provenance)

## [2.6.0] — 2026-04-13

Phase 2B release. Performance + analyst copilot UX + confidence calibration. 6 atomic commits, single-session parallel execution via worktree isolation. Merged via [PR #6](https://github.com/R00T-Kim/SCOUT/pull/6) (rebase). All downstream consumers untouched (PR #7a additive-first pattern maintained throughout).

### Added

- **`reasoning_trail.py`** — Structured reasoning trail capture for LLM-driven finding adjustments. `ReasoningEntry` dataclass with 200-char `raw_response_excerpt` cap enforced at construction (`__post_init__`). Helpers: `append_entry`, `redact_excerpt`, `empty_trail`, `format_trail_for_markdown`, `format_trail_for_tui`, `normalize_trail`. _(PR #11, PR #13)_
- **`scoring.py`** — Detection vs priority separation. `PriorityInputs` frozen dataclass (detection_confidence, epss_score, epss_percentile, reachability, backport_present, cvss_base) + `compute_priority_score()` (weights: detection 50% / EPSS 25% / reach 15% / CVSS 10%, backport -0.20 penalty) + `priority_bucket()` (critical/high/medium/low) + `priority_inputs_to_dict()`. Addresses external reviewer critique that EPSS-additive confidence looked like a ranking heuristic. _(PR #15)_
- **`stage_dag.py`** — Manual `STAGE_DEPS` dict (42 entries, exact `_STAGE_FACTORIES` match) + Kahn `topo_levels()` with deterministic alphabetic sort within levels + `validate_deps()` warning surface. `findings` excluded (integrated step), `exploit_gate` included (inline factory). 15 levels / max-width 7. _(PR #10)_
- **`run_stages_parallel()`** in `stage.py` — ThreadPoolExecutor level-wise execution with skip-on-failed-dep semantics, `fail_fast=True/False` modes, post-pool cancellation sweep. Sequential `run_stages()` unchanged. _(PR #10)_
- **`--experimental-parallel [N]`** CLI flag on both `analyze` and `stages` subparsers (default 4 workers when specified without value). _(PR #10)_
- **4 MCP analyst tools** in `mcp_server.py`: `scout_get_finding_reasoning`, `scout_inject_hint`, `scout_override_verdict`, `scout_filter_by_category`. Verdict enum validation, category validation via `FindingCategory` enum, `AIEDGE_MCP_MAX_OUTPUT_KB` truncation respected. _(PR #12)_
- **Feedback registry extension** in `terminator_feedback.py`: `add_analyst_hint`, `get_analyst_hints`, `set_verdict_override` with `fcntl.flock` write safety + `assert_under_dir` path enforcement. Backward-compatible schema (existing `verdicts` list preserved). _(PR #12)_
- **Analyst hint injection loop** in `adversarial_triage.py`: `_build_analyst_hint_prefix()` reads hints from `AIEDGE_FEEDBACK_DIR` and prefixes advocate prompts (priority-sorted). Opt-in via env var; byte-identical behavior when unset. _(PR #12)_
- **Extraction failure analyst guidance** in `extraction.py`: structured `extraction_guidance` injected into all 4 failure paths (firmware missing, invalid rootfs, no binwalk, timeout) + success path sweep. Surfaces vendor_decrypt hint, `--rootfs` option, binwalk variants, issue-filing template. `run.py._emit_extraction_guidance()` prints to stderr (quiet mode respected) and logs to run dir. _(PR #14)_
- **`docs/runbook.md#extraction-failure`** section with symptoms/causes/remediation table. _(PR #14)_
- **`docs/scoring_calibration.md`** — full two-score contract with before/after worked example. _(PR #15)_
- **`quality_metrics.py` per-priority bucket aggregation** (`count_findings_by_priority`, `PRIORITY_BUCKET_LABELS`) alongside existing per-confidence helpers. _(PR #15)_
- **Progress out-of-order mode** — `ProgressTracker(out_of_order=True)` uses internal `_completion_counter` independent of idx, for parallel stage completion. _(PR #10)_
- **Web viewer reasoning trail panel** — collapsible `<details>` section in the embedded template (`reporting.py`), CSS class set (`.reasoning-trail`, `.reasoning-trail-list`, `.reasoning-trail-rationale`), plain `Date()` for timestamp formatting. _(PR #13)_
- **Analyst markdown reasoning trail subsection** — numbered list in `report_assembler.py` `write_analyst_report_v2_md`. _(PR #13)_
- **TUI reasoning trail rendering** — `render_finding_detail_with_trail()` in `cli_tui_render.py`, `AIEDGE_TUI_ASCII`-compatible. _(PR #13)_

### Changed

- **`adversarial_triage.py`** debate loop now records structured reasoning trail entries for advocate / critic / decision steps with `llm_model` and truncated `raw_response_excerpt`. Existing `triage_outcome` field preserved unchanged. _(PR #11)_
- **`fp_verification.py`** records trail entries for `sanitizer_detected`, `non_propagating_detected`, `sysfile_detected`, and LLM `<pattern>_detected` / `llm_verdict` outcomes with per-pattern `delta`. Existing `fp_verdict` / `fp_rationale` fields preserved. _(PR #11)_
- **`findings.py`** additive `reasoning_trail` pass-through normalisation + `reasoning_trail_count` summary field (PR #11). Additive `priority_score` + `priority_inputs` + `priority_bucket_counts` annotation: CVE findings keep pre-computed score from `cve_scan.py`; all other findings get a default computed from `confidence` as the only known signal. **No schema version bump.** _(PR #11, PR #15)_
- **`cve_scan.py:1140-1170`** refactored: `confidence` field now strictly capped at `STATIC_CODE_VERIFIED_CAP=0.55` (static evidence only). EPSS / reachability / backport / CVSS now feed `priority_score` instead. Deleted orphan internals: `_REACHABILITY_MULTIPLIERS`, `_EPSS_BOOST_*`, `_EPSS_PENALTY_LOW`, `_epss_confidence_adjustment()`. _(PR #15)_
- **`sarif_export.py`** properties bag gains `scout_reasoning_trail` (PR #11) and `scout_priority_score` + `scout_priority_inputs` (PR #15) — mirrors the PR #7a `scout_category` precedent. _(PR #11, PR #15)_
- **`run.py`** `run_subset()` + `analyze_run()` now accept both `quiet: bool` (PR #14) and `experimental_parallel: int | None` (PR #10) kwargs; call sites in `__main__.py` plumb both through. Autopoc rerun (line ~4097) remains sequential (single-stage reinvocation). _(PR #10, PR #14)_
- **`reporting.py`** analyst report markdown path now consumes `reasoning_trail` via `report_assembler.py` helpers and includes a numbered "Reasoning Trail (N steps)" subsection per finding. Viewer template gains JS render block reading `item.reasoning_trail`. _(PR #13)_
- **`cli_tui_data.py`** surfaces `findings_with_trails` in snapshot dict via new `_collect_tui_findings_with_trails` helper. _(PR #13)_
- **`cli_tui_render.py`** snapshot includes `_append_findings_with_trails_section` block that runs even when no exploit candidates exist. _(PR #13)_

### Verified

- **pytest**: 865 → **1027 passed, 1 skipped** (+162 new tests: 20 reasoning_trail unit + 18 extraction_guidance + 33 mcp_analyst_tools + 14 stage_dag + 14 run_stages_parallel + 19 scoring + 44 reasoning_trail_viewer)
- **ruff**: all checks passed
- **pyright**: 0 errors, 0 warnings, 0 informations (Phase 2A baseline preserved)
- **CI 5/5 green**: lint / typecheck / test (3.10) / test (3.11) / test (3.12)
- **R7000 smoke (PR #15, codex driver)**: 3 findings, all carry `priority_score` + `priority_inputs`; `cve_confidence_above_0.55_cap = 0` (detection cap correctly enforced); `priority_bucket_counts = {critical: 0, high: 0, medium: 3, low: 0}`; `category_counts = {vulnerability: 1, pipeline_artifact: 2, misconfiguration: 0, unclassified: 0}`

### Design Invariants Preserved

- Additive only on `findings.py` (PR #7a pattern for `category`, now also `reasoning_trail`, `priority_score`, `priority_inputs`). **No report schema version bump.** Existing 7 downstream consumers untouched.
- Sequential `run_stages()` behavior bit-identical to pre-PR state.
- `StageContext` frozen invariant preserved (thread-safe sharing without locks).
- All file writes continue to route through `assert_under_dir()` (`path_safety.py`).
- Existing LLM driver contracts untouched; system_prompt + temperature + 5-stage parser (v2.5.0) all continue to work.
- 200-char `raw_response_excerpt` cap enforced at construction time in `ReasoningEntry.__post_init__` (cannot be bypassed by call sites).

## [2.5.0] — 2026-04-13

### Added
- **`llm_prompts.py`** — Centralized system prompt module: `STRUCTURED_JSON_SYSTEM`, `ADVOCATE_SYSTEM`, `CRITIC_SYSTEM`, `TAINT_SYSTEM`, `CLASSIFIER_SYSTEM`, `REPAIR_SYSTEM`, `SYNTHESIS_SYSTEM` + temperature constants
- **LLMDriver Protocol**: `system_prompt: str = ""` and `temperature: float | None = None` parameters wired into all 4 drivers (CodexCLI, ClaudeAPI, ClaudeCodeCLI, Ollama)
- **EPSS scoring** in `cve_scan.py`: FIRST.org API integration with batched queries, per-run + cross-run cache, confidence adjustment based on EPSS percentile
- **Sink expansion** (`taint_propagation.py`): `_SINK_SYMBOLS` 11 → 28 entries (memcpy, memmove, strcat, strncpy, gets, vsprintf, printf, fprintf, syslog, vprintf, vfprintf, snprintf, scanf, sscanf, fscanf, dlopen, realpath)
- **Format string sink set**: `_FORMAT_STRING_SINKS` + `_is_format_string_variable()` helper for variable-controlled format string detection
- **GitHub Action**: `.github/actions/scout-scan/` composite action for CI/CD with SARIF upload to GitHub Security tab
- **CRA compatibility documentation**: `docs/compliance_mapping/cra_annex_i.md` mapping all 12 EU Cyber Resilience Act Annex I requirements to SCOUT outputs (output formats compatible with CRA Annex I)
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
- Tier 2 LLM benchmark: 36 firmware, 2430 findings debated, 99.3% LLM-adjudicated FPR reduction, 18 maintained true findings

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
