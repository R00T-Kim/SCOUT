<div align="center">

<img src="https://img.shields.io/badge/SCOUT-Firmware_Evidence_Engine-0d1117?style=for-the-badge&labelColor=0d1117" alt="SCOUT" />

# SCOUT

### Firmware Security Analysis Pipeline with Deterministic Evidence Packaging

**Drop a firmware blob. Get SARIF findings, CycloneDX SBOM+VEX, and a hash-anchored evidence chain -- in one command.**

*Automated firmware vulnerability discovery with Ghidra P-code taint analysis, adversarial LLM debate, and zero pip dependencies.*

<br />

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=for-the-badge)](LICENSE)
[![Stages](https://img.shields.io/badge/Pipeline-42_Stages-blueviolet?style=for-the-badge)]()
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero_(stdlib)-orange?style=for-the-badge)]()
[![Version](https://img.shields.io/badge/Version-2.5.0-red?style=for-the-badge)]()

[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-blue?style=for-the-badge&logo=github)]()
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX_1.6+VEX-brightgreen?style=for-the-badge)]()
[![SLSA](https://img.shields.io/badge/SLSA-Level_2-purple?style=for-the-badge)]()

<br />

<table>
<tr>
<td align="center"><strong>1,123</strong><br/><sub>Firmware Analyzed<br/>(Tier 1)</sub></td>
<td align="center"><strong>99.2%</strong><br/><sub>Analysis Rate</sub></td>
<td align="center"><strong>13,893</strong><br/><sub>CVE Matches</sub></td>
<td align="center"><strong>99.3%</strong><br/><sub>FPR Reduction<br/>(Tier 2 LLM)</sub></td>
<td align="center"><strong>≈ 0%</strong><br/><sub>False Negative<br/>Rate</sub></td>
</tr>
</table>
<sub>Baseline (carry-over): Tier 1 v2.4.0, 2026-04-05, static-only, 1,123 firmware · Tier 2 v2.3.0, 2026-04-09, claude-code driver, 36 firmware</sub>

[English (this file)](README.md) | [한국어](README.ko.md)

</div>

---

> [!NOTE]
> **Benchmark numbers in this README are carry-over baselines** (Tier 1: v2.4.0 static-only, 2026-04-05, 1,123 firmware · Tier 2: v2.3.0 claude-code driver, 2026-04-09, 36 firmware). Fresh v2.5.0 corpus re-validation is pending. See [`docs/benchmark_governance.md`](docs/benchmark_governance.md) and [`benchmarks/baselines/v2.5.0/manifest.json`](benchmarks/baselines/v2.5.0/manifest.json).

---

## Why SCOUT?

> **Every finding has a hash-anchored evidence chain.**
> No finding without a file path, byte offset, SHA-256 hash, and rationale. Artifacts are immutable and traceable from firmware blob to final verdict.

> **4-tier confidence caps with Ghidra P-code verification -- honest scoring.**
> SYMBOL_COOCCURRENCE capped at 0.40, STATIC_CODE_VERIFIED at 0.55, STATIC_ONLY at 0.60, PCODE_VERIFIED at 0.75. Promotion to `confirmed` requires dynamic verification. We don't inflate scores.

> **SARIF + CycloneDX VEX + SLSA provenance -- standard formats.**
> GitHub Code Scanning, VS Code, CI/CD integration out of the box.

---

## How It Works

```
  firmware.bin  ──>  42-stage pipeline  ──>  SARIF findings       ──>  Web viewer
                     (auto Ghidra)          CycloneDX SBOM+VEX       TUI dashboard
                     (auto CVE match)       Evidence chain            GitHub/VS Code
                     (optional LLM)         SLSA attestation          MCP for AI agents
```

```bash
# Full analysis
./scout analyze firmware.bin

# Static-only (no LLM, $0)
./scout analyze firmware.bin --no-llm

# Pre-extracted rootfs
./scout analyze firmware.img --rootfs /path/to/rootfs

# Web viewer
./scout serve aiedge-runs/<run_id> --port 8080

# TUI dashboard
./scout ti                    # interactive (latest run)
./scout tw                    # watch mode (auto-refresh)

# MCP server for AI agents
./scout mcp --project-id aiedge-runs/<run_id>
```

---

## Comparison

| Feature | SCOUT | FirmAgent | EMBA | FACT | FirmAE |
|:--------|:-----:|:---------:|:----:|:----:|:------:|
| Scale (firmware tested) | 1,123 | 14 | -- | -- | 1,124 |
| SBOM (CycloneDX 1.6+VEX) | Yes | No | Yes | No | No |
| SARIF 2.1.0 Export | Yes | No | No | No | No |
| Hash-Anchored Evidence Chain | Yes | No | No | No | No |
| SLSA L2 Provenance | Yes | No | No | No | No |
| Known CVE Signature Matching | Yes (2,528 CVEs, 25 sigs) | No | No | No | No |
| Confidence Caps (honest scoring) | Yes | No | No | No | No |
| Ghidra Integration (auto-detect) | Yes | IDA Pro | Yes | No | No |
| AFL++ Fuzzing Pipeline | Yes | Yes | No | No | No |
| Cross-Binary IPC Chains | Yes (5 types) | No | No | No | No |
| Taint Propagation (LLM) | Yes | Yes (DeepSeek) | No | No | No |
| Adversarial FP Reduction | Yes | No | No | No | No |
| MCP Server (AI agent) | Yes | No | No | No | No |
| Web Report Viewer | Yes | No | Yes | Yes | No |
| Zero pip Dependencies | Yes | No | No | No | No |

---

## Key Features

| | Feature | Description |
|---|---------|-------------|
| :package: | **SBOM & CVE** | CycloneDX 1.6 + VEX + 25 known CVE signatures (8 vendors) + NVD scan + 2,528 local CVE DB + EPSS scoring (FIRST.org API, batched + cached) |
| :mag: | **Binary Analysis** | Ghidra P-code SSA dataflow taint + ELF hardening (NX/PIE/RELRO/Canary/FORTIFY) + `.dynstr` detection + 28 sink symbols + format string detection |
| :dart: | **Attack Surface** | Source→sink tracing, web server auto-detection, cross-binary IPC chains (5 types: unix socket, dbus, shm, pipe, exec) |
| :brain: | **Taint Analysis** | HTTP-aware inter-procedural taint, P-code SSA dataflow, call chain visualization, 4-strategy fallback (P-code → colocated → decompiled → interprocedural) |
| :robot: | **LLM Engine** | 4 backends (Codex CLI / Claude API / Claude Code CLI / Ollama) + centralized system prompts + structured JSON output + 5-stage parser (preamble/fence/raw/brace-counting/error-recovery) + temperature control |
| :crossed_swords: | **Adversarial Debate** | Advocate/Critic LLM debate for FPR reduction (99.3% on Tier 2). Separate parse_failures vs llm_call_failures observability with quota_exhausted detection |
| :shield: | **Security Assessment** | X.509 cert scan, boot service audit, filesystem permission checks, credential mapping, hardcoded secret detection |
| :test_tube: | **Fuzzing** *(optional)* | AFL++ with CMPLOG, persistent mode, NVRAM faker, harness generation, crash triage |
| :bug: | **Emulation** | 4-tier (FirmAE / Pandawan+FirmSolo / QEMU user-mode / rootfs inspection) + GDB remote debug |
| :electric_plug: | **MCP Server** | 12 tools via Model Context Protocol for Claude Code/Desktop integration |
| :bar_chart: | **Web Viewer** | Glassmorphism dashboard with KPI bar, IPC map, risk heatmap, interactive evidence navigation |
| :link: | **Evidence Chain** | SHA-256 anchored artifacts + 4-tier confidence caps (0.40/0.55/0.60/0.75) + 5-tier exploit promotion ladder |
| :scroll: | **Standard Output** | SARIF 2.1.0 (GitHub Code Scanning) + CycloneDX 1.6 + VEX + SLSA Level 2 in-toto attestation |
| :gear: | **CI/CD Integration** | GitHub Action (`.github/actions/scout-scan/`) with composite Docker action + automatic SARIF upload to GitHub Security tab |
| :scales: | **Regulatory Alignment** | Output formats compatible with EU CRA Annex I (`docs/cra_compliance_mapping.md`); SBOM output compatible with FDA Section 524B guidance; output formats compatible with ISO 21434 / UN R155 |
| :chart_with_upwards_trend: | **Benchmarking** | FirmAE dataset (1,123 firmware), analyst-readiness scoring, verifier-backed archive bundles, TP/FP analysis scripts |
| :key: | **Vendor Decrypt** | D-Link SHRS AES-128-CBC auto-decryption; Shannon entropy encryption detection (>7.9); binwalk v3 compatibility |
| :white_check_mark: | **Zero Dependencies** | Pure Python 3.10+ stdlib only — no pip dependencies, air-gap friendly deployment |

---

## Pipeline (42 Stages)

```
Firmware --> Unpack --> Profile --> Inventory --> Ghidra --> Semantic Classification
    --> SBOM --> CVE Scan --> Reachability --> Endpoints --> Surfaces
    --> Enhanced Source --> C-Source ID --> Taint Propagation
    --> FP Verification --> Adversarial Triage
    --> Graph --> Attack Surface --> Findings
    --> LLM Triage --> LLM Synthesis --> Emulation --> [Fuzzing]
    --> PoC Refinement --> Chain Construction --> Exploit Chain --> PoC --> Verification
```

Ghidra is auto-detected and enabled by default. Stages in `[brackets]` require optional external tools (AFL++/Docker).

<details>
<summary><strong>Pipeline Stages Reference (42)</strong></summary>

| Stage | Module | Purpose | LLM? | Cost |
|-------|--------|---------|------|------|
| `tooling` | `tooling.py` | External tool availability check (binwalk, Ghidra, Docker) | No | $0 |
| `extraction` | `extraction.py` | Firmware unpacking (binwalk + vendor_decrypt + Shannon entropy detection) | No | $0 |
| `structure` | `structure.py` | Filesystem structure analysis | No | $0 |
| `carving` | `carving.py` | File carving from unstructured regions | No | $0 |
| `firmware_profile` | `firmware_profile.py` | Architecture, kernel, init system fingerprinting | No | $0 |
| `inventory` | `inventory.py` | Per-binary ELF hardening + symbol extraction | No | $0 |
| `ghidra_analysis` | `ghidra_analysis.py` | Decompilation + P-code SSA dataflow analysis | No | $0 |
| `semantic_classification` | `semantic_classifier.py` | 3-pass function classifier (static → haiku → sonnet) | Yes | Low |
| `sbom` | `sbom.py` | CycloneDX 1.6 SBOM generation with VEX | No | $0 |
| `cve_scan` | `cve_scan.py` | NVD + 25 known signatures + EPSS enrichment | No | $0 |
| `reachability` | `reachability.py` | BFS-based call-graph reachability | No | $0 |
| `endpoints` | `endpoints.py` | Network endpoint discovery | No | $0 |
| `surfaces` | `surfaces.py` | Attack surface enumeration | No | $0 |
| `enhanced_source` | `enhanced_source.py` | Web server auto-detection + INPUT_APIS scan (21 APIs) | No | $0 |
| `csource_identification` | `csource_identification.py` | HTTP input source identification via static sentinel + QEMU | No | $0 |
| `taint_propagation` | `taint_propagation.py` | Inter-procedural taint with 28 sinks + format string detection | Yes | Medium |
| `fp_verification` | `fp_verification.py` | 3-pattern FP removal + LLM verification with parse/call failure separation | Yes | Low |
| `adversarial_triage` | `adversarial_triage.py` | Advocate/Critic LLM debate (99.3% FPR reduction) | Yes | Medium |
| `graph` | `graph.py` | Communication graph (5 IPC edge types) | No | $0 |
| `attack_surface` | `attack_surface.py` | Attack surface mapping with IPC chains | No | $0 |
| `attribution` | `attribution.py` | Vendor/firmware attribution | No | $0 |
| `functional_spec` | `functional_spec.py` | Functional specification extraction | No | $0 |
| `threat_model` | `threat_model.py` | STRIDE-based threat modeling | No | $0 |
| `web_ui` | `web_ui.py` | Web UI / CGI endpoint analysis | No | $0 |
| `findings` | `findings.py` | Finding aggregation + SARIF export | No | $0 |
| `llm_triage` | `llm_triage.py` | LLM finding triage (haiku/sonnet/opus auto-routing) | Yes | Variable |
| `llm_synthesis` | `llm_synthesis.py` | LLM finding synthesis | Yes | Medium |
| `emulation` | `emulation.py` | 4-tier emulation (FirmAE / Pandawan / QEMU / rootfs) | No | $0 |
| `dynamic_validation` | `dynamic_validation.py` | Dynamic behavior verification | No | $0 |
| `fuzzing` | `fuzz_*.py` | AFL++ fuzzing with NVRAM faker | No | $0 |
| `poc_refinement` | `poc_refinement.py` | Iterative PoC generation (5 attempts) | Yes | Medium |
| `chain_construction` | `chain_constructor.py` | Same-binary + cross-binary IPC exploit chains | No | $0 |
| `exploit_gate` | `stage_registry.py` | Exploit promotion gate | No | $0 |
| `exploit_chain` | `exploit_chain.py` | Exploit chain validation | No | $0 |
| `exploit_autopoc` | `exploit_autopoc.py` | Automated PoC orchestration | Yes | Medium |
| `poc_validation` | `poc_validation.py` | PoC reproduction validation | No | $0 |
| `exploit_policy` | `exploit_policy.py` | Final exploit promotion decision | No | $0 |

OTA-specific stages: `ota`, `ota_payload`, `ota_fs`, `ota_roots`, `ota_boottriage`, `firmware_lineage` (Android-style OTA payload analysis).

</details>

## Benchmarks

### Tier 1 (Static, frozen baseline)

_Baseline: v2.4.0, 2026-04-05, static-only (carry-over; fresh v2.5.0 corpus re-validation pending)_

- `1,123` firmware / `8` vendors / `99.2%` analysis rate
- `1,110` success / `4` partial / `9` failed
- `3,523` findings / `13,893` CVE matches

### Tier 2 (LLM Adversarial Debate, GPT-5.3-Codex)

_Baseline: v2.3.0, 2026-04-09, claude-code driver (carry-over; fresh v2.5.0 corpus re-validation pending)_

- `36` firmware / `9` vendors
- `2,430` findings debated → `2,412` downgraded + `18` maintained
- **FPR reduction: 99.3%** | **False negative rate: ≈ 0%**

### v2.5.0 Single-Firmware Verification (Netgear R7000, codex driver)
| Metric | Pre-v2.5 | v2.5.0 |
|---|---|---|
| `adversarial_triage` parse_failures | 100/100 | **0/100** |
| `fp_verification` unverified | 97/100 | **0/100** |
| `fp_verification` true_positives | 1 | **57** |
| `cve_scan` EPSS enriched | 0/23 | **23/23** |

See [`CHANGELOG.md`](CHANGELOG.md) for full version history.

---

## Architecture

```
+--------------------------------------------------------------------+
|                       SCOUT (Evidence Engine)                      |
|                                                                    |
|  Firmware --> Unpack --> Profile --> Inventory --> SBOM --> CVE    |
|                          |            |            |          |    |
|                       Ghidra     Binary Audit   40+ sigs    NVD+   |
|                       auto-detect  NX/PIE/etc              local DB|
|                                                                    |
|  --> Taint --> FP Filter --> Attack Surface --> Findings           |
|     (HTTP-aware)  (3-pattern)   (IPC chains)    (SARIF 2.1.0)      |
|                                                                    |
|  --> Emulation --> [Fuzzing] --> Exploit Chain --> PoC --> Verify  |
|                                                                    |
|  42 stages . SHA-256 manifests . 4-tier confidence caps (0.40/0.55/0.60/0.75) |
|  Outputs: SARIF + CycloneDX VEX + SLSA L2 + Markdown reports       |
+--------------------------------------------------------------------+
|                    Handoff (firmware_handoff.json)                 |
+--------------------------------------------------------------------+
|                     Terminator (Orchestrator)                      |
|  LLM Tribunal --> Dynamic Validation --> Verified Chain            |
+--------------------------------------------------------------------+
```

| Layer | Role | Deterministic? |
|:------|:-----|:--------------:|
| **SCOUT** | Evidence production (42 stages) | Yes |
| **Handoff** | JSON contract between engine and orchestrator | Yes |
| **Terminator** | LLM tribunal, dynamic validation, exploit dev | No (auditable) |

---

## Exploit Promotion Policy

| Level | Requirements | Placement |
|:------|:-------------|:----------|
| `dismissed` | Critic rebuttal strong or confidence < 0.5 | Appendix only |
| `candidate` | Confidence 0.5-0.8, evidence exists but chain incomplete | Report (flagged) |
| `high_confidence_static` | Confidence >= 0.8, strong static evidence, no dynamic | Report (highlighted) |
| `confirmed` | Confidence >= 0.8 AND >= 1 dynamic verification artifact | Report (top) |
| `verified_chain` | Confirmed AND PoC reproduced 3x in sandbox | Exploit report |

---

<details>
<summary><strong>CLI Reference</strong></summary>

| Command | Description |
|---------|-------------|
| `./scout analyze <firmware>` | Full 42-stage analysis pipeline |
| `./scout analyze <firmware> --quiet` | Suppress real-time progress output (CI/scripted use) |
| `./scout analyze-8mb <firmware>` | Truncated 8MB canonical track |
| `./scout stages <run_dir> --stages X,Y` | Rerun specific stages |
| `./scout serve <run_dir>` | Launch web report viewer |
| `./scout mcp [--project-id <id>]` | Start MCP stdio server |
| `./scout tui <run_dir>` | Terminal UI dashboard |
| `./scout ti` | TUI interactive (latest run) |
| `./scout tw` | TUI watch mode (auto-refresh) |
| `./scout to` | TUI one-shot (latest run) |
| `./scout t` | TUI default (latest run) |
| `./scout corpus-validate` | Validate corpus manifest |
| `./scout quality-metrics` | Compute quality metrics |
| `./scout quality-gate` | Check quality thresholds |
| `./scout release-quality-gate` | Unified release gate |

**Exit codes:** `0` success, `10` partial, `20` fatal, `30` policy violation

</details>

<details>
<summary><strong>Benchmarking</strong></summary>

```bash
# FirmAE dataset benchmark (1,123 usable firmware images in the current frozen baseline)
./scripts/benchmark_firmae.sh --parallel 8 --time-budget 1800 --cleanup

# Options
--dataset-dir DIR       # Firmware directory (default: aiedge-inputs/firmae-benchmark)
--results-dir DIR       # Output directory
--file-list PATH        # Explicit newline-delimited firmware list
--parallel N            # Concurrent jobs (default: 4)
--time-budget S         # Seconds per firmware (default: 600)
--stages STAGES         # Specific stages (default: full pipeline)
--max-images N          # Limit images (0 = all)
--llm                   # Enable LLM-backed stages
--8mb                   # Use 8MB truncated track
--full                  # Include dynamic stages
--cleanup               # Preserve a verifier-friendly run replica under results/archives/, then delete original run dirs
--dry-run               # List files without running

# Analyst-readiness re-evaluation for an existing benchmark-results tree
python3 scripts/reevaluate_benchmark_results.py \
  --results-dir benchmark-results/<run>

# Normalize legacy bundles and rerun a stage subset (useful for debugging archive fidelity issues)
python3 scripts/rerun_benchmark_stages.py \
  --results-dir benchmark-results/<legacy-run> \
  --out-dir benchmark-results/<rerun-out> \
  --stages attribution,graph,attack_surface \
  --no-llm

# Post-benchmark analysis
PYTHONPATH=src python3 scripts/cve_rematch.py \
  --results-dir benchmark-results/firmae-YYYYMMDD_HHMM \
  --nvd-dir data/nvd-cache \
  --csv-out cve_matches.csv

PYTHONPATH=src python3 scripts/analyze_findings.py \
  --results-dir benchmark-results/firmae-YYYYMMDD_HHMM \
  --output analysis_report.json

# FirmAE dataset setup
./scripts/unpack_firmae_dataset.sh [ZIP_FILE]

# Tier 1 frozen baseline docs
# - docs/tier1_rebenchmark_frozen_baseline.md
# - docs/tier1_rebenchmark_final_analysis.md
```

**Current benchmark contract**

- Archived benchmark bundles are now expected to be **run replicas**, not flattened JSON snapshots.
- Benchmark quality is reported in two layers:
  - **analysis rate** = pipeline completed (`success + partial`)
  - **analyst-ready rate** = archived bundle passes analyst/verifier checks and remains evidence-navigable
- `benchmark-results/legacy/tier2-llm-v2` is a **legacy snapshot**. It is useful for historical reference and re-evaluation, but it should not be used as the canonical analyst-readiness baseline.
- The current contract has been validated on a fresh single-sample run (`benchmark-results/tier2-single-fidelity`) where both analyst verifiers passed from the archived bundle.

**Current LLM quality behavior**

- `llm_triage` model routing: `<=10 haiku`, `11-50 sonnet`, `>50 or chain-backed opus`
- `llm_triage` retries with `sonnet` if a `haiku` call exits non-zero
- `llm_triage`, `semantic_classification`, `adversarial_triage`, and `fp_verification` now write `stages/<stage>/llm_trace/*.json`
- Parse failures are handled fail-closed: repaired when possible, otherwise reported as degraded/partial instead of silently treated as clean success

</details>

<details>
<summary><strong>Environment Variables</strong></summary>

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_LLM_DRIVER` | `codex` | LLM provider: `codex` / `claude` / `claude-code` / `ollama` |
| `ANTHROPIC_API_KEY` | -- | API key for Claude driver (not needed for `claude-code`) |
| `AIEDGE_OLLAMA_URL` | `http://localhost:11434` | Ollama server URL |
| `AIEDGE_LLM_BUDGET_USD` | -- | LLM cost budget limit |
| `AIEDGE_PRIV_RUNNER` | -- | Privileged command prefix for dynamic stages |
| `AIEDGE_FEEDBACK_DIR` | `aiedge-feedback` | Terminator feedback directory |

### Ghidra

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_GHIDRA_HOME` | auto-detect | Ghidra install path; probes `/opt/ghidra_*`, `/usr/local/ghidra*` |
| `AIEDGE_GHIDRA_MAX_BINARIES` | `20` | Max binaries to analyze |
| `AIEDGE_GHIDRA_TIMEOUT_S` | `300` | Per-binary analysis timeout |

### SBOM & CVE

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_NVD_API_KEY` | -- | NVD API key (optional, improves rate limits) |
| `AIEDGE_NVD_CACHE_DIR` | -- | Cross-run NVD response cache |
| `AIEDGE_SBOM_MAX_COMPONENTS` | `500` | Maximum SBOM components |
| `AIEDGE_CVE_SCAN_MAX_COMPONENTS` | `50` | Maximum components to CVE-scan |
| `AIEDGE_CVE_SCAN_TIMEOUT_S` | `30` | Per-request NVD API timeout |

### Fuzzing & Emulation

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_AFLPP_IMAGE` | `aflplusplus/aflplusplus` | AFL++ Docker image |
| `AIEDGE_FUZZ_BUDGET_S` | `3600` | Fuzzing time budget (seconds) |
| `AIEDGE_FUZZ_MAX_TARGETS` | `5` | Max fuzzing target binaries |
| `AIEDGE_EMULATION_IMAGE` | `scout-emulation:latest` | Emulation Docker image |
| `AIEDGE_FIRMAE_ROOT` | `/opt/FirmAE` | FirmAE installation path |
| `AIEDGE_QEMU_GDB_PORT` | `1234` | QEMU GDB remote port |

### Quality Gates

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_QG_PRECISION_MIN` | `0.9` | Minimum precision threshold |
| `AIEDGE_QG_RECALL_MIN` | `0.6` | Minimum recall threshold |
| `AIEDGE_QG_FPR_MAX` | `0.1` | Maximum false positive rate |

</details>

<details>
<summary><strong>Run Directory Structure</strong></summary>

```
aiedge-runs/<run_id>/
├── manifest.json
├── firmware_handoff.json
├── provenance.intoto.jsonl           # SLSA L2 attestation
├── input/firmware.bin
├── stages/
│   ├── extraction/                   # Unpacked filesystem
│   ├── inventory/
│   │   └── binary_analysis.json      # Per-binary hardening + symbols
│   ├── enhanced_source/
│   │   └── sources.json              # HTTP input sources + web server detection
│   ├── sbom/
│   │   ├── sbom.json                 # CycloneDX 1.6
│   │   └── vex.json                  # VEX exploitability
│   ├── cve_scan/
│   │   └── cve_matches.json          # NVD + known signature matches
│   ├── taint_propagation/
│   │   └── taint_results.json        # Taint paths + call chains
│   ├── ghidra_analysis/              # Decompiled functions (optional)
│   ├── chain_construction/
│   │   └── chains.json               # Same-binary + cross-binary IPC chains
│   ├── findings/
│   │   ├── findings.json             # All findings
│   │   ├── pattern_scan.json         # Static pattern matches
│   │   ├── sarif.json                # SARIF 2.1.0 export
│   │   └── stage.json                # SHA-256 manifest
│   └── ...                           # 42 stage directories total
└── report/
    ├── viewer.html                   # Web dashboard
    ├── report.json
    ├── analyst_digest.json
    └── executive_report.md
```

</details>

<details>
<summary><strong>Verification Scripts</strong></summary>

```bash
# Evidence chain integrity
python3 scripts/verify_analyst_digest.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_verified_chain.py --run-dir aiedge-runs/<run_id>

# Report schema compliance
python3 scripts/verify_aiedge_final_report.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_aiedge_analyst_report.py --run-dir aiedge-runs/<run_id>

# Security invariants
python3 scripts/verify_run_dir_evidence_only.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_network_isolation.py --run-dir aiedge-runs/<run_id>

# Quality gates
./scout release-quality-gate aiedge-runs/<run_id>
```

</details>

---

## Documentation

| Document | Purpose |
|:---------|:--------|
| [Blueprint](docs/blueprint.md) | Pipeline architecture and design rationale |
| [Status](docs/status.md) | Current implementation status |
| [Artifact Schema](docs/aiedge_firmware_artifacts_v1.md) | Profiling + inventory contracts |
| [Adapter Contract](docs/aiedge_adapter_contract.md) | Terminator-SCOUT handoff protocol |
| [Report Contract](docs/aiedge_report_contract.md) | Report structure and governance |
| [Analyst Digest](docs/analyst_digest_contract.md) | Digest schema and verdicts |
| [Verified Chain](docs/verified_chain_contract.md) | Evidence requirements |
| [Duplicate Gate](docs/aiedge_duplicate_gate_contract.md) | Cross-run dedup rules |
| [Known CVE Ground Truth](docs/known_cve_ground_truth.md) | CVE validation dataset |
| [Upgrade Plan v2](docs/upgrade_plan_v2.md) | v2.0 upgrade plan |
| [LLM Roadmap](docs/roadmap_llm_agent_integration.md) | LLM integration strategy |

---

## Security & Ethics

> **Authorized environments only.**

SCOUT is intended for contracted security audits, vulnerability research (responsible disclosure), and CTF/training in lab environments. Dynamic validation runs in network-isolated sandbox containers. No weaponized payloads are included.

---

## Contributing

1. **Read** [Blueprint](docs/blueprint.md) for architecture context
2. **Run** `pytest -q` -- all tests must pass
3. **Lint** `ruff check src/` -- zero violations
4. **Follow** the Stage protocol (`src/aiedge/stage.py`)
5. **Zero pip dependencies** -- stdlib only

---

## License

Apache 2.0

---

<div align="center">

<sub>Built for the security research community. Not for unauthorized access.</sub>

<br />

<a href="https://github.com/R00T-Kim/SCOUT">github.com/R00T-Kim/SCOUT</a>

</div>
