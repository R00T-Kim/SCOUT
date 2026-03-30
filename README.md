<div align="center">

<img src="https://img.shields.io/badge/SCOUT-Firmware_Evidence_Engine-0d1117?style=for-the-badge&labelColor=0d1117" alt="SCOUT" />

# SCOUT

### Firmware-to-Exploit Evidence Engine

**Drop a firmware blob. Get SARIF findings, CycloneDX SBOM+VEX, and a hash-anchored evidence chain.**

<br />

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Stages](https://img.shields.io/badge/Pipeline-42_Stages-blueviolet?style=for-the-badge)]()
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero_(stdlib)-orange?style=for-the-badge)]()

[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-blue?style=for-the-badge&logo=github)]()
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX_1.6+VEX-brightgreen?style=for-the-badge)]()
[![SLSA](https://img.shields.io/badge/SLSA-Level_2-purple?style=for-the-badge)]()

[English (this file)](README.md) | [한국어](README.ko.md)

</div>

---

## Why SCOUT?

> **Every finding has a hash-anchored evidence chain.**
> No finding without a file path, byte offset, SHA-256 hash, and rationale. Artifacts are immutable and traceable from firmware blob to final verdict.

> **Static-only findings capped at 0.60 -- honest confidence.**
> Promotion to `confirmed` requires dynamic verification. We don't inflate scores.

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
| Scale (firmware tested) | 1,124 | 14 | -- | -- | 1,124 |
| SBOM (CycloneDX 1.6+VEX) | Yes | No | Yes | No | No |
| SARIF 2.1.0 Export | Yes | No | No | No | No |
| Hash-Anchored Evidence Chain | Yes | No | No | No | No |
| SLSA L2 Provenance | Yes | No | No | No | No |
| Known CVE Signature Matching | Yes (2,239 CVEs) | No | No | No | No |
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
| :package: | **SBOM & CVE** | CycloneDX 1.6 (40+ signatures) + NVD CVE scan + 2,239 local CVE DB + 13 known CVE signatures |
| :mag: | **Binary Analysis** | ELF hardening (NX/PIE/RELRO/Canary) + `.dynstr` detection + FORTIFY_SOURCE + Ghidra decompilation |
| :dart: | **Attack Surface** | Source-to-sink tracing, web server auto-detection, cross-binary IPC chains (5 types) |
| :brain: | **Taint Analysis** | HTTP-aware inter-procedural taint with call chain visualization; web server priority |
| :shield: | **Security Assessment** | X.509 cert scan, boot service audit, filesystem permission checks, credential mapping |
| :test_tube: | **Fuzzing** *(optional)* | AFL++ with CMPLOG, persistent mode, NVRAM faker, harness generation, crash triage |
| :bug: | **Emulation** | 3-tier (FirmAE / QEMU user-mode / rootfs inspection) + GDB remote debug |
| :robot: | **MCP Server** | 12 tools via Model Context Protocol for Claude Code/Desktop |
| :bar_chart: | **Web Viewer** | Glassmorphism dashboard with KPI bar, IPC map, risk heatmap |
| :link: | **Evidence Chain** | SHA-256 anchored artifacts, confidence caps, 5-tier exploit promotion |
| :scroll: | **SARIF & SLSA** | SARIF 2.1.0 findings + SLSA Level 2 in-toto attestation |
| :chart_with_upwards_trend: | **Benchmarking** | FirmAE 1,124 dataset support, CVE rematch, TP/FP analysis scripts |

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
<summary><strong>v2.0 New Stages (8)</strong></summary>

| Stage | Module | Purpose | LLM? | Cost |
|-------|--------|---------|------|------|
| `enhanced_source` | `enhanced_source.py` | Web server auto-detection + INPUT_APIS scan (21 APIs) | No | $0 |
| `semantic_classification` | `semantic_classifier.py` | 3-pass function classifier (static, haiku, sonnet) | Yes | Low |
| `taint_propagation` | `taint_propagation.py` | HTTP-aware inter-procedural taint with call chain | Yes | Medium |
| `fp_verification` | `fp_verification.py` | 3-pattern FP removal (sanitizer/non-propagating/sysfile) | No | $0 |
| `adversarial_triage` | `adversarial_triage.py` | Advocate/Critic LLM debate for FPR reduction | Yes | Medium |
| `poc_refinement` | `poc_refinement.py` | Iterative PoC generation from fuzzing seeds (5 attempts) | Yes | Medium |
| `chain_construction` | `chain_constructor.py` | Same-binary + cross-binary IPC exploit chains | No | $0 |
| `csource_identification` | `csource_identification.py` | HTTP input source identification via static sentinel + QEMU | No | $0 |

</details>

---

## Architecture

```
+--------------------------------------------------------------------+
|                       SCOUT (Evidence Engine)                      |
|                                                                    |
|  Firmware --> Unpack --> Profile --> Inventory --> SBOM --> CVE     |
|                          |            |            |          |     |
|                       Ghidra     Binary Audit   40+ sigs    NVD+   |
|                       auto-detect  NX/PIE/etc              local DB|
|                                                                    |
|  --> Taint --> FP Filter --> Attack Surface --> Findings            |
|     (HTTP-aware)  (3-pattern)   (IPC chains)    (SARIF 2.1.0)      |
|                                                                    |
|  --> Emulation --> [Fuzzing] --> Exploit Chain --> PoC --> Verify   |
|                                                                    |
|  42 stages . SHA-256 manifests . confidence cap 0.60 (static)     |
|  Outputs: SARIF + CycloneDX VEX + SLSA L2 + Markdown reports      |
+--------------------------------------------------------------------+
|                    Handoff (firmware_handoff.json)                  |
+--------------------------------------------------------------------+
|                     Terminator (Orchestrator)                       |
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
# FirmAE dataset benchmark (1,124 firmware images, 8 vendors)
./scripts/benchmark_firmae.sh --parallel 8 --time-budget 1800 --cleanup

# Options
--dataset-dir DIR       # Firmware directory (default: aiedge-inputs/firmae-benchmark)
--results-dir DIR       # Output directory
--parallel N            # Concurrent jobs (default: 4)
--time-budget S         # Seconds per firmware (default: 600)
--stages STAGES         # Specific stages (default: full pipeline)
--max-images N          # Limit images (0 = all)
--8mb                   # Use 8MB truncated track
--full                  # Include dynamic stages
--cleanup               # Archive JSONs, delete run dirs (saves disk)
--dry-run               # List files without running

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
```

</details>

<details>
<summary><strong>Environment Variables</strong></summary>

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_LLM_DRIVER` | `codex` | LLM provider: `codex` / `claude` / `ollama` |
| `ANTHROPIC_API_KEY` | -- | API key for Claude driver |
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

MIT

---

<div align="center">

<sub>Built for the security research community. Not for unauthorized access.</sub>

<br />

<a href="https://github.com/R00T-Kim/SCOUT">github.com/R00T-Kim/SCOUT</a>

</div>
