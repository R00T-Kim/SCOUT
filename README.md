<div align="center">

<img src="https://img.shields.io/badge/SCOUT-Firmware_Evidence_Engine-0d1117?style=for-the-badge&labelColor=0d1117" alt="SCOUT" />

# SCOUT

### Firmware-to-Exploit Evidence Engine

**Drop a firmware blob. Get SARIF findings, CycloneDX SBOM+VEX, and a hash-anchored evidence chain.**

<br />

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Stages](https://img.shields.io/badge/Pipeline-34_Stages-blueviolet?style=for-the-badge)]()
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero_(stdlib)-orange?style=for-the-badge)]()

[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-blue?style=for-the-badge&logo=github)]()
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX_1.6+VEX-brightgreen?style=for-the-badge)]()
[![SLSA](https://img.shields.io/badge/SLSA-Level_2-purple?style=for-the-badge)]()

[English (this file)](README.md) | [한국어](README.ko.md)

</div>

---

## Why SCOUT?

> **Every finding has a hash-anchored evidence chain.**
>
> SCOUT does not emit a finding without a file path, byte offset, SHA-256 hash, and rationale. Artifacts are immutable and traceable from firmware blob to final verdict. No black-box scoring.

> **Static-only findings capped at 0.60 -- we don't inflate.**
>
> If a vulnerability hasn't been dynamically validated, its confidence is hard-capped. Promotion to `confirmed` requires at least one dynamic verification artifact. Honest confidence beats high numbers.

> **SARIF + CycloneDX VEX + SLSA provenance -- not another custom format.**
>
> Findings export to SARIF 2.1.0 for GitHub Code Scanning and VS Code. SBOM ships with CycloneDX 1.6 + Vulnerability Exploitability eXchange. Analysis artifacts carry SLSA Level 2 in-toto attestations.

---

## What's New

| Feature | Description |
|:--------|:------------|
| **SARIF 2.1.0 Export** | Standard findings output for GitHub Code Scanning, VS Code SARIF Viewer, and CI/CD integration |
| **CycloneDX VEX** | Vulnerability Exploitability eXchange states (exploitable / affected / not_affected) embedded in SBOM |
| **Precise .dynstr Detection** | ELF dynamic import table parsing replaces naive byte-scan; FORTIFY_SOURCE coverage detection |
| **40+ SBOM Signatures** | wolfSSL, mbedTLS, GoAhead, miniUPnPd, SQLite, U-Boot, lighttpd, and 30+ more (up from 8) |
| **Ghidra Headless Scripts** | 4 analysis scripts: `decompile_all`, `xref_graph`, `dataflow_trace`, `string_refs` |
| **AFL++ Performance** | CMPLOG, persistent mode, NVRAM faker, multi-instance campaigns, `AFL_ENTRYPOINT` support |
| **Reachability-Aware CVE** | CVE confidence auto-adjusted by BFS network reachability analysis |
| **SLSA L2 Provenance** | in-toto attestation for analysis artifacts, cosign-ready verification |
| **Benchmark Runner** | Corpus-based quality measurement with precision / recall / FPR tracking |
| **Quality Gate Overrides** | Configurable thresholds via environment variables for CI/CD pipelines |

---

## How It Works

```
  1. Drop            2. Analyze              3. Collect               4. Review
  ─────────          ──────────              ──────────               ────────
  firmware.bin  ──>  34-stage pipeline  ──>  SARIF findings      ──>  Web viewer
                     runs automatically      CycloneDX SBOM+VEX      VS Code (SARIF)
                                             Evidence chain           GitHub Code Scanning
                                             SLSA attestation         TUI dashboard
```

**Step 1** -- Point SCOUT at any firmware blob (or pre-extracted rootfs).

**Step 2** -- The 34-stage pipeline runs end-to-end: unpacking, profiling, binary analysis, SBOM generation, CVE scanning, reachability analysis, security assessment, attack surface mapping, exploit chain construction, optional Ghidra decompilation, optional AFL++ fuzzing.

**Step 3** -- Outputs land in a structured run directory: SARIF 2.1.0 findings, CycloneDX 1.6 SBOM with VEX annotations, hash-anchored evidence chain, SLSA L2 provenance attestation, and executive Markdown report.

**Step 4** -- Review results in the built-in web viewer, import SARIF into VS Code or GitHub Code Scanning, query artifacts via MCP server from Claude Code/Desktop, or inspect via TUI dashboard.

---

## Quick Start

```bash
# Full analysis (all features enabled by default)
./scout analyze firmware.bin

# Deterministic only (no LLM)
./scout analyze firmware.bin --no-llm

# Pre-extracted rootfs (bypasses weak unpacking)
./scout analyze firmware.img --rootfs /path/to/extracted/rootfs

# Analysis-only profile (no exploit chain)
./scout analyze firmware.bin --profile analysis --no-llm

# SARIF export for CI/CD
./scout analyze firmware.bin --no-llm
# -> aiedge-runs/<run_id>/stages/findings/sarif.json

# MCP server for AI agents
./scout mcp --project-id aiedge-runs/<run_id>

# Web viewer
./scout serve aiedge-runs/<run_id> --port 8080
```

---

## Comparison

| Feature | SCOUT | EMBA | FACT | FirmAE |
|:--------|:-----:|:----:|:----:|:------:|
| SBOM (CycloneDX 1.6) | Yes + VEX | Yes | No | No |
| SARIF 2.1.0 Export | Yes | No | No | No |
| Hash-Anchored Evidence Chain | Yes | No | No | No |
| SLSA L2 Provenance | Yes | No | No | No |
| Reachability-Aware CVE | Yes | No | No | No |
| Confidence Caps (honest scoring) | Yes | No | No | No |
| Ghidra Headless Integration | Yes | Yes | No | No |
| AFL++ Fuzzing Pipeline | Yes | No | No | No |
| 3-Tier Emulation | Yes | Partial | No | Yes |
| MCP Server (AI agent integration) | Yes | No | No | No |
| LLM Triage + Synthesis | Yes | No | No | No |
| Web Report Viewer | Yes | Yes | Yes | No |
| Zero pip Dependencies | Yes | No | No | No |

---

## Key Features

| | Feature | Description |
|---|---------|-------------|
| :package: | **SBOM & CVE** | CycloneDX 1.6 SBOM (40+ signatures) + NVD API 2.0 CVE scanning with VEX and reachability-aware confidence |
| :mag: | **Binary Analysis** | ELF hardening audit (NX/PIE/RELRO/Canary) + precise `.dynstr` symbol detection + FORTIFY_SOURCE + optional Ghidra headless decompilation |
| :dart: | **Attack Surface** | Source-to-sink tracing, IPC detection (5 types), credential auto-mapping |
| :shield: | **Security Assessment** | X.509 certificate scanning, boot service auditing, filesystem permission checks |
| :test_tube: | **Fuzzing** *(optional)* | AFL++ pipeline with CMPLOG, persistent mode, NVRAM faker, binary scoring, harness generation, crash triage — requires Docker + AFL++ image |
| :bug: | **Emulation** | 3-tier (FirmAE / QEMU user-mode / rootfs inspection) + GDB remote debugging |
| :robot: | **MCP Server** | 12 tools exposed via Model Context Protocol for Claude Code/Desktop integration |
| :brain: | **LLM Drivers** | Codex CLI + Claude API + Ollama -- with cost tracking and budget limits |
| :bar_chart: | **Web Viewer** | Glassmorphism dashboard with KPI bar, IPC map, risk heatmap, graph visualization |
| :link: | **Evidence Chain** | Hash-anchored artifacts, confidence caps, exploit tiering, verified chain gating |
| :scroll: | **SARIF Export** | SARIF 2.1.0 findings for GitHub Code Scanning, VS Code SARIF Viewer, CI/CD |
| :lock: | **SLSA Provenance** | Level 2 in-toto attestation for analysis artifacts, cosign-ready |
| :clipboard: | **Executive Reports** | Auto-generated Markdown reports with top risks, SBOM/CVE tables, attack surface |
| :arrows_counterclockwise: | **Firmware Diff** | Compare two analysis runs -- filesystem, hardening, and config security changes |
| :chart_with_upwards_trend: | **Benchmark Runner** | Corpus-based quality measurement with precision/recall/FPR tracking |

---

## Pipeline (34 Stages)

```
Firmware --> Unpack --> Profile --> Inventory --> [Ghidra] --> SBOM --> CVE Scan
    --> Reachability --> Security Assessment --> Endpoints --> Surfaces --> Graph
    --> Attack Surface --> Findings --> LLM Triage --> LLM Synthesis
    --> Emulation (3-tier) --> [Fuzzing] --> Exploit Chain --> PoC --> Verification
```

Stages in `[brackets]` require optional external tools (Ghidra, AFL++/Docker).

---

## Architecture

```
+------------------------------------------------------------------+
|                      SCOUT (Evidence Engine)                      |
|                                                                   |
|  Firmware --> Unpack --> Profile --> Inventory --> SBOM --> CVE    |
|                                      (+ hardening)  (NVD 2.0)    |
|                                                         |         |
|  --> Security Assessment --> Surfaces --> Reachability --> Find    |
|      (cert/init/fs-perm)                 (BFS graph)              |
|                                                                   |
|  --> [Ghidra] --> LLM Triage --> LLM Synthesis                    |
|  --> Emulation --> [Fuzzing] --> Exploit --> PoC --> Verify        |
|                                                                   |
|  34 stages . stage.json manifests . SHA-256 hashed artifacts      |
|  Outputs: SARIF 2.1.0 + CycloneDX 1.6+VEX + SLSA L2 provenance  |
+------------------------------------------------------------------+
|                   Handoff (firmware_handoff.json)                  |
+------------------------------------------------------------------+
|                    Terminator (Orchestrator)                       |
|  Tribunal --> Validator --> Exploit Dev --> Verified Chain         |
|  (LLM judge)  (emulation)   (lab-gated)    (dynamic evidence)    |
+------------------------------------------------------------------+
```

| Layer | Role | Deterministic? |
|:------|:-----|:--------------:|
| **SCOUT** | Evidence production (extraction, profiling, inventory, surfaces, findings) | Yes |
| **Handoff** | JSON contract between engine and orchestrator | Yes |
| **Terminator** | LLM tribunal, dynamic validation, exploit development, report promotion | No (auditable) |

---

## Exploit Promotion Policy

**Iron rule: no Confirmed without dynamic evidence.**

| Level | Requirements | Placement |
|:------|:-------------|:----------|
| `dismissed` | Critic rebuttal strong or confidence < 0.5 | Appendix only |
| `candidate` | Confidence 0.5-0.8, evidence exists but chain incomplete | Report (flagged) |
| `high_confidence_static` | Confidence >= 0.8, strong static evidence, no dynamic | Report (highlighted) |
| `confirmed` | Confidence >= 0.8 AND >= 1 dynamic verification artifact | Report (top) |
| `verified_chain` | Confirmed AND PoC reproduced 3x in sandbox, complete chain | Exploit report |

---

<details>
<summary><strong>CLI Reference</strong></summary>

| Command | Description |
|---------|-------------|
| `./scout analyze <firmware>` | Full firmware analysis pipeline |
| `./scout analyze-8mb <firmware>` | Truncated 8MB canonical track |
| `./scout stages <run_dir>` | Rerun specific stages on existing run |
| `./scout mcp --project-id <id>` | Start MCP stdio server |
| `./scout serve <run_dir>` | Launch web report viewer |
| `./scout tui <run_dir>` | Terminal UI dashboard |
| `./scout ti` | TUI interactive mode (latest run) |
| `./scout tw <run_dir> -t 2` | TUI watch mode (auto-refresh) |
| `./scout corpus-validate <run_dir>` | Validate corpus manifest |
| `./scout quality-metrics <run_dir>` | Compute quality metrics |
| `./scout quality-gate <run_dir>` | Check quality thresholds |
| `./scout release-quality-gate <run_dir>` | Unified release gate |

**Exit codes:** `0` success, `10` partial, `20` fatal, `30` policy violation

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

### SBOM & CVE

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_NVD_API_KEY` | -- | NVD API key (optional, improves rate limits) |
| `AIEDGE_NVD_CACHE_DIR` | `aiedge-nvd-cache` | Cross-run NVD response cache |
| `AIEDGE_SBOM_MAX_COMPONENTS` | `500` | Maximum SBOM components |
| `AIEDGE_CVE_SCAN_MAX_COMPONENTS` | `50` | Maximum components to CVE-scan |
| `AIEDGE_CVE_SCAN_TIMEOUT_S` | `30` | Per-request NVD API timeout |

### LLM Timeouts

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_LLM_CHAIN_TIMEOUT_S` | `180` | LLM synthesis timeout |
| `AIEDGE_LLM_CHAIN_MAX_ATTEMPTS` | `5` | LLM synthesis max retries |
| `AIEDGE_AUTOPOC_LLM_TIMEOUT_S` | `180` | Auto-PoC LLM timeout |
| `AIEDGE_AUTOPOC_LLM_MAX_ATTEMPTS` | `4` | Auto-PoC max retries |

### Ghidra

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_GHIDRA_HOME` | -- | Ghidra installation path |
| `AIEDGE_GHIDRA_MAX_BINARIES` | `20` | Max binaries to analyze |
| `AIEDGE_GHIDRA_TIMEOUT_S` | `300` | Per-binary analysis timeout |

### Fuzzing (AFL++)

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_AFLPP_IMAGE` | `aflplusplus/aflplusplus` | AFL++ Docker image |
| `AIEDGE_FUZZ_BUDGET_S` | `3600` | Fuzzing time budget (seconds) |
| `AIEDGE_FUZZ_MAX_TARGETS` | `5` | Max fuzzing target binaries |

### Emulation

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_EMULATION_IMAGE` | `scout-emulation:latest` | Tier 1 Docker image |
| `AIEDGE_FIRMAE_ROOT` | `/opt/FirmAE` | FirmAE installation path |
| `AIEDGE_QEMU_GDB_PORT` | `1234` | QEMU GDB remote port |

### MCP & Port Scanning

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_MCP_MAX_OUTPUT_KB` | `512` | MCP response max size |
| `AIEDGE_PORTSCAN_TOP_K` | `1000` | Top-K ports to scan |
| `AIEDGE_PORTSCAN_WORKERS` | `128` | Concurrent scan workers |
| `AIEDGE_PORTSCAN_BUDGET_S` | `120` | Port scan time budget |

### Quality Gate Overrides

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_QG_PRECISION_MIN` | `0.9` | Minimum precision threshold |
| `AIEDGE_QG_RECALL_MIN` | `0.6` | Minimum recall threshold |
| `AIEDGE_QG_FPR_MAX` | `0.1` | Maximum false positive rate |
| `AIEDGE_QG_ABSTAIN_MAX` | `0.25` | Maximum abstention rate |

</details>

<details>
<summary><strong>Run Directory Structure</strong></summary>

```
aiedge-runs/<run_id>/
├── manifest.json
├── firmware_handoff.json
├── provenance.intoto.jsonl          # SLSA L2 attestation
├── input/firmware.bin
├── stages/
│   ├── tooling/
│   ├── extraction/
│   ├── firmware_profile/
│   ├── inventory/
│   │   └── binary_analysis.json     # per-binary hardening data
│   ├── sbom/
│   │   ├── sbom.json                # CycloneDX 1.6 + CPE index
│   │   └── vex.json                 # VEX exploitability annotations
│   ├── cve_scan/
│   │   └── cve_scan.json            # NVD API CVE matches
│   ├── reachability/
│   │   └── reachability.json        # BFS reachability classification
│   ├── surfaces/
│   │   └── source_sink_graph.json
│   ├── ghidra_analysis/             # optional
│   ├── findings/
│   │   ├── pattern_scan.json
│   │   ├── credential_mapping.json
│   │   ├── chains.json
│   │   └── sarif.json               # SARIF 2.1.0 export
│   ├── fuzzing/                     # optional
│   │   └── fuzz_results.json
│   └── graph/
│       └── communication_graph.json
└── report/
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
python3 scripts/verify_exploit_meaningfulness.py --run-dir aiedge-runs/<run_id>

# SLSA provenance verification
cosign verify-attestation --type slsaprovenance \
  aiedge-runs/<run_id>/provenance.intoto.jsonl

# Quality gates
./scout quality-gate aiedge-runs/<run_id>
./scout release-quality-gate aiedge-runs/<run_id>
```

</details>

---

## Documentation

| Document | Purpose |
|:---------|:--------|
| [Blueprint](docs/blueprint.md) | Full pipeline architecture and design rationale |
| [Status](docs/status.md) | Current implementation status |
| [Artifact Schema](docs/aiedge_firmware_artifacts_v1.md) | Profiling + inventory artifact contracts |
| [Adapter Contract](docs/aiedge_adapter_contract.md) | Terminator-SCOUT handoff protocol |
| [Report Contract](docs/aiedge_report_contract.md) | Report structure and governance rules |
| [Analyst Digest](docs/analyst_digest_contract.md) | Digest schema and verdict semantics |
| [Verified Chain](docs/verified_chain_contract.md) | Evidence requirements for verified chains |
| [Duplicate Gate](docs/aiedge_duplicate_gate_contract.md) | Cross-run duplicate suppression rules |
| [Determinism Policy](docs/determinism_policy.md) | Replay gate rules and relaxation policy |
| [Quality SLO](docs/quality_slo.md) | Precision, recall, FPR thresholds |
| [Runbook](docs/runbook.md) | Operator flow for digest-first review |

---

## Security & Ethics

> **Authorized environments only.**

SCOUT is intended for use in controlled environments with proper authorization:

- **Contracted security audits** -- vendor-coordinated firmware assessments
- **Vulnerability research** -- responsible disclosure with coordinated timelines
- **CTF and training** -- designated targets in lab environments

Dynamic validation runs in network-isolated sandbox containers. Exploit profile and lab attestation are enabled by default. No weaponized payloads are included.

---

## Contributing

Contributions are welcome. Before submitting a pull request:

1. **Read** [Blueprint](docs/blueprint.md) for architecture context
2. **Run** `pytest -q` -- all tests must pass
3. **Check** `pyright src/` -- zero type errors
4. **Follow** the existing stage protocol (see `Stage` in `src/aiedge/stage.py`)
5. **Zero pip dependencies** -- stdlib only for core modules

For new pipeline stages, see the "Adding a New Pipeline Stage" section in `CLAUDE.md`.

---

## License

MIT

---

<div align="center">

<sub>Built for the security research community. Not for unauthorized access.</sub>

<br />

<a href="https://github.com/R00T-Kim/SCOUT">github.com/R00T-Kim/SCOUT</a>

</div>
