<p align="right">
  <strong>English</strong> |
  <a href="README.ko.md">한국어</a>
</p>

# SCOUT (v3.0.0-rc1)

### AEG-First Firmware Exploitability Platform with Deterministic Evidence Lineage

**SCOUT is an AEG-first firmware analysis platform that transforms raw firmware blobs into evidence-anchored exploitability chains, lab-bounded Proof-of-Vulnerability modules, controlled weaponization packages for authorized internal red teams, and audit-ready dossiers. Now featuring a Hybrid Analysis Engine for both Binary and Shell Script auditing.**

*While traditional scanners prioritize bulk and speed, SCOUT acts as a high-fidelity AEG copilot for product-security and internal red-team workflows: it reconstructs exploit chains across ELF binaries and shell scripts, explains its reasoning with evidence trails, and promotes lab-bounded PoV/PoC results toward scoped, private, evidence-led weaponization rather than raw public-PoC copies.*

<br />

<div align="center">
  <a href="#what-you-can-do">What you can do</a> •
  <a href="#why-scout">Why SCOUT?</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#key-features">Key Features</a> •
  <a href="CHANGELOG.md">Changelog</a>
</div>

<br />

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=for-the-badge)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero_(stdlib)-orange?style=for-the-badge)]()
[![Version](https://img.shields.io/badge/Version-3.0.0--rc1-red?style=for-the-badge)]()

[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-blue?style=for-the-badge&logo=github)]()
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX_1.6+VEX-brightgreen?style=for-the-badge)]()
[![SLSA](https://img.shields.io/badge/SLSA-Level_2-purple?style=for-the-badge)]()

<br />

<table>
<tr>
<td align="center"><strong>1,123</strong><br/><sub>Corpus Targets</sub></td>
<td align="center"><strong>98.8%</strong><br/><sub>Analysis Success</sub></td>
<td align="center"><strong>1,300+</strong><br/><sub>Scripts Scanned</sub></td>
<td align="center"><strong>99.3%</strong><br/><sub>FP Reduction (LLM)</sub></td>
<td align="center"><strong>v3.0.0-rc1</strong><br/><sub>Hybrid Engine</sub></td>
</tr>
</table>

</div>

---

<h2 id="what-you-can-do">🚀 What you can do with SCOUT</h2>

- **Hybrid Triage**: Audit both ELF binaries and shell scripts in a single unified pipeline.
- **Deep Exploit Discovery**: Find complex `Web -> IPC -> Config -> Daemon` or `Shell -> Binary` chains.
- **AEG-first AutoPoC**: Leverage the **Exploit Pattern RAG** to generate lab-ready Proof-of-Vulnerability modules from firmware evidence.
  - SCOUT now includes a runtime `exploit_intel` stage plus a metadata-only PoC-in-GitHub importer, Aqua `vuln-list-update`/NVD enrichment, and a human-review-required draft pattern-card promoter for firmware-relevant CVE seeds before AutoPoC retrieval.
  - SCOUT does **not** clone, execute, or prompt-inject raw public PoC repositories for copy-based exploitation. A platform-level AEG claim must pass the E2E dynamic/FP gate in [`docs/aeg_e2e_validation.md`](docs/aeg_e2e_validation.md). See also [`docs/exploit-pattern-rag.md`](docs/exploit-pattern-rag.md).
  - For internal red-team use, SCOUT treats weaponization as a **controlled, private, authorization-bound promotion layer**: scoped target profiling, precondition solving, reproducibility, cleanup, and evidence ledgers. See [`docs/controlled_weaponization_layer.md`](docs/controlled_weaponization_layer.md).
- **Evidence Investigation**: Use the Glassmorphism Web Dashboard to walk through decompiled P-code and shell logic.
- **Controlled Weaponization Readiness**: Promote verified PoV evidence into private, scope-bound exploit packages for authorized internal red teams without publishing working payloads.
- **Audit/compliance-compatible reporting**: Generate SARIF, CycloneDX 1.6 SBOM+VEX, and SLSA L2 attestations.

---

<h2 id="why-scout">💎 The SCOUT Advantage</h2>

> **[1] Hybrid Analysis Engine (v3)**
> Bridges the gap between binary-level execution and high-level shell logic, expanding coverage into script-driven firmware attack surfaces that binary-only pipelines miss.

> **[2] Hash-Anchored Evidence Lineage**
> Every finding is tied to a specific file path, byte offset, and SHA-256 hash. No black-box guesses.

> **[3] Intelligent Analyst Copilot**
> Built-in LLM tribunal (Advocate/Critic) reduces false positives by 99.3% on the historical Tier-2 benchmark using the registered multi-stage triage pipeline.

> **[4] Zero Dependency (Pure Stdlib)**
> No `pip install` nightmares. Deploy instantly in air-gapped labs or restricted environments.

---

<h2 id="quick-start">⚡ Quick Start</h2>

```bash
# Analyze a firmware image (Hybrid mode enabled by default)
./scout analyze firmware.bin

# Explore findings in the Web Dashboard
./scout serve aiedge-runs/<run_id> --port 8080

# Deep dive in the Terminal UI
./scout tui

# Seed Exploit Pattern RAG candidates from PoC-in-GitHub metadata only
python scripts/import_poc_in_github_candidates.py --dry-run

# Optionally enrich from a local Aqua vuln-list checkout generated by vuln-list-update
AIEDGE_VULN_LIST_DIR=/opt/vuln-list \
python scripts/import_poc_in_github_candidates.py --cve CVE-2023-1389 --vuln-list-dir /opt/vuln-list

# Draft a human-review-required pattern card from one candidate
python scripts/draft_exploit_pattern_card.py data/exploit_references/candidates/poc_in_github/cve-2024-1781.json --print-json

# After a real authorized lab run, enforce dynamic proof + FP/FPR evidence
./scout aeg-e2e-gate aiedge-runs/<run_id>

# Lower evidence + private package metadata into a bounded SCOUT-W Plan IR,
# then fail closed on scope/profile/precondition checks before private execution.
./scout weaponization-plan aiedge-runs/<run_id> \
  --package-manifest /secure/private/package.manifest.json \
  --out aiedge-runs/<run_id>/weaponization_plan.json
./scout weaponization-preflight aiedge-runs/<run_id> \
  --plan aiedge-runs/<run_id>/weaponization_plan.json \
  --package-manifest /secure/private/package.manifest.json \
  --out aiedge-runs/<run_id>/weaponization_preflight.json

# Lint and register private package metadata in a hash-only vault allowlist.
./scout weaponization-package lint \
  --package-manifest /secure/private/package.manifest.json \
  --out /secure/private/package.lint.json
./scout weaponization-package register \
  --registry /secure/private/package_vault.json \
  --package-manifest /secure/private/package.manifest.json

# Promote a private internal red-team package only after scope, firmware binding,
# cleanup, control-pair, and AEG evidence gates pass (no exploit source is loaded).
./scout weaponization-readiness aiedge-runs/<run_id> \
  --package-manifest /secure/private/package.manifest.json \
  --out aiedge-runs/<run_id>/controlled_weaponization_readiness.json

# Execute the private package only after plan/preflight/readiness gates pass,
# then write the L6/L7 execution ledger.
./scout weaponization-execute aiedge-runs/<run_id> \
  --exploit-dir /secure/private/exploits \
  --plan aiedge-runs/<run_id>/weaponization_plan.json \
  --preflight aiedge-runs/<run_id>/weaponization_preflight.json \
  --readiness aiedge-runs/<run_id>/controlled_weaponization_readiness.json \
  --cleanup-log /secure/private/cleanup.log \
  --vault-registry /secure/private/package_vault.json \
  --approval /secure/private/engagement_approval.json \
  --out-ledger aiedge-runs/<run_id>/weaponization_ledger.json

# Or aggregate already-captured execution evidence, cleanup proof,
# and optional engagement approval into the L6/L7 ledger.
./scout weaponization-ledger aiedge-runs/<run_id> \
  --plan aiedge-runs/<run_id>/weaponization_plan.json \
  --preflight aiedge-runs/<run_id>/weaponization_preflight.json \
  --readiness aiedge-runs/<run_id>/controlled_weaponization_readiness.json \
  --execution-evidence aiedge-runs/<run_id>/exploits/chain_<id>/evidence_bundle.json \
  --cleanup-log /secure/private/cleanup.log \
  --approval /secure/private/engagement_approval.json \
  --out aiedge-runs/<run_id>/weaponization_ledger.json

# CI-safe AEG regression: vulnerable lab service must pass, patched control must fail closed
python scripts/run_aeg_synthetic_pair.py --work-root /tmp/scout-aeg-synthetic-pair
python scripts/run_aeg_synthetic_pair.py --pattern cgi_param_cmd_injection --work-root /tmp/scout-aeg-cgi-pair
python scripts/run_aeg_synthetic_pair.py --pattern config_derived_cmd_injection --work-root /tmp/scout-aeg-config-pair

# Inspect which Exploit Pattern RAG cards have vulnerable/control evidence
python scripts/check_exploit_pattern_evidence.py
python scripts/check_exploit_pattern_evidence.py --require-real-firmware-pair

# Audit AEG platform readiness from card evidence + stable real-firmware pair proof
./scout aeg-readiness --out docs/pov/aeg_platform_readiness.json

# Run/reuse an official known-vulnerable/patched firmware pair and emit the fail-closed gate report.
./scout aeg-real-pair --pair-id <manifest-pair-id> --fetch --no-llm \
  --pattern-id <pattern-id> --out docs/pov/<stable-pair-evidence>.json

# Record real known-vulnerable/patched firmware pair evidence on a pattern card.
python scripts/record_pattern_pair_evidence.py <pattern-id> --kind real_firmware_pair \
  --vulnerable-run-dir aiedge-runs/<known-vulnerable-run> \
  --control-run-dir aiedge-runs/<patched-control-run> \
  --artifact docs/pov/<stable-pair-evidence>.json \
  --vulnerable-firmware-sha256 <sha256> \
  --control-firmware-sha256 <sha256> \
  --cve CVE-YYYY-NNNN --apply
```

---

<h2 id="key-features">✨ Key Features</h2>

| | Feature | Description |
|---|---------|-------------|
| :package: | **Hybrid SBOM & CVE** | CycloneDX 1.6 + VEX + NVD scan + 2,528 local CVE DB + Integrated Shell Script auditing |
| :mag: | **Binary Analysis** | Ghidra P-code SSA dataflow taint + ELF hardening detection + 28 sink symbols |
| :shell: | **Script Analysis** | Heuristic auditing of 1,000+ scripts for insecure `eval`, backticks, and unquoted variable usage |
| :dart: | **Attack Surface** | Source→sink tracing, web server auto-detection, cross-binary IPC chains (5 types) |
| :brain: | **Taint Analysis** | HTTP-aware inter-procedural taint, P-code SSA dataflow, call chain visualization |
| :robot: | **LLM Engine** | 4 backends + centralized system prompts + structured JSON output + 5-stage parser |
| :books: | **Exploit Pattern RAG** | Runtime `exploit_intel` seeds plus curated pattern-card retrieval, PoC-in-GitHub metadata, Aqua vuln-list-update/NVD enrichment, and reviewed draft promotion for firmware-relevant AEG candidates |
| :crossed_swords: | **LLM-Adjudicated Debate** | Advocate/Critic LLM debate for high-fidelity FPR reduction |
| :bar_chart: | **Web Viewer** | Glassmorphism dashboard with KPI bar, IPC map, risk heatmap, and evidence navigation |
