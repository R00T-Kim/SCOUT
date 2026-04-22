# SCOUT FDA Section 524B Compatibility Mapping

**Document Version:** 1.0
**SCOUT Version:** 2.5.0+
**Last revised:** 2026-04-19 (Phase 3'.1 step B-2)
**Regulation:** United States Food, Drug, and Cosmetic Act §524B (21 U.S.C. §360n-2), added by §3305 of the Consolidated Appropriations Act, 2023 ("FDORA"), effective 29 March 2023; FDA Premarket Cybersecurity Guidance ("Cybersecurity in Medical Devices: Quality System Considerations and Content of Premarket Submissions", final 27 September 2023)

---

> **Disclaimer**: This document maps SCOUT outputs to obligations established by FDA Section 524B and the FDA premarket cybersecurity guidance for reference. SCOUT's output formats are *compatible with* the technical evidence requirements that 524B and the guidance describe; full premarket submission acceptance depends on the operator's complete quality system, risk management documentation, labelling, and the FDA review itself. The phrase "compatible with" is mandatory throughout this directory; do not substitute "compliant with", "compliance", or "ready" — see `scripts/check_doc_consistency.py` for the regex enforcement.

---

## Companion mappings

This file is the second member of the four-document compliance-mapping suite established under Phase 3'.1:

- `docs/compliance_mapping/cra_annex_i.md` — EU Cyber Resilience Act Annex I (B-1, landed)
- **`docs/compliance_mapping/fda_section_524b.md`** — FDA Section 524B (this document, B-2)
- `docs/compliance_mapping/iso_21434.md` — ISO/SAE 21434 (B-3, planned)
- `docs/compliance_mapping/un_r155.md` — UN R155 (B-3, planned)

---

## Executive Summary

Section 524B of the FD&C Act, added by the FDORA omnibus on 29 December 2022 and effective 29 March 2023, makes cybersecurity a statutory submission requirement for any "cyber device" subject to premarket review by the United States Food and Drug Administration. A *cyber device* is a device that (1) includes software validated, installed, or authorised by the sponsor as a device or in a device, (2) has the ability to connect to the internet, and (3) contains any technological characteristics that could be vulnerable to cybersecurity threats. The statute is supplemented by the FDA's final 2023 premarket cybersecurity guidance, which expands the §524B language into a concrete evidence framework covering security risk management, threat modelling, architecture views, cybersecurity testing, and a software bill of materials (SBOM).

SCOUT addresses the technically demanding portions of that evidence framework — specifically the SBOM, vulnerability management, hardening attestation, and update-mechanism observability — through hash-anchored evidence packaging, machine-readable output, and deterministic pipeline reproducibility. SCOUT's outputs are produced in formats that the guidance recognises (CycloneDX 1.6 SBOM, VEX, SARIF 2.1.0 vulnerability reports, in-toto SLSA Level 2 provenance attestations); the burden of submission narrative, threat modelling diagrams, and SDLC documentation remains with the device sponsor.

This document maps SCOUT's analytical capabilities to:

- **Section 524B(b)** statutory cybersecurity requirements (four explicit obligations the sponsor must satisfy);
- the **FDA premarket guidance content elements** (security objectives, threat model, security risk management, cybersecurity testing, architecture views, SBOM); and
- the supporting **postmarket** expectations articulated in the 2016 postmarket cybersecurity guidance that §524B effectively brings forward.

---

## Regulatory Context

### Section 524B core obligations

Section 524B(b) requires the sponsor of a premarket submission for a cyber device to:

| Ref | Obligation (paraphrased from 21 U.S.C. §360n-2(b)) |
|-----|----------------------------------------------------|
| (b)(1) | Submit a plan to monitor, identify, and address (in a reasonable time) postmarket cybersecurity vulnerabilities and exploits, including coordinated vulnerability disclosure and related procedures |
| (b)(2)(A) | Design, develop, and maintain processes and procedures to provide reasonable assurance that the device and related systems are cybersecure |
| (b)(2)(B) | Make available postmarket updates and patches to the device and related systems — on a reasonably justified regular cycle for known unacceptable vulnerabilities, and as soon as possible out of cycle for critical vulnerabilities that could cause uncontrolled risks |
| (b)(3) | Provide a software bill of materials, including commercial, open-source, and off-the-shelf software components |

The statute also empowers the Secretary to impose additional requirements as needed to demonstrate reasonable assurance of safety and effectiveness for cybersecurity purposes (§524B(b)(4)).

### FDA premarket guidance — content elements

The September 2023 final guidance, "Cybersecurity in Medical Devices: Quality System Considerations and Content of Premarket Submissions", expands the statutory text into a content framework. SCOUT's output is most relevant to the following premarket content elements:

| Guidance element | Description |
|------------------|-------------|
| Security objectives | Documented confidentiality / integrity / availability objectives per device function |
| Security risk management | Risk register linking threats to safety hazards; risk acceptance criteria |
| Threat modelling | STRIDE / DREAD / attack-tree analysis tied to device architecture |
| Cybersecurity risk assessment | Vulnerability identification, exploitability assessment, risk scoring |
| SBOM | CycloneDX or SPDX inventory with versions and known vulnerability status |
| Vulnerability management | Process for monitoring, triaging, and disclosing newly discovered vulnerabilities |
| Architecture views | Global, multi-patient, updateability/patchability, and security use case views |
| Cybersecurity testing | Vulnerability testing, penetration testing, software composition analysis |
| Labelling | End-user-facing security documentation, dependency disclosure, update mechanisms |
| Postmarket cybersecurity management plan | The plan required by §524B(b)(1) plus postmarket monitoring procedures |

### Timeline

| Date | Milestone |
|------|-----------|
| 29 December 2022 | FDORA enacted; §3305 adds §524B to the FD&C Act |
| 29 March 2023 | §524B effective; FDA begins to "RTA" (refuse-to-accept) submissions for cyber devices that lack the §524B(b) elements |
| 27 September 2023 | FDA final premarket cybersecurity guidance issued |
| 1 October 2023 onward | Premarket submissions for cyber devices reviewed against the final guidance |

---

## Section 524B Core Requirements Mapping

| Req | §524B(b) Obligation | SCOUT Stage(s) | Output Artifact(s) | Coverage | Confidence | Notes |
|-----|---------------------|----------------|--------------------|----------|------------|-------|
| 524B(b)(1) | Postmarket vulnerability monitoring + coordinated disclosure plan | `cve_scan`, `findings`, `reporting` | `cve_matches.json`, `analyst_digest.json`, `executive_report.md`, `sarif.json` | **Partial** | High | SCOUT produces machine-readable disclosure-ready vulnerability reports (SARIF 2.1.0, analyst digest with severity / disposition / evidence-tier annotations). The *plan* itself — disclosure pipeline, contact addresses, response SLAs — is sponsor-side QMS documentation outside SCOUT's scope |
| 524B(b)(2)(A) | Design / develop / maintain cybersecure processes | `inventory`, `firmware_profile`, `enhanced_source`, `attack_surface`, `surfaces`, `init_analysis`, `fs_permissions`, `cert_analysis` | `binary_analysis.json` (hardening), `attack_surface.json`, `init_analysis.json`, `fs_permissions.json`, `certificate_analysis.json` | **Partial** | High | Static evidence of secure-design choices (NX/PIE/RELRO/Canary/FORTIFY hardening, init-service surface, file permissions, X.509 hygiene). Process maturity (SDLC documentation, change control records, training) remains sponsor-side |
| 524B(b)(2)(B) | Postmarket updates + patches (regular cycle + critical out-of-cycle) | `firmware_profile`, `sbom`, `cve_scan`, `firmware_diff` | `firmware_profile.json`, `sbom.json`, `cve_matches.json`, `firmware_diff.json` | **Full** | Very High | Update-mechanism detection in firmware profiling, SBOM-anchored patch tracking, cross-firmware diff stage for verifying that a postmarket update actually changes the affected components. CVE matching with EPSS prioritisation supports the "critical out-of-cycle" decision |
| 524B(b)(3) | SBOM (commercial / open-source / off-the-shelf components) | `sbom`, `inventory` | `sbom.json` (CycloneDX 1.6), `cpe_index.json` | **Full** | Very High | CycloneDX 1.6 SBOM with CPE 2.3 identifiers per component, derived from opkg/dpkg DB, binary version strings, shared-object versions, and kernel version. Schema is FDA-recognised for premarket submission |

---

## FDA Premarket Guidance Content Element Mapping

| Element | SCOUT Stage(s) | Output Artifact(s) | Coverage | Notes |
|---------|----------------|--------------------|----------|-------|
| Security objectives | — | — | **Out of scope** | Sponsor-side device-function-specific decision; SCOUT does not infer objectives from binaries |
| Security risk management | `findings`, `cve_scan`, `reachability` | `findings.json`, `cve_matches.json`, `reachability.json` | **Partial** | Vulnerability inventory + reachability + EPSS exploit-likelihood inputs feed the sponsor's risk register; risk acceptance criteria and safety-hazard linkage are sponsor-side |
| Threat modelling | `attack_surface`, `graph`, `surfaces`, `endpoints` | `attack_surface.json`, `communication_graph.json`, `source_sink_graph.json`, `endpoints.json` | **Partial** | Attack-surface and inter-component communication graphs support STRIDE / attack-tree analysis but do not replace the sponsor's threat model document |
| Cybersecurity risk assessment | `findings`, `cve_scan`, `taint_propagation`, `adversarial_triage`, `fp_verification`, `reachability` | `findings.json`, `triaged_findings.json`, `verified_alerts.json`, `reachability.json` | **Full** | End-to-end vulnerability identification + LLM-adjudicated triage + reachability scoring + EPSS-anchored prioritisation |
| SBOM | `sbom` | `sbom.json` (CycloneDX 1.6) | **Full** | See §524B(b)(3) row above |
| Vulnerability management | `cve_scan`, `findings`, `reporting` | `cve_matches.json`, `analyst_digest.json` | **Full** | Continuous CVE matching with NVD API 2.0; EPSS enrichment; analyst-digest with disposition + evidence-tier; SARIF 2.1.0 interop with downstream issue trackers |
| Architecture views | `inventory`, `graph`, `attack_surface`, `firmware_profile` | `inventory.json`, `communication_graph.json`, `attack_surface.json`, `firmware_profile.json` | **Partial** | Global view (component inventory + comm graph) and update / patch view (firmware profile + SBOM) are produced; multi-patient / use-case views require sponsor-side composition |
| Cybersecurity testing — vulnerability testing | `findings`, `cve_scan`, `taint_propagation`, `cert_analysis`, `init_analysis`, `fs_permissions` | `findings.json`, `cve_matches.json`, `certificate_analysis.json`, `init_analysis.json`, `fs_permissions.json` | **Full** | Static vulnerability identification across pattern families (cmd injection, format string, perms, weak crypto, etc.) with hardening-aware confidence scoring |
| Cybersecurity testing — software composition analysis | `sbom`, `cve_scan`, `inventory` | `sbom.json`, `cve_matches.json` | **Full** | Component-level SCA via CycloneDX + NVD CPE matching |
| Cybersecurity testing — penetration testing | `emulation`, `dynamic_validation`, `fuzzing`, `exploit_chain`, `exploit_autopoc`, `poc_validation` | Emulation logs, fuzzer crash artifacts, chain assembly | **Limited** | 4-tier emulation (FirmAE / Pandawan+FirmSolo / QEMU user-mode / rootfs inspect) + AFL++ fuzzing + exploit-autopoc; LLM-driven exploit chain assembly is in flight (Phase 2D'). Penetration testing in the regulatory sense remains a manual sponsor-side activity that SCOUT supports rather than replaces |
| Labelling | `reporting` | `executive_report.md`, `analyst_digest.json` | **Partial** | Executive report and analyst digest provide source material for end-user labelling content; labelling drafting and approval is sponsor-side |
| Postmarket cybersecurity management plan | `firmware_handoff` | `firmware_handoff.json`, run manifests | **Out of scope** | The *plan* is sponsor-side QMS documentation; SCOUT only provides the per-firmware evidence the plan needs to reference |

---

## SCOUT Output Formats for FDA Compatibility

### 1. CycloneDX 1.6 SBOM

**FDA Reference:** §524B(b)(3); FDA premarket guidance "SBOM" content element

**Output Location:** `aiedge-runs/<run_id>/stages/sbom/sbom.json`

**Schema:** CycloneDX 1.6 (OWASP / Ecma International, recognised in NTIA / CISA SBOM minimum elements)

**Content:**

- Software component inventory extracted from firmware binaries
- Per-component name, version, supplier, and CPE 2.3 identifier
- Component relationships and dependency edges
- Known vulnerability cross-reference (via VEX, see below)

The CycloneDX format is referenced by the FDA premarket guidance as one of the accepted SBOM formats for premarket submission, alongside SPDX. SCOUT does not currently emit SPDX; SPDX export is tracked as a follow-up to Phase 3'.1 step B-4.

### 2. VEX (Vulnerability Exploitability eXchange)

**FDA Reference:** Premarket guidance "Vulnerability management" + "SBOM" content elements

**Output Location:** Embedded in `sbom.json` (CycloneDX 1.6 vulnerabilities array) and in `cve_matches.json`

**Content:**

- Per-component vulnerability identifier (CVE / advisory ID)
- Exploitability status (`affected`, `not_affected`, `under_investigation`, `fixed`)
- Justification for `not_affected` decisions (e.g. component present but not invoked, vulnerable code path unreachable per `reachability.json`)
- EPSS score and percentile

This satisfies the FDA's expectation that SBOM be paired with vulnerability status, not delivered as a static inventory.

### 3. SARIF 2.1.0 Findings

**FDA Reference:** Premarket guidance "Cybersecurity testing — vulnerability testing"

**Output Location:** `aiedge-runs/<run_id>/stages/findings/sarif.json`

**Schema:** OASIS SARIF 2.1.0

**Content:**

- Per-finding rule, severity, location (file path + byte offset + SHA-256), and message
- `properties.scout_evidence_tier` — the evidence-quality classification (`symbol_only`, `static_colocated`, `static_interproc`, `pcode_verified`, `dynamic_verified`)
- `properties.scout_priority_score` and `properties.scout_priority_inputs` — ranking semantics separated from detection confidence
- `properties.scout_reasoning_trail` — LLM-adjudicated triage trace, when present

SARIF is consumable by GitHub Code Scanning, the VS Code SARIF Viewer, and most issue-tracker integrations, supporting the FDA's expectation of machine-readable cybersecurity testing outputs.

### 4. SLSA Level 2 in-toto Attestation

**FDA Reference:** Premarket guidance "Quality System Considerations" — evidence integrity

**Output Location:** `aiedge-runs/<run_id>/provenance.intoto.jsonl`

**Schema:** in-toto attestation v0.1, SLSA Level 2 builder model

**Content:**

- Subject digests for `firmware_handoff.json`, `analyst_digest.json`, `verified_chain.json`
- Builder identity, run reproducibility metadata, deterministic JSON canonicalisation

The provenance attestation provides an integrity anchor: a reviewer can verify that the SBOM and vulnerability artifacts in a premarket submission package were produced by the SCOUT pipeline against a specific firmware artifact, and that the artifacts have not been tampered with after pipeline emission.

---

## Coverage Gaps and Limitations

The following elements are explicitly **outside SCOUT's scope** and remain sponsor-side responsibilities:

1. **Security objectives and risk acceptance criteria.** SCOUT cannot infer the device's intended use, patient population, or safety hazards from binaries. The risk register and acceptance thresholds must be authored by the sponsor.
2. **Threat-model documents.** SCOUT produces the input data (attack surface, communication graph, source-sink graph) but does not draft STRIDE / attack-tree narratives.
3. **Quality management system documentation.** SDLC procedures, change control records, training records, and the postmarket cybersecurity management plan itself are QMS deliverables.
4. **Penetration testing in the regulatory sense.** SCOUT's emulation, fuzzing, and exploit-autopoc stages support a sponsor's penetration-testing program but do not by themselves constitute a documented penetration-testing report.
5. **Labelling content.** SCOUT outputs feed the labelling draft but the final labelling text, including recommended user actions and dependency disclosures, must be drafted and approved by the sponsor.
6. **SPDX SBOM export.** SCOUT currently emits CycloneDX 1.6 only; SPDX is a recognised alternative and is tracked as a follow-up to Phase 3'.1 step B-4 (`compliance_report` stage will package both formats when SPDX export lands).

---

## Roadmap

The following Phase 3'.1 sub-steps build on this mapping:

| Sub-step | Delivers |
|----------|----------|
| **B-2** (this document) | FDA Section 524B compatibility mapping |
| **B-3** | ISO 21434 + UN R155 mappings (parallel automotive cybersecurity standards) |
| **B-4** | `compliance_report` stage that emits per-standard reports (this document, CRA Annex I, ISO 21434, UN R155) per run, alongside `executive_report.md` |
| **B-5** | v2.7.1 release tag — **released 2026-04-22** (Phase 2C+.4 vendor corpus expansion; the four-document suite + the `compliance_report` stage are shipped. See [GitHub release](https://github.com/R00T-Kim/SCOUT/releases/tag/v2.7.1) and `docs/v2.7.1_release_plan.md`) |

SPDX SBOM export and CSAF advisory output are non-blocking follow-ups intended for a later release; both are recognised by the FDA premarket guidance and would broaden SCOUT's compatibility footprint.

---

## References

- 21 U.S.C. §360n-2 — added by §3305 of the Consolidated Appropriations Act, 2023 (P.L. 117-328)
- FDA, "Cybersecurity in Medical Devices: Quality System Considerations and Content of Premarket Submissions" — final guidance, 27 September 2023
- FDA, "Postmarket Management of Cybersecurity in Medical Devices" — final guidance, 28 December 2016
- NTIA, "The Minimum Elements For a Software Bill of Materials (SBOM)" — 12 July 2021
- CISA, "VEX Use Cases" — 26 April 2022
- OWASP CycloneDX 1.6 specification
- OASIS SARIF 2.1.0 specification
- SLSA Framework v1.0 specification
