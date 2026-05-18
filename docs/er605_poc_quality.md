# ER605-Inspired PoC Quality Review — Generalized Chaining Process

Source basis: Out of Bounds' ER605 write-up, "TP-Link ER605 DDNS Pre-Auth RCE: Chaining CVE-2024-5242, CVE-2024-5243, CVE-2024-5244" (2026-02-04), plus SCOUT's `aiedge-runs/2026-05-17_1347_sha256-db84e89cd312-1` ER605 artifact.

## Intent

The ER605 article is used as a **process benchmark**, not as a reason to hardcode one product or one protocol. The reusable lesson is: deep firmware exploitability often emerges when an outbound client trusts an upstream service response, parses encoded/delimited fields, and later turns that state into a leak, memory corruption primitive, config mutation, or command sink.

## General process extracted from the article

A high-quality SCOUT chain scaffold should model these dimensions for any firmware/protocol family:

1. **Boundary inversion**: input may arrive through an outbound client response, not an inbound LAN/WAN service.
2. **Lab network control**: proof may require authorized DNS/DHCP/routing or service emulation in an isolated lab.
3. **Protocol reconstruction**: response fields may be encoded, encrypted, delimited, compressed, or checksummed.
4. **Stateful staging**: one response may set up a leak/readback or state mutation before a later control-flow claim.
5. **Patch-diff focus**: patched builds should be compared for field lengths, delimiter handling, auth/state checks, and copy bounds.
6. **Verifier boundary**: static evidence and blueprint hashes do not equal exploit proof; live parser traces or marker/readback evidence are required.

## Previous SCOUT PoC quality

Before this correction, SCOUT had two qualities:

- **Good**: ranked config/parser candidates and propagated Plan IR/channel metadata.
- **Insufficiently general**: the first v2.7.3 pass made the ER605/Comexe/DDNS instance too prominent in code and docs.

That was the wrong abstraction level. The right feature is not "better DDNS analysis"; it is **generic deep-chain discovery for outbound response parsers and other multi-boundary state machines**.

## Corrected implementation model

The core implementation is now expressed as generic outbound response-chain modeling:

- `exploitability_dossier.py`
  - Detects `outbound_response_parser_chain:*` candidates using upstream-service markers, response field names, parser sinks, and client-ish binary names.
  - Emits generic families: `outbound_protocol_response_parser`, `stateful_response_parser`, `memory_corruption_candidate`, `info_leak_chain_candidate`, `lab_service_emulation_required`, `bounded_protocol_probe`.
  - Emits generic channels: `lab_network_redirection`, `protocol_response`, `parser_field`, `leak_before_control_boundary`.

- `exploit_state_machine.py`
  - Lowers these candidates to `classify_outbound_response_chain_quality` Plan IR.
  - Uses generic actions: `emulate_protocol_channel`, `stage_bounded_field_probe`, and `validate_leak_before_control_boundary`.

- `exploit_autopoc.py`
  - Synthesizes protocol-aware Plan IR from channel metadata.
  - Avoids duplicate candidate IDs across dossier and state-machine sources.

- `poc_templates.py`
  - Adds a non-weaponized `outbound_protocol_response` blueprint template.
  - Records packet/Plan-IR hashes and quality checks.
  - Does **not** generate overlong fields, ROP, command payloads, crypto/key recovery, or spoofing infrastructure.

## E2E evidence

Run: `aiedge-runs/2026-05-17_1347_sha256-db84e89cd312-1`

Subset rerun:

```text
chain_construction -> exploitability_dossier -> protocol_model -> exploit_state_machine -> exploit_autopoc -> poc_validation
```

Observed:

- `exploitability_dossier`: detects outbound response-parser chain candidates in the ER605 fixture.
- `exploit_state_machine`: emits `classify_outbound_response_chain_quality` Plan IR for those candidates.
- `exploit_autopoc`: emits blueprint-only probes with transition evidence.
- `poc_validation`: ok. AutoPoC remains `partial` without live target marker/readback, which is expected and honest.

## Current quality verdict

**Medium-high for generic safe reproduction planning / analyst handoff.**

The generated artifacts now encode the ER605-like analysis process without making DDNS or a specific vendor the feature. They are suitable to guide an analyst toward a lab harness and parser verifier for other outbound response-chain cases.

## Next quality upgrades

1. Add generic upstream-service-emulator harness descriptors for DNS/DHCP/HTTP/UDP/TCP response chains.
2. Add parser-only replay under QEMU/GDB to upgrade blueprint transitions to observed parser evidence.
3. Recover field bounds from vulnerable/patched diffs and encode only safe boundary checks.
4. Add live verifier support that upgrades `lab_network_redirection`, `protocol_response`, and `leak_before_control_boundary` transitions from planned to observed without weaponized payload generation.
