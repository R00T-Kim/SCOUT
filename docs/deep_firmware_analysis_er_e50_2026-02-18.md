# Deep Firmware Analysis (ER-e50.v3.0.1) — 2026-02-18

## Scope
- Firmware: `ER-e50.v3.0.1.tar`
- SHA256: `e3d3fe0697bc01d8d9347f3df2b38ce093c2db69f6fa8ea65170270d59a8fb3d`
- Primary run: `aiedge-runs/2026-02-18_1130_sha256-e3d3fe0697bc`

## 1) What the analyst concretely gets from one firmware input

### 1.1 Ground-truth inventory and footprint
- Inventory summary: `files=31403`, `binaries=5114`, `configs=1135`, `status=partial`
  - Evidence: `stages/inventory/inventory.json`
- Endpoint candidates: `1781`
  - Evidence: `stages/endpoints/endpoints.json`
- Surface candidates: `47`
  - Evidence: `stages/surfaces/surfaces.json`
- Graph summary: reference graph `nodes=1200`, `edges=105`
  - Evidence: `stages/attack_surface/attack_surface.json`, `stages/graph/reference_graph.json`

### 1.2 Candidate security findings distribution
- `pattern_scan` total: `124`
- Family split:
  - `cmd_exec_injection_risk`: 101
  - `archive_extraction`: 14
  - `upload_exec_chain`: 8
  - `auth_decorator_gaps`: 1
- Evidence: `stages/findings/pattern_scan.json`

### 1.3 Known-disclosure matches
- CVE string matches: `17`
- Evidence: `stages/findings/known_disclosures.json`

## 2) High-signal manual deep dive (code-evidence anchored)

## 2.1 Firmware-upgrade path exists and is externally reachable via GUI API
- Upgrade endpoint registration:
  - `var/www/python/edgeos_gui/api/edge.py:35-36`
- Upgrade handler accepts either URL-based or upload-based path:
  - `var/www/python/edgeos_gui/api/edge.py:208-223`
  - URL path intake: `payload = dict(path=request.POST.get("url"))` (`line 214`)
- Request is forwarded to backend socket with session ID:
  - `var/www/python/edgeos_gui/api/__init__.py:15`
  - `var/www/python/edgeos_gui/socket.py:136-140`

## 2.2 Backend upgrade scripts perform archive operations and checksum checks, but authenticity model is weak
- Main upgrade script:
  - URL download with curl: `usr/bin/ubnt-upgrade:114,116`
  - Tar extraction from provided image: `usr/bin/ubnt-upgrade:575,608,645`
  - Checksum check is MD5 of package-provided md5 files: `usr/bin/ubnt-upgrade:674-686`
- Boot upgrade path:
  - Insecure TLS accepted (`-k`): `usr/bin/ubnt-upgrade-boot:79,81`
  - Tar extraction: `usr/bin/ubnt-upgrade-boot:195,452`
- DPI signature updater:
  - Download source: `usr/sbin/ubnt-update-dpi:4,25,41,63`
  - Integrity validation via `md5sum -c`: `usr/sbin/ubnt-update-dpi:73`

**Interpretation**
- Integrity checks exist, but authenticity is not cryptographically strong enough (MD5 + package-contained checks) to be considered robust signed-update verification.

## 2.3 Auth/session/CSRF posture observations
- CSRF plugin bypasses token validation for XHR when `csrf_protect` is not forced:
  - `var/www/python/edgeos_gui/utils/csrf.py:44-51`
- Multiple auth routes explicitly marked `csrf_exempt=True`:
  - `var/www/python/edgeos_gui/__main__.py:123,126,136`
- Session cookie `PHPSESSID` is set in app responses (custom compatibility path):
  - `var/www/python/edgeos_gui/views.py:92,134,198`

## 2.4 Exposed management surface and default posture signals
- Websocket tunnel endpoints configured in web server:
  - `/ws/stats` and `/ws/cli`
  - `etc/lighttpd/lighttpd.conf:37-47`
- Default config includes GUI ports:
  - `opt/vyatta/etc/config.boot.default-e50:156-157`
- Default WAN policy appears deny-by-default in base template:
  - `opt/vyatta/etc/config.boot.default-e50:65,84`
- Default admin hash present for `ubnt` user in boot template:
  - `opt/vyatta/etc/config.boot.default-e50:166-169`

## 3) Exploit-chain readiness: current engine state vs analyst reality

## 3.1 Current report contradiction
- `report/report.json` says:
  - `exploit_assessment.decision = full_chain_ready`
  - `exploitable = true`
- But `report/analyst_digest.json` says:
  - `exploitability_verdict.state = NOT_ATTEMPTED`
  - reason: `NOT_ATTEMPTED_REQUIRED_VERIFIER_MISSING`

## 3.2 Why this matters
- Current “exploit profile” stages are mostly policy/attestation checks over artifacts, not actual chain execution:
  - `stages/exploit_chain/milestones.json`
  - `stages/poc_validation/poc_validation.json`
  - `stages/exploit_policy/policy.json`
- So for analyst requirements (“exploit 되냐/안되냐”), current output is still insufficient without runtime verifier evidence.

## 4) Practical analyst-grade conclusions (from this run only)

1. The firmware was unpacked at high coverage and contains rich actionable material (31k+ files, 5k+ binaries).
2. There is a concrete management upgrade path from web API to backend upgrade workflow.
3. Multiple weak-signal findings are present; high confidence currently requires manual triage + runtime confirmation.
4. Update authenticity/integrity design should be reviewed (MD5-based checks observed in multiple paths).
5. Current exploit verdict outputs are inconsistent across artifacts; analyst-facing verdict cannot yet be trusted as “full-chain confirmed.”

## 5) Next verification steps (for true full-chain analyst acceptance)

1. **Runtime verifier binding**: enforce that exploit decision is `CONFIRMED/NOT_CONFIRMED/NOT_ATTEMPTED` from a single source of truth, and block contradictory summaries.
2. **Upgrade path dynamic proof**: in isolated lab, verify exact backend validation boundaries on upgrade URL/upload path.
3. **Websocket authorization proof**: verify whether `/ws/cli` and `/ws/stats` reject unauthorized sessions at socket-service layer.
4. **Finding de-noising**: downrank distro baseline scripts/libs and promote only device-specific paths (`/var/www/python`, `/usr/bin/ubnt-*`, `/etc/ubnt/*`).

