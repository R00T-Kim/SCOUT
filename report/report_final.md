# SCOUT Vulnerability Candidate Report

**Total Candidates Found:** 2

---

## [HIGH] insecure_service
**ID:** CAND-001 | **Anchor:** `tcp:23/telnetd`

### Why this matters
Telnet sends credentials in cleartext. Presence confirmed both statically and dynamically.

### Evidence
- **[static]** Potential vulnerable binary found: /usr/bin/telnetd (`/usr/bin/telnetd`)
- **[dynamic]** Open port 23 (telnet) observed. Banner: "Welcome to Linux" (`192.168.0.1:23`)

### Reproduction Steps
1. Connect via 'telnet <target_ip>'
2. Capture traffic with Wireshark to see cleartext creds

### Next Actions
- [ ] Check for hardcoded credentials
- [ ] Attempt default login

---

## [MEDIUM] command_injection
**ID:** CAND-002 | **Anchor:** `/bin/httpd:process_input`

### Why this matters
Potential sink system() found in input processing function.

### Evidence
- **[code]** Potential Command Injection via system() (`/bin/httpd:process_input @ 0x00401234`)

### Reproduction Steps
1. Reverse engineer the binary to find input path to this function
2. Fuzz the HTTP interface

### Next Actions
- [ ] Static analysis of call graph
- [ ] Dynamic fuzzing

---

