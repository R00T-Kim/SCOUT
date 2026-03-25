# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in SCOUT itself (not in firmware being analyzed), please report it responsibly:

1. **Do not** open a public issue
2. Email: open a GitHub Security Advisory via the "Security" tab
3. Include: description, reproduction steps, and potential impact

We will respond within 7 days and aim to patch critical issues within 30 days.

## Scope

SCOUT is a firmware analysis tool that intentionally processes untrusted binary inputs. The following are **in scope**:

- Path traversal escaping the run directory (`assert_under_dir` bypass)
- Command injection through crafted firmware metadata
- Arbitrary file write outside `aiedge-runs/`

The following are **out of scope**:

- Findings or vulnerabilities discovered *in analyzed firmware* (that's SCOUT working as intended)
- Denial of service via large firmware inputs (known limitation)
- Issues requiring local access beyond what SCOUT already grants
