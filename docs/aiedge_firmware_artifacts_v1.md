# AIEdge Firmware Artifacts v1 (Deterministic JSON)

This document locks the v1 artifact contracts for firmware profiling + robust inventory.

Determinism rules (apply to both artifacts):

- JSON is written with stable key ordering (`sort_keys=True`) and fixed indentation (`indent=2`).
- Payloads are run-deterministic for the same input + stage conditions; no random IDs.
- Artifact references are run-relative POSIX paths.
- Artifact payloads MUST NOT include absolute host paths.
- Artifact payloads MUST NOT include timestamps.

## `stages/firmware_profile/firmware_profile.json`

Purpose: deterministic branch-planning signal for downstream orchestration.

Required fields:

| Field | Type | Meaning | Determinism notes |
| --- | --- | --- | --- |
| `schema_version` | integer | Profile schema version (v1 = `1`) | Fixed literal in v1 |
| `firmware_id` | string | `firmware:<sha256>` when input firmware exists, otherwise `firmware:unknown` | Derived deterministically from input bytes |
| `os_type_guess` | string enum | One of `linux_fs`, `rtos_monolithic`, `unextractable_or_unknown` | Derived from deterministic heuristics |
| `branch_plan` | object | Routing directive for downstream stages | Object key order is stable |
| `branch_plan.inventory_mode` | string enum | `filesystem` or `binary_only` | Derived deterministically from rootfs detection |
| `branch_plan.why` | string | Human-readable reason for branch selection | Static templates from branch outcome |
| `emulation_feasibility` | string enum | `high`, `medium`, `low`, or `unknown` | Deterministic mapping from branch outcome |
| `evidence_refs` | array of string | Supporting evidence paths under run directory | Sorted list; run-relative POSIX only |
| `sdk_hints` | array of string | Extracted SDK hints (e.g. `openwrt`, `busybox`) | Sorted list |
| `limitations` | array of string | Known confidence/coverage constraints | Sorted/de-duplicated list |

Minimal v1 example:

```json
{
  "branch_plan": {
    "inventory_mode": "filesystem",
    "why": "Found extracted rootfs candidate(s) containing etc/ and bin/ or usr/."
  },
  "emulation_feasibility": "high",
  "evidence_refs": [
    "stages/carving/roots.json",
    "stages/extraction/_firmware.bin.extracted",
    "stages/extraction/binwalk.log"
  ],
  "firmware_id": "firmware:8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
  "limitations": [],
  "os_type_guess": "linux_fs",
  "schema_version": 1,
  "sdk_hints": [
    "busybox"
  ]
}
```

## `stages/inventory/inventory.json`

Purpose: best-effort inventory output with explicit partiality and coverage accounting.

Required fields:

| Field | Type | Meaning | Determinism notes |
| --- | --- | --- | --- |
| `status` | string enum | `ok` or `partial` for inventory artifact payload | Derived from recoverable error state |
| `summary` | object | Aggregate scan counts | Integer counters only |
| `summary.roots_scanned` | integer | Number of roots scanned in this attempt | Deterministic count |
| `summary.files` | integer | Number of files traversed | Deterministic count |
| `summary.binaries` | integer | Number of binary-like files | Deterministic count |
| `summary.configs` | integer | Number of config-like files | Deterministic count |
| `summary.string_hits` | integer | Number of pattern matches in string scan | Deterministic count |
| `service_candidates` | array | Candidate services inferred from files | Stable discovery order and bounded output |
| `services` | array | Reserved normalized services list (currently may be empty) | Deterministic list |
| `errors` | array | Structured recoverable filesystem/write/runtime errors | Sorted by `(path, op, error, errno)` |
| `coverage_metrics` | object | Scan coverage counters for partial/complete runs | Integer counters only |
| `coverage_metrics.roots_considered` | integer | Candidate roots after source selection | Deterministic count |
| `coverage_metrics.roots_scanned` | integer | Roots actually scanned | Deterministic count |
| `coverage_metrics.files_seen` | integer | Total files observed | Deterministic count |
| `coverage_metrics.binaries_seen` | integer | Binary-like files observed | Deterministic count |
| `coverage_metrics.configs_seen` | integer | Config-like files observed | Deterministic count |
| `coverage_metrics.string_hits_seen` | integer | Total string-hit matches observed | Deterministic count |
| `coverage_metrics.skipped_dirs` | integer | Directories skipped due to recoverable errors | Deterministic count |
| `coverage_metrics.skipped_files` | integer | Files skipped due to recoverable errors | Deterministic count |

Optional fields (present depending on run conditions):

- `roots`: array of run-relative roots used for scanning.
- `extracted_dir`: run-relative extraction directory path.
- `artifacts.string_hits`: run-relative path to `stages/inventory/string_hits.json`.
- `reason`: explanatory reason for fallback/recovery payloads.
- `entry_count`: compatibility count alias for `coverage_metrics.files_seen`.
- `entries`: deprecated scalar compatibility alias for `entry_count` (legacy consumers only; prefer `summary.files` or `coverage_metrics.files_seen`).

Minimal v1 example:

```json
{
  "coverage_metrics": {
    "binaries_seen": 2,
    "configs_seen": 5,
    "files_seen": 7,
    "roots_considered": 1,
    "roots_scanned": 1,
    "skipped_dirs": 0,
    "skipped_files": 0,
    "string_hits_seen": 3
  },
  "errors": [],
  "extracted_dir": "stages/extraction/_firmware.bin.extracted",
  "roots": [
    "stages/carving/roots/root0"
  ],
  "service_candidates": [],
  "services": [],
  "status": "ok",
  "summary": {
    "binaries": 2,
    "configs": 5,
    "files": 7,
    "roots_scanned": 1,
    "string_hits": 3
  }
}
```

Path safety requirement (normative):

- `evidence_refs`, `roots`, and any embedded artifact paths MUST be run-relative POSIX paths.
- Absolute host paths (POSIX or Windows style) MUST NOT appear in these artifacts.
