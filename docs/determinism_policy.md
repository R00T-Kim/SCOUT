# SCOUT Determinism Relaxation Policy

## Overview

SCOUT's deterministic pipeline produces reproducible evidence artifacts through canonical JSON serialization and SHA-256 hashing of stage manifests. However, certain stages interact with external tools (binwalk, QEMU, FirmAE, carving algorithms) that introduce nondeterminism. This document defines which stages support deterministic guarantees and which have controlled relaxations.

**Key principle:** Determinism is relaxed only at the **boundaries of external tool integration**, never within SCOUT's internal analysis logic.

## Deterministic Pipeline Architecture

### Stage Manifests

Each stage writes a `stage.json` manifest to `run_dir/stages/<stage_name>/stage.json` containing:
- `status`: execution status (ok/partial/failed/skipped)
- `artifacts`: array of artifact objects with SHA-256 hashes
- `params`: stage-specific parameters
- `stage_key`: deterministic hash of inputs and parameters
- Timestamps: `created_at`, `started_at`, `finished_at`, `duration_s`

### Canonical JSON Serialization

SCOUT normalizes all JSON for comparison using:
- **Sort all object keys** alphabetically
- **Compact separators** (no whitespace)
- **ASCII encoding only** (Unicode escaped)
- **Floating-point rounding** to 6 decimal places

```python
json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
```

This ensures identical logical content produces identical byte sequences for hashing.

### Determinism Bundle

The `DeterminismBundle` combines:
1. `manifest.json` (pipeline metadata)
2. `report/report.json` (aggregated findings and summary)
3. All stage `stage.json` files (33 stages)

A single SHA-256 digest represents the entire run. Two runs with identical digests produced identical evidence.

## Deterministic vs. Relaxed Stages

### Fully Deterministic Stages

All stages except those listed below are **deterministic**. This includes:
- `tooling` — external tool detection and version inventory
- `structure` — filesystem tree parsing
- `firmware_profile` — device metadata extraction
- `inventory` — binary and package enumeration
- `sbom` — SBOM generation from inventory
- `cve_scan` — CVE matching against SBOM (NVD API responses are cached)
- `ghidra_analysis` — binary decompilation (Ghidra version fixed)
- `endpoints` — IPC socket/port discovery from binaries
- `surfaces` — attack surface aggregation
- `graph` — communication graph construction
- `attack_surface` — attack surface node enumeration
- `findings` — security finding aggregation
- `llm_synthesis` — LLM-based analysis (LLM responses are deterministic given identical prompts and model)
- All downstream analysis stages

**Definition:** A stage is deterministic if:
1. All inputs are deterministic (upstream stages or fixed parameters)
2. The stage contains no sources of nondeterminism (timestamps, random IDs, external tool output)
3. Running the stage twice with identical inputs produces identical `stage.json` and artifact hashes

### Relaxed Stages

#### `extraction` — Firmware Unpacking

**Why relaxed:** External tool (binwalk) may produce different file listings or ordering across versions or runs:
- Different file ordering in `.tar` archives
- Variation in fragmented filesystem reconstruction
- Tool version differences in magic byte matching
- Extraction timeout behavior (extraction may partially succeed with different file counts)

**Allowlisted mismatches:**
- `_ALLOW_MISMATCH_KEYS`: Entire `stages/extraction/stage.json` can differ
- `_ALLOW_MISMATCH_PATHS`:
  - `extraction/summary/extraction_timeout_s` — timeout may be different
  - `stages/extraction/stage.json/params/timeout_s` — configured timeout
  - `stages/extraction/stage.json/stage_key` — input hash may differ
- `_ALLOW_MISMATCH_PATTERNS`: Any artifact SHA-256 under `stages/extraction/stage.json/artifacts/*/sha256`

**What is deterministic within extraction:**
- File structure: directories, symlinks, permissions
- Extracted binary names and paths
- Filesystem metadata

**Impact:** Two extraction runs may produce different filesets from the same firmware. Subsequent stages (inventory, analysis, findings) are deterministic given a **specific** extracted rootfs, but the "correct" rootfs is not guaranteed to be stable across extraction runs.

#### `emulation` — QEMU Execution

**Why relaxed:** QEMU emulation output is nondeterministic:
- System time varies
- Process scheduling differs between runs
- Network traffic timing varies
- File modifications occur in different orders

**Allowlisted mismatches:**
- `_ALLOW_MISMATCH_KEYS`: Entire `stages/emulation/stage.json` can differ
- `_ALLOW_MISMATCH_PATTERNS`: Any artifact SHA-256 under `stages/emulation/stage.json/artifacts/*/sha256`

**What is deterministic within emulation:**
- The fact that an emulation was attempted
- Emulation status (success/timeout/crash)
- Reachable boot messages and kernel logs

**Impact:** Emulation artifacts (crash logs, GDB traces, console output) may differ between runs. However, the presence/absence of emulation evidence is recorded deterministically.

#### `carving` — Binary Carving from Unallocated Space

**Why relaxed:** Carving algorithm output depends on:
- Sector alignment during scanning
- Chunk boundaries in different firmware layouts
- Tool version-specific heuristics

**Allowlisted mismatches:**
- `_ALLOW_MISMATCH_PATTERNS`: Any artifact SHA-256 under `stages/carving/stage.json/artifacts/*/sha256`

**Note:** Unlike extraction and emulation, carving stage metadata is deterministic; only artifact hashes are relaxed.

**Impact:** The set of carved binaries may differ between runs. Downstream stages (Ghidra analysis, vulnerability scanning) inherit this variance.

## Volatile Fields

These fields are **always filtered out** during determinism checks and are expected to differ:

```python
_VOLATILE_KEYS = {
    "created_at",      # stage creation timestamp
    "run_id",          # unique run identifier
    "started_at",      # stage start timestamp
    "finished_at",     # stage end timestamp
    "duration_s",      # stage execution time
}
```

**Implementation:** `_normalize_json()` removes these keys before comparison.

## Verification: Comparing Runs

### Collect Bundle

```python
from aiedge.determinism import collect_run_bundle
from pathlib import Path

run1 = collect_run_bundle(Path("aiedge-runs/run_id_1"))
run2 = collect_run_bundle(Path("aiedge-runs/run_id_2"))

print(f"Run 1 digest: {run1.digest_sha256}")
print(f"Run 2 digest: {run2.digest_sha256}")
```

### Assert Equality

```python
from aiedge.determinism import assert_bundles_equal

try:
    assert_bundles_equal(run1, run2)
    print("Bundles are deterministically equal")
except AssertionError as e:
    print(f"Determinism violation: {e}")
```

The assertion passes if:
1. Bundle digests match exactly, OR
2. All differences fall within allowlisted categories:
   - Keys in `_ALLOW_MISMATCH_KEYS`
   - Paths in `_ALLOW_MISMATCH_PATHS`
   - Fields matching patterns in `_ALLOW_MISMATCH_PATTERNS`

### Expected Output

On mismatch, `assert_bundles_equal()` reports:
- `left_digest` / `right_digest` — SHA-256 comparison
- `missing_in_left` / `missing_in_right` — missing stage manifests
- `mismatched` — stage files with differing content
- `diff_paths` — specific JSON paths that differ (first 20)

Example:
```
determinism bundle mismatch; left_digest=abc123...; right_digest=def456...;
mismatched=stages/extraction/stage.json;
diff_paths=stages/extraction/stage.json/artifacts/0/sha256,
           stages/extraction/stage.json/artifacts/1/sha256
```

All reported `diff_paths` are checked against allowlists; if all match allowlists, assertion passes.

## Implications for External Verification

### What Can Be Reproduced Bit-For-Bit

- **All static analysis findings** (inventory, CVE matches, secrets, hardening flags, certificate issues)
- **Reachability analysis** to extracted rootfs
- **Attack surface enumeration** of extracted binaries
- **Verdict decisions** for exploit chain validation
- **Analyst reports** and digest structures

Running SCOUT twice on the same firmware (with `--no-llm` for deterministic LLM responses) with identical configuration should produce identical **deterministic stages**.

### What Cannot Be Reproduced Bit-For-Bit

- **Extracted filesystem** — extraction is relaxed; different runs may produce different file inventories
- **Emulation artifacts** — emulation is relaxed; console logs, crash dumps, GDB output may differ
- **Carved binaries** — carving is relaxed; binary recovery is not guaranteed stable
- **Downstream analysis of relaxed artifacts** — any findings derived from extraction/emulation/carving output inherit their variance

### External Verification Strategy

1. **Verify deterministic stages independently:** Run two analyses, extract determinism bundles, compare digests via `assert_bundles_equal()`.

2. **Accept relaxed stage variance:** Do not expect bit-for-bit identical extraction or emulation output. Instead, verify:
   - Extraction successfully produced a rootfs
   - Inventory stage enumerated binaries correctly
   - Findings are supported by inventory evidence (not affected by which specific extracted binaries were present)

3. **Validate evidence chains:** Use `verified_chain_contract.md` to confirm findings are traced to:
   - Source files with SHA-256 anchors
   - Evidence artifacts with deterministic source references
   - Analyst decisions (not dependent on extraction order)

4. **Audit allowlist policy:** Review the relaxation rules (`_ALLOW_MISMATCH_KEYS`, `_ALLOW_MISMATCH_PATTERNS`) to confirm they match the scope of external tool integration in your threat model.

## Configuration and Exceptions

### Adding New Relaxations

If a new stage must interact with an external tool and cannot guarantee determinism:

1. **Add stage key to `_ALLOW_MISMATCH_KEYS`** if entire stage manifest is nondeterministic:
   ```python
   _ALLOW_MISMATCH_KEYS = {
       "stages/extraction/stage.json",
       "stages/emulation/stage.json",
       "stages/new_tool/stage.json",  # <-- add here
   }
   ```

2. **Add specific path to `_ALLOW_MISMATCH_PATHS`** if only certain fields vary:
   ```python
   _ALLOW_MISMATCH_PATHS = {
       "stages/new_tool/stage.json/params/timeout_s",
   }
   ```

3. **Add regex pattern to `_ALLOW_MISMATCH_PATTERNS`** if artifact hashes vary:
   ```python
   _ALLOW_MISMATCH_PATTERNS = (
       re.compile(r"^stages/new_tool/stage\.json/artifacts/\d+/sha256$"),
   )
   ```

4. **Document the relaxation** in this file, explaining why the external tool cannot be made deterministic.

5. **Audit downstream impact** — verify that findings do not depend on the nondeterministic output, or document that downstream stages are also relaxed.

## References

- `src/aiedge/determinism.py` — Implementation of bundle collection and comparison
- `docs/aiedge_report_contract.md` — Report schema and artifact contracts
- `docs/verified_chain_contract.md` — Evidence chain requirements
