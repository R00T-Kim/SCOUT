# SCOUT Firmware Scan Action

Runs SCOUT firmware security analysis as a composite GitHub Action and optionally uploads findings to the GitHub Security tab via SARIF.

## What it does

1. Installs SCOUT and optional extraction tools (binwalk, squashfs-tools, mtd-utils, lzop)
2. Runs `scout analyze` against the specified firmware binary
3. Exports the SARIF findings file produced by the `findings` stage
4. Exposes the SARIF path and run directory as outputs for downstream steps

## Usage

```yaml
jobs:
  firmware-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Run SCOUT scan
        id: scout
        uses: ./.github/actions/scout-scan
        with:
          firmware-path: path/to/firmware.bin
          no-llm: 'true'
          time-budget-s: '1800'
          quiet: 'true'

      - name: Upload SARIF to GitHub Security tab
        if: steps.scout.outputs.sarif-file != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.scout.outputs.sarif-file }}
          category: scout-firmware
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `firmware-path` | Path to firmware binary relative to workspace | Yes | — |
| `no-llm` | Disable LLM-based stages (recommended for CI) | No | `true` |
| `time-budget-s` | Analysis time budget in seconds | No | `1800` |
| `stages` | Comma-separated list of stages to run (empty = all) | No | `''` |
| `quiet` | Suppress real-time progress output | No | `true` |

## Outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Absolute path to the SARIF results file |
| `run-dir` | Path to the SCOUT run directory (`aiedge-runs/<id>/`) |

## Uploading SARIF to GitHub Security tab

Use `github/codeql-action/upload-sarif@v3` with `permissions: security-events: write`:

```yaml
- name: Upload SARIF
  if: steps.scout.outputs.sarif-file != ''
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.scout.outputs.sarif-file }}
    category: scout-firmware
```

Findings appear under the repository's **Security > Code scanning** tab after the upload completes.

## Notes

- The action requires `--ack-authorization` which is passed automatically.
- If no SARIF file is produced (e.g. firmware extraction failed), a workflow warning is emitted and the job continues — the action never hard-fails on missing output.
- LLM stages are disabled by default (`no-llm: true`). To enable them, set `no-llm: false` and provide `AIEDGE_LLM_DRIVER` / `ANTHROPIC_API_KEY` as environment variables or secrets.
