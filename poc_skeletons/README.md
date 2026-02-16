# PoC Skeleton Interface (Public)

Public repository policy: this directory provides interface-only templates. Do not commit working exploit payloads.

## Private plugin contract

Private plugins are loaded only from `--exploit-dir` by `--chain-id`.

Each plugin must expose either:

- `build_poc()` returning a PoC object, or
- `PoC` class instantiable without arguments.

The PoC object must implement `PoCInterface` from `poc_skeletons/interface.py`:

- `chain_id: str`
- `target_service: str` (`http`, `tcp`, or `stdin`)
- `setup(target_ip: str, target_port: int, *, context: dict[str, object]) -> None`
- `execute() -> PoCResult`
- `cleanup() -> None`

`PoCResult` fields:

- `success: bool`
- `proof_type: str` (`shell`, `arbitrary_read`, `arbitrary_write`)
- `proof_evidence: str` (runner applies redaction before writing logs)
- `timestamp: str` (ISO8601 recommended)

## Runner CLI

```bash
python3 exploit_runner.py --run-dir <RUN_DIR> --exploit-dir <DIR> --chain-id <ID> --repro 3
```

Artifacts are written under `run_dir/exploits/chain_<safe_id>/`:

- `poc_sha256.txt`
- `execution_log_1.txt` ... `execution_log_N.txt`
- `network_capture.pcap` (placeholder when capture is unavailable)
- `evidence_bundle.json`

Runner constraints:

- never copies plugin source into `run_dir`
- stores plugin SHA256 only
- does not persist private absolute plugin paths in artifacts
