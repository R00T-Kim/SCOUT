# SCOUT Proof-of-Vulnerability evidence

Snapshots of successful `verdict_verified` runs, captured as immutable JSON
bundles for audit review. Each file name encodes the date and firmware/chain
target; the payload contains the full `evidence_bundle.json` + `verified_chain.json`
as they existed at PoV time.

## Reproducing a PoV run

1. **Author a weaponized plugin** at `private_exploits/<chain_id>.py` that conforms
   to the `PoCInterfaceRuntime` Protocol in `exploit_runner.py`. The plugin's
   `execute()` must return a `PoCResult` with
   `proof_type in {"shell", "arbitrary_read", "arbitrary_write"}` and an
   evidence string containing a `readback_hash=<sha256>` token. `private_exploits/`
   is gitignored; treat it as analyst-private.

2. **Narrow candidate selection to a single chain**:
   ```
   export AIEDGE_AUTOPOC_MAX_CANDIDATES=1
   ```
   `scripts/build_verified_chain.py::_status_3_of_3` aggregates attempts across
   every `exploits/chain_*/` directory and demands `len(attempts) == 3`; more
   than one chain pins the verdict at `ATTEMPTED_INCONCLUSIVE` by arithmetic.

3. **Drive the exploit stages**:
   ```
   ./scout analyze <firmware.chk> --ack-authorization
   ```
   For a post-hoc run on an existing run_dir:
   ```
   ./scout stages <run_dir> --stages exploit_autopoc,poc_validation,exploit_policy \
       --no-llm --time-budget-s 120
   ```

4. **Confirm reproducibility**: `exploits/chain_<id>/evidence_bundle.json`
   must report `reproducibility.status == "pass"` and `passed == requested == 3`.

5. **Build the verified chain**:
   ```
   python3 scripts/build_verified_chain.py --run-dir <run_dir>
   ```
   `verified_chain/verified_chain.json` must yield
   `verdict.state == "pass"` with reason codes
   `["isolation_verified", "repro_3_of_3"]`.

6. **Finalise the analyst digest**: re-running `./scout analyze` (or re-invoking
   `reporting.write_analyst_digest_json`) emits
   `analyst_digest.exploitability_verdict.state == "VERIFIED"` with
   `["VERIFIED_ALL_GATES_PASSED", "VERIFIED_REPRO_3_OF_3"]`.

## Privileged executor setup (required for real-run verified_chain)

`dynamic_validation` captures network pcap + firewall ruleset via
`tcpdump`, `iptables-save`, `ip6tables-save`, and `nft list ruleset`.
All four require root. SCOUT resolves a privileged executor via:

1. `AIEDGE_PRIV_RUNNER` env var (split via `shlex`) if set and
   executable.
2. Fallback: `sudo -n <cmd>` if `sudo` is on PATH.
3. Fallback: no-op (emits `privileged_executor_missing` /
   `sudo_nopasswd_required` limitations, which map to `boot_flaky` in
   `scripts/build_verified_chain.py` and block `state=pass`).

To reach `state=pass` on a real run, either configure `AIEDGE_PRIV_RUNNER`
to a wrapper that does the escalation, or install a `/etc/sudoers.d/`
NOPASSWD entry restricted to exactly these four commands. Example
installed on the 2026-04-25 reference workstation:

```
# /etc/sudoers.d/scout-priv
rootk1m ALL=(root) NOPASSWD: /usr/sbin/iptables-save, /usr/sbin/ip6tables-save, /usr/sbin/nft, /usr/bin/tcpdump
```

Install with `visudo -c -f <file>` validation first, then
`sudo install -m 0440 -o root -g root <file> /etc/sudoers.d/scout-priv`.
Paths may differ across distros; run `which tcpdump iptables-save` to
confirm before writing the sudoers entry.

## File naming convention

`<ISO-date>_<vendor_device>_verified.json` — e.g. `2026-04-24_r7000_verified.json`.
