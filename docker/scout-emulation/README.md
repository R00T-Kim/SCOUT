# scout-emulation Docker image

Tier-1 firmware emulation environment consumed by the `emulation` stage
(`src/aiedge/emulation.py`). Wraps [FirmAE](https://github.com/pr0v3rbs/FirmAE)
with the QEMU toolchain and all extraction dependencies SCOUT needs.

## Build

```bash
./build.sh                                      # default pinned commit
FIRMAE_COMMIT=<sha> ./build.sh                  # override the pin
AIEDGE_EMULATION_IMAGE=my-tag:v1 ./build.sh     # custom tag
```

Budget: **1.5-2 GB image, 20-40 min first-time build** (FirmAE's `download.sh`
fetches kernel images and root filesystems during the build).

## Runtime contract

`emulation._try_tier1` shells out with:

```
docker run --rm --privileged --pull=never \
    -v <firmware>:/mnt/firmware.bin:ro \
    -v <rootfs_i>:/mnt/rootfs<i>:ro \
    scout-emulation:latest /mnt/firmware.bin auto
```

The `entrypoint.sh` exit-code contract is the only signal SCOUT consumes:

| Code | Meaning                                    |
|------|--------------------------------------------|
| 0    | FirmAE boot succeeded                      |
| 1    | argument / setup error                     |
| 2    | boot log present but no IP (FirmAE failure)|
| 3    | extractor could not parse firmware         |

stdout / stderr are captured into `stages/emulation/emulation.log`.

## Why privileged?

FirmAE uses `kpartx`, `mount`, `tunctl`, and `qemu-system-*` with `-net bridge`.
These require `CAP_SYS_ADMIN` and access to `/dev/loop*`. `--privileged` is the
least surprising way to grant them; the `--rm` flag guarantees no persistent
state survives.

## Local-only safeguard

The image is meant for a single-analyst lab workstation. Do NOT expose the
running container to untrusted networks: emulated firmware is fully untrusted
code running with kernel-level privilege inside the container.

## Troubleshooting

| Symptom                         | Likely cause / fix |
|---------------------------------|--------------------|
| `tier1: image not available`    | `docker image inspect scout-emulation:latest` fails. Run `./build.sh`. |
| `tier1: exit code 2`            | FirmAE booted but no network came up. Inspect `stages/emulation/emulation.log`. |
| `download.sh` fails during build| Network blocked or FirmAE mirror rotated. Retry with a working egress. |
| PostgreSQL init failure         | Rebuild without cache: `docker build --no-cache ...`. |
| Container hangs at `----Mounting QEMU Image----` for hours (R7000 and similar) | FirmAE's `add_partition` inside `makeImage.sh` polls for loop partition devices. Inside a Docker container with `systemd-udevd` absent, `kpartx` successfully creates `/dev/mapper/loopNpM` but FirmAE's internal `losetup -fP` loop expects a different device naming and never unblocks. Confirmed 2026-04-24 against R7000-V1.0.11.136: 3 hours stuck, manual `kpartx -u` + starting `systemd-udevd --daemon` did not unblock the inner poll loop. **Status**: FirmAE Tier-1 real boot needs entrypoint patching to either (a) start `systemd-udevd` before `run.sh auto`, (b) LD_PRELOAD a shim that rewrites `losetup -fP` calls to use pre-provisioned devices, or (c) fork FirmAE's `makeImage.sh` to drop the kpartx step. Mock-based PoV via `docs/pov/` bypasses this blocker. |
