"""Pinning tests for docker/scout-emulation artefacts.

These guard the contract that `aiedge.emulation._try_tier1` relies on:
* the image tag default must stay in sync with `AIEDGE_EMULATION_IMAGE`
* `entrypoint.sh` must NEVER swallow FirmAE's exit code with a trailing
  `|| echo ...`, since SCOUT uses the container returncode as the sole
  tier-1 success signal
* the FirmAE commit pin must be a full-length (40 hex chars) SHA so that
  builds are reproducible -- a placeholder like "REPLACE_ME" or a short
  SHA must not survive code review
"""

from __future__ import annotations

import re
from pathlib import Path

DOCKER_DIR = Path(__file__).resolve().parent.parent / "docker" / "scout-emulation"


def _read(name: str) -> str:
    return (DOCKER_DIR / name).read_text(encoding="utf-8")


def test_docker_dir_exists() -> None:
    assert DOCKER_DIR.is_dir(), f"missing: {DOCKER_DIR}"
    for required in ("Dockerfile", "entrypoint.sh", "build.sh", "README.md"):
        assert (DOCKER_DIR / required).is_file(), f"missing: {required}"


def test_firmae_commit_is_full_length_sha() -> None:
    """FIRMAE_COMMIT must be a 40-char lowercase hex digest, not a placeholder."""
    dockerfile = _read("Dockerfile")
    match = re.search(r"^ARG FIRMAE_COMMIT=([0-9a-f]+)\s*$", dockerfile, re.MULTILINE)
    assert match is not None, "FIRMAE_COMMIT ARG not found in Dockerfile"
    sha = match.group(1)
    assert len(sha) == 40, f"FIRMAE_COMMIT must be 40 chars, got {len(sha)}: {sha!r}"
    # reject the obvious placeholder that shipped in the scaffold
    assert sha != "2e8b5c1e7f4a3d6c9b0e2f1a4d7c8b5e3f2a1d9c", (
        "FIRMAE_COMMIT is still the scaffold placeholder; resolve a real "
        "pr0v3rbs/FirmAE commit and update Dockerfile"
    )


def test_entrypoint_does_not_mask_firmae_exit_code() -> None:
    """The v1.0.0 scaffold shipped `./run.sh ... || echo "FirmAE boot failed"`
    which always returns 0 (echo succeeds), so the container exited 0 even
    when FirmAE's boot failed -- causing SCOUT to mis-classify tier1 as OK.
    This regression must not return.
    """
    entry = _read("entrypoint.sh")
    assert "FirmAE boot failed, try qemu-user" not in entry, (
        "entrypoint.sh must not swallow FirmAE's exit code via `|| echo`. "
        "Propagate the real return code so aiedge.emulation._try_tier1 can "
        "distinguish boot success from silent failure."
    )
    # positive: the entrypoint must explicitly propagate the exit code.
    assert (
        "exit $?" in entry or "return $rc" in entry
    ), "entrypoint.sh must explicitly propagate FirmAE's exit code"


def test_entrypoint_contract_documented() -> None:
    """The exit-code contract must be documented in the entrypoint itself,
    so operators wiring up CI know which codes mean what without grepping
    the Python side.
    """
    entry = _read("entrypoint.sh")
    # rubric: each documented exit code must appear in a comment block
    for code in ("0", "1", "2", "3"):
        assert re.search(
            rf"#\s*{code}\b", entry
        ), f"entrypoint.sh must document exit code {code} in its header"


def test_default_image_tag_matches_emulation_module() -> None:
    """README and build.sh default image tag must match the value
    `aiedge.emulation.EmulationStage._resolve_emulation_image()` falls
    back to (`scout-emulation:latest`). A drift here bricks tier-1 since
    `_try_tier1` calls `docker image inspect <tag>` with the Python-side
    default.
    """
    readme = _read("README.md")
    build_sh = _read("build.sh")
    assert "scout-emulation:latest" in readme
    assert "scout-emulation:latest" in build_sh
