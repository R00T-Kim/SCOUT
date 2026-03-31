from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .emulation_gdb import probe_with_gdb
from .path_safety import assert_under_dir
from .schema import JsonValue
from .stage import StageContext, StageOutcome


def _rel_to_run_dir(run_dir: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(run_dir.resolve()))
    except Exception:
        return str(path)


def _resolve_run_relative_dir(run_dir: Path, rel_path: str) -> Path | None:
    p = (run_dir / rel_path).resolve()
    if not p.is_relative_to(run_dir.resolve()):
        return None
    if not p.is_dir():
        return None
    return p


def _read_inventory_roots(run_dir: Path) -> list[Path]:
    inv_path = run_dir / "stages" / "inventory" / "inventory.json"
    if not inv_path.is_file():
        return []

    try:
        raw = cast(object, json.loads(inv_path.read_text(encoding="utf-8")))
    except Exception:
        return []
    if not isinstance(raw, dict):
        return []
    inv = cast(dict[str, object], raw)

    roots: list[Path] = []

    roots_any = inv.get("roots")
    if isinstance(roots_any, list):
        for item in cast(list[object], roots_any):
            if isinstance(item, str) and item:
                p = _resolve_run_relative_dir(run_dir, item)
                if isinstance(p, Path):
                    roots.append(p)

    extracted_any = inv.get("extracted_dir")
    if isinstance(extracted_any, str) and extracted_any:
        p2 = _resolve_run_relative_dir(run_dir, extracted_any)
        if isinstance(p2, Path):
            roots.append(p2)

    uniq: list[Path] = []
    seen: set[str] = set()
    for p in roots:
        key = str(p.resolve())
        if key in seen:
            continue
        seen.add(key)
        uniq.append(p)

    return uniq


def _fallback_extracted_dir(run_dir: Path) -> Path | None:
    p = run_dir / "stages" / "extraction" / "_firmware.bin.extracted"
    if p.is_dir():
        return p
    return None


def _format_log(
    *,
    attempted_cmd: list[str] | None,
    stdout: str,
    stderr: str,
    reason: str | None,
) -> str:
    lines = [
        "attempted_command:",
        " ".join(attempted_cmd) if attempted_cmd else "none",
        "--- stdout ---",
        stdout,
        "--- stderr ---",
        stderr,
        "failure_reason:",
        reason or "none",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tier helpers
# ---------------------------------------------------------------------------


def _try_tier1(
    docker_bin: str,
    emulation_image: str,
    roots: list[Path],
    firmware_path: Path | None,
    *,
    timeout_s: float,
    cpus: float | None,
    memory_mb: int | None,
    pids_limit: int | None,
) -> tuple[bool, str, str, str, int]:
    """Attempt Tier 1: scout-emulation Docker image with FirmAE inside.

    Returns (success, stdout, stderr, reason, returncode).
    """
    # Check if the scout-emulation image exists
    inspect_cmd = [docker_bin, "image", "inspect", emulation_image]
    try:
        inspect_res = subprocess.run(
            inspect_cmd,
            text=True,
            capture_output=True,
            check=False,
        )
    except Exception:
        return False, "", "", "tier1: image inspect failed", -1

    if inspect_res.returncode != 0:
        return False, "", inspect_res.stderr or "", "tier1: image not available", -1

    # Tier 1 runs FirmAE which needs: writable fs, network (QEMU bridge),
    # privileged caps (kpartx, mount, tunctl).  Security is provided by
    # container isolation itself + --rm (no persistent state).
    run_cmd: list[str] = [
        docker_bin,
        "run",
        "--rm",
        "--privileged",
        "--pull=never",
    ]
    if pids_limit is not None and int(pids_limit) > 0:
        run_cmd.extend(["--pids-limit", str(int(pids_limit))])
    if cpus is not None:
        run_cmd.extend(["--cpus", str(float(cpus))])
    if memory_mb is not None:
        run_cmd.extend(["--memory", f"{int(memory_mb)}m"])

    # Mount firmware file if available
    if firmware_path is not None and firmware_path.is_file():
        run_cmd.extend(
            ["-v", f"{str(firmware_path.resolve())}:/mnt/firmware.bin:ro"]
        )

    # Mount rootfs volumes
    for i, root in enumerate(roots[:3]):
        run_cmd.extend(["-v", f"{str(root.resolve())}:/mnt/rootfs{i}:ro"])

    run_cmd.extend([emulation_image, "/mnt/firmware.bin", "auto"])

    try:
        res = subprocess.run(
            run_cmd,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_s,
        )
        return (
            res.returncode == 0,
            res.stdout or "",
            res.stderr or "",
            "" if res.returncode == 0 else f"tier1: exit code {res.returncode}",
            res.returncode,
        )
    except subprocess.TimeoutExpired as exc:
        return (
            False,
            (exc.stdout or "") if isinstance(exc.stdout, str) else "",
            (exc.stderr or "") if isinstance(exc.stderr, str) else "",
            f"tier1: timed out after {timeout_s}s",
            -1,
        )
    except Exception as exc:
        return False, "", "", f"tier1: {type(exc).__name__}: {exc}", -1


def _try_pandawan(
    docker_bin: str,
    pandawan_image: str,
    roots: list[Path],
    firmware_path: Path | None,
    *,
    timeout_s: float,
) -> tuple[bool, str, str, str, int]:
    """Attempt Tier 1.5: Pandawan/FirmSolo KCRE emulation.

    Pandawan uses FirmSolo's Kernel Config Recovery Engine to build
    custom kernels for QEMU full-system emulation, achieving higher
    re-hosting success than FirmAE alone.

    Returns (success, stdout, stderr, reason, returncode).
    """
    # Check if Pandawan image exists
    try:
        inspect_res = subprocess.run(
            [docker_bin, "image", "inspect", pandawan_image],
            text=True, capture_output=True, check=False,
        )
    except Exception:
        return False, "", "", "pandawan: image inspect failed", -1

    if inspect_res.returncode != 0:
        return False, "", "", "pandawan: image not available", -1

    # Pandawan needs: privileged (kpartx, mount, QEMU), writable fs,
    # PostgreSQL for firmadyne/FirmAE extraction step.
    run_cmd: list[str] = [
        docker_bin, "run", "--rm", "--privileged", "--pull=never",
    ]

    # Create workdir for Pandawan output
    workdir = roots[0].parent / "_pandawan_workdir" if roots else Path("/tmp/_pandawan_workdir")
    workdir.mkdir(parents=True, exist_ok=True)
    run_cmd.extend(["-v", f"{str(workdir.resolve())}:/output"])

    # Mount firmware
    if firmware_path is not None and firmware_path.is_file():
        run_cmd.extend(["-v", f"{str(firmware_path.resolve())}:/mnt/firmware.bin:ro"])

    # Mount rootfs volumes
    for i, root in enumerate(roots[:3]):
        run_cmd.extend(["-v", f"{str(root.resolve())}:/mnt/rootfs{i}:ro"])

    # Pandawan entrypoint: start PostgreSQL, run extractor, then emulate
    # run_pandawan.py requires a numeric image ID (not a path), so we
    # must extract with FirmAE's extractor first, yielding ID "1".
    # NOTE: -e means "FirmAE stock" comparison mode — omit it to use
    # the Pandawan system (KCRE kernel augmentation).
    pandawan_timeout = int(timeout_s)
    pandawan_script = (
        "pg_ctlcluster 14 main start 2>/dev/null; "
        "if [ -f /mnt/firmware.bin ]; then "
        "  cd /output && "
        "  /FirmAE/sources/extractor/extractor.py -b auto -sql 127.0.0.1 -np /mnt/firmware.bin images/ 2>/dev/null && "
        "  cd /Pandawan && "
        f"  python3 run_pandawan.py 1 -a -s -g {pandawan_timeout} 2>&1; "
        "else "
        "  echo 'no firmware mounted'; exit 1; "
        "fi"
    )
    run_cmd.extend([pandawan_image, pandawan_script])

    try:
        res = subprocess.run(
            run_cmd,
            text=True, capture_output=True, check=False,
            timeout=timeout_s,
        )
        success = res.returncode == 0
        return (
            success,
            res.stdout or "",
            res.stderr or "",
            "" if success else f"pandawan: exit code {res.returncode}",
            res.returncode,
        )
    except subprocess.TimeoutExpired as exc:
        return (
            False,
            (exc.stdout or "") if isinstance(exc.stdout, str) else "",
            (exc.stderr or "") if isinstance(exc.stderr, str) else "",
            f"pandawan: timed out after {timeout_s}s",
            -1,
        )
    except Exception as exc:
        return False, "", "", f"pandawan: {type(exc).__name__}: {exc}", -1


def _try_tier2(roots: list[Path], *, timeout_s: float) -> tuple[bool, str, list[dict[str, JsonValue]]]:
    """Attempt Tier 2: QEMU user-mode service probes.

    Returns (success, log_text, probe_results_for_details).
    """
    from .emulation_qemu import execute_service_probes

    all_results: list[dict[str, JsonValue]] = []
    log_lines: list[str] = ["=== Tier 2: QEMU user-mode probes ==="]
    any_success = False

    per_root_timeout = max(timeout_s / max(len(roots), 1), 5.0)

    for root in roots[:3]:
        results = execute_service_probes(
            root,
            timeout_s=per_root_timeout,
            max_probes=8,
        )
        for r in results:
            probe_entry: dict[str, JsonValue] = {
                "binary": r.binary,
                "arch": r.arch,
                "exit_code": r.exit_code,
                "timed_out": r.timed_out,
                "args": cast(JsonValue, r.args),
                "stdout_snippet": r.stdout[:2000],
                "stderr_snippet": r.stderr[:2000],
            }
            all_results.append(probe_entry)
            log_lines.append(
                f"binary={r.binary} arch={r.arch} exit={r.exit_code} "
                f"timed_out={r.timed_out} args={r.args}"
            )
            if r.stdout.strip():
                log_lines.append(f"  stdout: {r.stdout[:500]}")
            if r.stderr.strip():
                log_lines.append(f"  stderr: {r.stderr[:500]}")
            if r.stdout.strip() or r.stderr.strip():
                any_success = True

    log_text = "\n".join(log_lines) + "\n"
    return any_success, log_text, all_results


@dataclass(frozen=True)
class EmulationStage:
    image: str = "alpine:3.23"
    emulation_image: str = ""  # resolved from env at runtime
    timeout_s: float | None = 30.0
    tier1_timeout_s: float | None = 480.0  # FirmAE needs minutes to boot
    cpus: float | None = 1.0
    memory_mb: int | None = 256
    pids_limit: int | None = 256

    @property
    def name(self) -> str:
        return "emulation"

    def _resolve_emulation_image(self) -> str:
        if self.emulation_image:
            return self.emulation_image
        return os.environ.get("AIEDGE_EMULATION_IMAGE", "scout-emulation:latest")

    def run(self, ctx: StageContext) -> StageOutcome:
        stage_dir = ctx.run_dir / "stages" / "emulation"
        assert_under_dir(ctx.run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)

        log_path = stage_dir / "emulation.log"
        assert_under_dir(stage_dir, log_path)

        roots = _read_inventory_roots(ctx.run_dir)
        if not roots:
            fallback = _fallback_extracted_dir(ctx.run_dir)
            if isinstance(fallback, Path):
                roots = [fallback]

        evidence: list[JsonValue] = [
            {"path": _rel_to_run_dir(ctx.run_dir, stage_dir)},
            {"path": _rel_to_run_dir(ctx.run_dir, log_path)},
        ]
        for r in roots[:5]:
            evidence.append({"path": _rel_to_run_dir(ctx.run_dir, r), "note": "rootfs"})

        if not roots:
            reason = "no extracted rootfs candidates"
            _ = log_path.write_text(
                _format_log(
                    attempted_cmd=None,
                    stdout="",
                    stderr="",
                    reason=reason,
                ),
                encoding="utf-8",
            )
            return StageOutcome(
                status="partial",
                details=cast(
                    dict[str, JsonValue],
                    {
                        "reason": reason,
                        "image": self.image,
                        "evidence": evidence,
                    },
                ),
                limitations=[
                    "Emulation skipped: no extracted root filesystem candidates were found."
                ],
            )

        log_sections: list[str] = []
        used_tier: str = ""

        # ---------------------------------------------------------------
        # Tier 1: scout-emulation Docker image (FirmAE inside)
        # ---------------------------------------------------------------
        docker_bin = shutil.which("docker")
        if docker_bin:
            emu_image = self._resolve_emulation_image()
            firmware_path = ctx.run_dir / "input" / "firmware.bin"
            t1_ok, t1_stdout, t1_stderr, t1_reason, t1_rc = _try_tier1(
                docker_bin,
                emu_image,
                roots,
                firmware_path if firmware_path.is_file() else None,
                timeout_s=float(self.tier1_timeout_s or 480.0),
                cpus=self.cpus,
                memory_mb=self.memory_mb,
                pids_limit=self.pids_limit,
            )
            log_sections.append(
                _format_log(
                    attempted_cmd=[docker_bin, "run", emu_image, "..."],
                    stdout=t1_stdout,
                    stderr=t1_stderr,
                    reason=t1_reason or None,
                )
            )
            if t1_ok:
                used_tier = "tier1"
                _ = log_path.write_text(
                    "\n".join(log_sections), encoding="utf-8"
                )
                return StageOutcome(
                    status="ok",
                    details=cast(
                        dict[str, JsonValue],
                        {
                            "reason": "",
                            "image": emu_image,
                            "used_tier": used_tier,
                            "returncode": t1_rc,
                            "log": _rel_to_run_dir(ctx.run_dir, log_path),
                            "evidence": evidence,
                        },
                    ),
                    limitations=[],
                )

        # ---------------------------------------------------------------
        # Tier 1.5: Pandawan (FirmSolo KCRE) fallback
        # ---------------------------------------------------------------
        if docker_bin:
            pandawan_image = os.environ.get("AIEDGE_PANDAWAN_IMAGE", "pandawan:latest")
            p_ok, p_stdout, p_stderr, p_reason, p_rc = _try_pandawan(
                docker_bin,
                pandawan_image,
                roots,
                firmware_path if firmware_path.is_file() else None,
                timeout_s=float(self.tier1_timeout_s or 600.0),
            )
            log_sections.append(
                _format_log(
                    attempted_cmd=[docker_bin, "run", pandawan_image, "..."],
                    stdout=p_stdout,
                    stderr=p_stderr,
                    reason=p_reason or None,
                )
            )
            if p_ok:
                used_tier = "tier1.5_pandawan"
                _ = log_path.write_text(
                    "\n".join(log_sections), encoding="utf-8"
                )
                return StageOutcome(
                    status="ok",
                    details=cast(
                        dict[str, JsonValue],
                        {
                            "reason": "",
                            "image": pandawan_image,
                            "used_tier": used_tier,
                            "returncode": p_rc,
                            "log": _rel_to_run_dir(ctx.run_dir, log_path),
                            "evidence": evidence,
                        },
                    ),
                    limitations=[],
                )

        # ---------------------------------------------------------------
        # Tier 2: QEMU user-mode service probes
        # ---------------------------------------------------------------
        t2_ok, t2_log, t2_probes = _try_tier2(
            roots, timeout_s=float(self.timeout_s or 30.0)
        )
        log_sections.append(t2_log)

        if t2_ok:
            used_tier = "tier2"
            _ = log_path.write_text(
                "\n".join(log_sections), encoding="utf-8"
            )
            gdb_port = int(os.environ.get("AIEDGE_QEMU_GDB_PORT", "1234"))
            try:
                gdb_info = probe_with_gdb("127.0.0.1", gdb_port, timeout_s=10.0)
            except Exception:
                gdb_info = None
            t2_details: dict[str, JsonValue] = {
                "reason": "",
                "used_tier": used_tier,
                "qemu_probes": cast(JsonValue, t2_probes),
                "log": _rel_to_run_dir(ctx.run_dir, log_path),
                "evidence": evidence,
            }
            if gdb_info is not None:
                t2_details["gdb_probe"] = cast(JsonValue, gdb_info)
            return StageOutcome(
                status="ok",
                details=cast(dict[str, JsonValue], t2_details),
                limitations=[],
            )

        # ---------------------------------------------------------------
        # Tier 3: rootfs inspection via Alpine Docker (original behavior)
        # ---------------------------------------------------------------
        used_tier = "tier3"

        if not docker_bin:
            reason = "docker not installed"
            log_sections.append(
                _format_log(
                    attempted_cmd=None,
                    stdout="",
                    stderr="",
                    reason=reason,
                )
            )
            _ = log_path.write_text(
                "\n".join(log_sections), encoding="utf-8"
            )
            return StageOutcome(
                status="partial",
                details=cast(
                    dict[str, JsonValue],
                    {
                        "reason": reason,
                        "image": self.image,
                        "used_tier": used_tier,
                        "evidence": evidence,
                    },
                ),
                limitations=["Emulation skipped: docker is not installed."],
            )

        inspect_cmd = [docker_bin, "image", "inspect", self.image]
        inspect_stdout = ""
        inspect_stderr = ""
        try:
            inspect_res = subprocess.run(
                inspect_cmd,
                text=True,
                capture_output=True,
                check=False,
            )
            inspect_stdout = inspect_res.stdout or ""
            inspect_stderr = inspect_res.stderr or ""
        except Exception as e:
            reason = f"docker image inspect failed: {type(e).__name__}: {e}"
            log_sections.append(
                _format_log(
                    attempted_cmd=inspect_cmd,
                    stdout=inspect_stdout,
                    stderr=inspect_stderr,
                    reason=reason,
                )
            )
            _ = log_path.write_text(
                "\n".join(log_sections), encoding="utf-8"
            )
            return StageOutcome(
                status="partial",
                details=cast(
                    dict[str, JsonValue],
                    {
                        "reason": reason,
                        "image": self.image,
                        "used_tier": used_tier,
                        "evidence": evidence,
                    },
                ),
                limitations=[
                    "Emulation skipped: unable to inspect required docker image."
                ],
            )

        if inspect_res.returncode != 0:
            stderr_lc = (inspect_stderr or "").lower()
            if "permission denied" in stderr_lc or "docker.sock" in stderr_lc:
                reason = "docker permission denied"
                limitations = [
                    "Emulation skipped: docker is installed but not usable (permission denied talking to daemon)."
                ]
            else:
                reason = f"required docker image missing: {self.image}"
                limitations = ["Emulation skipped: required docker image is missing."]
            log_sections.append(
                _format_log(
                    attempted_cmd=inspect_cmd,
                    stdout=inspect_stdout,
                    stderr=inspect_stderr,
                    reason=reason,
                )
            )
            _ = log_path.write_text(
                "\n".join(log_sections), encoding="utf-8"
            )
            return StageOutcome(
                status="partial",
                details=cast(
                    dict[str, JsonValue],
                    {
                        "reason": reason,
                        "image": self.image,
                        "used_tier": used_tier,
                        "evidence": evidence,
                    },
                ),
                limitations=limitations,
            )

        run_cmd: list[str] = [
            docker_bin,
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(int(self.pids_limit)) if self.pids_limit is not None else "0",
            "--pull=never",
        ]
        if self.cpus is not None:
            run_cmd.extend(["--cpus", str(float(self.cpus))])
        if self.memory_mb is not None:
            run_cmd.extend(["--memory", f"{int(self.memory_mb)}m"])
        run_cmd.extend(["--tmpfs", "/tmp:rw,nosuid,noexec,size=64m"])
        for i, root in enumerate(roots[:3]):
            run_cmd.extend(["-v", f"{str(root.resolve())}:/mnt/rootfs{i}:ro"])
        run_cmd.extend(
            [
                self.image,
                "sh",
                "-lc",
                'for d in /mnt/rootfs*; do ls -la "$d"; test -e "$d/etc"; find "$d" -maxdepth 3 -type f; done',
            ]
        )

        stdout = ""
        stderr = ""
        try:
            run_res = subprocess.run(
                run_cmd,
                text=True,
                capture_output=True,
                check=False,
                timeout=self.timeout_s,
            )
            stdout = run_res.stdout or ""
            stderr = run_res.stderr or ""
        except subprocess.TimeoutExpired as e:
            reason = f"emulation timed out after {self.timeout_s}s"
            log_sections.append(
                _format_log(
                    attempted_cmd=run_cmd,
                    stdout=(e.stdout or "") if isinstance(e.stdout, str) else "",
                    stderr=(e.stderr or "") if isinstance(e.stderr, str) else "",
                    reason=reason,
                )
            )
            _ = log_path.write_text(
                "\n".join(log_sections), encoding="utf-8"
            )
            return StageOutcome(
                status="partial",
                details=cast(
                    dict[str, JsonValue],
                    {
                        "reason": reason,
                        "image": self.image,
                        "used_tier": used_tier,
                        "timeout_s": float(self.timeout_s or 0.0),
                        "evidence": evidence,
                    },
                ),
                limitations=["Emulation attempt timed out."],
            )
        except Exception as e:
            reason = f"docker run failed: {type(e).__name__}: {e}"
            log_sections.append(
                _format_log(
                    attempted_cmd=run_cmd,
                    stdout=stdout,
                    stderr=stderr,
                    reason=reason,
                )
            )
            _ = log_path.write_text(
                "\n".join(log_sections), encoding="utf-8"
            )
            return StageOutcome(
                status="failed",
                details=cast(
                    dict[str, JsonValue],
                    {
                        "reason": reason,
                        "image": self.image,
                        "used_tier": used_tier,
                        "evidence": evidence,
                    },
                ),
                limitations=["Emulation attempt failed unexpectedly."],
            )

        if run_res.returncode == 0:
            status = "ok"
            reason_final: str | None = None
            limits: list[str] = []
        else:
            status = "partial"
            reason_final = f"docker command exited with return code {run_res.returncode}"
            limits = ["Emulation command failed; review emulation log for details."]

        log_sections.append(
            _format_log(
                attempted_cmd=run_cmd,
                stdout=stdout,
                stderr=stderr,
                reason=reason_final,
            )
        )
        _ = log_path.write_text(
            "\n".join(log_sections), encoding="utf-8"
        )

        return StageOutcome(
            status=status,
            details=cast(
                dict[str, JsonValue],
                {
                    "reason": reason_final or "",
                    "image": self.image,
                    "used_tier": used_tier,
                    "returncode": int(run_res.returncode),
                    "log": _rel_to_run_dir(ctx.run_dir, log_path),
                    "evidence": evidence,
                },
            ),
            limitations=limits,
        )
