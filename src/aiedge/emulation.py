from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .policy import AIEdgePolicyViolation
from .schema import JsonValue
from .stage import StageContext, StageOutcome


def _assert_under_dir(base_dir: Path, target: Path) -> None:
    base = base_dir.resolve()
    resolved = target.resolve()
    if not resolved.is_relative_to(base):
        raise AIEdgePolicyViolation(
            f"Refusing to write outside run dir: target={resolved} base={base}"
        )


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


@dataclass(frozen=True)
class EmulationStage:
    image: str = "alpine:3.23"
    timeout_s: float | None = 30.0
    cpus: float | None = 1.0
    memory_mb: int | None = 256
    pids_limit: int | None = 256

    @property
    def name(self) -> str:
        return "emulation"

    def run(self, ctx: StageContext) -> StageOutcome:
        stage_dir = ctx.run_dir / "stages" / "emulation"
        _assert_under_dir(ctx.run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)

        log_path = stage_dir / "emulation.log"
        _assert_under_dir(stage_dir, log_path)

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

        docker_bin = shutil.which("docker")
        if not docker_bin:
            reason = "docker not installed"
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
            _ = log_path.write_text(
                _format_log(
                    attempted_cmd=inspect_cmd,
                    stdout=inspect_stdout,
                    stderr=inspect_stderr,
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
            _ = log_path.write_text(
                _format_log(
                    attempted_cmd=inspect_cmd,
                    stdout=inspect_stdout,
                    stderr=inspect_stderr,
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
            _ = log_path.write_text(
                _format_log(
                    attempted_cmd=run_cmd,
                    stdout=(e.stdout or "") if isinstance(e.stdout, str) else "",
                    stderr=(e.stderr or "") if isinstance(e.stderr, str) else "",
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
                        "timeout_s": float(self.timeout_s or 0.0),
                        "evidence": evidence,
                    },
                ),
                limitations=["Emulation attempt timed out."],
            )
        except Exception as e:
            reason = f"docker run failed: {type(e).__name__}: {e}"
            _ = log_path.write_text(
                _format_log(
                    attempted_cmd=run_cmd,
                    stdout=stdout,
                    stderr=stderr,
                    reason=reason,
                ),
                encoding="utf-8",
            )
            return StageOutcome(
                status="failed",
                details=cast(
                    dict[str, JsonValue],
                    {
                        "reason": reason,
                        "image": self.image,
                        "evidence": evidence,
                    },
                ),
                limitations=["Emulation attempt failed unexpectedly."],
            )

        if run_res.returncode == 0:
            status = "ok"
            reason: str | None = None
            limits: list[str] = []
        else:
            status = "partial"
            reason = f"docker command exited with return code {run_res.returncode}"
            limits = ["Emulation command failed; review emulation log for details."]

        _ = log_path.write_text(
            _format_log(
                attempted_cmd=run_cmd,
                stdout=stdout,
                stderr=stderr,
                reason=reason,
            ),
            encoding="utf-8",
        )

        return StageOutcome(
            status=status,
            details=cast(
                dict[str, JsonValue],
                {
                    "reason": reason or "",
                    "image": self.image,
                    "returncode": int(run_res.returncode),
                    "log": _rel_to_run_dir(ctx.run_dir, log_path),
                    "evidence": evidence,
                },
            ),
            limitations=limits,
        )
