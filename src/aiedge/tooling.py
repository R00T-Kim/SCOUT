from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .policy import AIEdgePolicyViolation
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus


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


def _evidence_path(
    run_dir: Path, path: Path, *, note: str | None = None
) -> dict[str, JsonValue]:
    ev: dict[str, JsonValue] = {"path": _rel_to_run_dir(run_dir, path)}
    if note:
        ev["note"] = note
    return ev


def _truncate_text(s: str, *, max_chars: int) -> str:
    if len(s) <= max_chars:
        return s
    if max_chars <= 3:
        return s[:max_chars]
    return s[: max_chars - 3] + "..."


_VERSION_RE = re.compile(r"\b(\d+\.)+\d+\b")


def _extract_version(text: str) -> str:
    m = _VERSION_RE.search(text)
    return m.group(0) if m else ""


@dataclass(frozen=True)
class _ToolProbe:
    key: str
    candidates: list[list[str]]
    timeout_s: float
    which_name: str | None = None


def _resolve_argv(argv: list[str], *, which_name: str | None) -> tuple[list[str], bool]:
    if not argv:
        return [], False

    if which_name:
        resolved = shutil.which(which_name)
        if not resolved:
            return list(argv), False
        out = list(argv)
        out[0] = resolved
        return out, True

    return list(argv), True


def _probe_one(
    *, argv: list[str], timeout_s: float, max_output_chars: int
) -> dict[str, JsonValue]:
    try:
        res = subprocess.run(
            list(argv),
            text=True,
            capture_output=True,
            check=False,
            timeout=float(timeout_s),
        )
        stdout = res.stdout or ""
        stderr = res.stderr or ""
        return {
            "exit_code": int(res.returncode),
            "stdout": _truncate_text(stdout, max_chars=max_output_chars),
            "stderr": _truncate_text(stderr, max_chars=max_output_chars),
        }
    except subprocess.TimeoutExpired as e:
        stdout = getattr(e, "stdout", None) or ""
        stderr = getattr(e, "stderr", None) or ""
        return {
            "exit_code": None,
            "stdout": _truncate_text(str(stdout), max_chars=max_output_chars),
            "stderr": _truncate_text(str(stderr), max_chars=max_output_chars),
        }
    except FileNotFoundError:
        return {"exit_code": None, "stdout": "", "stderr": ""}


@dataclass(frozen=True)
class ToolingStage:
    timeout_s: float = 1.5
    max_output_chars: int = 4096

    _REQUIRED_TOOLS: tuple[str, ...] = (
        "dtc",
        "fdtget",
        "fdtdump",
        "binwalk",
        "unsquashfs",
        "docker",
    )
    _OPTIONAL_TOOLS: tuple[str, ...] = ("lzop", "ubidump")

    @property
    def name(self) -> str:
        return "tooling"

    def run(self, ctx: StageContext) -> StageOutcome:
        stage_dir = ctx.run_dir / "stages" / "tooling"
        _assert_under_dir(ctx.run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)

        tools_path = stage_dir / "tools.json"
        _assert_under_dir(stage_dir, tools_path)

        probes: list[_ToolProbe] = [
            _ToolProbe("dtc", [["dtc", "-v"]], self.timeout_s, which_name="dtc"),
            _ToolProbe(
                "fdtget",
                [["fdtget", "--version"], ["fdtget", "--help"]],
                self.timeout_s,
                which_name="fdtget",
            ),
            _ToolProbe(
                "fdtdump",
                [["fdtdump", "--version"], ["fdtdump", "--help"]],
                self.timeout_s,
                which_name="fdtdump",
            ),
            _ToolProbe(
                "binwalk",
                [["binwalk", "--version"], ["binwalk", "--help"]],
                self.timeout_s,
                which_name="binwalk",
            ),
            _ToolProbe(
                "unsquashfs",
                [["unsquashfs", "-version"], ["unsquashfs", "-v"]],
                self.timeout_s,
                which_name="unsquashfs",
            ),
            _ToolProbe(
                "lzop",
                [["lzop", "-V"], ["lzop", "--version"]],
                self.timeout_s,
                which_name="lzop",
            ),
            _ToolProbe(
                "docker",
                [["docker", "--version"]],
                self.timeout_s,
                which_name="docker",
            ),
            _ToolProbe(
                "ubidump",
                [["ubidump", "--help"], [sys.executable, "-m", "ubidump", "--help"]],
                self.timeout_s,
                which_name="ubidump",
            ),
        ]

        tools: dict[str, JsonValue] = {}
        limitations: list[str] = []
        missing_required: list[str] = []
        missing_optional: list[str] = []
        timed_out: list[str] = []

        for p in probes:
            tool_obj: dict[str, JsonValue] = {
                "required": p.key in self._REQUIRED_TOOLS,
                "available": False,
                "version": "",
                "argv": [],
                "timeout_s": float(p.timeout_s),
                "exit_code": None,
                "stdout": "",
                "stderr": "",
            }

            last_argv: list[str] = []
            found_any_candidate = False

            for cand in p.candidates:
                which_for_cand = (
                    p.which_name
                    if (p.which_name and cand and cand[0] == p.which_name)
                    else None
                )
                argv0, ok = _resolve_argv(cand, which_name=which_for_cand)
                last_argv = argv0
                tool_obj["argv"] = cast(JsonValue, list(argv0))

                if not ok:
                    continue

                found_any_candidate = True
                last_result = _probe_one(
                    argv=argv0,
                    timeout_s=float(p.timeout_s),
                    max_output_chars=int(self.max_output_chars),
                )
                for k in ["exit_code", "stdout", "stderr"]:
                    tool_obj[k] = last_result.get(k)

                exit_code = last_result.get("exit_code")
                if exit_code is None:
                    timed_out.append(p.key)
                if isinstance(exit_code, int) and exit_code == 0:
                    break

            out_text = "".join(
                [
                    cast(str, tool_obj.get("stdout") or ""),
                    "\n",
                    cast(str, tool_obj.get("stderr") or ""),
                ]
            )
            tool_obj["version"] = _extract_version(out_text)

            if p.key == "ubidump":
                if p.which_name and shutil.which(p.which_name):
                    tool_obj["available"] = True
                else:
                    ec_any = tool_obj.get("exit_code")
                    tool_obj["available"] = bool(
                        isinstance(ec_any, int) and ec_any == 0
                    )
            else:
                tool_obj["available"] = bool(
                    p.which_name and shutil.which(p.which_name)
                )

            if not tool_obj["available"]:
                if bool(tool_obj["required"]):
                    missing_required.append(p.key)
                else:
                    missing_optional.append(p.key)
                tool_obj["argv"] = cast(JsonValue, list(last_argv))
                tool_obj["version"] = ""
                if not found_any_candidate:
                    tool_obj["stdout"] = ""
                    tool_obj["stderr"] = ""
                    tool_obj["exit_code"] = None
            else:
                v = tool_obj.get("version")
                if not isinstance(v, str):
                    tool_obj["version"] = ""

            tools[p.key] = cast(JsonValue, tool_obj)

        _ = tools_path.write_text(
            json.dumps(tools, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        evidence: list[dict[str, JsonValue]] = [
            _evidence_path(ctx.run_dir, stage_dir),
            _evidence_path(ctx.run_dir, tools_path),
        ]

        ordered_probe_keys = [p.key for p in probes]
        ordered_missing_required = [
            key for key in ordered_probe_keys if key in set(missing_required)
        ]
        ordered_missing_optional = [
            key for key in ordered_probe_keys if key in set(missing_optional)
        ]
        ordered_timed_out = [key for key in ordered_probe_keys if key in set(timed_out)]

        if ordered_missing_required:
            limitations.append(
                "Some required tooling is not available; related analysis stages may be limited: "
                + ", ".join(ordered_missing_required)
            )
        if ordered_missing_optional:
            limitations.append(
                "Some optional tooling is not available; run validity is unchanged but coverage may be reduced: "
                + ", ".join(ordered_missing_optional)
            )
        if ordered_timed_out:
            limitations.append(
                "Some tooling probes timed out (versions may be unknown): "
                + ", ".join(ordered_timed_out)
            )

        details: dict[str, JsonValue] = {
            "evidence": cast(list[JsonValue], cast(list[object], evidence)),
            "artifacts": {"tools_json": _rel_to_run_dir(ctx.run_dir, tools_path)},
            "missing_tools": cast(
                list[JsonValue],
                list(ordered_missing_required + ordered_missing_optional),
            ),
            "missing_required_tools": cast(list[JsonValue], ordered_missing_required),
            "missing_optional_tools": cast(list[JsonValue], ordered_missing_optional),
            "timed_out_tools": cast(list[JsonValue], ordered_timed_out),
        }

        status: StageStatus = (
            "partial" if (ordered_missing_required or ordered_timed_out) else "ok"
        )
        return StageOutcome(status=status, details=details, limitations=limitations)
