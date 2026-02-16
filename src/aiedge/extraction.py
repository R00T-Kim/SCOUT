from __future__ import annotations

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


def _evidence_path(
    run_dir: Path, path: Path, *, note: str | None = None
) -> dict[str, JsonValue]:
    ev: dict[str, JsonValue] = {"path": _rel_to_run_dir(run_dir, path)}
    if note:
        ev["note"] = note
    return ev


def _count_files(root: Path) -> int:
    if not root.exists():
        return 0
    n = 0
    for p in root.rglob("*"):
        if p.is_file():
            n += 1
    return n


@dataclass(frozen=True)
class ExtractionStage:
    firmware_path: Path
    timeout_s: float | None = 120.0
    matryoshka: bool = True
    matryoshka_depth: int = 8

    @property
    def name(self) -> str:
        return "extraction"

    def run(self, ctx: StageContext) -> StageOutcome:
        fw = self.firmware_path
        if not fw.is_file():
            return StageOutcome(
                status="failed",
                details={
                    "confidence": 0.0,
                    "reasons": [f"firmware not found: {str(fw)}"],
                    "evidence": [
                        _evidence_path(ctx.run_dir, fw, note="missing"),
                    ],
                },
                limitations=["Firmware file missing inside run directory."],
            )

        stage_dir = ctx.run_dir / "stages" / "extraction"
        _assert_under_dir(ctx.run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)

        reasons: list[str] = []
        evidence: list[dict[str, JsonValue]] = [
            _evidence_path(ctx.run_dir, stage_dir),
            _evidence_path(ctx.run_dir, fw),
        ]
        details: dict[str, JsonValue] = {
            "stage_dir": _rel_to_run_dir(ctx.run_dir, stage_dir),
            "tool": "binwalk",
            "firmware": _rel_to_run_dir(ctx.run_dir, fw),
        }

        details["matryoshka"] = bool(self.matryoshka)
        details["matryoshka_depth"] = int(self.matryoshka_depth)
        details["lzop_available"] = bool(shutil.which("lzop"))

        log_path = stage_dir / "binwalk.log"
        _assert_under_dir(stage_dir, log_path)
        extracted_dir = stage_dir / f"_{fw.name}.extracted"

        binwalk = shutil.which("binwalk")
        if not binwalk:
            reasons.append("binwalk not installed")
            details["confidence"] = 0.0
            details["reasons"] = cast(list[JsonValue], list(reasons))
            details["binwalk_available"] = False
            _ = log_path.write_text(
                "binwalk not installed; extraction skipped\n", encoding="utf-8"
            )
            evidence.append(_evidence_path(ctx.run_dir, log_path))
            evidence.append(_evidence_path(ctx.run_dir, extracted_dir, note="missing"))
            details["evidence"] = cast(list[JsonValue], cast(list[object], evidence))
            return StageOutcome(
                status="partial",
                details=details,
                limitations=["binwalk not installed; skipping extraction."],
            )

        details["binwalk_available"] = True
        argv: list[str] = [binwalk]
        if self.matryoshka:
            argv.append("-M")
            argv.extend(["-d", str(int(self.matryoshka_depth))])
        argv.append("-e")
        argv.append(str(fw))
        try:
            res = subprocess.run(
                argv,
                cwd=str(stage_dir),
                text=True,
                capture_output=True,
                check=False,
                timeout=self.timeout_s,
            )
        except subprocess.TimeoutExpired:
            reasons.append(f"binwalk timed out after {self.timeout_s}s")
            details["confidence"] = 0.0
            details["reasons"] = cast(list[JsonValue], list(reasons))
            _ = log_path.write_text(
                "\n".join(
                    [
                        f"argv: {argv}",
                        f"timeout_s: {self.timeout_s}",
                        "binwalk timed out",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            evidence.append(_evidence_path(ctx.run_dir, log_path))
            evidence.append(_evidence_path(ctx.run_dir, extracted_dir, note="unknown"))
            details["evidence"] = cast(list[JsonValue], cast(list[object], evidence))
            return StageOutcome(
                status="failed",
                details=details,
                limitations=["Extraction timed out."],
            )

        _ = log_path.write_text(
            "\n".join(
                [
                    f"argv: {argv}",
                    f"returncode: {res.returncode}",
                    "--- stdout ---",
                    res.stdout or "",
                    "--- stderr ---",
                    res.stderr or "",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        extracted_files = _count_files(extracted_dir)

        details["binwalk_returncode"] = int(res.returncode)
        details["binwalk_log"] = _rel_to_run_dir(ctx.run_dir, log_path)
        details["extracted_dir"] = _rel_to_run_dir(ctx.run_dir, extracted_dir)
        details["extracted_file_count"] = int(extracted_files)

        evidence.append(_evidence_path(ctx.run_dir, log_path))
        if extracted_dir.exists():
            evidence.append(_evidence_path(ctx.run_dir, extracted_dir))
        else:
            evidence.append(_evidence_path(ctx.run_dir, extracted_dir, note="missing"))

        if res.returncode != 0:
            reasons.append(f"binwalk failed with return code {res.returncode}")
            confidence = 0.1
            status = "partial"
        elif extracted_files <= 0:
            reasons.append("binwalk succeeded but no extracted files were produced")
            confidence = 0.4
            status = "partial"
        else:
            reasons.append(f"extracted {extracted_files} files via binwalk")
            confidence = 0.85
            status = "ok"

        details["confidence"] = float(confidence)
        details["reasons"] = cast(list[JsonValue], list(reasons))
        details["evidence"] = cast(list[JsonValue], cast(list[object], evidence))
        return StageOutcome(status=status, details=details)
