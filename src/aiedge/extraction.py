from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .policy import AIEdgePolicyViolation
from .schema import JsonValue
from .stage import StageContext, StageOutcome

_UBI_MAGIC = b"UBI#"
_SQUASHFS_MAGICS = (b"hsqs", b"sqsh")


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


def _append_log(log_path: Path, line: str) -> None:
    try:
        with log_path.open("a", encoding="utf-8") as f:
            _ = f.write(line)
            if not line.endswith("\n"):
                _ = f.write("\n")
    except Exception:
        return


def _read_head(path: Path, size: int = 4) -> bytes:
    try:
        with path.open("rb") as f:
            return f.read(int(max(1, size)))
    except Exception:
        return b""


def _has_magic(path: Path, magics: tuple[bytes, ...]) -> bool:
    if not path.is_file():
        return False
    head = _read_head(path, size=max(len(m) for m in magics))
    if not head:
        return False
    return any(head.startswith(m) for m in magics)


def _iter_magic_files(
    root: Path,
    *,
    magics: tuple[bytes, ...],
    max_candidates: int,
    max_file_bytes: int,
    skip_part: str | None = None,
) -> list[Path]:
    out: list[Path] = []
    if not root.is_dir():
        return out
    for p in sorted(root.rglob("*")):
        if len(out) >= int(max_candidates):
            break
        if skip_part and skip_part in p.parts:
            continue
        if not p.is_file():
            continue
        try:
            size = int(p.stat().st_size)
        except OSError:
            continue
        if size <= 0 or size > int(max_file_bytes):
            continue
        if _has_magic(p, magics):
            out.append(p)
    return out


def _recursive_nested_extraction(
    *,
    run_dir: Path,
    stage_dir: Path,
    extracted_dir: Path,
    firmware_path: Path,
    log_path: Path,
    timeout_s: float | None,
) -> tuple[dict[str, JsonValue], list[str], list[dict[str, JsonValue]]]:
    details: dict[str, JsonValue] = {
        "attempted": False,
        "ubi_candidates": cast(list[JsonValue], cast(list[object], [])),
        "squashfs_candidates": cast(list[JsonValue], cast(list[object], [])),
        "ubi_extract_attempted": 0,
        "ubi_extract_ok": 0,
        "squashfs_extract_attempted": 0,
        "squashfs_extract_ok": 0,
    }
    limitations: list[str] = []
    evidence: list[dict[str, JsonValue]] = []

    if not extracted_dir.is_dir():
        details["reason"] = "missing_extracted_dir"
        return details, limitations, evidence

    details["attempted"] = True

    ubireader = shutil.which("ubireader_extract_images")
    unsquashfs = shutil.which("unsquashfs")
    details["ubireader_extract_images_available"] = bool(ubireader)
    details["unsquashfs_available"] = bool(unsquashfs)

    ubi_out_root = extracted_dir / "__ubi_recursive"
    squash_out_root = extracted_dir / "__recursive_squashfs"
    _assert_under_dir(run_dir, ubi_out_root)
    _assert_under_dir(run_dir, squash_out_root)
    if ubi_out_root.exists():
        shutil.rmtree(ubi_out_root, ignore_errors=True)
    if squash_out_root.exists():
        shutil.rmtree(squash_out_root, ignore_errors=True)

    ubi_candidates: list[Path] = []
    if _has_magic(firmware_path, (_UBI_MAGIC,)):
        ubi_candidates.append(firmware_path)
    ubi_candidates.extend(
        _iter_magic_files(
            extracted_dir,
            magics=(_UBI_MAGIC,),
            max_candidates=12,
            max_file_bytes=2 * 1024 * 1024 * 1024,
            skip_part="__recursive_squashfs",
        )
    )
    dedup_ubi: list[Path] = []
    seen_ubi: set[str] = set()
    for p in ubi_candidates:
        key = str(p.resolve())
        if key in seen_ubi:
            continue
        seen_ubi.add(key)
        dedup_ubi.append(p)
    ubi_candidates = dedup_ubi[:8]

    details["ubi_candidates"] = cast(
        list[JsonValue],
        cast(list[object], [_rel_to_run_dir(run_dir, p) for p in ubi_candidates]),
    )
    details["ubi_candidate_count"] = int(len(ubi_candidates))

    if ubi_candidates and not ubireader:
        limitations.append(
            "UBI container detected but ubireader_extract_images is unavailable; nested extraction skipped."
        )

    ubi_ok = 0
    for idx, ubi_path in enumerate(ubi_candidates, start=1):
        if not ubireader:
            break
        out_dir = ubi_out_root / f"ubi_{idx:02d}"
        _assert_under_dir(run_dir, out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        evidence.append(_evidence_path(run_dir, out_dir))
        argv = [ubireader, "-o", str(out_dir), str(ubi_path)]
        _append_log(log_path, f"recursive ubireader argv: {argv}")
        try:
            cp = subprocess.run(
                argv,
                cwd=str(stage_dir),
                text=True,
                capture_output=True,
                check=False,
                timeout=max(30.0, min(float(timeout_s or 0.0), 300.0)),
            )
        except subprocess.TimeoutExpired:
            limitations.append(
                f"ubireader_extract_images timed out for {_rel_to_run_dir(run_dir, ubi_path)}"
            )
            continue
        details["ubi_extract_attempted"] = int(
            cast(int, details.get("ubi_extract_attempted", 0)) + 1
        )
        _append_log(log_path, f"recursive ubireader returncode: {cp.returncode}")
        if cp.stdout:
            _append_log(log_path, "--- recursive ubireader stdout (trunc) ---")
            _append_log(log_path, cp.stdout[:4096])
        if cp.stderr:
            _append_log(log_path, "--- recursive ubireader stderr (trunc) ---")
            _append_log(log_path, cp.stderr[:4096])
        if cp.returncode != 0:
            limitations.append(
                f"ubireader_extract_images failed for {_rel_to_run_dir(run_dir, ubi_path)} (rc={cp.returncode})"
            )
            continue
        ubi_ok += 1

    details["ubi_extract_ok"] = int(ubi_ok)

    squashfs_candidates = _iter_magic_files(
        extracted_dir,
        magics=_SQUASHFS_MAGICS,
        max_candidates=24,
        max_file_bytes=1024 * 1024 * 1024,
        skip_part="__recursive_squashfs",
    )
    details["squashfs_candidates"] = cast(
        list[JsonValue],
        cast(
            list[object],
            [_rel_to_run_dir(run_dir, p) for p in squashfs_candidates[:12]],
        ),
    )
    details["squashfs_candidate_count"] = int(len(squashfs_candidates))

    if squashfs_candidates and not unsquashfs:
        limitations.append(
            "SquashFS candidate detected but unsquashfs is unavailable; nested squashfs extraction skipped."
        )

    squash_ok = 0
    for idx, sq_path in enumerate(squashfs_candidates, start=1):
        if not unsquashfs:
            break
        out_dir = squash_out_root / f"root_{idx:02d}"
        _assert_under_dir(run_dir, out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        argv = [unsquashfs, "-d", str(out_dir), str(sq_path)]
        _append_log(log_path, f"recursive unsquashfs argv: {argv}")
        try:
            cp = subprocess.run(
                argv,
                cwd=str(stage_dir),
                text=True,
                capture_output=True,
                check=False,
                timeout=max(30.0, min(float(timeout_s or 0.0) * 2.0, 600.0)),
            )
        except subprocess.TimeoutExpired:
            limitations.append(
                f"unsquashfs timed out for {_rel_to_run_dir(run_dir, sq_path)}"
            )
            continue
        details["squashfs_extract_attempted"] = int(
            cast(int, details.get("squashfs_extract_attempted", 0)) + 1
        )
        _append_log(log_path, f"recursive unsquashfs returncode: {cp.returncode}")
        if cp.stdout:
            _append_log(log_path, "--- recursive unsquashfs stdout (trunc) ---")
            _append_log(log_path, cp.stdout[:4096])
        if cp.stderr:
            _append_log(log_path, "--- recursive unsquashfs stderr (trunc) ---")
            _append_log(log_path, cp.stderr[:4096])
        if cp.returncode != 0:
            limitations.append(
                f"unsquashfs failed for {_rel_to_run_dir(run_dir, sq_path)} (rc={cp.returncode})"
            )
            continue
        if _count_files(out_dir) <= 0:
            limitations.append(
                f"unsquashfs produced empty output for {_rel_to_run_dir(run_dir, sq_path)}"
            )
            continue
        squash_ok += 1
        evidence.append(_evidence_path(run_dir, out_dir))

    details["squashfs_extract_ok"] = int(squash_ok)

    return details, limitations, evidence


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

        recursive_info: dict[str, JsonValue] = {"attempted": False}
        recursive_limits: list[str] = []
        if extracted_dir.is_dir():
            recursive_info, recursive_limits, recursive_evidence = (
                _recursive_nested_extraction(
                    run_dir=ctx.run_dir,
                    stage_dir=stage_dir,
                    extracted_dir=extracted_dir,
                    firmware_path=fw,
                    log_path=log_path,
                    timeout_s=self.timeout_s,
                )
            )
            for ev in recursive_evidence:
                if ev not in evidence:
                    evidence.append(ev)
            if recursive_limits:
                reasons.extend(recursive_limits)

        extracted_files = _count_files(extracted_dir)

        details["binwalk_returncode"] = int(res.returncode)
        details["binwalk_log"] = _rel_to_run_dir(ctx.run_dir, log_path)
        details["extracted_dir"] = _rel_to_run_dir(ctx.run_dir, extracted_dir)
        details["extracted_file_count"] = int(extracted_files)
        details["recursive_extraction"] = recursive_info

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
        return StageOutcome(status=status, details=details, limitations=recursive_limits)
