#!/usr/bin/env python3
from __future__ import annotations

import argparse
import stat
from pathlib import Path

_REQUIRED_EVIDENCE_DIRS: tuple[str, ...] = ("exploits", "verified_chain")
_BLOCKED_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".sh", ".elf", ".so", ".a", ".o", ".zip", ".tar"}
)


class VerificationError(ValueError):
    reason_code: str
    detail: str

    def __init__(self, reason_code: str, detail: str) -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}: {detail}")


def _resolve_under_run_dir(run_dir: Path, rel_path: Path) -> Path:
    candidate = (run_dir / rel_path).resolve()
    run_root = run_dir.resolve()
    try:
        _ = candidate.relative_to(run_root)
    except ValueError as exc:
        raise VerificationError(
            "symlink_escape",
            f"path escapes run_dir: {rel_path.as_posix()}",
        ) from exc
    return candidate


def _has_blocked_extension(path: Path) -> bool:
    return path.suffix.lower() in _BLOCKED_EXTENSIONS


def _is_executable(path: Path) -> bool:
    mode = path.stat().st_mode
    return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def _verify_tree(run_dir: Path, tree_name: str) -> None:
    tree_root = run_dir / tree_name
    if not tree_root.is_dir():
        raise VerificationError(
            "missing_required_artifact",
            f"missing directory: {tree_name}",
        )

    for path in tree_root.rglob("*"):
        rel_path = path.relative_to(run_dir)

        if path.is_symlink():
            _ = _resolve_under_run_dir(run_dir, rel_path)

        if not path.is_file():
            continue

        resolved = _resolve_under_run_dir(run_dir, rel_path)
        if _has_blocked_extension(path) or _has_blocked_extension(resolved):
            raise VerificationError(
                "disallowed_extension",
                f"blocked file extension under {tree_name}: {rel_path.as_posix()}",
            )

        if _is_executable(path):
            raise VerificationError(
                "executable_file",
                f"executable file under {tree_name}: {rel_path.as_posix()}",
            )


def verify_run_dir_evidence_only(run_dir: Path) -> None:
    if not run_dir.is_dir():
        raise VerificationError(
            "missing_required_artifact",
            f"run_dir is not a directory: {run_dir}",
        )

    for tree_name in _REQUIRED_EVIDENCE_DIRS:
        _verify_tree(run_dir, tree_name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify run_dir evidence-only policy for exploits/ and verified_chain/."
        )
    )
    _ = parser.add_argument("--run-dir", required=True, help="Path to run directory")
    args = parser.parse_args(argv)

    run_dir_raw = getattr(args, "run_dir", None)
    if not isinstance(run_dir_raw, str) or not run_dir_raw:
        print("[FAIL] invalid_contract: --run-dir must be a non-empty path")
        return 1

    run_dir = Path(run_dir_raw).resolve()

    try:
        verify_run_dir_evidence_only(run_dir)
    except VerificationError as exc:
        print(f"[FAIL] {exc.reason_code}: {exc.detail}")
        return 1
    except Exception as exc:
        print(f"[FAIL] invalid_contract: unexpected verifier error: {exc}")
        return 1

    print(f"[OK] run_dir evidence-only policy verified: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
