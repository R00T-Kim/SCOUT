#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import cast

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC_DIR = _REPO_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from aiedge.schema import validate_analyst_digest

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class VerificationError(ValueError):
    reason_code: str
    detail: str

    def __init__(self, reason_code: str, detail: str) -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}: {detail}")


def _as_object(value: object, *, path: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise VerificationError("invalid_contract", f"{path} must be object")
    src = cast(dict[object, object], value)
    out: dict[str, object] = {}
    for key, item in src.items():
        out[str(key)] = item
    return out


def _load_json_object(path: Path, *, reason_code: str) -> dict[str, object]:
    try:
        obj = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception as exc:
        raise VerificationError(reason_code, f"invalid JSON: {path}: {exc}") from exc
    return _as_object(obj, path=str(path))


def _is_run_relative_path(path: str) -> bool:
    if not path:
        return False
    if path.startswith("/"):
        return False
    if re.match(r"^[A-Za-z]:\\", path):
        return False
    return True


def _resolve_linked_path(run_dir: Path, rel_path: str, *, field_path: str) -> Path:
    if not _is_run_relative_path(rel_path):
        raise VerificationError(
            "invalid_contract", f"{field_path} must be run-relative path: {rel_path!r}"
        )
    candidate = (run_dir / rel_path).resolve()
    run_root = run_dir.resolve()
    try:
        _ = candidate.relative_to(run_root)
    except ValueError as exc:
        raise VerificationError(
            "invalid_contract", f"{field_path} escapes run dir: {rel_path!r}"
        ) from exc
    if not candidate.is_file():
        raise VerificationError(
            "missing_required_artifact",
            f"missing file at {field_path}: {rel_path!r}",
        )
    return candidate


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _verify_analyst_digest(run_dir: Path) -> None:
    digest_path = run_dir / "report" / "analyst_digest.json"
    if not digest_path.is_file():
        raise VerificationError(
            "missing_required_artifact", "missing file: report/analyst_digest.json"
        )

    digest = _load_json_object(digest_path, reason_code="invalid_contract")
    schema_errors = validate_analyst_digest(digest)
    if schema_errors:
        raise VerificationError("invalid_contract", "; ".join(sorted(schema_errors)))

    finding_verdicts_any = digest.get("finding_verdicts")
    finding_verdicts = (
        cast(list[object], finding_verdicts_any)
        if isinstance(finding_verdicts_any, list)
        else []
    )
    for finding_idx, finding_any in enumerate(finding_verdicts):
        finding = _as_object(finding_any, path=f"finding_verdicts[{finding_idx}]")
        evidence_refs_any = finding.get("evidence_refs")
        if not isinstance(evidence_refs_any, list):
            raise VerificationError(
                "invalid_contract",
                f"finding_verdicts[{finding_idx}].evidence_refs must be list",
            )
        evidence_refs = cast(list[object], evidence_refs_any)
        for ref_idx, ref_any in enumerate(evidence_refs):
            if not isinstance(ref_any, str):
                raise VerificationError(
                    "invalid_contract",
                    f"finding_verdicts[{finding_idx}].evidence_refs[{ref_idx}] must be string",
                )
            _ = _resolve_linked_path(
                run_dir,
                ref_any,
                field_path=f"finding_verdicts[{finding_idx}].evidence_refs[{ref_idx}]",
            )

        verifier_refs_any = finding.get("verifier_refs")
        if not isinstance(verifier_refs_any, list):
            raise VerificationError(
                "invalid_contract",
                f"finding_verdicts[{finding_idx}].verifier_refs must be list",
            )
        verifier_refs = cast(list[object], verifier_refs_any)
        for ref_idx, ref_any in enumerate(verifier_refs):
            if not isinstance(ref_any, str):
                raise VerificationError(
                    "invalid_contract",
                    f"finding_verdicts[{finding_idx}].verifier_refs[{ref_idx}] must be string",
                )
            _ = _resolve_linked_path(
                run_dir,
                ref_any,
                field_path=f"finding_verdicts[{finding_idx}].verifier_refs[{ref_idx}]",
            )

    evidence_index_any = digest.get("evidence_index")
    evidence_index = (
        cast(list[object], evidence_index_any)
        if isinstance(evidence_index_any, list)
        else []
    )
    seen_refs: set[str] = set()
    for idx, item_any in enumerate(evidence_index):
        item = _as_object(item_any, path=f"evidence_index[{idx}]")
        ref_any = item.get("ref")
        sha_any = item.get("sha256")
        if not isinstance(ref_any, str):
            raise VerificationError(
                "invalid_contract", f"evidence_index[{idx}].ref must be string"
            )
        if not isinstance(sha_any, str) or not _SHA256_RE.fullmatch(sha_any):
            raise VerificationError(
                "invalid_contract",
                f"evidence_index[{idx}].sha256 must be lowercase hex sha256",
            )
        if ref_any in seen_refs:
            raise VerificationError(
                "invalid_contract", f"duplicate evidence_index ref: {ref_any!r}"
            )
        seen_refs.add(ref_any)

        candidate = _resolve_linked_path(
            run_dir,
            ref_any,
            field_path=f"evidence_index[{idx}].ref",
        )
        actual_sha = _sha256_file(candidate)
        if actual_sha != sha_any:
            raise VerificationError(
                "evidence_hash_mismatch",
                f"sha256 mismatch for {ref_any!r}: expected {sha_any}, got {actual_sha}",
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify analyst_digest contract, refs, and evidence hashes."
    )
    _ = parser.add_argument("--run-dir", required=True, help="Path to run directory")
    args = parser.parse_args(argv)

    run_dir_raw = getattr(args, "run_dir", None)
    if not isinstance(run_dir_raw, str) or not run_dir_raw:
        print("[FAIL] invalid_contract: --run-dir must be a non-empty path")
        return 1

    run_dir = Path(run_dir_raw).resolve()
    if not run_dir.is_dir():
        print(
            f"[FAIL] missing_required_artifact: run_dir is not a directory: {run_dir}"
        )
        return 1

    try:
        _verify_analyst_digest(run_dir)
    except VerificationError as exc:
        print(f"[FAIL] {exc.reason_code}: {exc.detail}")
        return 1
    except Exception as exc:
        print(f"[FAIL] invalid_contract: unexpected verifier error: {exc}")
        return 1

    print(f"[OK] analyst_digest verified: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
