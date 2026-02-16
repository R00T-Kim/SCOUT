#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import cast

_VERIFIED_CHAIN_SCHEMA_VERSION = "verified-chain-v1"
_VERDICT_STATES = frozenset({"pass", "fail", "inconclusive"})
_ATTEMPT_STATES = frozenset({"pass", "fail", "inconclusive"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REASON_CODE_RE = re.compile(r"^[a-z0-9_]+$")

_ALLOWED_REASON_CODES = frozenset(
    {
        "repro_3_of_3",
        "isolation_verified",
        "poc_repro_failed",
        "isolation_violation",
        "boot_flaky",
        "boot_timeout",
        "missing_dynamic_bundle",
        "missing_exploit_bundle",
        "missing_required_artifact",
        "invalid_contract",
    }
)

_PASS_REASON_CODES = frozenset({"repro_3_of_3", "isolation_verified"})
_FAIL_REASON_CODES = frozenset(
    {
        "poc_repro_failed",
        "isolation_violation",
        "missing_dynamic_bundle",
        "missing_exploit_bundle",
        "missing_required_artifact",
        "invalid_contract",
    }
)
_INCONCLUSIVE_REASON_CODES = frozenset(
    {
        "boot_flaky",
        "boot_timeout",
        "missing_dynamic_bundle",
        "missing_exploit_bundle",
        "missing_required_artifact",
    }
)


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


def _require_str(obj: dict[str, object], key: str, *, path: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise VerificationError(
            "invalid_contract", f"{path}.{key} must be non-empty string"
        )
    return value


def _require_bool(obj: dict[str, object], key: str, *, path: str) -> bool:
    value = obj.get(key)
    if not isinstance(value, bool):
        raise VerificationError("invalid_contract", f"{path}.{key} must be bool")
    return value


def _require_int(obj: dict[str, object], key: str, *, path: str) -> int:
    value = obj.get(key)
    if not isinstance(value, int):
        raise VerificationError("invalid_contract", f"{path}.{key} must be int")
    return value


def _validate_iso8601(value: str, *, field_path: str) -> None:
    try:
        _ = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise VerificationError(
            "invalid_contract", f"{field_path} must be ISO8601 timestamp"
        ) from exc


def _validate_linked_path(
    run_dir: Path,
    rel_path: str,
    *,
    field_path: str,
    missing_reason: str,
) -> Path:
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

    if not candidate.exists():
        raise VerificationError(
            missing_reason, f"missing path at {field_path}: {rel_path!r}"
        )
    return candidate


def _validate_evidence_refs(
    run_dir: Path,
    refs_any: object,
    *,
    field_path: str,
    missing_reason: str,
) -> list[str]:
    if not isinstance(refs_any, list) or not refs_any:
        raise VerificationError(
            "invalid_contract", f"{field_path} must be non-empty list"
        )
    refs = cast(list[object], refs_any)
    out: list[str] = []
    for idx, ref_any in enumerate(refs):
        if not isinstance(ref_any, str):
            raise VerificationError(
                "invalid_contract", f"{field_path}[{idx}] must be string"
            )
        _ = _validate_linked_path(
            run_dir,
            ref_any,
            field_path=f"{field_path}[{idx}]",
            missing_reason=missing_reason,
        )
        out.append(ref_any)
    return out


def _validate_reason_codes(state: str, reason_codes: list[str]) -> None:
    if not reason_codes:
        raise VerificationError(
            "invalid_contract", "verdict.reason_codes must be non-empty"
        )
    for idx, code in enumerate(reason_codes):
        if not _REASON_CODE_RE.fullmatch(code):
            raise VerificationError(
                "invalid_contract",
                f"verdict.reason_codes[{idx}] must match {_REASON_CODE_RE.pattern!r}",
            )
        if code not in _ALLOWED_REASON_CODES:
            raise VerificationError(
                "invalid_contract", f"unsupported reason code: {code}"
            )

    reason_set = set(reason_codes)
    if state == "pass":
        missing = sorted(_PASS_REASON_CODES - reason_set)
        if missing:
            raise VerificationError(
                "invalid_contract",
                "pass verdict missing required reason codes: " + ", ".join(missing),
            )
    elif state == "fail":
        if not reason_set.intersection(_FAIL_REASON_CODES):
            raise VerificationError(
                "invalid_contract",
                "fail verdict missing failure reason code",
            )
    else:
        if not reason_set.intersection(_INCONCLUSIVE_REASON_CODES):
            raise VerificationError(
                "invalid_contract",
                "inconclusive verdict missing inconclusive reason code",
            )


def _verify_verified_chain(run_dir: Path) -> None:
    verified_dir = run_dir / "verified_chain"
    if not verified_dir.is_dir():
        raise VerificationError(
            "missing_required_artifact", "missing directory: verified_chain"
        )

    dynamic_dir = run_dir / "stages" / "dynamic_validation"
    if not dynamic_dir.is_dir():
        raise VerificationError(
            "missing_dynamic_bundle", "missing directory: stages/dynamic_validation"
        )

    exploits_dir = run_dir / "exploits"
    if not exploits_dir.is_dir():
        raise VerificationError("missing_exploit_bundle", "missing directory: exploits")

    contract_path = verified_dir / "verified_chain.json"
    if not contract_path.is_file():
        raise VerificationError(
            "missing_required_artifact",
            "missing file: verified_chain/verified_chain.json",
        )

    contract = _load_json_object(contract_path, reason_code="invalid_contract")

    schema_version = _require_str(contract, "schema_version", path="verified_chain")
    if schema_version != _VERIFIED_CHAIN_SCHEMA_VERSION:
        raise VerificationError(
            "invalid_contract",
            f"verified_chain.schema_version must be {_VERIFIED_CHAIN_SCHEMA_VERSION!r}",
        )

    generated_at = _require_str(contract, "generated_at", path="verified_chain")
    _validate_iso8601(generated_at, field_path="verified_chain.generated_at")

    _ = _require_str(contract, "run_id", path="verified_chain")

    firmware_any = contract.get("firmware")
    firmware = _as_object(firmware_any, path="verified_chain.firmware")
    firmware_sha256 = _require_str(firmware, "sha256", path="verified_chain.firmware")
    if not _SHA256_RE.fullmatch(firmware_sha256):
        raise VerificationError(
            "invalid_contract",
            "verified_chain.firmware.sha256 must be lowercase sha256",
        )
    _ = _require_str(firmware, "profile", path="verified_chain.firmware")

    tool_versions_any = contract.get("tool_versions")
    tool_versions = _as_object(tool_versions_any, path="verified_chain.tool_versions")
    for key in ("firmae_commit", "firmae_version", "tcpdump", "iproute2"):
        _ = _require_str(tool_versions, key, path="verified_chain.tool_versions")

    timestamps_any = contract.get("timestamps")
    timestamps = _as_object(timestamps_any, path="verified_chain.timestamps")
    started_at = _require_str(
        timestamps, "started_at", path="verified_chain.timestamps"
    )
    finished_at = _require_str(
        timestamps, "finished_at", path="verified_chain.timestamps"
    )
    _validate_iso8601(started_at, field_path="verified_chain.timestamps.started_at")
    _validate_iso8601(finished_at, field_path="verified_chain.timestamps.finished_at")

    dynamic_any = contract.get("dynamic_validation")
    dynamic = _as_object(dynamic_any, path="verified_chain.dynamic_validation")
    dynamic_bundle_dir = _require_str(
        dynamic, "bundle_dir", path="verified_chain.dynamic_validation"
    )
    dynamic_dir_candidate = _validate_linked_path(
        run_dir,
        dynamic_bundle_dir,
        field_path="verified_chain.dynamic_validation.bundle_dir",
        missing_reason="missing_dynamic_bundle",
    )
    if not dynamic_dir_candidate.is_dir():
        raise VerificationError(
            "missing_dynamic_bundle",
            "verified_chain.dynamic_validation.bundle_dir must point to directory",
        )
    _ = _require_bool(
        dynamic, "isolation_verified", path="verified_chain.dynamic_validation"
    )
    _ = _validate_evidence_refs(
        run_dir,
        dynamic.get("evidence_refs"),
        field_path="verified_chain.dynamic_validation.evidence_refs",
        missing_reason="missing_dynamic_bundle",
    )

    verdict_any = contract.get("verdict")
    verdict = _as_object(verdict_any, path="verified_chain.verdict")
    state = _require_str(verdict, "state", path="verified_chain.verdict")
    if state not in _VERDICT_STATES:
        raise VerificationError(
            "invalid_contract",
            "verified_chain.verdict.state must be one of "
            + ", ".join(sorted(_VERDICT_STATES)),
        )
    reason_codes_any = verdict.get("reason_codes")
    if not isinstance(reason_codes_any, list) or not reason_codes_any:
        raise VerificationError(
            "invalid_contract",
            "verified_chain.verdict.reason_codes must be non-empty list",
        )
    reason_codes: list[str] = []
    for idx, code_any in enumerate(cast(list[object], reason_codes_any)):
        if not isinstance(code_any, str):
            raise VerificationError(
                "invalid_contract",
                f"verified_chain.verdict.reason_codes[{idx}] must be string",
            )
        reason_codes.append(code_any)
    _validate_reason_codes(state, reason_codes)
    _ = _validate_evidence_refs(
        run_dir,
        verdict.get("evidence_refs"),
        field_path="verified_chain.verdict.evidence_refs",
        missing_reason="missing_required_artifact",
    )

    attempts_any = contract.get("attempts")
    if not isinstance(attempts_any, list) or not attempts_any:
        raise VerificationError(
            "invalid_contract", "verified_chain.attempts must be non-empty list"
        )
    attempts = cast(list[object], attempts_any)
    pass_attempt_count = 0
    for idx, attempt_any in enumerate(attempts):
        attempt = _as_object(attempt_any, path=f"verified_chain.attempts[{idx}]")
        _ = _require_int(attempt, "attempt", path=f"verified_chain.attempts[{idx}]")
        attempt_state = _require_str(
            attempt, "status", path=f"verified_chain.attempts[{idx}]"
        )
        if attempt_state not in _ATTEMPT_STATES:
            raise VerificationError(
                "invalid_contract",
                f"verified_chain.attempts[{idx}].status must be one of {sorted(_ATTEMPT_STATES)}",
            )
        if attempt_state == "pass":
            pass_attempt_count += 1

        bundle_dir = _require_str(
            attempt, "bundle_dir", path=f"verified_chain.attempts[{idx}]"
        )
        bundle_candidate = _validate_linked_path(
            run_dir,
            bundle_dir,
            field_path=f"verified_chain.attempts[{idx}].bundle_dir",
            missing_reason="missing_exploit_bundle",
        )
        if not bundle_candidate.is_dir():
            raise VerificationError(
                "missing_exploit_bundle",
                f"verified_chain.attempts[{idx}].bundle_dir must point to directory",
            )

        attempt_started = _require_str(
            attempt, "started_at", path=f"verified_chain.attempts[{idx}]"
        )
        attempt_finished = _require_str(
            attempt, "finished_at", path=f"verified_chain.attempts[{idx}]"
        )
        _validate_iso8601(
            attempt_started,
            field_path=f"verified_chain.attempts[{idx}].started_at",
        )
        _validate_iso8601(
            attempt_finished,
            field_path=f"verified_chain.attempts[{idx}].finished_at",
        )
        _ = _validate_evidence_refs(
            run_dir,
            attempt.get("evidence_refs"),
            field_path=f"verified_chain.attempts[{idx}].evidence_refs",
            missing_reason="missing_exploit_bundle",
        )

    if state == "pass":
        if len(attempts) != 3:
            raise VerificationError(
                "invalid_contract",
                "pass verdict requires exactly 3 attempts",
            )
        if pass_attempt_count != 3:
            raise VerificationError(
                "invalid_contract",
                "pass verdict requires 3/3 passing attempts",
            )

    _ = _validate_evidence_refs(
        run_dir,
        contract.get("evidence_refs"),
        field_path="verified_chain.evidence_refs",
        missing_reason="missing_required_artifact",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify verified_chain contract and evidence bundle paths."
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
        _verify_verified_chain(run_dir)
    except VerificationError as exc:
        print(f"[FAIL] {exc.reason_code}: {exc.detail}")
        return 1
    except Exception as exc:
        print(f"[FAIL] invalid_contract: unexpected verifier error: {exc}")
        return 1

    print(f"[OK] verified_chain contract verified: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
