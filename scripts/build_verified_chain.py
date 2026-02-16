#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Callable, cast

_SCHEMA_VERSION = "verified-chain-v1"
_ISO_FALLBACK = "1970-01-01T00:00:00Z"

EvidenceVerifier = Callable[[Path], None]
StatusVerifier = Callable[[Path], object]
VerifiedChainVerifier = Callable[[Path], None]


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise BuildError("invalid_contract", f"unable to load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BuildError(ValueError):
    reason_code: str
    detail: str

    def __init__(self, reason_code: str, detail: str) -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}: {detail}")


def _utc_now() -> str:
    return (
        datetime.now(tz=timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _load_json(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        raw = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, object] = {}
    for key, value in cast(dict[object, object], raw).items():
        out[str(key)] = value
    return out


def _is_iso8601(value: str) -> bool:
    if not value:
        return False
    try:
        _ = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return False
    return True


def _pick_iso(*values: object) -> str:
    for value in values:
        if isinstance(value, str) and _is_iso8601(value):
            return value
    return _ISO_FALLBACK


def _sha256_like(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    s = value.strip().lower()
    if len(s) != 64:
        return None
    if not all(ch in "0123456789abcdef" for ch in s):
        return None
    return s


def _as_rel_path(run_dir: Path, value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    candidate = Path(value)
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(run_dir.resolve()).as_posix()
        except Exception:
            return None
    rel = candidate.as_posix()
    if rel.startswith("/"):
        return None
    if rel.startswith("../") or rel == "..":
        return None
    resolved = (run_dir / rel).resolve()
    try:
        _ = resolved.relative_to(run_dir.resolve())
    except ValueError:
        return None
    return rel


def _existing_refs(run_dir: Path, refs: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for ref in refs:
        if not ref or ref in seen:
            continue
        abs_path = (run_dir / ref).resolve()
        try:
            _ = abs_path.relative_to(run_dir.resolve())
        except ValueError:
            continue
        if abs_path.exists():
            out.append(ref)
            seen.add(ref)
    return out


def _read_dynamic_context(
    run_dir: Path,
) -> tuple[dict[str, object], dict[str, object], list[str], set[str]]:
    summary = _load_json(
        run_dir / "stages" / "dynamic_validation" / "dynamic_validation.json"
    )
    stage = _load_json(run_dir / "stages" / "dynamic_validation" / "stage.json")

    refs: list[str] = ["stages/dynamic_validation/dynamic_validation.json"]
    artifacts_any = stage.get("artifacts")
    if isinstance(artifacts_any, list):
        for item in cast(list[object], artifacts_any):
            if not isinstance(item, dict):
                continue
            path_raw = cast(dict[str, object], item).get("path")
            rel = _as_rel_path(run_dir, path_raw)
            if rel:
                refs.append(rel)

    for key in ("boot", "network", "probes", "isolation", "fallback"):
        obj_any = summary.get(key)
        if not isinstance(obj_any, dict):
            continue
        obj = cast(dict[str, object], obj_any)
        for value in obj.values():
            rel = _as_rel_path(run_dir, value)
            if rel:
                refs.append(rel)

    limitations: set[str] = set()
    lim_any = summary.get("limitations")
    if isinstance(lim_any, list):
        for item in cast(list[object], lim_any):
            if isinstance(item, str) and item:
                limitations.add(item)

    return summary, stage, _existing_refs(run_dir, refs), limitations


def _collect_attempts(run_dir: Path) -> tuple[list[dict[str, object]], list[str], bool]:
    attempts: list[dict[str, object]] = []
    evidence_refs: list[str] = []

    exploits_dir = run_dir / "exploits"
    if not exploits_dir.is_dir():
        return attempts, evidence_refs, False

    chain_dirs = sorted(
        [
            p
            for p in exploits_dir.iterdir()
            if p.is_dir() and p.name.startswith("chain_")
        ],
        key=lambda p: p.name,
    )
    found_bundle = False
    for chain_dir in chain_dirs:
        bundle_path = chain_dir / "evidence_bundle.json"
        if not bundle_path.is_file():
            continue
        found_bundle = True
        bundle = _load_json(bundle_path)
        bundle_rel = bundle_path.resolve().relative_to(run_dir.resolve()).as_posix()
        evidence_refs.append(bundle_rel)

        bundle_attempts_any = bundle.get("attempts")
        if not isinstance(bundle_attempts_any, list):
            continue

        bundle_dir_rel = chain_dir.resolve().relative_to(run_dir.resolve()).as_posix()
        for idx, item in enumerate(cast(list[object], bundle_attempts_any)):
            if not isinstance(item, dict):
                continue
            attempt = cast(dict[str, object], item)

            status_raw = attempt.get("status")
            status = "inconclusive"
            if status_raw == "pass":
                status = "pass"
            elif status_raw == "fail":
                status = "fail"

            ts = _pick_iso(attempt.get("timestamp"), bundle.get("generated_at"))
            attempt_index = idx + 1
            from_bundle = attempt.get("attempt")
            if isinstance(from_bundle, int) and from_bundle > 0:
                attempt_index = from_bundle

            refs = [bundle_rel]
            log_rel = f"{bundle_dir_rel}/execution_log_{attempt_index}.txt"
            capture_rel = f"{bundle_dir_rel}/network_capture.pcap"
            refs.extend([log_rel, capture_rel])
            refs = _existing_refs(run_dir, refs)
            if not refs:
                refs = [bundle_rel]

            attempts.append(
                {
                    "attempt": len(attempts) + 1,
                    "status": status,
                    "bundle_dir": bundle_dir_rel,
                    "started_at": ts,
                    "finished_at": ts,
                    "evidence_refs": refs,
                }
            )
            evidence_refs.extend(refs)

    return attempts, _existing_refs(run_dir, evidence_refs), found_bundle


def _extract_verifier_reason(exc: Exception) -> str:
    reason = getattr(exc, "reason_code", None)
    if isinstance(reason, str) and reason:
        return reason
    return "invalid_contract"


def _status_3_of_3(attempts: list[dict[str, object]]) -> bool:
    return len(attempts) == 3 and all(item.get("status") == "pass" for item in attempts)


def _write_contract(path: Path, contract: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(
        json.dumps(contract, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def build_verified_chain(run_dir: Path) -> tuple[Path, str, list[str]]:
    if not run_dir.is_dir():
        raise BuildError(
            "missing_required_artifact", f"run_dir is not a directory: {run_dir}"
        )

    scripts_dir = Path(__file__).resolve().parent
    evidence_mod = _load_module(
        "verify_run_dir_evidence_only", scripts_dir / "verify_run_dir_evidence_only.py"
    )
    network_mod = _load_module(
        "verify_network_isolation", scripts_dir / "verify_network_isolation.py"
    )
    meaningful_mod = _load_module(
        "verify_exploit_meaningfulness",
        scripts_dir / "verify_exploit_meaningfulness.py",
    )
    verified_chain_mod = _load_module(
        "verify_verified_chain", scripts_dir / "verify_verified_chain.py"
    )

    evidence_fn_obj = getattr(evidence_mod, "verify_run_dir_evidence_only", None)
    network_fn_obj = getattr(network_mod, "_verify_network_isolation", None)
    meaningful_fn_obj = getattr(meaningful_mod, "_verify_exploit_meaningfulness", None)
    verified_fn_obj = getattr(verified_chain_mod, "_verify_verified_chain", None)
    verified_error_obj = getattr(verified_chain_mod, "VerificationError", Exception)

    if not callable(evidence_fn_obj):
        raise BuildError(
            "invalid_contract",
            "missing verifier function: verify_run_dir_evidence_only",
        )
    if not callable(network_fn_obj):
        raise BuildError(
            "invalid_contract", "missing verifier function: _verify_network_isolation"
        )
    if not callable(meaningful_fn_obj):
        raise BuildError(
            "invalid_contract",
            "missing verifier function: _verify_exploit_meaningfulness",
        )
    if not callable(verified_fn_obj):
        raise BuildError(
            "invalid_contract", "missing verifier function: _verify_verified_chain"
        )
    if not isinstance(verified_error_obj, type) or not issubclass(
        verified_error_obj, Exception
    ):
        verified_error_obj = Exception

    verify_run_dir_evidence_only = cast(EvidenceVerifier, evidence_fn_obj)
    verify_network_isolation = cast(StatusVerifier, network_fn_obj)
    verify_exploit_meaningfulness = cast(StatusVerifier, meaningful_fn_obj)
    verify_verified_chain = cast(VerifiedChainVerifier, verified_fn_obj)
    verified_chain_error = cast(type[Exception], verified_error_obj)

    verified_dir = run_dir / "verified_chain"
    verified_dir.mkdir(parents=True, exist_ok=True)

    manifest = _load_json(run_dir / "manifest.json")
    dynamic_summary, dynamic_stage, dynamic_refs, dynamic_limitations = (
        _read_dynamic_context(run_dir)
    )
    attempts, exploit_refs, has_bundle = _collect_attempts(run_dir)

    generated_at = _utc_now()
    run_id = (
        cast(str, manifest.get("run_id"))
        if isinstance(manifest.get("run_id"), str)
        else run_dir.name
    )
    firmware_sha = (
        _sha256_like(manifest.get("analyzed_input_sha256"))
        or _sha256_like(manifest.get("input_sha256"))
        or _sha256_like(manifest.get("source_input_sha256"))
        or "0" * 64
    )
    firmware_profile = (
        cast(str, manifest.get("profile"))
        if isinstance(manifest.get("profile"), str)
        and cast(str, manifest.get("profile"))
        else "unknown"
    )

    versions_any = dynamic_summary.get("versions")
    versions = (
        cast(dict[str, object], versions_any) if isinstance(versions_any, dict) else {}
    )
    firmae_any = versions.get("firmae")
    firmae = cast(dict[str, object], firmae_any) if isinstance(firmae_any, dict) else {}
    tools_any = versions.get("tools")
    tools = cast(dict[str, object], tools_any) if isinstance(tools_any, dict) else {}

    stage_started = dynamic_stage.get("started_at")
    stage_finished = dynamic_stage.get("finished_at")
    manifest_created = manifest.get("created_at")
    started_at = _pick_iso(stage_started, manifest_created, generated_at)
    finished_at = _pick_iso(stage_finished, generated_at)

    verifier_failures: dict[str, str] = {}
    isolation_verified = False
    try:
        verify_run_dir_evidence_only(run_dir)
    except Exception as exc:
        verifier_failures["evidence_only"] = _extract_verifier_reason(exc)

    try:
        _ = verify_network_isolation(run_dir)
        isolation_verified = True
    except Exception as exc:
        verifier_failures["network_isolation"] = _extract_verifier_reason(exc)

    try:
        _ = verify_exploit_meaningfulness(run_dir)
    except Exception as exc:
        verifier_failures["exploit_meaningfulness"] = _extract_verifier_reason(exc)

    repro_3_of_3 = _status_3_of_3(attempts)

    reason_codes: set[str] = set()
    deterministic_fail = False
    missing_evidence_only = False

    network_reason = verifier_failures.get("network_isolation")
    if network_reason == "egress_violation":
        deterministic_fail = True
        reason_codes.add("isolation_violation")
    elif network_reason in {
        "missing_required_artifact",
        "pcap_parse_unavailable",
        "invalid_contract",
    }:
        deterministic_fail = True
        reason_codes.add("missing_required_artifact")
    elif network_reason == "missing_dynamic_bundle":
        missing_evidence_only = True
        reason_codes.add("missing_dynamic_bundle")

    evidence_reason = verifier_failures.get("evidence_only")
    if evidence_reason in {
        "disallowed_extension",
        "executable_file",
        "symlink_escape",
        "invalid_contract",
    }:
        deterministic_fail = True
        reason_codes.add("invalid_contract")
    elif evidence_reason == "missing_required_artifact":
        deterministic_fail = True
        reason_codes.add("missing_required_artifact")

    meaningful_reason = verifier_failures.get("exploit_meaningfulness")
    if meaningful_reason in {
        "marker_only_evidence",
        "proof_type_invalid",
        "repro_incomplete",
        "pcap_missing",
    }:
        deterministic_fail = True
        reason_codes.add("poc_repro_failed")
    elif meaningful_reason == "missing_exploit_bundle" or not has_bundle:
        missing_evidence_only = True
        reason_codes.add("missing_exploit_bundle")
    elif meaningful_reason:
        deterministic_fail = True
        reason_codes.add("poc_repro_failed")

    if not repro_3_of_3:
        if has_bundle:
            deterministic_fail = True
            reason_codes.add("poc_repro_failed")
        else:
            missing_evidence_only = True
            reason_codes.add("missing_exploit_bundle")

    if "boot_timeout" in dynamic_limitations:
        missing_evidence_only = True
        reason_codes.add("boot_timeout")
    if "boot_flaky" in dynamic_limitations:
        missing_evidence_only = True
        reason_codes.add("boot_flaky")

    all_verifiers_pass = not verifier_failures
    if (
        all_verifiers_pass
        and isolation_verified
        and repro_3_of_3
        and not dynamic_limitations
    ):
        state = "pass"
        reason_codes = {"repro_3_of_3", "isolation_verified"}
    elif deterministic_fail:
        state = "fail"
        if not reason_codes:
            reason_codes.add("invalid_contract")
    else:
        state = "inconclusive"
        if not reason_codes:
            if missing_evidence_only:
                reason_codes.add("missing_required_artifact")
            else:
                reason_codes.add("boot_flaky")

    if state == "pass":
        reason_codes = {"repro_3_of_3", "isolation_verified"}
    elif (
        state == "inconclusive"
        and "boot_timeout" not in reason_codes
        and "boot_flaky" not in reason_codes
    ):
        if (
            "missing_dynamic_bundle" not in reason_codes
            and "missing_exploit_bundle" not in reason_codes
        ):
            reason_codes.add("missing_required_artifact")

    if not attempts:
        attempt_ref = dynamic_refs[0] if dynamic_refs else "manifest.json"
        fallback_ref = (
            attempt_ref if (run_dir / attempt_ref).exists() else "manifest.json"
        )
        attempts = [
            {
                "attempt": 1,
                "status": "inconclusive",
                "bundle_dir": "exploits",
                "started_at": started_at,
                "finished_at": finished_at,
                "evidence_refs": [fallback_ref],
            }
        ]

    top_refs = _existing_refs(
        run_dir,
        [
            "manifest.json",
            "stages/dynamic_validation/dynamic_validation.json",
            *dynamic_refs,
            *exploit_refs,
        ],
    )
    if not top_refs:
        top_refs = ["manifest.json"] if (run_dir / "manifest.json").is_file() else []
    if not top_refs:
        raise BuildError(
            "missing_required_artifact", "unable to derive top-level evidence_refs"
        )

    verdict_refs = _existing_refs(run_dir, [*dynamic_refs, *exploit_refs, *top_refs])
    if not verdict_refs:
        verdict_refs = list(top_refs)

    dynamic_bundle_dir = "stages/dynamic_validation"
    if not (run_dir / dynamic_bundle_dir).is_dir():
        reason_codes.add("missing_dynamic_bundle")
        if state != "fail":
            state = "inconclusive"

    contract: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "generated_at": generated_at,
        "run_id": run_id,
        "firmware": {
            "sha256": firmware_sha,
            "profile": firmware_profile,
        },
        "tool_versions": {
            "firmae_commit": cast(str, firmae.get("git_commit"))
            if isinstance(firmae.get("git_commit"), str)
            and cast(str, firmae.get("git_commit"))
            else "unknown",
            "firmae_version": cast(str, firmae.get("git_describe"))
            if isinstance(firmae.get("git_describe"), str)
            and cast(str, firmae.get("git_describe"))
            else "unknown",
            "tcpdump": cast(str, tools.get("tcpdump"))
            if isinstance(tools.get("tcpdump"), str) and cast(str, tools.get("tcpdump"))
            else "unknown",
            "iproute2": cast(str, tools.get("ip"))
            if isinstance(tools.get("ip"), str) and cast(str, tools.get("ip"))
            else "unknown",
        },
        "timestamps": {
            "started_at": started_at,
            "finished_at": finished_at,
        },
        "dynamic_validation": {
            "bundle_dir": dynamic_bundle_dir,
            "isolation_verified": isolation_verified,
            "evidence_refs": dynamic_refs if dynamic_refs else top_refs,
        },
        "verdict": {
            "state": state,
            "reason_codes": sorted(reason_codes),
            "evidence_refs": verdict_refs,
        },
        "attempts": attempts,
        "evidence_refs": top_refs,
    }

    contract_path = verified_dir / "verified_chain.json"
    _write_contract(contract_path, contract)

    try:
        verify_verified_chain(run_dir)
    except verified_chain_error as exc:
        reason_code = _extract_verifier_reason(exc)
        detail = str(exc)
        if hasattr(exc, "detail") and isinstance(getattr(exc, "detail"), str):
            detail = cast(str, getattr(exc, "detail"))
        raise BuildError(reason_code, detail) from exc
    except Exception as exc:
        raise BuildError(
            "invalid_contract", f"unexpected contract verification error: {exc}"
        ) from exc

    return contract_path, state, sorted(reason_codes)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build verified_chain/verified_chain.json from run_dir evidence and verifier policy."
    )
    _ = parser.add_argument("--run-dir", required=True, help="Path to run directory")
    args = parser.parse_args(argv)

    run_dir_raw = getattr(args, "run_dir", None)
    if not isinstance(run_dir_raw, str) or not run_dir_raw:
        print("[FAIL] invalid_contract: --run-dir must be a non-empty path")
        return 1

    run_dir = Path(run_dir_raw).resolve()
    try:
        contract_path, state, reason_codes = build_verified_chain(run_dir)
    except BuildError as exc:
        print(f"[FAIL] {exc.reason_code}: {exc.detail}")
        return 1
    except Exception as exc:
        print(f"[FAIL] invalid_contract: unexpected builder error: {exc}")
        return 1

    print(
        "[OK] built verified_chain: "
        + f"{contract_path} state={state} reason_codes={','.join(reason_codes)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
