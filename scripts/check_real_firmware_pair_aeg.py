#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from aiedge.pair_eval import PairSpec, load_pairs_manifest  # noqa: E402

_DYNAMIC_PROOF_CHECKS = {
    "autopoc_runner_pass",
    "poc_validation_reproducible",
    "verified_chain_pass",
}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _load_gate() -> Any:
    script_path = Path(__file__).resolve().with_name("aeg_e2e_gate.py")
    spec = importlib.util.spec_from_file_location("aeg_e2e_gate", script_path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError("scripts/aeg_e2e_gate.py is required")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.evaluate_aeg_e2e_gate


def _sha256_file(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _firmware_status(path_text: str, expected_sha256: str) -> dict[str, Any]:
    path = Path(path_text)
    actual = _sha256_file(path)
    return {
        "path": path_text,
        "exists": path.is_file(),
        "expected_sha256": expected_sha256,
        "actual_sha256": actual,
        "sha256_match": actual == expected_sha256,
    }


def _find_pair(pairs: list[PairSpec], pair_id: str) -> PairSpec:
    for pair in pairs:
        if pair.pair_id == pair_id:
            return pair
    raise ValueError(f"pair_id not found in manifest: {pair_id}")


def _resolve_discovered_run_dir(results_dir: Path, pair_id: str, side: str) -> Path | None:
    side_root = results_dir / "runs" / pair_id / side
    latest = side_root / "latest"
    if latest.exists() or latest.is_symlink():
        try:
            return latest.resolve(strict=True)
        except OSError:
            return None
    last_run = side_root / "last_run.json"
    try:
        payload = json.loads(last_run.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    run_dir = payload.get("run_dir")
    if not isinstance(run_dir, str) or not run_dir:
        return None
    return Path(run_dir)


def _gate_checks(gate: dict[str, Any]) -> list[dict[str, Any]]:
    checks = gate.get("checks")
    return [item for item in checks if isinstance(item, dict)] if isinstance(checks, list) else []


def _failed_check_names(gate: dict[str, Any]) -> list[str]:
    failed: list[str] = []
    for check in _gate_checks(gate):
        name = check.get("name")
        if isinstance(name, str) and check.get("passed") is not True:
            failed.append(name)
    return failed


def _missing_gate_artifacts(run_dir: Path | None, gate: dict[str, Any]) -> list[str]:
    if run_dir is None:
        return ["<run_dir>"]
    missing: list[str] = []
    for check in _gate_checks(gate):
        rel = check.get("path")
        if isinstance(rel, str) and rel and not (run_dir / rel).is_file():
            missing.append(rel)
    return missing


def _missing_run_gate(side: str) -> dict[str, Any]:
    return {
        "schema_version": "aeg-e2e-gate-v1",
        "verdict": "missing",
        "passed": False,
        "run_dir": "",
        "checks": [
            {
                "name": "run_dir_present",
                "passed": False,
                "path": "<run_dir>",
                "message": f"{side} run directory was not supplied or discoverable.",
            }
        ],
    }


def _side_report(
    *,
    side: str,
    run_dir: Path | None,
    evaluate_gate: Any,
    fpr_max: float,
    min_runner_pass: int,
) -> dict[str, Any]:
    gate = (
        _missing_run_gate(side)
        if run_dir is None
        else evaluate_gate(run_dir, fpr_max=fpr_max, min_runner_pass=min_runner_pass)
    )
    failed_checks = _failed_check_names(gate)
    missing_artifacts = _missing_gate_artifacts(run_dir, gate)
    return {
        "side": side,
        "run_dir": str(run_dir) if run_dir is not None else "",
        "gate_passed": gate.get("passed") is True,
        "gate_verdict": str(gate.get("verdict", "unknown")),
        "failed_checks": failed_checks,
        "missing_gate_artifacts": missing_artifacts,
        "dynamic_failed_checks": sorted(set(failed_checks) & _DYNAMIC_PROOF_CHECKS),
        "gate": gate,
    }


def build_pair_gate_report(
    *,
    pair: PairSpec,
    vulnerable_run_dir: Path | None,
    control_run_dir: Path | None,
    fpr_max: float = 0.10,
    min_runner_pass: int = 1,
    pattern_id: str | None = None,
) -> dict[str, Any]:
    evaluate_gate = _load_gate()
    firmware = {
        "vulnerable": _firmware_status(
            pair.vulnerable.firmware_path, pair.vulnerable.sha256
        ),
        "patched": _firmware_status(pair.patched.firmware_path, pair.patched.sha256),
    }
    runs = {
        "vulnerable": _side_report(
            side="vulnerable",
            run_dir=vulnerable_run_dir,
            evaluate_gate=evaluate_gate,
            fpr_max=fpr_max,
            min_runner_pass=min_runner_pass,
        ),
        "patched": _side_report(
            side="patched",
            run_dir=control_run_dir,
            evaluate_gate=evaluate_gate,
            fpr_max=fpr_max,
            min_runner_pass=min_runner_pass,
        ),
    }

    blocked: list[str] = []
    for side, status in firmware.items():
        if not bool(status.get("exists")):
            blocked.append(f"{side}_firmware_missing")
        elif status.get("sha256_match") is not True:
            blocked.append(f"{side}_firmware_sha256_mismatch")

    vulnerable_report = runs["vulnerable"]
    control_report = runs["patched"]
    if vulnerable_report["missing_gate_artifacts"]:
        blocked.append("vulnerable_gate_artifacts_missing")
    if control_report["missing_gate_artifacts"]:
        blocked.append("patched_gate_artifacts_missing")
    if vulnerable_report["gate_passed"] is not True:
        blocked.append("vulnerable_gate_not_passed")
    if control_report["gate_passed"] is True:
        blocked.append("patched_control_unexpectedly_passed")
    if not control_report["dynamic_failed_checks"]:
        blocked.append("patched_control_dynamic_fail_closed_missing")

    promotable = not blocked
    payload: dict[str, Any] = {
        "schema_version": "real-firmware-pair-aeg-gate-v1",
        "pair_id": pair.pair_id,
        "vendor": pair.vendor,
        "model": pair.model,
        "cve_id": pair.cve_id,
        "policy": {"fpr_max": fpr_max, "min_runner_pass": min_runner_pass},
        "firmware": firmware,
        "runs": runs,
        "promotable_real_firmware_pair": promotable,
        "verdict": "promotable" if promotable else "blocked",
        "blocked_reasons": sorted(set(blocked)),
    }
    if promotable and pattern_id:
        payload["record_command"] = " ".join(
            [
                "python scripts/record_pattern_pair_evidence.py",
                pattern_id,
                "--kind real_firmware_pair",
                f"--vulnerable-run-dir {vulnerable_run_dir}",
                f"--control-run-dir {control_run_dir}",
                f"--artifact docs/pov/{pair.pair_id}_real_pair.json",
                f"--vulnerable-firmware-sha256 {pair.vulnerable.sha256}",
                f"--control-firmware-sha256 {pair.patched.sha256}",
                f"--cve {pair.cve_id}",
                "--apply",
            ]
        )
    return payload


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Fail-closed preflight for promoting an official vulnerable/patched "
            "firmware pair to real_firmware_pair AEG evidence."
        )
    )
    parser.add_argument("--pairs", type=Path, default=Path("benchmarks/pair-eval/pairs.json"))
    parser.add_argument("--pair-id", required=True)
    parser.add_argument("--results-dir", type=Path, default=Path("benchmark-results/aeg-real-pair"))
    parser.add_argument("--vulnerable-run-dir", type=Path, default=None)
    parser.add_argument("--control-run-dir", type=Path, default=None)
    parser.add_argument("--patched-run-dir", type=Path, default=None, help="Alias for --control-run-dir.")
    parser.add_argument("--pattern-id", default=None, help="Optional pattern id for an emitted record command.")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--fpr-max", type=float, default=0.10)
    parser.add_argument("--min-runner-pass", type=int, default=1)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        pairs = load_pairs_manifest(args.pairs)
        pair = _find_pair(pairs, args.pair_id)
        control_run_dir = args.control_run_dir or args.patched_run_dir
        vulnerable_run_dir = args.vulnerable_run_dir or _resolve_discovered_run_dir(
            args.results_dir, pair.pair_id, "vulnerable"
        )
        if control_run_dir is None:
            control_run_dir = _resolve_discovered_run_dir(
                args.results_dir, pair.pair_id, "patched"
            )
        payload = build_pair_gate_report(
            pair=pair,
            vulnerable_run_dir=vulnerable_run_dir,
            control_run_dir=control_run_dir,
            fpr_max=float(args.fpr_max),
            min_runner_pass=int(args.min_runner_pass),
            pattern_id=args.pattern_id,
        )
    except Exception as exc:
        payload = {
            "schema_version": "real-firmware-pair-aeg-gate-v1",
            "verdict": "error",
            "promotable_real_firmware_pair": False,
            "error": str(exc),
        }
        if args.out:
            _write_json(args.out, payload)
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", end="")
        return 48

    if args.out:
        _write_json(args.out, payload)
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", end="")
    return 0 if payload.get("promotable_real_firmware_pair") is True else 32


if __name__ == "__main__":
    raise SystemExit(main())
