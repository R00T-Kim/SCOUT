#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

_DEFAULT_FPR_MAX = 0.10


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _check(name: str, passed: bool, *, path: str, message: str, evidence: object = None) -> dict[str, object]:
    out: dict[str, object] = {
        "name": name,
        "passed": passed,
        "path": path,
        "message": message,
    }
    if evidence is not None:
        out["evidence"] = evidence
    return out


def evaluate_aeg_e2e_gate(
    run_dir: Path,
    *,
    fpr_max: float = _DEFAULT_FPR_MAX,
    min_runner_pass: int = 1,
) -> dict[str, object]:
    """Evaluate whether a SCOUT run proves AEG claims strongly enough.

    This gate is intentionally stricter than unit/stage-contract tests: a pass
    requires dynamic PoC validation evidence plus an FP/FPR signal. It does not
    run exploits itself; it fails closed over the artifacts produced by an
    already completed authorized lab run.
    """
    checks: list[dict[str, object]] = []

    autopoc_path = run_dir / "stages" / "exploit_autopoc" / "exploit_autopoc.json"
    autopoc = _load_json(autopoc_path)
    runner_pass = 0
    if autopoc:
        summary = autopoc.get("summary")
        if isinstance(summary, dict):
            runner_pass = _as_int(summary.get("runner_pass"))
    checks.append(
        _check(
            "autopoc_runner_pass",
            bool(autopoc) and runner_pass >= min_runner_pass,
            path=str(autopoc_path.relative_to(run_dir)),
            message=f"AutoPoC must record at least {min_runner_pass} passing lab runner attempt(s).",
            evidence={"runner_pass": runner_pass},
        )
    )

    validation_path = run_dir / "stages" / "poc_validation" / "poc_validation.json"
    validation = _load_json(validation_path)
    reason_codes: list[str] = []
    validation_status = "missing"
    if validation:
        validation_status = str(validation.get("status", "missing"))
        raw_codes = validation.get("verification_reason_codes")
        if isinstance(raw_codes, list):
            reason_codes = [str(code) for code in raw_codes]
    checks.append(
        _check(
            "poc_validation_reproducible",
            validation_status == "ok" and "repro_3_of_3" in reason_codes,
            path=str(validation_path.relative_to(run_dir)),
            message="PoC validation must pass with reproducibility evidence, not merely a generated plugin.",
            evidence={"status": validation_status, "verification_reason_codes": reason_codes},
        )
    )

    verified_chain_path = run_dir / "verified_chain" / "verified_chain.json"
    verified_chain = _load_json(verified_chain_path)
    verdict: dict[str, object] = {}
    if verified_chain and isinstance(verified_chain.get("verdict"), dict):
        verdict = dict(verified_chain["verdict"])
    vc_reason_codes = verdict.get("reason_codes") if isinstance(verdict, dict) else []
    vc_reasons = [str(code) for code in vc_reason_codes] if isinstance(vc_reason_codes, list) else []
    checks.append(
        _check(
            "verified_chain_pass",
            bool(verified_chain) and verdict.get("state") == "pass" and "isolation_verified" in vc_reasons,
            path=str(verified_chain_path.relative_to(run_dir)),
            message="Verified chain must pass with isolation evidence for a real AEG success claim.",
            evidence={"state": verdict.get("state"), "reason_codes": vc_reasons},
        )
    )

    quality_path = run_dir / "quality_metrics.json"
    quality = _load_json(quality_path)
    fpr: float | None = None
    if quality and isinstance(quality.get("overall"), dict):
        raw_fpr = quality["overall"].get("fpr")
        fpr = _as_float(raw_fpr)
    checks.append(
        _check(
            "quality_fpr_ceiling",
            fpr is not None and fpr <= fpr_max,
            path=str(quality_path.relative_to(run_dir)),
            message=f"Run-level FP/FPR evidence must show high-severity FPR <= {fpr_max}.",
            evidence={"fpr": fpr, "threshold": fpr_max},
        )
    )

    fp_path = run_dir / "stages" / "fp_verification" / "verified_alerts.json"
    fp = _load_json(fp_path)
    fp_list: list[dict[str, object]] = []
    if fp and isinstance(fp.get("verified_alerts"), list):
        fp_list = [item for item in fp["verified_alerts"] if isinstance(item, dict)]
    high_fp = [
        item
        for item in fp_list
        if str(item.get("severity", "")).lower() in {"high", "critical"}
        and str(item.get("fp_verdict", "")).upper() == "FP"
    ]
    checks.append(
        _check(
            "no_high_severity_fp_verified",
            bool(fp) and not high_fp,
            path=str(fp_path.relative_to(run_dir)),
            message="FP verification must not classify high/critical AEG findings as false positives.",
            evidence={"high_or_critical_fp_count": len(high_fp)},
        )
    )

    passed = all(bool(check["passed"]) for check in checks)
    return {
        "schema_version": "aeg-e2e-gate-v1",
        "verdict": "pass" if passed else "fail",
        "passed": passed,
        "run_dir": str(run_dir),
        "policy": {"fpr_max": fpr_max, "min_runner_pass": min_runner_pass},
        "checks": checks,
    }


def _as_int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except Exception:
        return 0


def _as_float(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except Exception:
        return None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fail-closed E2E gate for SCOUT AEG runs: dynamic proof + FP/FPR evidence."
    )
    parser.add_argument("run_dir", type=Path, help="Completed SCOUT run directory.")
    parser.add_argument("--out", type=Path, default=None, help="Optional output JSON path.")
    parser.add_argument("--fpr-max", type=float, default=_DEFAULT_FPR_MAX)
    parser.add_argument("--min-runner-pass", type=int, default=1)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    payload = evaluate_aeg_e2e_gate(
        args.run_dir,
        fpr_max=float(args.fpr_max),
        min_runner_pass=int(args.min_runner_pass),
    )
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if payload["passed"] is True else 31


if __name__ == "__main__":
    raise SystemExit(main())
