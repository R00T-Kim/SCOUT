from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .exploit_rag import evaluate_pattern_evidence

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DYNAMIC_PROOF_CHECKS = {
    "autopoc_runner_pass",
    "poc_validation_reproducible",
    "verified_chain_pass",
}


def write_readiness_report(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def format_readiness_report(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _resolve_artifact(repo_root: Path, artifact: object) -> Path | None:
    if not isinstance(artifact, str) or not artifact:
        return None
    return repo_root / artifact


def _is_repo_relative(repo_root: Path, artifact: object) -> bool:
    if not isinstance(artifact, str) or not artifact:
        return False
    path = Path(artifact)
    if path.is_absolute():
        return False
    try:
        (repo_root / path).resolve(strict=False).relative_to(repo_root.resolve(strict=False))
    except ValueError:
        return False
    return True


def _as_int(value: object, default: int = 0) -> int:
    return value if isinstance(value, int) else default


def _check(name: str, passed: bool, message: str, **details: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"name": name, "passed": passed, "message": message}
    payload.update(details)
    return payload


def _real_evidence_items(pattern_report: dict[str, object]) -> list[tuple[str, dict[str, object]]]:
    items: list[tuple[str, dict[str, object]]] = []
    patterns = pattern_report.get("patterns")
    if not isinstance(patterns, list):
        return items
    for pattern in patterns:
        if not isinstance(pattern, dict):
            continue
        pattern_id = str(pattern.get("id", ""))
        validation = pattern.get("validation_evidence")
        if not isinstance(validation, list):
            continue
        for item in validation:
            if isinstance(item, dict) and item.get("kind") == "real_firmware_pair":
                items.append((pattern_id, item))
    return items


def _artifact_report_check(
    *,
    repo_root: Path,
    pattern_id: str,
    evidence: dict[str, object],
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    artifact_path = _resolve_artifact(repo_root, evidence.get("artifact"))
    artifact_label = str(evidence.get("artifact", ""))
    if artifact_path is None:
        return [
            _check(
                "real_firmware_evidence_has_stable_artifact",
                False,
                "real_firmware_pair evidence must reference a stable artifact path.",
                pattern_id=pattern_id,
            )
        ]
    if not _is_repo_relative(repo_root, evidence.get("artifact")):
        return [
            _check(
                "real_firmware_evidence_artifact_repo_relative",
                False,
                "real_firmware_pair stable artifact must be a repository-relative path under repo_root.",
                pattern_id=pattern_id,
                artifact=artifact_label,
            )
        ]

    if not artifact_path.is_file():
        return [
            _check(
                "real_firmware_evidence_artifact_exists",
                False,
                "real_firmware_pair stable artifact is missing.",
                pattern_id=pattern_id,
                artifact=artifact_label,
            )
        ]

    try:
        report_any = json.loads(artifact_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [
            _check(
                "real_firmware_evidence_artifact_valid_json",
                False,
                "real_firmware_pair stable artifact is not valid JSON.",
                pattern_id=pattern_id,
                artifact=artifact_label,
                error=str(exc),
            )
        ]
    if not isinstance(report_any, dict):
        return [
            _check(
                "real_firmware_evidence_artifact_contract",
                False,
                "real_firmware_pair stable artifact must be a JSON object.",
                pattern_id=pattern_id,
                artifact=artifact_label,
            )
        ]
    report = report_any

    checks.append(
        _check(
            "real_firmware_evidence_artifact_promotable",
            report.get("schema_version") == "real-firmware-pair-aeg-gate-v1"
            and report.get("promotable_real_firmware_pair") is True
            and report.get("verdict") == "promotable",
            "stable real firmware pair report must be promotable and use the expected schema.",
            pattern_id=pattern_id,
            artifact=artifact_label,
            verdict=report.get("verdict"),
        )
    )
    checks.append(
        _check(
            "real_firmware_evidence_pattern_binding",
            report.get("pattern_id") in {None, pattern_id}
            and evidence.get("target_family") in {None, pattern_id},
            "stable report and pattern-card evidence must bind to the same pattern family.",
            pattern_id=pattern_id,
            artifact=artifact_label,
            report_pattern_id=report.get("pattern_id"),
            evidence_target_family=evidence.get("target_family"),
        )
    )

    firmware = report.get("firmware")
    if not isinstance(firmware, dict):
        firmware = {}
    vulnerable_fw = firmware.get("vulnerable")
    patched_fw = firmware.get("patched")
    vulnerable_sha = vulnerable_fw.get("expected_sha256") if isinstance(vulnerable_fw, dict) else None
    patched_sha = patched_fw.get("expected_sha256") if isinstance(patched_fw, dict) else None
    checks.append(
        _check(
            "real_firmware_evidence_sha_binding",
            vulnerable_sha == evidence.get("vulnerable_firmware_sha256")
            and patched_sha == evidence.get("control_firmware_sha256")
            and (not isinstance(vulnerable_fw, dict) or vulnerable_fw.get("sha256_match") is True)
            and (not isinstance(patched_fw, dict) or patched_fw.get("sha256_match") is True),
            "pattern-card firmware hashes must match the stable pair report and local firmware status must be hash-matched when present.",
            pattern_id=pattern_id,
            artifact=artifact_label,
        )
    )

    runs = report.get("runs")
    if not isinstance(runs, dict):
        runs = {}
    vulnerable_run = runs.get("vulnerable")
    patched_run = runs.get("patched")
    dynamic_failed: list[object] = []
    if isinstance(patched_run, dict):
        raw_dynamic = patched_run.get("dynamic_failed_checks")
        if isinstance(raw_dynamic, list):
            dynamic_failed = raw_dynamic
    checks.append(
        _check(
            "real_firmware_evidence_fail_closed_pair",
            isinstance(vulnerable_run, dict)
            and vulnerable_run.get("gate_passed") is True
            and isinstance(patched_run, dict)
            and patched_run.get("gate_passed") is False
            and bool(set(str(item) for item in dynamic_failed) & _DYNAMIC_PROOF_CHECKS),
            "vulnerable firmware must pass and patched/control firmware must fail a dynamic proof check.",
            pattern_id=pattern_id,
            artifact=artifact_label,
            patched_dynamic_failed_checks=dynamic_failed,
        )
    )
    return checks


def build_readiness_report(
    *,
    repo_root: Path = _REPO_ROOT,
    patterns_dir: Path | None = None,
    require_all_patterns: bool = True,
    min_real_firmware_pairs: int = 1,
) -> dict[str, Any]:
    pattern_evidence = evaluate_pattern_evidence(patterns_dir).to_json()
    checks: list[dict[str, Any]] = []
    pattern_count = _as_int(pattern_evidence.get("pattern_count"))
    missing_pair_evidence = pattern_evidence.get("missing_pair_evidence")
    if not isinstance(missing_pair_evidence, list):
        missing_pair_evidence = []
    real_count = _as_int(pattern_evidence.get("real_firmware_pair_validated"))

    checks.append(
        _check(
            "curated_pattern_cards_present",
            pattern_count > 0,
            "Exploit Pattern RAG must contain curated pattern cards.",
            pattern_count=pattern_count,
        )
    )
    checks.append(
        _check(
            "curated_patterns_pair_validated",
            (not require_all_patterns) or not missing_pair_evidence,
            "Every curated pattern card must have vulnerable/control pair evidence for platform readiness.",
            missing_pair_evidence=missing_pair_evidence,
            require_all_patterns=require_all_patterns,
        )
    )
    checks.append(
        _check(
            "real_firmware_pair_floor",
            real_count >= min_real_firmware_pairs,
            "At least one known-vulnerable/patched real firmware pair must be validated.",
            real_firmware_pair_validated=real_count,
            min_real_firmware_pairs=min_real_firmware_pairs,
        )
    )

    real_items = _real_evidence_items(pattern_evidence)
    checks.append(
        _check(
            "real_firmware_pair_evidence_items_present",
            len(real_items) >= min_real_firmware_pairs,
            "Pattern cards must expose real_firmware_pair evidence items, not only aggregate counters.",
            real_firmware_pair_evidence_items=len(real_items),
            min_real_firmware_pairs=min_real_firmware_pairs,
        )
    )
    for pattern_id, evidence in real_items:
        checks.extend(
            _artifact_report_check(
                repo_root=repo_root,
                pattern_id=pattern_id,
                evidence=evidence,
            )
        )

    blockers = [str(check["name"]) for check in checks if check.get("passed") is not True]
    ready = not blockers
    return {
        "schema_version": "aeg-platform-readiness-v1",
        "verdict": "platform-ready" if ready else "blocked",
        "ready": ready,
        "policy": {
            "require_all_patterns": require_all_patterns,
            "min_real_firmware_pairs": min_real_firmware_pairs,
        },
        "pattern_evidence": pattern_evidence,
        "checks": checks,
        "blocked_reasons": sorted(set(blockers)),
    }
