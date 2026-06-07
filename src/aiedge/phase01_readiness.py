from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .aeg_readiness import build_readiness_report
from .exploit_rag import evaluate_pattern_evidence

DEFAULT_REPORT = Path("docs/scout_zero_day_aeg_develop_plan.md")
DEFAULT_AEG_READINESS = Path("docs/pov/aeg_platform_readiness.json")
DEFAULT_REAL_PAIR = Path("docs/pov/netgear-r7000-cve-2017-5521_real_pair.json")
DEFAULT_MIN_REAL_PAIRS = 1
DEFAULT_PHASE1_TARGET_REAL_PAIRS = 3

_REPORT_REQUIRED_LABELS = {
    "report_date": "작성일: 2026-06-07 KST",
    "update_date": "작성/반영일: 2026-06-07 KST",
    "version_name": "scout-firmware 3.0.0rc1",
    "version_tag": "v3.0.0-rc1",
    "commit": "a7891f0",
    "evidence_tier_s0": "S0",
    "evidence_tier_s1": "S1",
    "stale_artifact_policy": "stale",
    "promotion_gate": "승격 게이트",
    "phase0": "P0 Evidence Ledger",
    "phase1": "P1 Pair Benchmark Floor",
}


@dataclass(frozen=True)
class ArtifactSpec:
    path: Path
    tier: str
    role: str
    release_claim: bool


def _repo_root(path: Path | None = None) -> Path:
    if path is not None:
        return path
    return Path(__file__).resolve().parents[2]


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _sha256(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _git(repo_root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _package_version(repo_root: Path) -> str:
    try:
        pyproject = (repo_root / "pyproject.toml").read_text(encoding="utf-8")
    except Exception:
        return ""
    in_project = False
    for line in pyproject.splitlines():
        stripped = line.strip()
        if stripped == "[project]":
            in_project = True
            continue
        if in_project and stripped.startswith("["):
            return ""
        if in_project:
            match = re.match(r'version\s*=\s*"([^"]+)"', stripped)
            if match:
                return match.group(1)
    return ""


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_repo_metadata(repo_root: Path | None = None, *, generated_at: str | None = None) -> dict[str, Any]:
    root = _repo_root(repo_root)
    commit = _git(root, "rev-parse", "HEAD")
    return {
        "generated_at": generated_at or _now(),
        "repo_root": str(root),
        "branch": _git(root, "branch", "--show-current"),
        "commit": commit,
        "commit_date": _git(root, "show", "-s", "--format=%cI", commit) if commit else "",
        "package": "scout-firmware",
        "package_version": _package_version(root),
    }


def build_artifact_entry(repo_root: Path, spec: ArtifactSpec) -> dict[str, Any]:
    path = spec.path if spec.path.is_absolute() else repo_root / spec.path
    try:
        rel = path.resolve(strict=False).relative_to(repo_root.resolve(strict=False)).as_posix()
    except ValueError:
        rel = str(spec.path)
    exists = path.is_file()
    tier = spec.tier.upper()
    release_claim_allowed = spec.release_claim and tier in {"S0", "S1"} and exists
    entry = {
        "path": rel,
        "role": spec.role,
        "evidence_tier": tier,
        "release_claim": bool(spec.release_claim),
        "release_claim_allowed": release_claim_allowed,
        "exists": exists,
        "sha256": _sha256(path) if exists else None,
    }
    if tier in {"S2", "S3"} and spec.release_claim:
        entry["blocker"] = "stale_or_unrevalidated_evidence_cannot_support_release_claim"
    if not exists:
        entry["blocker"] = "artifact_missing"
    return entry


def build_report_evidence_audit(
    *,
    repo_root: Path | None = None,
    report_path: Path = DEFAULT_REPORT,
    required_labels: dict[str, str] | None = None,
) -> dict[str, Any]:
    root = _repo_root(repo_root)
    path = report_path if report_path.is_absolute() else root / report_path
    labels = dict(required_labels or _REPORT_REQUIRED_LABELS)
    checks: list[dict[str, Any]] = []
    text = ""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        pass
    checks.append(
        {
            "name": "report_exists",
            "passed": path.is_file(),
            "path": str(report_path),
            "message": "Phase 0/1 report must exist.",
        }
    )
    for name, needle in labels.items():
        checks.append(
            {
                "name": f"report_contains_{name}",
                "passed": bool(text) and needle in text,
                "path": str(report_path),
                "needle": needle,
                "message": f"Report must contain {name} marker.",
            }
        )
    passed = all(check["passed"] is True for check in checks)
    return {
        "schema_version": "scout-report-evidence-audit-v1",
        "report": str(report_path),
        "passed": passed,
        "verdict": "pass" if passed else "fail",
        "checks": checks,
        "artifact": build_artifact_entry(
            root,
            ArtifactSpec(
                path=report_path,
                tier="S0",
                role="phase0_phase1_report",
                release_claim=False,
            ),
        ),
    }


def _promotable_real_pair_rows(repo_root: Path) -> list[dict[str, Any]]:
    pattern_report = evaluate_pattern_evidence().to_json()
    rows: list[dict[str, Any]] = []
    patterns = pattern_report.get("patterns")
    if not isinstance(patterns, list):
        return rows
    for pattern in patterns:
        if not isinstance(pattern, dict):
            continue
        pattern_id = str(pattern.get("id", ""))
        evidence_items = pattern.get("validation_evidence")
        if not isinstance(evidence_items, list):
            continue
        for item in evidence_items:
            if not isinstance(item, dict) or item.get("kind") != "real_firmware_pair":
                continue
            artifact_raw = item.get("artifact")
            artifact_path = repo_root / str(artifact_raw) if isinstance(artifact_raw, str) else None
            payload = _load_json(artifact_path) if artifact_path is not None else None
            row: dict[str, Any] = {
                "pattern_id": pattern_id,
                "evidence_id": item.get("id"),
                "artifact": artifact_raw,
                "exists": artifact_path.is_file() if artifact_path is not None else False,
                "promotable": bool(payload and payload.get("promotable_real_firmware_pair") is True),
                "verdict": payload.get("verdict") if payload else "missing",
                "pair_id": payload.get("pair_id") if payload else None,
                "cve_id": payload.get("cve_id") if payload else item.get("cve"),
            }
            if payload:
                runs = payload.get("runs") if isinstance(payload.get("runs"), dict) else {}
                vuln = runs.get("vulnerable") if isinstance(runs, dict) else {}
                patched = runs.get("patched") if isinstance(runs, dict) else {}
                row.update(
                    {
                        "vulnerable_gate_passed": isinstance(vuln, dict)
                        and vuln.get("gate_passed") is True,
                        "control_gate_passed": isinstance(patched, dict)
                        and patched.get("gate_passed") is True,
                        "control_dynamic_failed_checks": patched.get("dynamic_failed_checks", [])
                        if isinstance(patched, dict)
                        else [],
                    }
                )
            rows.append(row)
    return rows


def build_phase01_readiness(
    *,
    repo_root: Path | None = None,
    report_path: Path = DEFAULT_REPORT,
    min_real_firmware_pairs: int = DEFAULT_MIN_REAL_PAIRS,
    phase1_target_real_pairs: int = DEFAULT_PHASE1_TARGET_REAL_PAIRS,
    generated_at: str | None = None,
) -> dict[str, Any]:
    root = _repo_root(repo_root)
    meta = build_repo_metadata(root, generated_at=generated_at)
    report_audit = build_report_evidence_audit(repo_root=root, report_path=report_path)
    aeg_readiness = build_readiness_report(
        repo_root=root,
        min_real_firmware_pairs=min_real_firmware_pairs,
    )
    pair_rows = _promotable_real_pair_rows(root)
    promotable_pair_count = sum(1 for row in pair_rows if row.get("promotable") is True)

    artifact_specs = [
        ArtifactSpec(report_path, "S0", "phase0_phase1_report", False),
        ArtifactSpec(DEFAULT_AEG_READINESS, "S1", "aeg_platform_readiness", True),
        ArtifactSpec(DEFAULT_REAL_PAIR, "S1", "stable_real_firmware_pair", True),
    ]
    artifacts = [build_artifact_entry(root, spec) for spec in artifact_specs]
    stale_release_blockers = [
        entry for entry in artifacts if entry.get("release_claim") and not entry.get("release_claim_allowed")
    ]

    phase0_checks = [
        {
            "name": "report_evidence_audit_passed",
            "passed": report_audit.get("passed") is True,
            "message": "Report includes mandatory date/version/commit/evidence-tier markers.",
        },
        {
            "name": "release_artifacts_exist_and_are_s1_or_better",
            "passed": not stale_release_blockers,
            "message": "Release-facing artifacts must exist and be S0/S1 only.",
            "blocked_artifacts": stale_release_blockers,
        },
    ]
    phase1_checks = [
        {
            "name": "aeg_platform_readiness_passed",
            "passed": aeg_readiness.get("ready") is True,
            "message": "AEG platform readiness must pass with curated pattern and real-pair evidence.",
        },
        {
            "name": "minimum_real_pair_floor_met",
            "passed": promotable_pair_count >= min_real_firmware_pairs,
            "message": f"At least {min_real_firmware_pairs} promotable real pair(s) must exist.",
            "promotable_real_pairs": promotable_pair_count,
        },
        {
            "name": "phase1_scale_target_met",
            "passed": promotable_pair_count >= phase1_target_real_pairs,
            "message": (
                f"Phase 1 scale target is {phase1_target_real_pairs} promotable real pairs; "
                "this is tracked separately from the minimum Phase 2 entry floor."
            ),
            "promotable_real_pairs": promotable_pair_count,
            "target": phase1_target_real_pairs,
        },
    ]
    phase0_ready = all(check["passed"] is True for check in phase0_checks)
    phase1_minimum_ready = all(
        check["passed"] is True
        for check in phase1_checks
        if check["name"] != "phase1_scale_target_met"
    )
    phase2_entry_ready = phase0_ready and phase1_minimum_ready

    return {
        "schema_version": "scout-phase0-phase1-readiness-v1",
        "verdict": "phase2-entry-ready" if phase2_entry_ready else "blocked",
        "metadata": meta,
        "policy": {
            "min_real_firmware_pairs_for_phase2_entry": min_real_firmware_pairs,
            "phase1_scale_target_real_pairs": phase1_target_real_pairs,
            "stale_release_claim_policy": "S2/S3 artifacts may be recorded but cannot support release-facing claims.",
            "phase1_scale_target_is_blocking": False,
        },
        "phase0": {
            "ready": phase0_ready,
            "checks": phase0_checks,
            "report_audit": report_audit,
            "artifacts": artifacts,
        },
        "phase1": {
            "minimum_ready": phase1_minimum_ready,
            "scale_target_met": promotable_pair_count >= phase1_target_real_pairs,
            "checks": phase1_checks,
            "promotable_real_pair_count": promotable_pair_count,
            "pair_matrix": pair_rows,
            "aeg_readiness": aeg_readiness,
        },
        "phase2_entry_ready": phase2_entry_ready,
        "blocked_reasons": [
            check["name"]
            for check in [*phase0_checks, *phase1_checks]
            if check["passed"] is not True and check["name"] != "phase1_scale_target_met"
        ],
    }


def write_phase01_readiness(path: Path, payload: dict[str, Any]) -> None:
    _write_json(path, payload)
