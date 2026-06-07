from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .pair_eval import PairSpec, load_pairs_manifest
from .phase01_readiness import build_repo_metadata

DEFAULT_PAIRS = Path("benchmarks/pair-eval/pairs.json")
DEFAULT_PHASE1_MATRIX = Path("docs/pov/phase1_pair_matrix.json")
DEFAULT_PHASE2_DOSSIER = Path("docs/pov/phase2_novelty_dossier.json")
DEFAULT_PHASE1_SCALE_TARGET = 3

_REQUIRED_NOVELTY_FIELDS = (
    "known_cve_overlap",
    "public_advisory_overlap",
    "pattern_seed_used",
    "lineage_delta",
    "dynamic_reachability",
)
_SOURCE_TAXONOMY = (
    "config_derived_input",
    "cgi_environment",
    "nvram_getter",
    "shell_script_variable_expansion",
)
_DYNAMIC_PROOF_FAILURES = {
    "autopoc_runner_pass",
    "poc_validation_reproducible",
    "verified_chain_pass",
}
_SERVICE_OR_ENVIRONMENT_FAILURES = {
    "service_ready",
    "service_reachable",
    "emulation_ready",
    "run_dir_present",
}


def _repo_root(path: Path | None = None) -> Path:
    return path if path is not None else Path(__file__).resolve().parents[2]


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _sha256(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _rel(repo_root: Path, path: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(repo_root.resolve(strict=False)).as_posix()
    except ValueError:
        return str(path)


def _side_status(repo_root: Path, firmware_path: str, expected_sha256: str) -> dict[str, Any]:
    path = Path(firmware_path)
    abs_path = path if path.is_absolute() else repo_root / path
    exists = abs_path.is_file()
    actual_sha256 = _sha256(abs_path) if exists else None
    return {
        "path": firmware_path,
        "exists": exists,
        "expected_sha256": expected_sha256,
        "actual_sha256": actual_sha256,
        "sha256_match": actual_sha256 == expected_sha256 if exists else False,
    }


def _real_pair_reports(repo_root: Path) -> dict[str, dict[str, Any]]:
    reports: dict[str, dict[str, Any]] = {}
    for path in sorted((repo_root / "docs" / "pov").glob("*_real_pair.json")):
        payload = _load_json(path)
        if not payload or payload.get("schema_version") != "real-firmware-pair-aeg-gate-v1":
            continue
        pair_id = payload.get("pair_id")
        if isinstance(pair_id, str) and pair_id:
            reports[pair_id] = {"path": _rel(repo_root, path), "payload": payload}
    return reports


def _control_fail_reason(report: dict[str, Any] | None) -> str:
    if not report:
        return "not_evaluated"
    runs = report.get("runs") if isinstance(report.get("runs"), dict) else {}
    patched = runs.get("patched") if isinstance(runs, dict) else None
    if not isinstance(patched, dict):
        return "not_evaluated"
    if patched.get("gate_passed") is True:
        return "control_unexpectedly_passed"
    failed_checks = {str(item) for item in patched.get("failed_checks", []) if item is not None}
    dynamic_failed = {str(item) for item in patched.get("dynamic_failed_checks", []) if item is not None}
    missing = patched.get("missing_gate_artifacts", [])
    if dynamic_failed & _DYNAMIC_PROOF_FAILURES:
        return "dynamic_fail_closed"
    if failed_checks & _SERVICE_OR_ENVIRONMENT_FAILURES or missing:
        return "environment_unverified"
    if failed_checks:
        return "non_dynamic_gate_failure"
    return "control_not_promotable_without_reason"


def _emulation_ready(report: dict[str, Any] | None) -> bool | None:
    if not report:
        return None
    runs = report.get("runs") if isinstance(report.get("runs"), dict) else {}
    if not isinstance(runs, dict):
        return None
    sides = [runs.get("vulnerable"), runs.get("patched")]
    if not all(isinstance(side, dict) for side in sides):
        return None
    return all(not side.get("missing_gate_artifacts") for side in sides if isinstance(side, dict))


def _pair_row(repo_root: Path, pair: PairSpec, report_entry: dict[str, Any] | None, duplicate_count: int) -> dict[str, Any]:
    report = report_entry.get("payload") if report_entry else None
    report_path = report_entry.get("path") if report_entry else None
    vulnerable = _side_status(repo_root, pair.vulnerable.firmware_path, pair.vulnerable.sha256)
    patched = _side_status(repo_root, pair.patched.firmware_path, pair.patched.sha256)
    local_firmware_ready = vulnerable["sha256_match"] is True and patched["sha256_match"] is True
    promotable = bool(report and report.get("promotable_real_firmware_pair") is True)
    dedupe_key = f"{pair.vulnerable.sha256}:{pair.patched.sha256}"
    duplicate_firmware_sha_pair = duplicate_count > 1
    counted_for_scale = promotable and not duplicate_firmware_sha_pair
    return {
        "pair_id": pair.pair_id,
        "vendor": pair.vendor,
        "model": pair.model,
        "cve_id": pair.cve_id,
        "vuln_sha": pair.vulnerable.sha256,
        "patched_sha": pair.patched.sha256,
        "firmware": {"vulnerable": vulnerable, "patched": patched},
        "local_firmware_ready": local_firmware_ready,
        "real_pair_report": report_path,
        "promotable": promotable,
        "verdict": report.get("verdict") if report else "not_evaluated",
        "control_fail_reason": _control_fail_reason(report),
        "emulation_ready": _emulation_ready(report),
        "dedupe_key": dedupe_key,
        "dedupe_key_scope": "firmware-package-sha-pair",
        "duplicate_firmware_sha_pair": duplicate_firmware_sha_pair,
        "counted_for_phase1_scale": counted_for_scale,
        "next_action": "promoted" if counted_for_scale else ("run_real_pair_gate" if local_firmware_ready else "source_firmware_artifacts"),
    }


def build_phase1_pair_matrix(
    *,
    repo_root: Path | None = None,
    pairs_path: Path = DEFAULT_PAIRS,
    phase1_scale_target: int = DEFAULT_PHASE1_SCALE_TARGET,
    generated_at: str | None = None,
    phase_start_commit: str | None = None,
) -> dict[str, Any]:
    root = _repo_root(repo_root)
    pairs = load_pairs_manifest(pairs_path if pairs_path.is_absolute() else root / pairs_path)
    reports = _real_pair_reports(root)
    duplicate_counts = Counter(f"{pair.vulnerable.sha256}:{pair.patched.sha256}" for pair in pairs)
    rows = [_pair_row(root, pair, reports.get(pair.pair_id), duplicate_counts[f"{pair.vulnerable.sha256}:{pair.patched.sha256}"]) for pair in pairs]
    promotable_count = sum(1 for row in rows if row["counted_for_phase1_scale"] is True)
    local_ready_count = sum(1 for row in rows if row["local_firmware_ready"] is True)
    queue = [
        row["pair_id"]
        for row in rows
        if row["local_firmware_ready"] is True and row["counted_for_phase1_scale"] is not True
    ]
    metadata = build_repo_metadata(root, generated_at=generated_at)
    if phase_start_commit:
        metadata["phase_start_commit"] = phase_start_commit
    return {
        "schema_version": "scout-phase1-pair-matrix-v1",
        "metadata": metadata,
        "policy": {
            "phase1_scale_target_real_pairs": phase1_scale_target,
            "control_environment_fail_policy": "service_unreachable/control artifacts missing means environment_unverified, not patched-clean.",
            "dedupe_policy": "Pairs with identical vulnerable+patched firmware SHA tuple count once for scale targets.",
        },
        "summary": {
            "pair_corpus_size": len(rows),
            "local_firmware_pair_ready_count": local_ready_count,
            "promotable_real_pair_count": promotable_count,
            "phase1_scale_target_met": promotable_count >= phase1_scale_target,
            "next_pair_run_queue": queue,
        },
        "pairs": rows,
        "status": "phase1-scale-target-met" if promotable_count >= phase1_scale_target else "phase1-in-progress",
    }


def _candidate_from_pair(row: dict[str, Any]) -> dict[str, Any]:
    cve_id = str(row.get("cve_id") or "")
    known_cve_overlap = cve_id.startswith("CVE-")
    public_advisory_overlap = bool(cve_id)
    pattern_seed_used = bool(row.get("real_pair_report"))
    if row.get("promotable") is True:
        dynamic_reachability = "L5_lab_dynamic_proof"
    elif row.get("local_firmware_ready") is True:
        dynamic_reachability = "queued_pair_dynamic_gate"
    else:
        dynamic_reachability = "not_evaluated_missing_firmware"
    lineage_delta = "firmware_sha_delta_present" if row.get("vuln_sha") != row.get("patched_sha") else "no_firmware_sha_delta"
    zero_day_eligible = not (known_cve_overlap or public_advisory_overlap or pattern_seed_used)
    classification = "unknown_hypothesis" if zero_day_eligible else "known_or_one_day"
    return {
        "candidate_id": f"{classification}:{row['pair_id']}",
        "pair_id": row["pair_id"],
        "vendor": row["vendor"],
        "model": row["model"],
        "cve_id": cve_id,
        "known_cve_overlap": known_cve_overlap,
        "public_advisory_overlap": public_advisory_overlap,
        "pattern_seed_used": pattern_seed_used,
        "lineage_delta": lineage_delta,
        "dynamic_reachability": dynamic_reachability,
        "source_taxonomy": list(_SOURCE_TAXONOMY),
        "zero_day_eligible": zero_day_eligible,
        "classification": classification,
        "exclusion_reason": "known_or_seeded_overlap" if not zero_day_eligible else "",
    }


def build_phase2_novelty_dossier(
    phase1_matrix: dict[str, Any],
    *,
    repo_root: Path | None = None,
    generated_at: str | None = None,
    phase_start_commit: str | None = None,
) -> dict[str, Any]:
    root = _repo_root(repo_root)
    metadata = build_repo_metadata(root, generated_at=generated_at)
    if phase_start_commit:
        metadata["phase_start_commit"] = phase_start_commit
    rows = phase1_matrix.get("pairs") if isinstance(phase1_matrix.get("pairs"), list) else []
    candidates = [_candidate_from_pair(row) for row in rows if isinstance(row, dict)]
    missing_required = [
        candidate["candidate_id"]
        for candidate in candidates
        if any(field not in candidate for field in _REQUIRED_NOVELTY_FIELDS)
    ]
    unknown = [candidate for candidate in candidates if candidate.get("zero_day_eligible") is True]
    known = [candidate for candidate in candidates if candidate.get("zero_day_eligible") is not True]
    dynamic_shortlist_violations = [
        candidate["candidate_id"]
        for candidate in unknown
        if str(candidate.get("dynamic_reachability", "")).startswith("not_evaluated")
    ]
    family_channel_target_met = len({candidate["vendor"] for candidate in unknown}) >= 3
    return {
        "schema_version": "scout-zero-day-novelty-dossier-v1",
        "metadata": metadata,
        "required_candidate_fields": list(_REQUIRED_NOVELTY_FIELDS),
        "claim_boundary": "Known CVE/advisory/pattern-seeded candidates are tracked as one-day or validation seeds and excluded from zero-day KPIs.",
        "source_taxonomy": list(_SOURCE_TAXONOMY),
        "dashboard": {
            "candidate_count": len(candidates),
            "known_or_one_day_count": len(known),
            "unknown_hypothesis_count": len(unknown),
            "zero_day_kpi_count": len(unknown),
            "family_channel_target_met": family_channel_target_met,
        },
        "promotion_gates": [
            {
                "name": "required_novelty_fields_present",
                "passed": not missing_required,
                "failed_candidates": missing_required,
            },
            {
                "name": "known_overlap_excluded_from_zero_day_kpi",
                "passed": all(candidate.get("zero_day_eligible") is not True for candidate in known),
            },
            {
                "name": "dynamic_reachability_required_for_unknown_shortlist",
                "passed": not dynamic_shortlist_violations,
                "failed_candidates": dynamic_shortlist_violations,
            },
            {
                "name": "three_family_channel_unknown_target",
                "passed": family_channel_target_met,
                "blocking": False,
                "message": "Phase 2 lane is active, but the 3-family/channel unknown hypothesis target still needs new non-overlap candidates.",
            },
        ],
        "candidates": candidates,
        "next_actions": [
            "Run queued local Phase 1 pairs through real_firmware_pair_gate before counting scale progress.",
            "Generate unknown candidates from firmware lineage/source-sink evidence, not from known CVE or public PoC seeds.",
            "Promote only candidates with dynamic_reachability evidence or an explicit gap dossier.",
        ],
        "status": "phase2-started-known-unknown-split-active",
    }


def build_phase12_progress(
    *,
    repo_root: Path | None = None,
    pairs_path: Path = DEFAULT_PAIRS,
    phase1_scale_target: int = DEFAULT_PHASE1_SCALE_TARGET,
    generated_at: str | None = None,
    phase_start_commit: str | None = None,
) -> dict[str, Any]:
    phase1 = build_phase1_pair_matrix(
        repo_root=repo_root,
        pairs_path=pairs_path,
        phase1_scale_target=phase1_scale_target,
        generated_at=generated_at,
        phase_start_commit=phase_start_commit,
    )
    phase2 = build_phase2_novelty_dossier(
        phase1,
        repo_root=repo_root,
        generated_at=generated_at,
        phase_start_commit=phase_start_commit,
    )
    return {"phase1": phase1, "phase2": phase2}


def write_phase12_progress(
    *,
    phase1_path: Path,
    phase2_path: Path,
    payload: dict[str, Any],
) -> None:
    _write_json(phase1_path, payload["phase1"])
    _write_json(phase2_path, payload["phase2"])
