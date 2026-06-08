from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any, cast

from .exploit_autopoc import (
    _PHASE3_FAILURE_CATEGORIES,
    _PHASE3_PLAN_IR_CONTRACT_VERSION,
    _PHASE3_RELIABILITY_VARIANTS,
    _PHASE3_REQUIRED_PLAN_IR_FIELDS,
    _candidate_family_bucket,
    _classify_runner_outcome,
    _ensure_phase3_plan_ir,
    _select_candidates,
)
from .phase01_readiness import build_repo_metadata

DEFAULT_PHASE3_READINESS = Path("docs/pov/phase3_aeg_readiness.json")

_EXPECTED_PLAN_IR_FIELDS = {
    "scope",
    "target_profile",
    "primitive",
    "preconditions",
    "execution",
    "verification",
    "cleanup",
    "gate",
    "backend_plan",
}
_EXPECTED_RELIABILITY_VARIANTS = {
    "baseline",
    "cold_start",
    "service_restart",
    "reboot",
}
_EXPECTED_BACKENDS = {
    "service_harness",
    "qemu_user",
    "full_system_emulation",
    "hardware_in_loop",
}
_EXPECTED_NONPASS_TAXONOMY = {
    "payload",
    "precondition",
    "harness",
    "false_hypothesis",
    "environment",
}


def _repo_root(path: Path | None = None) -> Path:
    return path if path is not None else Path(__file__).resolve().parents[2]


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _load_exploit_runner_contract(repo_root: Path) -> dict[str, Any]:
    runner_path = repo_root / "exploit_runner.py"
    if not runner_path.is_file():
        return {"exists": False, "reliability_variants": [], "has_cli_flag": False}
    spec = importlib.util.spec_from_file_location("_phase3_readiness_runner", runner_path)
    if spec is None or spec.loader is None:
        return {"exists": True, "reliability_variants": [], "has_cli_flag": False}
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cast(ModuleType, module))
    variants_any = getattr(module, "_ALLOWED_RELIABILITY_VARIANTS", frozenset())
    variants = sorted(str(item) for item in variants_any) if isinstance(variants_any, frozenset) else []
    source = runner_path.read_text(encoding="utf-8")
    return {
        "exists": True,
        "reliability_variants": variants,
        "has_cli_flag": "--reliability-variants" in source,
        "has_run_exploit": callable(getattr(module, "run_exploit", None)),
    }


def _selection_probe() -> dict[str, Any]:
    candidates: list[dict[str, object]] = [
        {
            "candidate_id": "cmd-a",
            "chain_id": "chain-cmd-a",
            "priority": "high",
            "score": 0.99,
            "families": ["cmd_exec_injection_risk"],
        },
        {
            "candidate_id": "cmd-b",
            "chain_id": "chain-cmd-b",
            "priority": "high",
            "score": 0.98,
            "families": ["cmd_exec_injection_risk"],
        },
        {
            "candidate_id": "auth-a",
            "chain_id": "chain-auth-a",
            "priority": "high",
            "score": 0.80,
            "families": ["auth_bypass"],
            "plan_ir": {"transitions": []},
        },
        {
            "candidate_id": "path-a",
            "chain_id": "chain-path-a",
            "priority": "medium",
            "score": 0.75,
            "families": ["path_traversal"],
            "channels": [{"kind": "http"}],
        },
    ]
    selected = _select_candidates(candidates, max_candidates=3)
    families = [_candidate_family_bucket(item) for item in selected]
    return {
        "selected_ids": [item.get("candidate_id") for item in selected],
        "families": families,
        "family_diverse": len(set(families)) == len(families),
        "plan_ir_candidate_selected": any(item.get("candidate_id") == "auth-a" for item in selected),
    }


def _plan_ir_probe(repo_root: Path) -> dict[str, Any]:
    plan_ir, status = _ensure_phase3_plan_ir(
        run_dir=repo_root,
        candidate={
            "candidate_id": "phase3-readiness",
            "chain_id": "phase3-readiness",
            "families": ["cmd_exec_injection_risk"],
            "summary": "Phase 3 readiness probe",
        },
        chain_id="phase3-readiness",
        candidate_id="phase3-readiness",
        target_service="http",
        gate={"scope": "lab-only", "attestation": "authorized"},
    )
    backends = {
        str(item.get("backend"))
        for item in cast(list[dict[str, object]], plan_ir.get("backend_plan", []))
        if isinstance(item, dict)
    }
    return {
        "status": status,
        "backend_names": sorted(backends),
        "backend_complete": _EXPECTED_BACKENDS.issubset(backends),
    }


def _taxonomy_probe() -> dict[str, Any]:
    result = _classify_runner_outcome(
        rc=1,
        runner_output="[FAIL] precondition missing auth session",
        bundle={},
        plan_ir={"preconditions": {"solved": False}},
    )
    return {
        "sample_category": result.get("category"),
        "sample_reason_codes": result.get("reason_codes", []),
    }


def build_phase3_readiness(
    *,
    repo_root: Path | None = None,
    generated_at: str | None = None,
    phase_start_commit: str | None = None,
) -> dict[str, Any]:
    root = _repo_root(repo_root)
    metadata = build_repo_metadata(root, generated_at=generated_at)
    if phase_start_commit:
        metadata["phase_start_commit"] = phase_start_commit
    runner_contract = _load_exploit_runner_contract(root)
    selection = _selection_probe()
    plan_ir = _plan_ir_probe(root)
    taxonomy = _taxonomy_probe()
    required_fields = set(_PHASE3_REQUIRED_PLAN_IR_FIELDS)
    autopoc_variants = set(_PHASE3_RELIABILITY_VARIANTS)
    runner_variants = {str(item) for item in runner_contract.get("reliability_variants", [])}
    taxonomy_categories = set(_PHASE3_FAILURE_CATEGORIES)

    checks = [
        {
            "name": "plan_ir_contract_required_fields",
            "passed": _EXPECTED_PLAN_IR_FIELDS.issubset(required_fields)
            and cast(dict[str, Any], plan_ir["status"]).get("complete") is True,
            "required": sorted(_EXPECTED_PLAN_IR_FIELDS),
            "observed": sorted(required_fields),
        },
        {
            "name": "candidate_selection_family_diversity_and_plan_ir_weighting",
            "passed": selection["family_diverse"] is True
            and selection["plan_ir_candidate_selected"] is True,
            "probe": selection,
        },
        {
            "name": "reliability_variants_added",
            "passed": _EXPECTED_RELIABILITY_VARIANTS.issubset(autopoc_variants)
            and _EXPECTED_RELIABILITY_VARIANTS.issubset(runner_variants)
            and runner_contract.get("has_cli_flag") is True,
            "autopoc_variants": sorted(autopoc_variants),
            "runner_contract": runner_contract,
        },
        {
            "name": "backend_redundancy_map",
            "passed": plan_ir["backend_complete"] is True,
            "observed": plan_ir["backend_names"],
            "required": sorted(_EXPECTED_BACKENDS),
        },
        {
            "name": "runner_failure_taxonomy_complete",
            "passed": _EXPECTED_NONPASS_TAXONOMY.issubset(taxonomy_categories)
            and taxonomy["sample_category"] == "precondition",
            "observed": sorted(taxonomy_categories),
            "probe": taxonomy,
        },
    ]
    ready = all(check["passed"] is True for check in checks)
    return {
        "schema_version": "scout-phase3-aeg-readiness-v1",
        "metadata": metadata,
        "phase": "Phase 3 — AEG robustness and Plan IR 중심화",
        "phase3_contract_version": _PHASE3_PLAN_IR_CONTRACT_VERSION,
        "baseline_version": {
            "package": "scout-firmware",
            "package_version": metadata.get("package_version", ""),
            "release_tag": "v3.0.0-rc1",
            "artifact_date": "2026-06-08 KST",
        },
        "policy": {
            "selection_policy": "priority + Plan IR presence + proof feasibility + family diversity",
            "failure_taxonomy_policy": "all runner_nonpass outcomes require payload/precondition/harness/false_hypothesis/environment reason category",
            "reliability_policy": "baseline plus cold_start/service_restart/reboot variants are represented in Plan IR and runner evidence bundles",
        },
        "checks": checks,
        "phase3_ready": ready,
        "verdict": "phase3-complete" if ready else "phase3-incomplete",
    }


def write_phase3_readiness(path: Path, payload: dict[str, Any]) -> None:
    _write_json(path, payload)
