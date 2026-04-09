from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import cast

from .schema import JsonValue


def _load_json(path: Path) -> object | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _count_listish(obj: object) -> int:
    if isinstance(obj, list):
        return len(obj)
    if isinstance(obj, dict):
        src = cast(dict[str, object], obj)
        for key in ("matches", "cves", "candidates", "findings", "items", "entries"):
            value = src.get(key)
            if isinstance(value, list):
                return len(value)
    return 0


def manifest_primary_sha256(manifest: object) -> str:
    if not isinstance(manifest, dict):
        return ""
    obj = cast(dict[str, object], manifest)
    for key in (
        "analyzed_input_sha256",
        "input_sha256",
        "source_input_sha256",
        "sha256",
    ):
        value = obj.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def manifest_primary_size_bytes(manifest: object) -> int:
    if not isinstance(manifest, dict):
        return 0
    obj = cast(dict[str, object], manifest)
    for key in (
        "analyzed_input_size_bytes",
        "input_size_bytes",
        "source_input_size_bytes",
        "file_size_bytes",
    ):
        value = obj.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
    return 0


def copy_run_bundle(run_dir: Path, archive_dir: Path) -> Path:
    if archive_dir.exists():
        shutil.rmtree(archive_dir)
    archive_dir.parent.mkdir(parents=True, exist_ok=True)
    _ = shutil.copytree(run_dir, archive_dir, symlinks=True)
    return archive_dir


def collect_run_metrics(run_dir: Path) -> dict[str, JsonValue]:
    stages_ok = 0
    stages_partial = 0
    stages_failed = 0
    stages_skipped = 0
    for stage_json in run_dir.glob("stages/*/stage.json"):
        obj = _load_json(stage_json)
        if not isinstance(obj, dict):
            continue
        status = str(cast(dict[str, object], obj).get("status", "") or "")
        if status == "ok":
            stages_ok += 1
        elif status == "partial":
            stages_partial += 1
        elif status == "failed":
            stages_failed += 1
        elif status == "skipped":
            stages_skipped += 1

    findings_path = run_dir / "stages" / "findings" / "findings.json"
    findings_obj = _load_json(findings_path)
    findings_count = _count_listish(findings_obj)
    high_or_critical_findings = 0
    if isinstance(findings_obj, dict):
        findings_any = cast(dict[str, object], findings_obj).get("findings", [])
    elif isinstance(findings_obj, list):
        findings_any = findings_obj
    else:
        findings_any = []
    if isinstance(findings_any, list):
        for item in cast(list[object], findings_any):
            if not isinstance(item, dict):
                continue
            severity = str(cast(dict[str, object], item).get("severity", "")).lower()
            if severity in {"critical", "high"}:
                high_or_critical_findings += 1

    cve_count = 0
    for cve_path in (
        run_dir / "stages" / "cve_scan" / "cve_matches.json",
        run_dir / "stages" / "cve_scan" / "cve_scan.json",
    ):
        cve_obj = _load_json(cve_path)
        if cve_obj is not None:
            cve_count = _count_listish(cve_obj)
            break

    extraction_status = ""
    extraction_stage = _load_json(run_dir / "stages" / "extraction" / "stage.json")
    if isinstance(extraction_stage, dict):
        extraction_status = str(
            cast(dict[str, object], extraction_stage).get("status", "") or ""
        )

    inventory_quality_status = ""
    files_seen = 0
    binaries_seen = 0
    inventory_obj = _load_json(run_dir / "stages" / "inventory" / "inventory.json")
    if isinstance(inventory_obj, dict):
        quality_any = cast(dict[str, object], inventory_obj).get("quality")
        if isinstance(quality_any, dict):
            quality = cast(dict[str, object], quality_any)
            inventory_quality_status = str(quality.get("status", "") or "")
            files_seen = int(quality.get("files_seen", 0) or 0)
            binaries_seen = int(quality.get("binaries_seen", 0) or 0)

    exploit_candidates_count = _count_listish(
        _load_json(run_dir / "stages" / "findings" / "exploit_candidates.json")
    )
    actionable_candidate_count = max(exploit_candidates_count, high_or_critical_findings)

    llm_triage_status = ""
    llm_triage_reason = ""
    llm_triage_model_tier = ""
    llm_triage_ranking_count = 0
    llm_triage_obj = _load_json(run_dir / "stages" / "llm_triage" / "triage.json")
    if isinstance(llm_triage_obj, dict):
        triage = cast(dict[str, object], llm_triage_obj)
        llm_triage_status = str(triage.get("status", "") or "")
        llm_triage_reason = str(triage.get("reason", "") or "")
        llm_triage_model_tier = str(triage.get("model_tier", "") or "")
        llm_triage_ranking_count = _count_listish(triage.get("rankings"))

    adv_total = 0
    adv_parsed_ok = 0
    adv_parse_failures = 0
    adv_obj = _load_json(
        run_dir / "stages" / "adversarial_triage" / "triaged_findings.json"
    )
    if isinstance(adv_obj, dict):
        triaged_any = cast(dict[str, object], adv_obj).get("triaged_findings", [])
        if isinstance(triaged_any, list):
            triaged = cast(list[object], triaged_any)
            adv_total = len(triaged)
            for item in triaged:
                if not isinstance(item, dict):
                    continue
                item_obj = cast(dict[str, object], item)
                advocate = item_obj.get("advocate_argument")
                critic = item_obj.get("critic_rebuttal")
                advocate_ok = isinstance(advocate, dict) and isinstance(
                    cast(dict[str, object], advocate).get("argument"), str
                )
                critic_ok = isinstance(critic, dict) and isinstance(
                    cast(dict[str, object], critic).get("rebuttal"), str
                )
                if advocate_ok and critic_ok:
                    adv_parsed_ok += 1
            adv_parse_failures = max(0, adv_total - adv_parsed_ok)

    fp_verified_total = 0
    fp_tp = 0
    fp_fp = 0
    fp_unverified = 0
    fp_obj = _load_json(run_dir / "stages" / "fp_verification" / "verified_alerts.json")
    if isinstance(fp_obj, dict):
        verified_any = cast(dict[str, object], fp_obj).get("verified_alerts", [])
        if isinstance(verified_any, list):
            verified = cast(list[object], verified_any)
            fp_verified_total = len(verified)
            for item in verified:
                if not isinstance(item, dict):
                    continue
                verdict = str(cast(dict[str, object], item).get("fp_verdict", "") or "")
                if verdict == "TP":
                    fp_tp += 1
                elif verdict == "FP":
                    fp_fp += 1
                elif verdict == "unverified":
                    fp_unverified += 1

    graph_nodes = 0
    graph_edges = 0
    reference_graph_nodes = 0
    reference_graph_edges = 0
    graph_obj = _load_json(run_dir / "stages" / "graph" / "communication_graph.json")
    if isinstance(graph_obj, dict):
        graph = cast(dict[str, object], graph_obj)
        nodes_any = graph.get("nodes", [])
        edges_any = graph.get("edges", [])
        if isinstance(nodes_any, list):
            graph_nodes = len(nodes_any)
        if isinstance(edges_any, list):
            graph_edges = len(edges_any)
    ref_graph_obj = _load_json(run_dir / "stages" / "graph" / "reference_graph.json")
    if isinstance(ref_graph_obj, dict):
        graph = cast(dict[str, object], ref_graph_obj)
        nodes_any = graph.get("nodes", [])
        edges_any = graph.get("edges", [])
        if isinstance(nodes_any, list):
            reference_graph_nodes = len(nodes_any)
        if isinstance(edges_any, list):
            reference_graph_edges = len(edges_any)

    attack_surface_count = 0
    attack_surface_reference_only_count = 0
    attack_surface_obj = _load_json(
        run_dir / "stages" / "attack_surface" / "attack_surface.json"
    )
    if isinstance(attack_surface_obj, dict):
        attack_surface = cast(dict[str, object], attack_surface_obj)
        items_any = attack_surface.get("attack_surface", attack_surface.get("endpoints", []))
        if isinstance(items_any, list):
            items = cast(list[object], items_any)
            attack_surface_count = len(items)
            for item in items:
                if not isinstance(item, dict):
                    continue
                promotion = str(
                    cast(dict[str, object], item).get("promotion_status", "") or ""
                )
                if "reference" in promotion:
                    attack_surface_reference_only_count += 1

    llm_trace_count = len(list(run_dir.glob("stages/*/llm_trace/*.json")))
    manifest = _load_json(run_dir / "manifest.json")

    return {
        "findings_count": findings_count,
        "cve_count": cve_count,
        "extraction_status": extraction_status,
        "inventory_quality_status": inventory_quality_status,
        "files_seen": files_seen,
        "binaries_seen": binaries_seen,
        "stages_ok": stages_ok,
        "stages_partial": stages_partial,
        "stages_failed": stages_failed,
        "stages_skipped": stages_skipped,
        "exploit_candidates_count": exploit_candidates_count,
        "actionable_candidate_count": actionable_candidate_count,
        "llm_triage_status": llm_triage_status,
        "llm_triage_reason": llm_triage_reason,
        "llm_triage_model_tier": llm_triage_model_tier,
        "llm_triage_ranking_count": llm_triage_ranking_count,
        "adversarial_total": adv_total,
        "adversarial_parsed_ok": adv_parsed_ok,
        "adversarial_parse_failures": adv_parse_failures,
        "fp_verified_total": fp_verified_total,
        "fp_tp": fp_tp,
        "fp_fp": fp_fp,
        "fp_unverified": fp_unverified,
        "graph_nodes": graph_nodes,
        "graph_edges": graph_edges,
        "reference_graph_nodes": reference_graph_nodes,
        "reference_graph_edges": reference_graph_edges,
        "graph_empty": (
            graph_nodes == 0
            and graph_edges == 0
            and reference_graph_nodes == 0
            and reference_graph_edges == 0
        ),
        "attack_surface_count": attack_surface_count,
        "attack_surface_reference_only_count": attack_surface_reference_only_count,
        "llm_trace_count": llm_trace_count,
        "manifest_primary_sha256": manifest_primary_sha256(manifest),
        "manifest_primary_size_bytes": manifest_primary_size_bytes(manifest),
    }


def run_bundle_verifier(repo_root: Path, script_rel: str, bundle_dir: Path) -> dict[str, JsonValue]:
    script_path = repo_root / script_rel
    if not script_path.is_file():
        return {
            "ok": False,
            "reason": f"missing_script:{script_rel}",
            "stdout": "",
            "stderr": "",
        }
    cp = subprocess.run(
        [sys.executable, str(script_path), "--run-dir", str(bundle_dir)],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )
    stdout = cp.stdout.strip()
    stderr = cp.stderr.strip()
    reason = "ok" if cp.returncode == 0 else (stdout or stderr or f"exit_{cp.returncode}")
    return {
        "ok": cp.returncode == 0,
        "reason": reason,
        "stdout": stdout,
        "stderr": stderr,
    }


def evaluate_analyst_readiness(
    *,
    metrics: dict[str, JsonValue],
    digest_verifier: dict[str, JsonValue],
    report_verifier: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    blocked_reasons: list[str] = []
    degraded_reasons: list[str] = []

    if not bool(digest_verifier.get("ok")):
        blocked_reasons.append("digest_verifier_failed")
    if not bool(report_verifier.get("ok")):
        blocked_reasons.append("report_verifier_failed")

    extraction_status = str(metrics.get("extraction_status", "") or "")
    inventory_quality_status = str(metrics.get("inventory_quality_status", "") or "")
    if extraction_status and extraction_status != "ok":
        blocked_reasons.append(f"extraction_{extraction_status}")
    if inventory_quality_status and inventory_quality_status != "sufficient":
        blocked_reasons.append(f"inventory_{inventory_quality_status}")

    llm_triage_status = str(metrics.get("llm_triage_status", "") or "")
    if llm_triage_status and llm_triage_status != "ok":
        degraded_reasons.append(f"llm_triage_{llm_triage_status}")

    adv_total = int(metrics.get("adversarial_total", 0) or 0)
    adv_ok = int(metrics.get("adversarial_parsed_ok", 0) or 0)
    if adv_total > 0 and adv_ok < adv_total:
        degraded_reasons.append("adversarial_parse_incomplete")

    fp_total = int(metrics.get("fp_verified_total", 0) or 0)
    fp_unverified = int(metrics.get("fp_unverified", 0) or 0)
    if fp_total > 0 and fp_unverified > max(1, int(fp_total * 0.10)):
        degraded_reasons.append("fp_unverified_high")

    if bool(metrics.get("graph_empty")):
        degraded_reasons.append("graph_empty")
    if int(metrics.get("attack_surface_reference_only_count", 0) or 0) > 0:
        degraded_reasons.append("attack_surface_reference_only")
    if int(metrics.get("actionable_candidate_count", 0) or 0) == 0:
        degraded_reasons.append("no_actionable_candidates")

    readiness = "ready"
    reasons: list[str] = []
    if blocked_reasons:
        readiness = "blocked"
        reasons = blocked_reasons
    elif degraded_reasons:
        readiness = "degraded"
        reasons = degraded_reasons

    return {
        "analyst_readiness": readiness,
        "analyst_ready": readiness == "ready",
        "analyst_degraded": readiness == "degraded",
        "analyst_blocked": readiness == "blocked",
        "analyst_reason_codes": reasons,
    }
