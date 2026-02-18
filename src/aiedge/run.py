from __future__ import annotations

import hashlib
import importlib
import json
import shutil
from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, cast

from .duplicate_gate import (
    DuplicateRegistryError,
    apply_duplicate_gate,
)
from .extraction import ExtractionStage
from .findings import run_findings
from .inventory import InventoryStage
from .endpoints import EndpointsStage
from .surfaces import SurfacesStage
from .graph import GraphStage
from .attack_surface import AttackSurfaceStage
from .functional_spec import FunctionalSpecStage
from .firmware_profile import FirmwareProfileStage
from .threat_model import ThreatModelStage
from .llm_synthesis import LLMSynthesisStage
from .attribution import AttributionStage
from .llm_codex import run_codex_exec_summary
from .ota import OtaStage
from .ota_payload import OtaPayloadStage
from .carving import CarvingStage
from .structure import StructureStage
from .tooling import ToolingStage
from . import reporting
from . import __version__ as _AIEDGE_ENGINE_VERSION
from .policy import AIEdgePolicyViolation
from .schema import (
    JsonValue,
    REQUIRED_FINAL_STAGES,
    TERMINAL_STAGE_STATUSES,
    empty_report,
)
from .stage import RunReport, Stage, StageContext, StageResult, run_stages
from .stage_registry import stage_factories


DEFAULT_EGRESS_ALLOWLIST: tuple[str, ...] = (
    "pypi.org",
    "files.pythonhosted.org",
    "github.com",
)

STAGE_MANIFEST_CONTRACT_VERSION = "1.0"
STAGE_ARTIFACT_HASH_CAP_BYTES = 64 * 1024 * 1024


def _read_report_stage_status(report: dict[str, JsonValue], stage_name: str) -> str:
    stage_any = report.get(stage_name)
    if not isinstance(stage_any, dict):
        return "pending"
    status_any = cast(dict[str, object], stage_any).get("status")
    if isinstance(status_any, str):
        return status_any
    return "pending"


def _required_stage_statuses(
    report: dict[str, JsonValue], *, findings_executed: bool
) -> dict[str, str]:
    statuses = {
        "tooling": _read_report_stage_status(report, "tooling"),
        "extraction": _read_report_stage_status(report, "extraction"),
        "inventory": _read_report_stage_status(report, "inventory"),
        "findings": "ok" if findings_executed else "pending",
    }
    return statuses


def _set_report_completion(
    report: dict[str, JsonValue],
    *,
    is_final: bool,
    reason: str,
    findings_executed: bool,
) -> None:
    required_stage_statuses = _required_stage_statuses(
        report, findings_executed=findings_executed
    )
    if is_final:
        for stage_name in REQUIRED_FINAL_STAGES:
            status = required_stage_statuses.get(stage_name, "pending")
            if status == "pending" or status not in TERMINAL_STAGE_STATUSES:
                raise ValueError(
                    f"finalized report invariant violated: required stage '{stage_name}' has non-terminal status '{status}'"
                )

    completion_obj: dict[str, JsonValue] = {
        "is_final": is_final,
        "is_partial": not is_final,
        "reason": reason,
        "required_stage_statuses": cast(dict[str, JsonValue], required_stage_statuses),
    }
    report["run_completion"] = completion_obj


def _read_json_object(path: Path) -> dict[str, object] | None:
    try:
        data = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return cast(dict[str, object], data)


def _evidence_paths_from_obj(stage_obj: object) -> list[str]:
    if not isinstance(stage_obj, dict):
        return []
    evidence_any = cast(dict[str, object], stage_obj).get("evidence")
    if not isinstance(evidence_any, list):
        return []
    out: list[str] = []
    for item_any in cast(list[object], evidence_any):
        if not isinstance(item_any, dict):
            continue
        path_any = cast(dict[str, object], item_any).get("path")
        if isinstance(path_any, str) and path_any:
            out.append(path_any)
    return out


def _findings_evidence_paths(report: dict[str, JsonValue]) -> list[str]:
    findings_any = report.get("findings")
    if not isinstance(findings_any, list):
        return []
    out: list[str] = []
    for finding_any in cast(list[object], findings_any):
        if not isinstance(finding_any, dict):
            continue
        evidence_any = cast(dict[str, object], finding_any).get("evidence")
        if not isinstance(evidence_any, list):
            continue
        for ev_any in cast(list[object], evidence_any):
            if not isinstance(ev_any, dict):
                continue
            path_any = cast(dict[str, object], ev_any).get("path")
            if isinstance(path_any, str) and path_any:
                out.append(path_any)
    return sorted(set(out))


def _required_stage_manifest_paths(run_dir: Path) -> dict[str, JsonValue]:
    out: dict[str, JsonValue] = {}
    for stage_name in REQUIRED_FINAL_STAGES:
        if stage_name == "findings":
            out[stage_name] = None
            continue
        manifest_path = run_dir / "stages" / stage_name / "stage.json"
        rel = _try_run_relative(manifest_path, run_dir)
        out[stage_name] = (
            rel
            if rel is not None
            else str((Path("stages") / stage_name / "stage.json").as_posix())
        )
    return out


def _required_stage_evidence_paths(
    report: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    out: dict[str, JsonValue] = {
        "tooling": cast(JsonValue, _evidence_paths_from_obj(report.get("tooling"))),
        "extraction": cast(
            JsonValue, _evidence_paths_from_obj(report.get("extraction"))
        ),
        "inventory": cast(JsonValue, _evidence_paths_from_obj(report.get("inventory"))),
        "findings": cast(JsonValue, _findings_evidence_paths(report)),
    }
    return out


def _stage_missing_required_inputs(
    run_dir: Path, required_stage_statuses: dict[str, str]
) -> list[str]:
    missing: list[str] = []
    for stage_name in REQUIRED_FINAL_STAGES:
        if stage_name == "findings":
            continue
        if required_stage_statuses.get(stage_name, "pending") == "pending":
            missing.append(stage_name)
            continue
        manifest_path = run_dir / "stages" / stage_name / "stage.json"
        manifest = _read_json_object(manifest_path)
        if manifest is None:
            missing.append(stage_name)
            continue
        inputs_any = manifest.get("inputs")
        if not isinstance(inputs_any, list) or not inputs_any:
            missing.append(stage_name)
            continue
        has_firmware_input = False
        for item_any in cast(list[object], inputs_any):
            if not isinstance(item_any, dict):
                continue
            path_any = cast(dict[str, object], item_any).get("path")
            if path_any == "input/firmware.bin":
                has_firmware_input = True
                break
        if not has_firmware_input:
            missing.append(stage_name)
    return sorted(set(missing))


def _replace_no_signals_with_incomplete(
    report: dict[str, JsonValue], *, reasons: list[str], run_dir: Path
) -> None:
    findings_any = report.get("findings")
    if not isinstance(findings_any, list):
        return
    findings = cast(list[object], findings_any)
    has_no_signals = False
    retained: list[JsonValue] = []
    for item_any in findings:
        if not isinstance(item_any, dict):
            continue
        item = cast(dict[str, object], item_any)
        finding_id = item.get("id")
        if finding_id == "aiedge.findings.no_signals":
            has_no_signals = True
            continue
        retained.append(cast(JsonValue, dict(item)))
    if not has_no_signals:
        return

    evidence: list[dict[str, JsonValue]] = []
    for stage_name in ("tooling", "extraction", "inventory"):
        manifest_path = run_dir / "stages" / stage_name / "stage.json"
        rel = _try_run_relative(manifest_path, run_dir)
        if rel is not None:
            evidence.append({"path": rel, "note": "required stage manifest"})
    if not evidence:
        evidence = [{"path": "stages", "note": "required stage evidence missing"}]

    retained.append(
        {
            "id": "aiedge.findings.analysis_incomplete",
            "title": "Analysis completeness gate failed",
            "severity": "info",
            "confidence": 0.8,
            "disposition": "suspected",
            "description": "; ".join(reasons),
            "evidence": cast(list[JsonValue], cast(list[object], evidence)),
        }
    )
    report["findings"] = retained


def _refresh_integrity_and_completeness(
    report: dict[str, JsonValue], info: RunInfo, *, findings_executed: bool
) -> None:
    def downgrade_findings_for_incomplete() -> None:
        findings_any = report.get("findings")
        if not isinstance(findings_any, list):
            return
        out: list[JsonValue] = []
        for item_any in cast(list[object], findings_any):
            if not isinstance(item_any, dict):
                continue
            item = cast(dict[str, JsonValue], item_any)
            fid_any = item.get("id")
            fid = fid_any if isinstance(fid_any, str) else ""
            if fid == "aiedge.findings.analysis_incomplete":
                out.append(cast(JsonValue, dict(item)))
                continue

            f: dict[str, JsonValue] = dict(item)
            f["disposition"] = "suspected"

            conf_any = f.get("confidence")
            conf: float
            if isinstance(conf_any, (int, float)):
                conf = float(conf_any)
            elif isinstance(conf_any, str):
                try:
                    conf = float(conf_any)
                except ValueError:
                    conf = 0.5
            else:
                conf = 0.5
            if conf < 0.0:
                conf = 0.0
            if conf > 1.0:
                conf = 1.0
            f["confidence"] = float(min(conf, 0.6))

            sev_any = f.get("severity")
            if isinstance(sev_any, str) and sev_any in ("critical", "high"):
                f["severity"] = "medium"

            out.append(cast(JsonValue, f))

        if out:
            report["findings"] = cast(JsonValue, out)

    required_stage_statuses = _required_stage_statuses(
        report, findings_executed=findings_executed
    )
    overview_any = report.get("overview")
    overview = (
        cast(dict[str, object], overview_any) if isinstance(overview_any, dict) else {}
    )

    manifest = _read_json_object(info.manifest_path) or {}
    source_sha = manifest.get("source_input_sha256")
    if not isinstance(source_sha, str) or not source_sha:
        source_sha = (
            manifest.get("input_sha256")
            if isinstance(manifest.get("input_sha256"), str)
            else ""
        )
    source_size = manifest.get("source_input_size_bytes")
    if not isinstance(source_size, int):
        src_size_alt = manifest.get("input_size_bytes")
        source_size = src_size_alt if isinstance(src_size_alt, int) else 0
    source_path_any = manifest.get("input_path")
    source_path = source_path_any if isinstance(source_path_any, str) else ""

    analyzed_sha = ""
    analyzed_size = 0
    analyzed_exists = info.firmware_dest.is_file()
    if analyzed_exists:
        analyzed_sha = _sha256_file(info.firmware_dest)
        analyzed_size = info.firmware_dest.stat().st_size

    overview_sha_any = overview.get("input_sha256")
    overview_size_any = overview.get("input_size_bytes")
    overview_sha_match = (
        isinstance(overview_sha_any, str) and overview_sha_any == analyzed_sha
    )
    overview_size_match = (
        isinstance(overview_size_any, int) and overview_size_any == analyzed_size
    )

    manifest_paths = _required_stage_manifest_paths(info.run_dir)
    evidence_paths = _required_stage_evidence_paths(report)

    report["ingestion_integrity"] = cast(
        JsonValue,
        {
            "source_input": {
                "path": source_path,
                "sha256": source_sha,
                "size_bytes": source_size,
            },
            "analyzed_input": {
                "path": "input/firmware.bin",
                "sha256": analyzed_sha,
                "size_bytes": analyzed_size,
                "exists": analyzed_exists,
            },
            "overview_link": {
                "input_sha256_matches_analyzed": overview_sha_match,
                "input_size_bytes_matches_analyzed": overview_size_match,
            },
            "stage_consumption": {
                "required_stage_manifest_paths": manifest_paths,
                "required_stage_evidence_paths": evidence_paths,
            },
        },
    )

    reasons: list[str] = []
    missing_required_inputs = _stage_missing_required_inputs(
        info.run_dir, required_stage_statuses
    )
    if missing_required_inputs:
        reasons.append(
            "required stage inputs missing: " + ", ".join(missing_required_inputs)
        )
    if not analyzed_exists:
        reasons.append("analyzed input missing: run_dir/input/firmware.bin")
    if analyzed_exists and source_sha and source_sha != analyzed_sha:
        reasons.append("source and analyzed input sha256 mismatch")
    if not overview_sha_match or not overview_size_match:
        reasons.append("overview metadata does not match analyzed input metadata")
    for stage_name in REQUIRED_FINAL_STAGES:
        if required_stage_statuses.get(stage_name, "pending") == "pending":
            reasons.append(f"required stage pending: {stage_name}")

    gate_passed = not reasons
    report["report_completeness"] = {
        "gate_passed": gate_passed,
        "status": "complete" if gate_passed else "incomplete",
        "reasons": cast(list[JsonValue], cast(list[object], reasons or ["complete"])),
        "missing_required_stage_inputs": cast(
            list[JsonValue], cast(list[object], missing_required_inputs)
        ),
    }

    completion_any = report.get("run_completion")
    if isinstance(completion_any, dict):
        completion_obj = cast(dict[str, JsonValue], completion_any)
        completion_obj["conclusion_ready"] = gate_passed
        completion_obj["conclusion_note"] = (
            "Completeness gate passed; conclusions may be consumed."
            if gate_passed
            else "Completeness gate failed; conclusions are provisional due to incomplete analysis inputs."
        )

    if not gate_passed:
        limits_any = report.get("limitations")
        limits = (
            cast(list[JsonValue], limits_any) if isinstance(limits_any, list) else []
        )
        note = "Completeness gate failed: " + "; ".join(reasons)
        if note not in limits:
            limits.append(note)
        report["limitations"] = limits
        _replace_no_signals_with_incomplete(
            report, reasons=reasons, run_dir=info.run_dir
        )
        downgrade_findings_for_incomplete()


@dataclass(frozen=True)
class RunInfo:
    run_id: str
    run_dir: Path
    firmware_dest: Path
    manifest_path: Path
    report_json_path: Path
    report_html_path: Path
    log_path: Path
    artifacts_dir: Path
    input_sha256: str
    input_size_bytes: int
    created_at: str


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_ref_md_context(
    *,
    ref_md_path: str | None,
    require_ref_md: bool,
) -> tuple[str | None, str | None]:
    raw = (ref_md_path or "").strip()
    if not raw:
        if require_ref_md:
            raise ValueError(
                "REF_MD_REQUIRED_MISSING: provide --ref-md PATH or disable --require-ref-md"
            )
        return None, None

    candidate = Path(raw).expanduser().resolve()
    if not candidate.is_file():
        if require_ref_md:
            raise ValueError(
                f"REF_MD_REQUIRED_MISSING: ref.md not found at path={candidate}"
            )
        raise ValueError(f"ref.md not found: {candidate}")

    return str(candidate), _sha256_file(candidate)


def _canonical_json(value: JsonValue) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _quantize_remaining_budget_s(remaining_budget_s: float) -> int:
    return max(0, int(float(remaining_budget_s)))


def _try_run_relative(path: Path, run_dir: Path) -> str | None:
    try:
        rel = path.resolve().relative_to(run_dir.resolve())
    except ValueError:
        return None
    return rel.as_posix()


def _to_jsonable(value: object, *, run_dir: Path) -> JsonValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return cast(JsonValue, value)
    if isinstance(value, Path):
        rel = _try_run_relative(value, run_dir)
        return cast(JsonValue, rel if rel is not None else str(value))
    if isinstance(value, dict):
        obj = cast(dict[object, object], value)
        out: dict[str, JsonValue] = {}
        for key, item in sorted(obj.items(), key=lambda pair: str(pair[0])):
            out[str(key)] = _to_jsonable(item, run_dir=run_dir)
        return out
    if isinstance(value, (list, tuple, set)):
        if isinstance(value, list):
            seq = cast(list[object], value)
        elif isinstance(value, tuple):
            seq = cast(tuple[object, ...], value)
        else:
            seq = cast(set[object], value)
        return [_to_jsonable(v, run_dir=run_dir) for v in seq]
    return cast(JsonValue, str(value))


def _build_stage_params(
    stage: Stage,
    *,
    run_dir: Path,
    limitations: list[str],
) -> dict[str, JsonValue]:
    raw: dict[str, object] = {}
    if is_dataclass(stage):
        for field_obj in fields(stage):
            if field_obj.name.startswith("_"):
                continue
            raw[field_obj.name] = getattr(stage, field_obj.name)
    else:
        raw_obj = cast(dict[str, object], getattr(stage, "__dict__", {}))
        for key, value in raw_obj.items():
            if key.startswith("_"):
                continue
            raw[key] = value

    params: dict[str, JsonValue] = {}
    for key in sorted(raw.keys()):
        try:
            params[key] = _to_jsonable(raw[key], run_dir=run_dir)
        except Exception:
            limitations.append(
                f"params omitted field '{key}' (serialization unavailable)"
            )

    if not params:
        limitations.append("params unavailable; emitted empty object")
    return params


def _next_attempt_dir(stage_dir: Path) -> tuple[int, Path]:
    attempts_dir = stage_dir / "attempts"
    attempts_dir.mkdir(parents=True, exist_ok=True)
    max_attempt = 0
    for child in attempts_dir.iterdir():
        if not child.is_dir() or not child.name.startswith("attempt-"):
            continue
        suffix = child.name.removeprefix("attempt-")
        if suffix.isdigit():
            max_attempt = max(max_attempt, int(suffix))
    attempt = max_attempt + 1
    return attempt, attempts_dir / f"attempt-{attempt}"


def _list_run_inputs(
    run_dir: Path, *, sha_cache: dict[Path, str]
) -> list[dict[str, JsonValue]]:
    input_dir = run_dir / "input"
    if not input_dir.is_dir():
        return []
    out: list[dict[str, JsonValue]] = []
    for path in sorted(p for p in input_dir.rglob("*") if p.is_file()):
        rel = _try_run_relative(path, run_dir)
        if rel is None:
            continue
        digest = sha_cache.get(path)
        if digest is None:
            digest = _sha256_file(path)
            sha_cache[path] = digest
        out.append({"path": rel, "sha256": digest})
    return out


def _list_stage_artifacts(
    stage_dir: Path,
    *,
    run_dir: Path,
    limitations: list[str],
    sha_cache: dict[Path, str | None],
) -> list[dict[str, JsonValue]]:
    if not stage_dir.is_dir():
        return []
    out: list[dict[str, JsonValue]] = []
    for artifact in sorted(p for p in stage_dir.rglob("*") if p.is_file()):
        if artifact.name == "stage.json":
            continue
        if "attempts" in artifact.parts:
            continue
        rel = _try_run_relative(artifact, run_dir)
        if rel is None:
            limitations.append(f"artifact omitted outside run_dir: {artifact}")
            continue

        digest = sha_cache.get(artifact)
        if digest is None:
            if artifact.stat().st_size > STAGE_ARTIFACT_HASH_CAP_BYTES:
                limitations.append(
                    f"sha256 skipped for {rel} (size>{STAGE_ARTIFACT_HASH_CAP_BYTES} bytes cap)"
                )
                digest = None
            else:
                digest = _sha256_file(artifact)
            sha_cache[artifact] = digest
        out.append({"path": rel, "sha256": digest})
    return out


def _build_stage_manifest(
    *,
    ctx: StageContext,
    stage_result: StageResult,
    stage: Stage | None,
    attempt: int,
    input_cache: dict[Path, str],
    artifact_cache: dict[Path, str | None],
) -> dict[str, JsonValue]:
    limitations = list(stage_result.limitations)
    stage_name = stage_result.stage
    stage_identity = f"{stage_name}@{_AIEDGE_ENGINE_VERSION}"
    inputs = _list_run_inputs(ctx.run_dir, sha_cache=input_cache)
    if not inputs:
        limitations.append("input files unavailable under run_dir/input")

    if stage is None:
        params: dict[str, JsonValue] = {}
        limitations.append("params unavailable; stage object not found")
    else:
        params = _build_stage_params(
            stage, run_dir=ctx.run_dir, limitations=limitations
        )

    stage_key_payload: dict[str, JsonValue] = {
        "stage_identity": stage_identity,
        "inputs": cast(JsonValue, inputs),
        "params": params,
    }
    stage_key = hashlib.sha256(
        _canonical_json(stage_key_payload).encode("ascii")
    ).hexdigest()

    stage_dir = ctx.run_dir / "stages" / stage_name
    artifacts = _list_stage_artifacts(
        stage_dir,
        run_dir=ctx.run_dir,
        limitations=limitations,
        sha_cache=artifact_cache,
    )

    return {
        "contract_version": STAGE_MANIFEST_CONTRACT_VERSION,
        "stage_name": stage_name,
        "stage_identity": stage_identity,
        "stage_key": stage_key,
        "attempt": attempt,
        "status": stage_result.status,
        "limitations": cast(list[JsonValue], list(limitations)),
        "inputs": cast(list[JsonValue], cast(list[object], inputs)),
        "params": params,
        "artifacts": cast(list[JsonValue], cast(list[object], artifacts)),
        "started_at": stage_result.started_at,
        "finished_at": stage_result.finished_at,
        "duration_s": stage_result.duration_s,
    }


def _write_stage_manifests(
    *,
    ctx: StageContext,
    stages: list[Stage],
    report: RunReport,
) -> None:
    stages_by_name = {s.name: s for s in stages}
    input_cache: dict[Path, str] = {}
    artifact_cache: dict[Path, str | None] = {}

    for stage_result in report.stage_results:
        stage_name = stage_result.stage
        stage_dir = ctx.run_dir / "stages" / stage_name
        stage_dir.mkdir(parents=True, exist_ok=True)
        attempt, attempt_dir = _next_attempt_dir(stage_dir)
        attempt_dir.mkdir(parents=False, exist_ok=False)

        manifest = _build_stage_manifest(
            ctx=ctx,
            stage_result=stage_result,
            stage=stages_by_name.get(stage_name),
            attempt=attempt,
            input_cache=input_cache,
            artifact_cache=artifact_cache,
        )

        payload = (
            json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        )
        _ = (attempt_dir / "stage.json").write_text(payload, encoding="utf-8")
        _ = (stage_dir / "stage.json").write_text(payload, encoding="utf-8")


def _utc_run_id(input_sha256: str, *, prefix_len: int = 12) -> str:
    if not (6 <= prefix_len <= 12):
        raise ValueError("prefix_len must be 6..12")
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M")
    return f"{stamp}_sha256-{input_sha256[:prefix_len]}"


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _reserve_run_dir(
    runs_root: Path,
    base_run_id: str,
    *,
    max_tries: int = 10_000,
) -> tuple[str, Path]:
    for i in range(max_tries):
        run_id = base_run_id if i == 0 else f"{base_run_id}-{i}"
        run_dir = runs_root / run_id
        try:
            run_dir.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            continue
        return run_id, run_dir

    raise FileExistsError(
        f"Unable to create unique run dir for '{base_run_id}' after {max_tries} attempts"
    )


def create_run(
    input_path: str,
    *,
    case_id: str,
    ack_authorization: bool,
    open_egress: bool = False,
    egress_allowlist: list[str] | None = None,
    ref_md_path: str | None = None,
    require_ref_md: bool = False,
    runs_root: Path | None = None,
) -> RunInfo:

    if not ack_authorization:
        raise AIEdgePolicyViolation(
            "Missing required acknowledgement: --ack-authorization"
        )

    src = Path(input_path)
    if not src.is_file():
        raise FileNotFoundError(input_path)

    if runs_root is None:
        runs_root = Path.cwd() / "aiedge-runs"

    src_resolved = src.resolve()
    runs_root_resolved = runs_root.resolve()
    try:
        _ = src_resolved.relative_to(runs_root_resolved)
    except ValueError:
        pass
    else:
        raise AIEdgePolicyViolation(
            "Refusing to analyze firmware located inside runs root; choose an input outside aiedge-runs/."
        )

    source_input_sha256 = _sha256_file(src_resolved)
    source_input_size_bytes = src_resolved.stat().st_size
    resolved_ref_md_path, ref_md_sha256 = _load_ref_md_context(
        ref_md_path=ref_md_path,
        require_ref_md=require_ref_md,
    )

    base_run_id = _utc_run_id(source_input_sha256)
    run_id, run_dir = _reserve_run_dir(runs_root, base_run_id)
    input_dir = run_dir / "input"
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    input_dir.mkdir(exist_ok=False)
    logs_dir.mkdir(exist_ok=False)
    report_dir.mkdir(exist_ok=False)

    firmware_dest = input_dir / "firmware.bin"
    _ = shutil.copy2(src_resolved, firmware_dest)
    analyzed_input_sha256 = _sha256_file(firmware_dest)
    analyzed_input_size_bytes = firmware_dest.stat().st_size
    if (
        analyzed_input_sha256 != source_input_sha256
        or analyzed_input_size_bytes != source_input_size_bytes
    ):
        raise ValueError(
            "Copied firmware bytes differ from source input; refusing integrity downgrade."
        )

    input_sha256 = analyzed_input_sha256
    input_size_bytes = analyzed_input_size_bytes

    created_at = _iso_utc_now()
    manifest_path = run_dir / "manifest.json"

    report_rel = {
        "json": str(Path("report") / "report.json"),
        "html": str(Path("report") / "report.html"),
    }
    log_rel = str(Path("logs") / "aiedge.log")
    artifacts_rel = str(Path("artifacts"))
    allowlist = list(egress_allowlist or list(DEFAULT_EGRESS_ALLOWLIST))
    warnings: list[str] = []
    if open_egress:
        warnings.append("open_egress enabled")

    network_policy = {
        "internal_comms": {"allowed": True},
        "internet_egress": {
            "mode": "open" if open_egress else "allowlist",
            "allowlist": allowlist,
        },
        "override_open_egress": bool(open_egress),
        "warnings": warnings,
    }

    manifest = {
        "run_id": run_id,
        "input_path": input_path,
        "input_sha256": input_sha256,
        "input_size_bytes": input_size_bytes,
        "source_input_sha256": source_input_sha256,
        "source_input_size_bytes": source_input_size_bytes,
        "analyzed_input_path": "input/firmware.bin",
        "analyzed_input_sha256": analyzed_input_sha256,
        "analyzed_input_size_bytes": analyzed_input_size_bytes,
        "case_id": case_id,
        "ack_authorization": bool(ack_authorization),
        "created_at": created_at,
        "report": report_rel,
        "logs": [log_rel],
        "artifacts_dir": artifacts_rel,
        "network_policy": network_policy,
        "ref_md_path": resolved_ref_md_path,
        "ref_md_sha256": ref_md_sha256,
        "warnings": warnings,
    }
    _ = manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    limitations: list[str] = [
        "Extraction is best-effort and may be incomplete depending on available tools.",
        "Inventory is best-effort and depends on extraction output.",
        "Findings are best-effort and may be incomplete depending on extraction/inventory outputs.",
    ]
    report: dict[str, JsonValue] = empty_report()
    report["overview"] = {
        "run_id": run_id,
        "case_id": case_id,
        "created_at": created_at,
        "input_sha256": input_sha256,
        "input_size_bytes": input_size_bytes,
        "source_input_path": input_path,
        "source_input_sha256": source_input_sha256,
        "source_input_size_bytes": source_input_size_bytes,
        "analyzed_input_path": "input/firmware.bin",
        "analyzed_input_sha256": analyzed_input_sha256,
        "analyzed_input_size_bytes": analyzed_input_size_bytes,
        "ref_md_path": resolved_ref_md_path,
        "ref_md_sha256": ref_md_sha256,
    }
    report["limitations"] = cast(list[JsonValue], list(limitations))
    _set_report_completion(
        report,
        is_final=False,
        reason="initialized run; analysis not finalized",
        findings_executed=False,
    )
    _refresh_integrity_and_completeness(
        report,
        info=RunInfo(
            run_id=run_id,
            run_dir=run_dir,
            firmware_dest=firmware_dest,
            manifest_path=manifest_path,
            report_json_path=report_dir / "report.json",
            report_html_path=report_dir / "report.html",
            log_path=logs_dir / "aiedge.log",
            artifacts_dir=run_dir / "artifacts",
            input_sha256=input_sha256,
            input_size_bytes=input_size_bytes,
            created_at=created_at,
        ),
        findings_executed=False,
    )

    log_path = reporting.write_stub_log(logs_dir)
    artifacts_dir = reporting.ensure_artifacts_dir(run_dir)
    report_json_path = reporting.write_report_json(report_dir, report)
    report_html_path = reporting.write_report_html(report_dir, report)

    return RunInfo(
        run_id=run_id,
        run_dir=run_dir,
        firmware_dest=firmware_dest,
        manifest_path=manifest_path,
        report_json_path=report_json_path,
        report_html_path=report_html_path,
        log_path=log_path,
        artifacts_dir=artifacts_dir,
        input_sha256=input_sha256,
        input_size_bytes=input_size_bytes,
        created_at=created_at,
    )


def load_existing_run(run_dir_path: str | Path) -> RunInfo:
    run_dir = Path(run_dir_path).resolve()
    if not run_dir.exists():
        raise ValueError(f"Run directory not found: {run_dir}")
    if not run_dir.is_dir():
        raise ValueError(f"Run path is not a directory: {run_dir}")

    manifest_path = run_dir / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"Run manifest not found: {manifest_path}")

    try:
        manifest_any = cast(
            object, json.loads(manifest_path.read_text(encoding="utf-8"))
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"Run manifest is not valid JSON: {manifest_path}") from exc
    except OSError as exc:
        raise ValueError(f"Failed to read run manifest: {manifest_path}") from exc

    if not isinstance(manifest_any, dict):
        raise ValueError(f"Run manifest must be a JSON object: {manifest_path}")

    manifest = cast(dict[str, object], manifest_any)
    report_dir = run_dir / "report"
    report_json_path = report_dir / "report.json"
    if not report_json_path.exists():
        try:
            _ = reporting.write_report_json(report_dir, empty_report())
        except Exception:
            pass

    run_id_any = manifest.get("run_id")
    run_id = run_id_any if isinstance(run_id_any, str) and run_id_any else run_dir.name

    input_sha_any = manifest.get("input_sha256")
    input_sha256 = input_sha_any if isinstance(input_sha_any, str) else ""

    input_size_any = manifest.get("input_size_bytes")
    input_size_bytes = input_size_any if isinstance(input_size_any, int) else 0

    created_at_any = manifest.get("created_at")
    created_at = created_at_any if isinstance(created_at_any, str) else ""

    return RunInfo(
        run_id=run_id,
        run_dir=run_dir,
        firmware_dest=run_dir / "input" / "firmware.bin",
        manifest_path=manifest_path,
        report_json_path=report_json_path,
        report_html_path=report_dir / "report.html",
        log_path=run_dir / "logs" / "aiedge.log",
        artifacts_dir=run_dir / "artifacts",
        input_sha256=input_sha256,
        input_size_bytes=input_size_bytes,
        created_at=created_at,
    )


def _load_report_json(path: Path) -> dict[str, JsonValue]:
    try:
        data = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return empty_report()

    if not isinstance(data, dict):
        return empty_report()
    return cast(dict[str, JsonValue], data)


def _load_manifest_input_path(path: Path) -> str | None:
    try:
        data = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    val = cast(dict[str, object], data).get("input_path")
    if isinstance(val, str) and val:
        return val
    return None


def _load_manifest_profile(path: Path) -> str:
    data = _read_json_object(path)
    if data is None:
        return "analysis"
    profile_any = data.get("profile")
    if isinstance(profile_any, str) and profile_any:
        return profile_any
    return "analysis"


def _build_exploit_assessment(
    *, profile: str, report: dict[str, JsonValue], run_dir: Path
) -> dict[str, JsonValue]:
    stage_names = (
        "exploit_gate",
        "exploit_chain",
        "poc_validation",
        "exploit_policy",
    )
    stage_statuses: dict[str, JsonValue] = {
        stage_name: _read_report_stage_status(report, stage_name)
        for stage_name in stage_names
    }

    digest_verdict: dict[str, JsonValue] | None = None
    if profile == "exploit":
        try:
            digest_payload = reporting.build_analyst_digest(report, run_dir=run_dir)
        except Exception:
            digest_payload = None
        if isinstance(digest_payload, dict):
            verdict_any = digest_payload.get("exploitability_verdict")
            if isinstance(verdict_any, dict):
                digest_verdict = cast(dict[str, JsonValue], verdict_any)

    return reporting.build_exploit_assessment_from_digest_verdict(
        profile=profile,
        stage_statuses=cast(dict[str, JsonValue], stage_statuses),
        digest_verdict=digest_verdict,
    )


def _llm_skipped_report(reason: str) -> dict[str, JsonValue]:
    return {
        "driver": "codex",
        "status": "skipped",
        "probe": {
            "version_ok": False,
            "version_out": "skipped",
            "help_ok": False,
            "help_out": "skipped",
        },
        "reason": reason,
    }


def _apply_llm_exec_step(
    *, info: RunInfo, report: dict[str, JsonValue], no_llm: bool
) -> dict[str, JsonValue]:
    llm_any = report.get("llm")
    llm_obj: dict[str, JsonValue]
    if isinstance(llm_any, dict):
        llm_obj = cast(dict[str, JsonValue], llm_any)
    else:
        llm_obj = _llm_skipped_report("missing llm probe section")

    if no_llm:
        return llm_obj

    status_any = llm_obj.get("status")
    status_s = status_any if isinstance(status_any, str) else ""
    if status_s != "available":
        return llm_obj

    try:
        exec_result = run_codex_exec_summary(run_dir=info.run_dir, report=report)
    except Exception as exc:
        llm_obj["status"] = "failed"
        llm_obj["reason"] = f"Codex summary invocation crashed: {exc}"
        return llm_obj

    for k, v in exec_result.items():
        llm_obj[k] = v
    return llm_obj


def normalize_evidence_list(
    evidence_any: object, *, fallback: list[dict[str, JsonValue]]
) -> list[dict[str, JsonValue]]:
    if not isinstance(evidence_any, list):
        return list(fallback)
    out: list[dict[str, JsonValue]] = []
    for item in cast(list[object], evidence_any):
        if isinstance(item, dict):
            obj = cast(dict[str, object], item)
            path_s = obj.get("path")
            if isinstance(path_s, str) and path_s:
                ev: dict[str, JsonValue] = {"path": path_s}
                note_any = obj.get("note")
                if isinstance(note_any, str) and note_any:
                    ev["note"] = note_any
                snippet_any = obj.get("snippet")
                if isinstance(snippet_any, str) and snippet_any:
                    ev["snippet"] = snippet_any
                snippet_sha_any = obj.get("snippet_sha256")
                if isinstance(snippet_sha_any, str) and snippet_sha_any:
                    ev["snippet_sha256"] = snippet_sha_any
                out.append(ev)
        elif isinstance(item, str) and item:
            out.append({"path": item})
    return out if out else list(fallback)


def normalize_limitations_list(limits_any: object) -> list[str]:
    if not isinstance(limits_any, list):
        return []
    out: list[str] = []
    for x in cast(list[object], limits_any):
        if isinstance(x, str) and x:
            out.append(x)
    return out


def _write_analyst_report_artifacts(
    report_dir: Path, report: dict[str, JsonValue]
) -> None:
    analyst_report = reporting.build_analyst_report(report)
    _ = reporting.write_analyst_report_json(report_dir, analyst_report)
    _ = reporting.write_analyst_report_md(report_dir, analyst_report)
    _ = reporting.write_analyst_report_v2_json(report_dir, report)
    _ = reporting.write_analyst_report_v2_md(report_dir, report)
    _ = reporting.write_analyst_report_v2_viewer(report_dir, report)
    _ = reporting.write_analyst_overview_json(report_dir, report)
    _ = reporting.write_analyst_digest_json(report_dir, report)
    _ = reporting.write_analyst_digest_md(report_dir, report)


def _mark_report_incomplete_due_to_digest(
    *,
    report: dict[str, JsonValue],
    info: RunInfo,
    err: Exception,
) -> None:
    reason = f"analyst digest emission failed: {err}"
    _set_report_completion(
        report,
        is_final=False,
        reason=reason,
        findings_executed=True,
    )
    _refresh_integrity_and_completeness(report, info, findings_executed=True)
    limits = normalize_limitations_list(report.get("limitations"))
    if reason not in limits:
        limits.append(reason)
    report["limitations"] = cast(list[JsonValue], cast(list[object], limits))


def _apply_duplicate_gate_to_findings(
    *,
    report: dict[str, JsonValue],
    info: RunInfo,
    findings_any: object,
    force_retriage: bool,
) -> list[dict[str, JsonValue]]:
    findings: list[dict[str, JsonValue]] = []
    if isinstance(findings_any, list):
        for item_any in cast(list[object], findings_any):
            if isinstance(item_any, dict):
                findings.append(cast(dict[str, JsonValue], item_any))

    seen_at = info.created_at if info.created_at else _iso_utc_now()
    try:
        gate = apply_duplicate_gate(
            findings=findings,
            run_id=info.run_id,
            run_dir=info.run_dir,
            seen_at=seen_at,
            force_retriage=force_retriage,
        )
    except DuplicateRegistryError as exc:
        raise ValueError(str(exc)) from exc

    report["duplicate_gate"] = gate.report_section
    if gate.warnings:
        existing_limits = normalize_limitations_list(report.get("limitations"))
        for warning in gate.warnings:
            tokenized = warning
            if tokenized not in existing_limits:
                existing_limits.append(tokenized)
        report["limitations"] = cast(
            list[JsonValue], cast(list[object], existing_limits)
        )

    # Duplicate gate is an informational/triage signal. The top-level report
    # must preserve stage-produced findings (including `info` severity) even
    # when the gate suppresses exact duplicates.
    return findings


def _apply_stage_result_to_report(
    report: dict[str, JsonValue], stage_result: StageResult, *, budget_s: int
) -> None:
    stage = stage_result.stage
    details = dict(stage_result.details)

    if stage == "tooling":
        tooling_evidence = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/tooling", "note": "evidence missing"}],
        )
        report["tooling"] = {
            "status": stage_result.status,
            "evidence": cast(list[JsonValue], cast(list[object], tooling_evidence)),
            "details": details,
        }
        return

    if stage == "ota":
        ota_evidence = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/ota", "note": "evidence missing"}],
        )
        report["ota"] = {
            "status": stage_result.status,
            "evidence": cast(list[JsonValue], cast(list[object], ota_evidence)),
            "details": details,
        }
        return

    if stage == "ota_payload":
        ota_payload_evidence = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/ota", "note": "evidence missing"}],
        )
        report["ota_payload"] = {
            "status": stage_result.status,
            "evidence": cast(list[JsonValue], cast(list[object], ota_payload_evidence)),
            "details": details,
        }
        return

    if stage == "ota_fs":
        ota_fs_evidence = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/ota", "note": "evidence missing"}],
        )
        report["ota_fs"] = {
            "status": stage_result.status,
            "evidence": cast(list[JsonValue], cast(list[object], ota_fs_evidence)),
            "details": details,
        }
        return

    if stage == "ota_roots":
        ota_roots_evidence = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/ota", "note": "evidence missing"}],
        )
        report["ota_roots"] = {
            "status": stage_result.status,
            "evidence": cast(list[JsonValue], cast(list[object], ota_roots_evidence)),
            "details": details,
        }
        return

    if stage == "ota_boottriage":
        ota_boottriage_evidence = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/ota/boottriage", "note": "evidence missing"}],
        )
        report["ota_boottriage"] = {
            "status": stage_result.status,
            "evidence": cast(
                list[JsonValue], cast(list[object], ota_boottriage_evidence)
            ),
            "details": details,
        }
        return

    if stage == "firmware_lineage":
        firmware_lineage_evidence = normalize_evidence_list(
            details.get("evidence"),
            fallback=[
                {
                    "path": "stages/firmware_lineage",
                    "note": "evidence missing",
                }
            ],
        )
        report["firmware_lineage"] = {
            "status": stage_result.status,
            "evidence": cast(
                list[JsonValue], cast(list[object], firmware_lineage_evidence)
            ),
            "details": details,
        }
        return

    if stage == "extraction":
        conf_any = details.get("confidence")
        if isinstance(conf_any, (int, float)):
            confidence = float(conf_any)
        elif isinstance(conf_any, str):
            try:
                confidence = float(conf_any)
            except ValueError:
                confidence = 0.0
        else:
            confidence = 0.0

        reasons_any = details.get("reasons")
        if isinstance(reasons_any, list) and all(
            isinstance(x, str) for x in reasons_any
        ):
            reasons = cast(list[JsonValue], reasons_any)
        else:
            reasons = cast(list[JsonValue], list(stage_result.limitations))

        evidence = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/extraction", "note": "evidence missing"}],
        )
        extracted_dir_any = details.get("extracted_dir")
        extracted_dir = (
            extracted_dir_any
            if isinstance(extracted_dir_any, str) and extracted_dir_any
            else "stages/extraction/_firmware.bin.extracted"
        )
        extracted_count_any = details.get("extracted_file_count")
        extracted_count = (
            int(extracted_count_any) if isinstance(extracted_count_any, int) else 0
        )
        binwalk_av_any = details.get("binwalk_available")
        binwalk_available = (
            bool(binwalk_av_any) if isinstance(binwalk_av_any, bool) else False
        )
        binwalk_log_any = details.get("binwalk_log")
        binwalk_log = (
            binwalk_log_any
            if isinstance(binwalk_log_any, str)
            else "stages/extraction/binwalk.log"
        )
        tool_any = details.get("tool")
        tool_s = tool_any if isinstance(tool_any, str) and tool_any else "binwalk"
        mat_any = details.get("matryoshka")
        mat_enabled = bool(mat_any) if isinstance(mat_any, bool) else False
        mat_depth_any = details.get("matryoshka_depth")
        mat_depth = int(mat_depth_any) if isinstance(mat_depth_any, int) else 0
        lzop_any = details.get("lzop_available")
        lzop_available = bool(lzop_any) if isinstance(lzop_any, bool) else False
        extraction_timeout_any = details.get("extraction_timeout_s")
        extraction_timeout = (
            float(extraction_timeout_any)
            if isinstance(extraction_timeout_any, (int, float))
            else 0.0
        )

        report["extraction"] = {
            "status": stage_result.status,
            "confidence": float(max(0.0, min(1.0, confidence))),
            "summary": {
                "tool": tool_s,
                "binwalk_available": bool(binwalk_available),
                "binwalk_log": binwalk_log,
                "matryoshka": bool(mat_enabled),
                "matryoshka_depth": int(mat_depth),
                "lzop_available": bool(lzop_available),
                "extracted_dir": extracted_dir,
                "extracted_file_count": int(extracted_count),
                "time_budget_s": int(budget_s),
                "extraction_timeout_s": float(extraction_timeout),
            },
            "evidence": cast(list[JsonValue], cast(list[object], evidence)),
            "reasons": reasons,
            "details": details,
        }
        return

    if stage == "structure":
        structure_evidence = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/structure", "note": "evidence missing"}],
        )
        report["structure"] = {
            "status": stage_result.status,
            "evidence": cast(list[JsonValue], cast(list[object], structure_evidence)),
            "details": details,
        }
        return

    if stage == "carving":
        carving_evidence = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/carving", "note": "evidence missing"}],
        )
        report["carving"] = {
            "status": stage_result.status,
            "evidence": cast(list[JsonValue], cast(list[object], carving_evidence)),
            "details": details,
        }
        return

    if stage == "firmware_profile":
        firmware_profile_evidence = normalize_evidence_list(
            details.get("evidence_refs"),
            fallback=[{"path": "stages/firmware_profile", "note": "evidence missing"}],
        )
        report["firmware_profile"] = {
            "status": stage_result.status,
            "evidence": cast(
                list[JsonValue], cast(list[object], firmware_profile_evidence)
            ),
            "details": details,
            "branch_plan": details.get("branch_plan", {}),
            "os_type_guess": details.get("os_type_guess", "unextractable_or_unknown"),
        }
        return

    if stage == "inventory":
        evidence_list = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/inventory", "note": "evidence missing"}],
        )
        summary_any = details.get("summary")
        summary_dict: dict[str, JsonValue]
        if isinstance(summary_any, dict):
            summary_dict = cast(dict[str, JsonValue], summary_any)
        else:
            summary_dict = {
                "roots_scanned": 0,
                "files": 0,
                "binaries": 0,
                "configs": 0,
                "string_hits": 0,
            }
        candidates_any = details.get("service_candidates")
        service_candidates: list[JsonValue]
        if isinstance(candidates_any, list):
            service_candidates = cast(list[JsonValue], candidates_any)
        else:
            service_candidates = []
        services_any = details.get("services")
        services: list[JsonValue]
        if isinstance(services_any, list):
            services = cast(list[JsonValue], services_any)
        else:
            services = []
        report["inventory"] = {
            "status": stage_result.status,
            "evidence": cast(list[JsonValue], cast(list[object], evidence_list)),
            "summary": summary_dict,
            "service_candidates": service_candidates,
            "services": services,
        }
        return

    if stage == "attribution":
        evidence_list = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/attribution", "note": "evidence missing"}],
        )
        claims_any = details.get("claims")
        attr_claims: list[JsonValue]
        if isinstance(claims_any, list):
            attr_claims = cast(list[JsonValue], claims_any)
        else:
            attr_claims = []
        report["attribution"] = {
            "status": stage_result.status,
            "evidence": cast(list[JsonValue], cast(list[object], evidence_list)),
            "claims": attr_claims,
            "details": details,
        }
        return

    if stage == "endpoints":
        evidence_list = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/endpoints", "note": "evidence missing"}],
        )
        summary_any = details.get("summary")
        endpoint_summary: dict[str, JsonValue]
        if isinstance(summary_any, dict):
            endpoint_summary = cast(dict[str, JsonValue], summary_any)
        else:
            endpoint_summary = {
                "roots_scanned": 0,
                "files_scanned": 0,
                "endpoints": 0,
                "matches_seen": 0,
                "classification": "candidate",
                "observation": "static_reference",
            }
        endpoints_any = details.get("endpoints")
        endpoints: list[JsonValue]
        if isinstance(endpoints_any, list):
            endpoints = cast(list[JsonValue], endpoints_any)
        else:
            endpoints = []
        report["endpoints"] = {
            "status": stage_result.status,
            "evidence": cast(list[JsonValue], cast(list[object], evidence_list)),
            "summary": endpoint_summary,
            "endpoints": endpoints,
        }
        return

    if stage == "surfaces":
        evidence_list = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/surfaces", "note": "evidence missing"}],
        )
        summary_any = details.get("summary")
        surfaces_summary: dict[str, JsonValue]
        if isinstance(summary_any, dict):
            surfaces_summary = cast(dict[str, JsonValue], summary_any)
        else:
            surfaces_summary = {
                "service_candidates_seen": 0,
                "surfaces": 0,
                "unknowns": 0,
                "classification": "candidate",
                "observation": "static_reference",
            }
        surfaces_any = details.get("surfaces")
        surfaces: list[JsonValue]
        if isinstance(surfaces_any, list):
            surfaces = cast(list[JsonValue], surfaces_any)
        else:
            surfaces = []
        unknowns_any = details.get("unknowns")
        surface_unknowns: list[JsonValue]
        if isinstance(unknowns_any, list):
            surface_unknowns = cast(list[JsonValue], unknowns_any)
        else:
            surface_unknowns = []
        report["surfaces"] = {
            "status": stage_result.status,
            "evidence": cast(list[JsonValue], cast(list[object], evidence_list)),
            "summary": surfaces_summary,
            "surfaces": surfaces,
            "unknowns": surface_unknowns,
        }
        return

    if stage == "graph":
        evidence_list = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/graph", "note": "evidence missing"}],
        )
        summary_any = details.get("summary")
        graph_summary: dict[str, JsonValue]
        if isinstance(summary_any, dict):
            graph_summary = cast(dict[str, JsonValue], summary_any)
        else:
            graph_summary = {
                "nodes": 0,
                "edges": 0,
                "components": 0,
                "endpoints": 0,
                "surfaces": 0,
                "vendors": 0,
                "classification": "candidate",
                "observation": "static_reference",
            }
        nodes_any = details.get("nodes")
        nodes: list[JsonValue]
        if isinstance(nodes_any, list):
            nodes = cast(list[JsonValue], nodes_any)
        else:
            nodes = []
        edges_any = details.get("edges")
        edges: list[JsonValue]
        if isinstance(edges_any, list):
            edges = cast(list[JsonValue], edges_any)
        else:
            edges = []
        report["graph"] = {
            "status": stage_result.status,
            "evidence": cast(list[JsonValue], cast(list[object], evidence_list)),
            "summary": graph_summary,
            "nodes": nodes,
            "edges": edges,
            "details": details,
        }
        return

    if stage == "attack_surface":
        evidence_list = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/attack_surface", "note": "evidence missing"}],
        )
        summary_any = details.get("summary")
        attack_surface_summary: dict[str, JsonValue]
        if isinstance(summary_any, dict):
            attack_surface_summary = cast(dict[str, JsonValue], summary_any)
        else:
            attack_surface_summary = {
                "surfaces": 0,
                "endpoints": 0,
                "graph_nodes": 0,
                "graph_edges": 0,
                "attack_surface_items": 0,
                "unknowns": 0,
                "classification": "candidate",
                "observation": "static_reference",
            }
        items_any = details.get("attack_surface")
        items: list[JsonValue]
        if isinstance(items_any, list):
            items = cast(list[JsonValue], items_any)
        else:
            items = []
        unknowns_any = details.get("unknowns")
        attack_surface_unknowns: list[JsonValue]
        if isinstance(unknowns_any, list):
            attack_surface_unknowns = cast(list[JsonValue], unknowns_any)
        else:
            attack_surface_unknowns = []
        report["attack_surface"] = {
            "status": stage_result.status,
            "evidence": cast(list[JsonValue], cast(list[object], evidence_list)),
            "summary": attack_surface_summary,
            "attack_surface": items,
            "unknowns": attack_surface_unknowns,
            "details": details,
        }
        return

    if stage == "functional_spec":
        evidence_list = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/functional_spec", "note": "evidence missing"}],
        )
        summary_any = details.get("summary")
        functional_spec_summary: dict[str, JsonValue]
        if isinstance(summary_any, dict):
            functional_spec_summary = cast(dict[str, JsonValue], summary_any)
        else:
            functional_spec_summary = {
                "components": 0,
                "components_with_inputs": 0,
                "components_with_endpoints": 0,
                "classification": "candidate",
                "observation": "deterministic_static_inference",
            }
        spec_any = details.get("functional_spec")
        spec: list[JsonValue]
        if isinstance(spec_any, list):
            spec = cast(list[JsonValue], spec_any)
        else:
            spec = []
        report["functional_spec"] = {
            "status": stage_result.status,
            "evidence": cast(list[JsonValue], cast(list[object], evidence_list)),
            "summary": functional_spec_summary,
            "functional_spec": spec,
            "details": details,
        }
        return

    if stage == "threat_model":
        evidence_list = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/threat_model", "note": "evidence missing"}],
        )
        summary_any = details.get("summary")
        threat_model_summary: dict[str, JsonValue]
        if isinstance(summary_any, dict):
            threat_model_summary = cast(dict[str, JsonValue], summary_any)
        else:
            threat_model_summary = {
                "taxonomy": [
                    "spoofing",
                    "tampering",
                    "repudiation",
                    "information_disclosure",
                    "denial_of_service",
                    "elevation_of_privilege",
                ],
                "attack_surface_items": 0,
                "threats": 0,
                "assumptions": 0,
                "mitigations": 0,
                "unknowns": 0,
                "classification": "candidate",
                "observation": "deterministic_static_inference",
            }
        threats_any = details.get("threats")
        threats: list[JsonValue]
        if isinstance(threats_any, list):
            threats = cast(list[JsonValue], threats_any)
        else:
            threats = []
        assumptions_any = details.get("assumptions")
        assumptions: list[JsonValue]
        if isinstance(assumptions_any, list):
            assumptions = cast(list[JsonValue], assumptions_any)
        else:
            assumptions = []
        mitigations_any = details.get("mitigations")
        mitigations: list[JsonValue]
        if isinstance(mitigations_any, list):
            mitigations = cast(list[JsonValue], mitigations_any)
        else:
            mitigations = []
        unknowns_any = details.get("unknowns")
        unknowns: list[JsonValue]
        if isinstance(unknowns_any, list):
            unknowns = cast(list[JsonValue], unknowns_any)
        else:
            unknowns = []
        report["threat_model"] = {
            "status": stage_result.status,
            "evidence": cast(list[JsonValue], cast(list[object], evidence_list)),
            "summary": threat_model_summary,
            "threats": threats,
            "assumptions": assumptions,
            "mitigations": mitigations,
            "unknowns": unknowns,
            "details": details,
        }
        return

    if stage == "llm_synthesis":
        evidence_list = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/llm_synthesis", "note": "evidence missing"}],
        )
        summary_any = details.get("summary")
        llm_synthesis_summary: dict[str, JsonValue]
        if isinstance(summary_any, dict):
            llm_synthesis_summary = cast(dict[str, JsonValue], summary_any)
        else:
            llm_synthesis_summary = {
                "input_artifacts": 0,
                "candidate_claims": 0,
                "claims_emitted": 0,
                "claims_dropped": 0,
                "max_claims": 0,
                "bounded_output": True,
            }
        claims_any = details.get("claims")
        claims: list[JsonValue]
        if isinstance(claims_any, list):
            claims = cast(list[JsonValue], claims_any)
        else:
            claims = []
        reason_any = details.get("reason")
        reason = reason_any if isinstance(reason_any, str) else ""
        report["llm_synthesis"] = {
            "status": stage_result.status,
            "summary": llm_synthesis_summary,
            "claims": claims,
            "reason": reason,
            "evidence": cast(list[JsonValue], cast(list[object], evidence_list)),
            "details": details,
        }
        return

    if stage == "poc_validation":
        poc_validation_evidence = normalize_evidence_list(
            details.get("evidence"),
            fallback=[
                {
                    "path": "stages/poc_validation",
                    "note": "evidence missing",
                }
            ],
        )
        report["poc_validation"] = {
            "status": stage_result.status,
            "evidence": cast(
                list[JsonValue], cast(list[object], poc_validation_evidence)
            ),
            "details": details,
        }
        return

    if stage in ("exploit_gate", "exploit_chain", "exploit_policy"):
        exploit_stage_evidence = normalize_evidence_list(
            details.get("evidence"),
            fallback=[
                {
                    "path": f"stages/{stage}",
                    "note": "evidence missing",
                }
            ],
        )
        report[stage] = {
            "status": stage_result.status,
            "evidence": cast(
                list[JsonValue], cast(list[object], exploit_stage_evidence)
            ),
            "details": details,
        }
        return

    if stage == "dynamic_validation":
        dynamic_validation_evidence = normalize_evidence_list(
            details.get("evidence"),
            fallback=[
                {
                    "path": "stages/dynamic_validation",
                    "note": "evidence missing",
                }
            ],
        )
        dynamic_scope_any = details.get("dynamic_scope")
        dynamic_scope = (
            dynamic_scope_any if isinstance(dynamic_scope_any, str) else "single_binary"
        )
        report["dynamic_validation"] = {
            "status": stage_result.status,
            "dynamic_scope": dynamic_scope,
            "evidence": cast(
                list[JsonValue], cast(list[object], dynamic_validation_evidence)
            ),
            "details": details,
        }
        return

    if stage == "emulation":
        emu_evidence = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/emulation", "note": "evidence missing"}],
        )
        emu_reason_any = details.get("reason")
        emu_reason = (
            emu_reason_any if isinstance(emu_reason_any, str) and emu_reason_any else ""
        )
        report["emulation"] = {
            "status": stage_result.status,
            "reason": emu_reason,
            "evidence": cast(list[JsonValue], cast(list[object], emu_evidence)),
            "details": details,
        }


def _resolve_subset_stages(
    info: RunInfo,
    stage_names: list[str],
    *,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> list[Stage]:
    factories = stage_factories()
    valid_names = ", ".join(factories.keys())
    resolved: list[Stage] = []

    for raw_name in stage_names:
        stage_name = raw_name.strip()
        if not stage_name:
            raise ValueError("stage_name must be a non-empty, non-whitespace string")
        factory = factories.get(stage_name)
        if factory is None:
            raise ValueError(
                f"Unknown stage '{stage_name}'. Valid stage names: {valid_names}"
            )
        resolved.append(factory(info, source_input_path, remaining_s, no_llm))

    return resolved


def run_subset(
    info: RunInfo,
    stage_names: list[str],
    *,
    time_budget_s: int = 3600,
    no_llm: bool = False,
) -> RunReport:
    ctx = StageContext(
        run_dir=info.run_dir,
        logs_dir=info.run_dir / "logs",
        report_dir=info.run_dir / "report",
    )

    report = _load_report_json(info.report_json_path)
    source_input_path = _load_manifest_input_path(info.manifest_path)

    budget_s = int(time_budget_s)
    if budget_s < 0:
        budget_s = 0

    def remaining_s() -> float:
        return float(budget_s)

    stages = _resolve_subset_stages(
        info,
        stage_names,
        source_input_path=source_input_path,
        remaining_s=remaining_s,
        no_llm=no_llm,
    )

    rep = run_stages(stages, ctx)
    _write_stage_manifests(ctx=ctx, stages=stages, report=rep)

    for stage_result in rep.stage_results:
        _apply_stage_result_to_report(report, stage_result, budget_s=budget_s)

    existing_limits = normalize_limitations_list(report.get("limitations"))
    report["limitations"] = cast(
        list[JsonValue], list(existing_limits) + list(rep.limitations)
    )

    _set_report_completion(
        report,
        is_final=False,
        reason="subset execution does not produce a finalized report",
        findings_executed=False,
    )
    _refresh_integrity_and_completeness(report, info, findings_executed=False)

    _ = reporting.write_report_json(info.run_dir / "report", report)
    return rep


def analyze_run(
    info: RunInfo,
    *,
    time_budget_s: int = 3600,
    no_llm: bool = False,
    force_retriage: bool = False,
) -> str:
    ctx = StageContext(
        run_dir=info.run_dir,
        logs_dir=info.run_dir / "logs",
        report_dir=info.run_dir / "report",
    )

    report = _load_report_json(info.report_json_path)
    source_input_path = _load_manifest_input_path(info.manifest_path)
    manifest_profile = _load_manifest_profile(info.manifest_path)
    if no_llm:
        report["llm"] = _llm_skipped_report("disabled by --no-llm")
    else:
        codex_probe_mod = importlib.import_module("aiedge.codex_probe")
        codex_probe_fn = cast(
            Callable[[], dict[str, JsonValue]],
            getattr(codex_probe_mod, "probe_codex_cli"),
        )
        report["llm"] = codex_probe_fn()

    budget_s = int(time_budget_s)
    if budget_s < 0:
        budget_s = 0

    def remaining_s() -> float:
        return float(budget_s)

    def combine_overall_status(*statuses: str) -> str:
        sts = list(statuses)
        if not sts:
            return "skipped"
        if all(s == "skipped" for s in sts):
            return "skipped"
        if any(s in ("failed", "partial") for s in sts):
            return "partial"
        return "ok"

    def normalize_evidence_list(
        evidence_any: object, *, fallback: list[dict[str, JsonValue]]
    ) -> list[dict[str, JsonValue]]:
        if not isinstance(evidence_any, list):
            return list(fallback)
        out: list[dict[str, JsonValue]] = []
        for item in cast(list[object], evidence_any):
            if isinstance(item, dict):
                obj = cast(dict[str, object], item)
                path_s = obj.get("path")
                if isinstance(path_s, str) and path_s:
                    ev: dict[str, JsonValue] = {"path": path_s}
                    note_any = obj.get("note")
                    if isinstance(note_any, str) and note_any:
                        ev["note"] = note_any
                    snippet_any = obj.get("snippet")
                    if isinstance(snippet_any, str) and snippet_any:
                        ev["snippet"] = snippet_any
                    snippet_sha_any = obj.get("snippet_sha256")
                    if isinstance(snippet_sha_any, str) and snippet_sha_any:
                        ev["snippet_sha256"] = snippet_sha_any
                    out.append(ev)
            elif isinstance(item, str) and item:
                out.append({"path": item})
        return out if out else list(fallback)

    def normalize_limitations_list(limits_any: object) -> list[str]:
        if not isinstance(limits_any, list):
            return []
        out: list[str] = []
        for x in cast(list[object], limits_any):
            if isinstance(x, str) and x:
                out.append(x)
        return out

    def make_emulation_stage() -> Stage:
        mod = importlib.import_module("aiedge.emulation")
        cls = cast(type[Stage], getattr(mod, "EmulationStage"))
        return cls()

    def make_ota_fs_stage() -> Stage:
        mod = importlib.import_module("aiedge.ota_fs")
        cls = cast(type[Stage], getattr(mod, "OtaFsStage"))
        return cls()

    def make_ota_roots_stage() -> Stage:
        mod = importlib.import_module("aiedge.ota_roots")
        cls = cast(type[Stage], getattr(mod, "OtaRootsStage"))
        return cls()

    def make_ota_boottriage_stage() -> Stage:
        mod = importlib.import_module("aiedge.ota_boottriage")
        cls = cast(type[Stage], getattr(mod, "OtaBootTriageStage"))
        return cls()

    extraction_default_timeout_s = 600
    extraction_timeout_s: int | None
    budget_limits: list[str] = []

    remaining_before_extraction_s_raw = remaining_s()
    remaining_before_extraction_s = _quantize_remaining_budget_s(
        remaining_before_extraction_s_raw
    )
    if remaining_before_extraction_s <= 0:
        budget_limits.append(
            f"Time budget exhausted before extraction started (budget={budget_s}s); extraction skipped."
        )
        report["extraction"] = {
            "status": "skipped",
            "confidence": 0.0,
            "summary": {
                "tool": "binwalk",
                "binwalk_available": False,
                "extracted_dir": "stages/extraction/_firmware.bin.extracted",
                "extracted_file_count": 0,
                "time_budget_s": int(budget_s),
                "extraction_timeout_s": 0.0,
            },
            "evidence": [
                {"path": "stages/extraction", "note": "skipped"},
                {"path": "stages/extraction/binwalk.log", "note": "not generated"},
            ],
            "reasons": [
                "extraction skipped due to overall time budget",
            ],
            "details": {
                "time_budget_s": int(budget_s),
                "remaining_budget_s": 0.0,
            },
        }

        existing_limits_early = normalize_limitations_list(report.get("limitations"))
        report["limitations"] = cast(
            list[JsonValue],
            list(existing_limits_early) + list(budget_limits),
        )

        early_stages = [
            ToolingStage(),
            OtaStage(info.firmware_dest, source_input_path=source_input_path),
            OtaPayloadStage(info.firmware_dest),
            make_ota_fs_stage(),
            make_ota_roots_stage(),
            make_ota_boottriage_stage(),
            StructureStage(info.firmware_dest),
            CarvingStage(info.firmware_dest),
            FirmwareProfileStage(),
            InventoryStage(),
            EndpointsStage(),
            SurfacesStage(),
            GraphStage(),
            AttackSurfaceStage(),
            FunctionalSpecStage(),
            ThreatModelStage(),
            AttributionStage(),
            LLMSynthesisStage(no_llm=no_llm),
            make_emulation_stage(),
        ]
        inv_rep = run_stages(early_stages, ctx)
        _write_stage_manifests(ctx=ctx, stages=early_stages, report=inv_rep)

        ota_res = next((r for r in inv_rep.stage_results if r.stage == "ota"), None)
        if ota_res is not None:
            ota_details = dict(ota_res.details)
            ota_evidence = normalize_evidence_list(
                ota_details.get("evidence"),
                fallback=[{"path": "stages/ota", "note": "evidence missing"}],
            )
            report["ota"] = {
                "status": ota_res.status,
                "evidence": cast(list[JsonValue], cast(list[object], ota_evidence)),
                "details": ota_details,
            }
        ota_payload_res = next(
            (r for r in inv_rep.stage_results if r.stage == "ota_payload"), None
        )
        if ota_payload_res is not None:
            ota_payload_details = dict(ota_payload_res.details)
            ota_payload_evidence = normalize_evidence_list(
                ota_payload_details.get("evidence"),
                fallback=[{"path": "stages/ota", "note": "evidence missing"}],
            )
            report["ota_payload"] = {
                "status": ota_payload_res.status,
                "evidence": cast(
                    list[JsonValue], cast(list[object], ota_payload_evidence)
                ),
                "details": ota_payload_details,
            }
        ota_fs_res = next(
            (r for r in inv_rep.stage_results if r.stage == "ota_fs"), None
        )
        if ota_fs_res is not None:
            ota_fs_details = dict(ota_fs_res.details)
            ota_fs_evidence = normalize_evidence_list(
                ota_fs_details.get("evidence"),
                fallback=[{"path": "stages/ota", "note": "evidence missing"}],
            )
            report["ota_fs"] = {
                "status": ota_fs_res.status,
                "evidence": cast(list[JsonValue], cast(list[object], ota_fs_evidence)),
                "details": ota_fs_details,
            }
        ota_roots_res = next(
            (r for r in inv_rep.stage_results if r.stage == "ota_roots"), None
        )
        if ota_roots_res is not None:
            ota_roots_details = dict(ota_roots_res.details)
            ota_roots_evidence = normalize_evidence_list(
                ota_roots_details.get("evidence"),
                fallback=[{"path": "stages/ota", "note": "evidence missing"}],
            )
            report["ota_roots"] = {
                "status": ota_roots_res.status,
                "evidence": cast(
                    list[JsonValue], cast(list[object], ota_roots_evidence)
                ),
                "details": ota_roots_details,
            }
        ota_boottriage_res = next(
            (r for r in inv_rep.stage_results if r.stage == "ota_boottriage"), None
        )
        if ota_boottriage_res is not None:
            ota_boottriage_details = dict(ota_boottriage_res.details)
            ota_boottriage_evidence = normalize_evidence_list(
                ota_boottriage_details.get("evidence"),
                fallback=[
                    {"path": "stages/ota/boottriage", "note": "evidence missing"}
                ],
            )
            report["ota_boottriage"] = {
                "status": ota_boottriage_res.status,
                "evidence": cast(
                    list[JsonValue], cast(list[object], ota_boottriage_evidence)
                ),
                "details": ota_boottriage_details,
            }
        tooling_res = next(
            (r for r in inv_rep.stage_results if r.stage == "tooling"), None
        )
        if tooling_res is not None:
            tooling_details = dict(tooling_res.details)
            tooling_evidence = normalize_evidence_list(
                tooling_details.get("evidence"),
                fallback=[{"path": "stages/tooling", "note": "evidence missing"}],
            )
            report["tooling"] = {
                "status": tooling_res.status,
                "evidence": cast(list[JsonValue], cast(list[object], tooling_evidence)),
                "details": tooling_details,
            }

        structure_res = next(
            (r for r in inv_rep.stage_results if r.stage == "structure"), None
        )
        if structure_res is not None:
            structure_details = dict(structure_res.details)
            structure_evidence = normalize_evidence_list(
                structure_details.get("evidence"),
                fallback=[{"path": "stages/structure", "note": "evidence missing"}],
            )
            report["structure"] = {
                "status": structure_res.status,
                "evidence": cast(
                    list[JsonValue], cast(list[object], structure_evidence)
                ),
                "details": structure_details,
            }

        carving_res = next(
            (r for r in inv_rep.stage_results if r.stage == "carving"), None
        )
        if carving_res is not None:
            carving_details = dict(carving_res.details)
            carving_evidence = normalize_evidence_list(
                carving_details.get("evidence"),
                fallback=[{"path": "stages/carving", "note": "evidence missing"}],
            )
            report["carving"] = {
                "status": carving_res.status,
                "evidence": cast(list[JsonValue], cast(list[object], carving_evidence)),
                "details": carving_details,
            }
        firmware_profile_res = next(
            (r for r in inv_rep.stage_results if r.stage == "firmware_profile"), None
        )
        if firmware_profile_res is not None:
            _apply_stage_result_to_report(
                report, firmware_profile_res, budget_s=budget_s
            )
        inv_res = next(
            (r for r in inv_rep.stage_results if r.stage == "inventory"), None
        )
        llm_synthesis_res = next(
            (r for r in inv_rep.stage_results if r.stage == "llm_synthesis"), None
        )
        if llm_synthesis_res is None:
            report["llm_synthesis"] = {
                "status": "failed",
                "summary": {
                    "input_artifacts": 0,
                    "candidate_claims": 0,
                    "claims_emitted": 0,
                    "claims_dropped": 0,
                    "max_claims": 0,
                    "bounded_output": True,
                },
                "claims": [],
                "reason": "llm_synthesis stage did not run",
                "evidence": [
                    {"path": "stages/llm_synthesis", "note": "did not run"},
                ],
            }
        else:
            _apply_stage_result_to_report(report, llm_synthesis_res, budget_s=budget_s)
        emu_res = next(
            (r for r in inv_rep.stage_results if r.stage == "emulation"), None
        )
        inv_status = "failed"
        emu_status = "failed"
        if inv_res is None:
            report["inventory"] = {
                "status": "failed",
                "evidence": [
                    {"path": "stages/inventory", "note": "did not run"},
                ],
                "summary": {
                    "roots_scanned": 0,
                    "files": 0,
                    "binaries": 0,
                    "configs": 0,
                    "string_hits": 0,
                },
                "service_candidates": [],
                "services": [],
            }
        else:
            inv_status = inv_res.status
            inv_details = dict(inv_res.details)
            inv_evidence = normalize_evidence_list(
                inv_details.get("evidence"),
                fallback=[{"path": "stages/inventory", "note": "evidence missing"}],
            )
            summary_any = inv_details.get("summary")
            inv_summary: dict[str, JsonValue]
            if isinstance(summary_any, dict):
                inv_summary = cast(dict[str, JsonValue], summary_any)
            else:
                inv_summary = {
                    "roots_scanned": 0,
                    "files": 0,
                    "binaries": 0,
                    "configs": 0,
                    "string_hits": 0,
                }
            candidates_any = inv_details.get("service_candidates")
            inv_service_candidates: list[JsonValue]
            if isinstance(candidates_any, list):
                inv_service_candidates = cast(list[JsonValue], candidates_any)
            else:
                inv_service_candidates = []
            services_any = inv_details.get("services")
            inv_services: list[JsonValue]
            if isinstance(services_any, list):
                inv_services = cast(list[JsonValue], services_any)
            else:
                inv_services = []
            report["inventory"] = {
                "status": inv_res.status,
                "evidence": cast(list[JsonValue], cast(list[object], inv_evidence)),
                "summary": inv_summary,
                "service_candidates": inv_service_candidates,
                "services": inv_services,
            }

        attr_res = next(
            (r for r in inv_rep.stage_results if r.stage == "attribution"), None
        )
        if attr_res is None:
            report["attribution"] = {
                "status": "failed",
                "evidence": [
                    {"path": "stages/attribution", "note": "did not run"},
                ],
                "claims": [],
            }
        else:
            attr_details = dict(attr_res.details)
            attr_evidence = normalize_evidence_list(
                attr_details.get("evidence"),
                fallback=[{"path": "stages/attribution", "note": "evidence missing"}],
            )
            claims_any = attr_details.get("claims")
            attr_claims: list[JsonValue]
            if isinstance(claims_any, list):
                attr_claims = cast(list[JsonValue], claims_any)
            else:
                attr_claims = []
            report["attribution"] = {
                "status": attr_res.status,
                "evidence": cast(list[JsonValue], cast(list[object], attr_evidence)),
                "claims": attr_claims,
                "details": attr_details,
            }

        endpoints_res = next(
            (r for r in inv_rep.stage_results if r.stage == "endpoints"), None
        )
        if endpoints_res is None:
            report["endpoints"] = {
                "status": "failed",
                "evidence": [
                    {"path": "stages/endpoints", "note": "did not run"},
                ],
                "summary": {
                    "roots_scanned": 0,
                    "files_scanned": 0,
                    "endpoints": 0,
                    "matches_seen": 0,
                    "classification": "candidate",
                    "observation": "static_reference",
                },
                "endpoints": [],
            }
        else:
            endpoints_details = dict(endpoints_res.details)
            endpoints_evidence = normalize_evidence_list(
                endpoints_details.get("evidence"),
                fallback=[{"path": "stages/endpoints", "note": "evidence missing"}],
            )
            summary_any = endpoints_details.get("summary")
            endpoints_summary: dict[str, JsonValue]
            if isinstance(summary_any, dict):
                endpoints_summary = cast(dict[str, JsonValue], summary_any)
            else:
                endpoints_summary = {
                    "roots_scanned": 0,
                    "files_scanned": 0,
                    "endpoints": 0,
                    "matches_seen": 0,
                    "classification": "candidate",
                    "observation": "static_reference",
                }
            endpoints_any = endpoints_details.get("endpoints")
            endpoints_payload: list[JsonValue]
            if isinstance(endpoints_any, list):
                endpoints_payload = cast(list[JsonValue], endpoints_any)
            else:
                endpoints_payload = []
            report["endpoints"] = {
                "status": endpoints_res.status,
                "evidence": cast(
                    list[JsonValue], cast(list[object], endpoints_evidence)
                ),
                "summary": endpoints_summary,
                "endpoints": endpoints_payload,
            }

        surfaces_res = next(
            (r for r in inv_rep.stage_results if r.stage == "surfaces"), None
        )
        if surfaces_res is None:
            report["surfaces"] = {
                "status": "failed",
                "evidence": [
                    {"path": "stages/surfaces", "note": "did not run"},
                ],
                "summary": {
                    "service_candidates_seen": 0,
                    "surfaces": 0,
                    "unknowns": 0,
                    "classification": "candidate",
                    "observation": "static_reference",
                },
                "surfaces": [],
                "unknowns": [],
            }
        else:
            surfaces_details = dict(surfaces_res.details)
            surfaces_evidence = normalize_evidence_list(
                surfaces_details.get("evidence"),
                fallback=[{"path": "stages/surfaces", "note": "evidence missing"}],
            )
            surfaces_summary_any = surfaces_details.get("summary")
            surfaces_summary: dict[str, JsonValue]
            if isinstance(surfaces_summary_any, dict):
                surfaces_summary = cast(dict[str, JsonValue], surfaces_summary_any)
            else:
                surfaces_summary = {
                    "service_candidates_seen": 0,
                    "surfaces": 0,
                    "unknowns": 0,
                    "classification": "candidate",
                    "observation": "static_reference",
                }
            surfaces_any = surfaces_details.get("surfaces")
            surfaces_payload: list[JsonValue]
            if isinstance(surfaces_any, list):
                surfaces_payload = cast(list[JsonValue], surfaces_any)
            else:
                surfaces_payload = []
            unknowns_any = surfaces_details.get("unknowns")
            surface_unknowns_payload: list[JsonValue]
            if isinstance(unknowns_any, list):
                surface_unknowns_payload = cast(list[JsonValue], unknowns_any)
            else:
                surface_unknowns_payload = []
            report["surfaces"] = {
                "status": surfaces_res.status,
                "evidence": cast(
                    list[JsonValue], cast(list[object], surfaces_evidence)
                ),
                "summary": surfaces_summary,
                "surfaces": surfaces_payload,
                "unknowns": surface_unknowns_payload,
            }

        graph_res = next((r for r in inv_rep.stage_results if r.stage == "graph"), None)
        if graph_res is None:
            report["graph"] = {
                "status": "failed",
                "evidence": [{"path": "stages/graph", "note": "did not run"}],
                "summary": {
                    "nodes": 0,
                    "edges": 0,
                    "components": 0,
                    "endpoints": 0,
                    "surfaces": 0,
                    "vendors": 0,
                    "classification": "candidate",
                    "observation": "static_reference",
                },
                "nodes": [],
                "edges": [],
            }
        else:
            graph_details = dict(graph_res.details)
            graph_evidence = normalize_evidence_list(
                graph_details.get("evidence"),
                fallback=[{"path": "stages/graph", "note": "evidence missing"}],
            )
            graph_summary_any = graph_details.get("summary")
            graph_summary: dict[str, JsonValue]
            if isinstance(graph_summary_any, dict):
                graph_summary = cast(dict[str, JsonValue], graph_summary_any)
            else:
                graph_summary = {
                    "nodes": 0,
                    "edges": 0,
                    "components": 0,
                    "endpoints": 0,
                    "surfaces": 0,
                    "vendors": 0,
                    "classification": "candidate",
                    "observation": "static_reference",
                }
            graph_nodes_any = graph_details.get("nodes")
            graph_nodes: list[JsonValue]
            if isinstance(graph_nodes_any, list):
                graph_nodes = cast(list[JsonValue], graph_nodes_any)
            else:
                graph_nodes = []
            graph_edges_any = graph_details.get("edges")
            graph_edges: list[JsonValue]
            if isinstance(graph_edges_any, list):
                graph_edges = cast(list[JsonValue], graph_edges_any)
            else:
                graph_edges = []
            report["graph"] = {
                "status": graph_res.status,
                "evidence": cast(list[JsonValue], cast(list[object], graph_evidence)),
                "summary": graph_summary,
                "nodes": graph_nodes,
                "edges": graph_edges,
                "details": graph_details,
            }

        attack_surface_res = next(
            (r for r in inv_rep.stage_results if r.stage == "attack_surface"), None
        )
        if attack_surface_res is None:
            report["attack_surface"] = {
                "status": "failed",
                "evidence": [
                    {"path": "stages/attack_surface", "note": "did not run"},
                ],
                "summary": {
                    "surfaces": 0,
                    "endpoints": 0,
                    "graph_nodes": 0,
                    "graph_edges": 0,
                    "attack_surface_items": 0,
                    "unknowns": 0,
                    "classification": "candidate",
                    "observation": "static_reference",
                },
                "attack_surface": [],
                "unknowns": [],
            }
        else:
            attack_surface_details = dict(attack_surface_res.details)
            attack_surface_evidence = normalize_evidence_list(
                attack_surface_details.get("evidence"),
                fallback=[
                    {"path": "stages/attack_surface", "note": "evidence missing"}
                ],
            )
            attack_surface_summary_any = attack_surface_details.get("summary")
            attack_surface_summary: dict[str, JsonValue]
            if isinstance(attack_surface_summary_any, dict):
                attack_surface_summary = cast(
                    dict[str, JsonValue], attack_surface_summary_any
                )
            else:
                attack_surface_summary = {
                    "surfaces": 0,
                    "endpoints": 0,
                    "graph_nodes": 0,
                    "graph_edges": 0,
                    "attack_surface_items": 0,
                    "unknowns": 0,
                    "classification": "candidate",
                    "observation": "static_reference",
                }
            attack_surface_items_any = attack_surface_details.get("attack_surface")
            attack_surface_items: list[JsonValue]
            if isinstance(attack_surface_items_any, list):
                attack_surface_items = cast(list[JsonValue], attack_surface_items_any)
            else:
                attack_surface_items = []
            unknowns_any = attack_surface_details.get("unknowns")
            attack_surface_unknowns_payload: list[JsonValue]
            if isinstance(unknowns_any, list):
                attack_surface_unknowns_payload = cast(list[JsonValue], unknowns_any)
            else:
                attack_surface_unknowns_payload = []
            report["attack_surface"] = {
                "status": attack_surface_res.status,
                "evidence": cast(
                    list[JsonValue], cast(list[object], attack_surface_evidence)
                ),
                "summary": attack_surface_summary,
                "attack_surface": attack_surface_items,
                "unknowns": attack_surface_unknowns_payload,
                "details": attack_surface_details,
            }

        threat_model_res = next(
            (r for r in inv_rep.stage_results if r.stage == "threat_model"), None
        )
        if threat_model_res is None:
            report["threat_model"] = {
                "status": "failed",
                "evidence": [
                    {"path": "stages/threat_model", "note": "did not run"},
                ],
                "summary": {
                    "taxonomy": [
                        "spoofing",
                        "tampering",
                        "repudiation",
                        "information_disclosure",
                        "denial_of_service",
                        "elevation_of_privilege",
                    ],
                    "attack_surface_items": 0,
                    "threats": 0,
                    "assumptions": 0,
                    "mitigations": 0,
                    "unknowns": 0,
                    "classification": "candidate",
                    "observation": "deterministic_static_inference",
                },
                "threats": [],
                "assumptions": [],
                "mitigations": [],
                "unknowns": [],
            }
        else:
            threat_model_details = dict(threat_model_res.details)
            threat_model_evidence = normalize_evidence_list(
                threat_model_details.get("evidence"),
                fallback=[{"path": "stages/threat_model", "note": "evidence missing"}],
            )
            threat_model_summary_any = threat_model_details.get("summary")
            threat_model_summary: dict[str, JsonValue]
            if isinstance(threat_model_summary_any, dict):
                threat_model_summary = cast(
                    dict[str, JsonValue], threat_model_summary_any
                )
            else:
                threat_model_summary = {
                    "taxonomy": [
                        "spoofing",
                        "tampering",
                        "repudiation",
                        "information_disclosure",
                        "denial_of_service",
                        "elevation_of_privilege",
                    ],
                    "attack_surface_items": 0,
                    "threats": 0,
                    "assumptions": 0,
                    "mitigations": 0,
                    "unknowns": 0,
                    "classification": "candidate",
                    "observation": "deterministic_static_inference",
                }
            threat_model_threats_any = threat_model_details.get("threats")
            threat_model_threats: list[JsonValue]
            if isinstance(threat_model_threats_any, list):
                threat_model_threats = cast(list[JsonValue], threat_model_threats_any)
            else:
                threat_model_threats = []
            threat_model_assumptions_any = threat_model_details.get("assumptions")
            threat_model_assumptions: list[JsonValue]
            if isinstance(threat_model_assumptions_any, list):
                threat_model_assumptions = cast(
                    list[JsonValue], threat_model_assumptions_any
                )
            else:
                threat_model_assumptions = []
            threat_model_mitigations_any = threat_model_details.get("mitigations")
            threat_model_mitigations: list[JsonValue]
            if isinstance(threat_model_mitigations_any, list):
                threat_model_mitigations = cast(
                    list[JsonValue], threat_model_mitigations_any
                )
            else:
                threat_model_mitigations = []
            threat_model_unknowns_any = threat_model_details.get("unknowns")
            threat_model_unknowns: list[JsonValue]
            if isinstance(threat_model_unknowns_any, list):
                threat_model_unknowns = cast(list[JsonValue], threat_model_unknowns_any)
            else:
                threat_model_unknowns = []
            report["threat_model"] = {
                "status": threat_model_res.status,
                "evidence": cast(
                    list[JsonValue], cast(list[object], threat_model_evidence)
                ),
                "summary": threat_model_summary,
                "threats": threat_model_threats,
                "assumptions": threat_model_assumptions,
                "mitigations": threat_model_mitigations,
                "unknowns": threat_model_unknowns,
                "details": threat_model_details,
            }

        functional_spec_res = next(
            (r for r in inv_rep.stage_results if r.stage == "functional_spec"), None
        )
        if functional_spec_res is None:
            report["functional_spec"] = {
                "status": "failed",
                "evidence": [
                    {"path": "stages/functional_spec", "note": "did not run"},
                ],
                "summary": {
                    "components": 0,
                    "components_with_inputs": 0,
                    "components_with_endpoints": 0,
                    "classification": "candidate",
                    "observation": "deterministic_static_inference",
                },
                "functional_spec": [],
            }
        else:
            functional_spec_details = dict(functional_spec_res.details)
            functional_spec_evidence = normalize_evidence_list(
                functional_spec_details.get("evidence"),
                fallback=[
                    {"path": "stages/functional_spec", "note": "evidence missing"}
                ],
            )
            functional_spec_summary_any = functional_spec_details.get("summary")
            functional_spec_summary: dict[str, JsonValue]
            if isinstance(functional_spec_summary_any, dict):
                functional_spec_summary = cast(
                    dict[str, JsonValue], functional_spec_summary_any
                )
            else:
                functional_spec_summary = {
                    "components": 0,
                    "components_with_inputs": 0,
                    "components_with_endpoints": 0,
                    "classification": "candidate",
                    "observation": "deterministic_static_inference",
                }
            functional_spec_items_any = functional_spec_details.get("functional_spec")
            functional_spec_items: list[JsonValue]
            if isinstance(functional_spec_items_any, list):
                functional_spec_items = cast(list[JsonValue], functional_spec_items_any)
            else:
                functional_spec_items = []
            report["functional_spec"] = {
                "status": functional_spec_res.status,
                "evidence": cast(
                    list[JsonValue], cast(list[object], functional_spec_evidence)
                ),
                "summary": functional_spec_summary,
                "functional_spec": functional_spec_items,
                "details": functional_spec_details,
            }

        if emu_res is None:
            report["emulation"] = {
                "status": "failed",
                "reason": "emulation stage did not run",
                "evidence": [{"path": "stages/emulation", "note": "did not run"}],
            }
        else:
            emu_status = emu_res.status
            emu_details = dict(emu_res.details)
            emu_evidence = normalize_evidence_list(
                emu_details.get("evidence"),
                fallback=[{"path": "stages/emulation", "note": "evidence missing"}],
            )
            emu_reason_any = emu_details.get("reason")
            emu_reason = (
                emu_reason_any
                if isinstance(emu_reason_any, str) and emu_reason_any
                else ""
            )
            report["emulation"] = {
                "status": emu_res.status,
                "reason": emu_reason,
                "evidence": cast(list[JsonValue], cast(list[object], emu_evidence)),
                "details": emu_details,
            }

        findings_res = run_findings(ctx)
        deduped_findings_early = _apply_duplicate_gate_to_findings(
            report=report,
            info=info,
            findings_any=findings_res.findings,
            force_retriage=force_retriage,
        )
        report["findings"] = cast(
            list[JsonValue], cast(list[object], deduped_findings_early)
        )
        report["llm"] = _apply_llm_exec_step(info=info, report=report, no_llm=no_llm)
        _set_report_completion(
            report,
            is_final=True,
            reason="full analyze_run completed",
            findings_executed=True,
        )
        _refresh_integrity_and_completeness(report, info, findings_executed=True)

        report_dir = info.run_dir / "report"
        _ = reporting.write_report_json(report_dir, report)
        _ = reporting.write_report_html(report_dir, report)
        try:
            _write_analyst_report_artifacts(report_dir, report)
        except Exception as exc:
            _mark_report_incomplete_due_to_digest(report=report, info=info, err=exc)
            _ = reporting.write_report_json(report_dir, report)
            _ = reporting.write_report_html(report_dir, report)
            raise
        return combine_overall_status("skipped", inv_status, emu_status)

    extraction_timeout_s = min(
        extraction_default_timeout_s, remaining_before_extraction_s
    )
    if extraction_timeout_s < extraction_default_timeout_s:
        budget_limits.append(
            (
                f"Overall time budget capped extraction timeout to {extraction_timeout_s}s "
                f"(default {extraction_default_timeout_s}s, remaining budget {remaining_before_extraction_s}s)."
            )
        )

    stages = [
        ToolingStage(),
        OtaStage(info.firmware_dest, source_input_path=source_input_path),
        OtaPayloadStage(info.firmware_dest),
        make_ota_fs_stage(),
        make_ota_roots_stage(),
        make_ota_boottriage_stage(),
        ExtractionStage(info.firmware_dest, timeout_s=float(extraction_timeout_s)),
        StructureStage(info.firmware_dest),
        CarvingStage(info.firmware_dest),
        FirmwareProfileStage(),
        InventoryStage(),
        EndpointsStage(),
        SurfacesStage(),
        GraphStage(),
        AttackSurfaceStage(),
        FunctionalSpecStage(),
        ThreatModelStage(),
        AttributionStage(),
        LLMSynthesisStage(no_llm=no_llm),
        make_emulation_stage(),
    ]
    try:
        from .exploit_chain import ExploitChainStage, ExploitGateStage
        from .poc_validation import PocValidationStage
        from .exploit_policy import ExploitEvidencePolicyStage

        stages.append(ExploitGateStage())
        stages.append(ExploitChainStage())
        stages.append(PocValidationStage())
        stages.append(ExploitEvidencePolicyStage())
    except Exception:
        pass
    rep = run_stages(stages, ctx)
    _write_stage_manifests(ctx=ctx, stages=stages, report=rep)

    extraction_res = next(
        (r for r in rep.stage_results if r.stage == "extraction"), None
    )
    if extraction_res is None:
        confidence = 0.0
        reasons: list[JsonValue] = ["extraction stage did not run"]
        status: JsonValue = "failed"
        details: dict[str, JsonValue] = {}
        evidence = [
            {"path": "stages/extraction", "note": "did not run"},
        ]
    else:
        details = dict(extraction_res.details)
        conf_any = details.get("confidence")
        if isinstance(conf_any, (int, float)):
            confidence = float(conf_any)
        elif isinstance(conf_any, str):
            try:
                confidence = float(conf_any)
            except ValueError:
                confidence = 0.0
        else:
            confidence = 0.0
        reasons_any = details.get("reasons")
        if isinstance(reasons_any, list) and all(
            isinstance(x, str) for x in reasons_any
        ):
            reasons = cast(list[JsonValue], reasons_any)
        else:
            reasons = cast(list[JsonValue], list(extraction_res.limitations))
        status = extraction_res.status

        evidence = normalize_evidence_list(
            details.get("evidence"),
            fallback=[{"path": "stages/extraction", "note": "evidence missing"}],
        )

    extracted_dir_any = details.get("extracted_dir")
    extracted_dir = (
        extracted_dir_any
        if isinstance(extracted_dir_any, str) and extracted_dir_any
        else "stages/extraction/_firmware.bin.extracted"
    )
    extracted_count_any = details.get("extracted_file_count")
    extracted_count = (
        int(extracted_count_any) if isinstance(extracted_count_any, int) else 0
    )
    binwalk_av_any = details.get("binwalk_available")
    binwalk_available = (
        bool(binwalk_av_any) if isinstance(binwalk_av_any, bool) else False
    )
    binwalk_log_any = details.get("binwalk_log")
    binwalk_log = (
        binwalk_log_any
        if isinstance(binwalk_log_any, str)
        else "stages/extraction/binwalk.log"
    )
    tool_any = details.get("tool")
    tool_s = tool_any if isinstance(tool_any, str) and tool_any else "binwalk"

    mat_any = details.get("matryoshka")
    mat_enabled = bool(mat_any) if isinstance(mat_any, bool) else False
    mat_depth_any = details.get("matryoshka_depth")
    mat_depth = int(mat_depth_any) if isinstance(mat_depth_any, int) else 0
    lzop_any = details.get("lzop_available")
    lzop_available = bool(lzop_any) if isinstance(lzop_any, bool) else False

    report["extraction"] = {
        "status": status,
        "confidence": float(max(0.0, min(1.0, confidence))),
        "summary": {
            "tool": tool_s,
            "binwalk_available": bool(binwalk_available),
            "binwalk_log": binwalk_log,
            "matryoshka": bool(mat_enabled),
            "matryoshka_depth": int(mat_depth),
            "lzop_available": bool(lzop_available),
            "extracted_dir": extracted_dir,
            "extracted_file_count": int(extracted_count),
            "time_budget_s": int(budget_s),
            "extraction_timeout_s": float(extraction_timeout_s or 0),
        },
        "evidence": cast(list[JsonValue], cast(list[object], evidence)),
        "reasons": reasons,
        "details": details,
    }

    tooling_res2 = next((r for r in rep.stage_results if r.stage == "tooling"), None)
    if tooling_res2 is not None:
        tooling_details2 = dict(tooling_res2.details)
        tooling_evidence2 = normalize_evidence_list(
            tooling_details2.get("evidence"),
            fallback=[{"path": "stages/tooling", "note": "evidence missing"}],
        )
        report["tooling"] = {
            "status": tooling_res2.status,
            "evidence": cast(list[JsonValue], cast(list[object], tooling_evidence2)),
            "details": tooling_details2,
        }

    ota_res2 = next((r for r in rep.stage_results if r.stage == "ota"), None)
    if ota_res2 is not None:
        ota_details2 = dict(ota_res2.details)
        ota_evidence2 = normalize_evidence_list(
            ota_details2.get("evidence"),
            fallback=[{"path": "stages/ota", "note": "evidence missing"}],
        )
        report["ota"] = {
            "status": ota_res2.status,
            "evidence": cast(list[JsonValue], cast(list[object], ota_evidence2)),
            "details": ota_details2,
        }
    ota_payload_res2 = next(
        (r for r in rep.stage_results if r.stage == "ota_payload"), None
    )
    if ota_payload_res2 is not None:
        ota_payload_details2 = dict(ota_payload_res2.details)
        ota_payload_evidence2 = normalize_evidence_list(
            ota_payload_details2.get("evidence"),
            fallback=[{"path": "stages/ota", "note": "evidence missing"}],
        )
        report["ota_payload"] = {
            "status": ota_payload_res2.status,
            "evidence": cast(
                list[JsonValue], cast(list[object], ota_payload_evidence2)
            ),
            "details": ota_payload_details2,
        }
    ota_fs_res2 = next((r for r in rep.stage_results if r.stage == "ota_fs"), None)
    if ota_fs_res2 is not None:
        ota_fs_details2 = dict(ota_fs_res2.details)
        ota_fs_evidence2 = normalize_evidence_list(
            ota_fs_details2.get("evidence"),
            fallback=[{"path": "stages/ota", "note": "evidence missing"}],
        )
        report["ota_fs"] = {
            "status": ota_fs_res2.status,
            "evidence": cast(list[JsonValue], cast(list[object], ota_fs_evidence2)),
            "details": ota_fs_details2,
        }
    ota_roots_res2 = next(
        (r for r in rep.stage_results if r.stage == "ota_roots"), None
    )
    if ota_roots_res2 is not None:
        ota_roots_details2 = dict(ota_roots_res2.details)
        ota_roots_evidence2 = normalize_evidence_list(
            ota_roots_details2.get("evidence"),
            fallback=[{"path": "stages/ota", "note": "evidence missing"}],
        )
        report["ota_roots"] = {
            "status": ota_roots_res2.status,
            "evidence": cast(list[JsonValue], cast(list[object], ota_roots_evidence2)),
            "details": ota_roots_details2,
        }
    ota_boottriage_res2 = next(
        (r for r in rep.stage_results if r.stage == "ota_boottriage"), None
    )
    if ota_boottriage_res2 is not None:
        ota_boottriage_details2 = dict(ota_boottriage_res2.details)
        ota_boottriage_evidence2 = normalize_evidence_list(
            ota_boottriage_details2.get("evidence"),
            fallback=[{"path": "stages/ota/boottriage", "note": "evidence missing"}],
        )
        report["ota_boottriage"] = {
            "status": ota_boottriage_res2.status,
            "evidence": cast(
                list[JsonValue], cast(list[object], ota_boottriage_evidence2)
            ),
            "details": ota_boottriage_details2,
        }

    structure_res2 = next(
        (r for r in rep.stage_results if r.stage == "structure"), None
    )
    if structure_res2 is not None:
        structure_details2 = dict(structure_res2.details)
        structure_evidence2 = normalize_evidence_list(
            structure_details2.get("evidence"),
            fallback=[{"path": "stages/structure", "note": "evidence missing"}],
        )
        report["structure"] = {
            "status": structure_res2.status,
            "evidence": cast(list[JsonValue], cast(list[object], structure_evidence2)),
            "details": structure_details2,
        }

    carving_res2 = next((r for r in rep.stage_results if r.stage == "carving"), None)
    if carving_res2 is not None:
        carving_details2 = dict(carving_res2.details)
        carving_evidence2 = normalize_evidence_list(
            carving_details2.get("evidence"),
            fallback=[{"path": "stages/carving", "note": "evidence missing"}],
        )
        report["carving"] = {
            "status": carving_res2.status,
            "evidence": cast(list[JsonValue], cast(list[object], carving_evidence2)),
            "details": carving_details2,
        }

    firmware_profile_res2 = next(
        (r for r in rep.stage_results if r.stage == "firmware_profile"), None
    )
    if firmware_profile_res2 is not None:
        _apply_stage_result_to_report(report, firmware_profile_res2, budget_s=budget_s)

    inv_res = next((r for r in rep.stage_results if r.stage == "inventory"), None)
    if inv_res is None:
        report["inventory"] = {
            "status": "failed",
            "evidence": [
                {"path": "stages/inventory", "note": "did not run"},
            ],
            "summary": {
                "roots_scanned": 0,
                "files": 0,
                "binaries": 0,
                "configs": 0,
                "string_hits": 0,
            },
            "service_candidates": [],
            "services": [],
        }
    else:
        inv_details = dict(inv_res.details)
        evidence_list = normalize_evidence_list(
            inv_details.get("evidence"),
            fallback=[{"path": "stages/inventory", "note": "evidence missing"}],
        )
        summary_any = inv_details.get("summary")
        summary_dict: dict[str, JsonValue]
        if isinstance(summary_any, dict):
            summary_dict = cast(dict[str, JsonValue], summary_any)
        else:
            summary_dict = {
                "roots_scanned": 0,
                "files": 0,
                "binaries": 0,
                "configs": 0,
                "string_hits": 0,
            }
        candidates_any = inv_details.get("service_candidates")
        inv_service_candidates2: list[JsonValue]
        if isinstance(candidates_any, list):
            inv_service_candidates2 = cast(list[JsonValue], candidates_any)
        else:
            inv_service_candidates2 = []
        services_any = inv_details.get("services")
        inv_services2: list[JsonValue]
        if isinstance(services_any, list):
            inv_services2 = cast(list[JsonValue], services_any)
        else:
            inv_services2 = []
        report["inventory"] = {
            "status": inv_res.status,
            "evidence": cast(list[JsonValue], cast(list[object], evidence_list)),
            "summary": summary_dict,
            "service_candidates": inv_service_candidates2,
            "services": inv_services2,
        }

    attr_res2 = next((r for r in rep.stage_results if r.stage == "attribution"), None)
    if attr_res2 is None:
        report["attribution"] = {
            "status": "failed",
            "evidence": [
                {"path": "stages/attribution", "note": "did not run"},
            ],
            "claims": [],
        }
    else:
        attr_details2 = dict(attr_res2.details)
        attr_evidence2 = normalize_evidence_list(
            attr_details2.get("evidence"),
            fallback=[{"path": "stages/attribution", "note": "evidence missing"}],
        )
        claims_any2 = attr_details2.get("claims")
        attr_claims2: list[JsonValue]
        if isinstance(claims_any2, list):
            attr_claims2 = cast(list[JsonValue], claims_any2)
        else:
            attr_claims2 = []
        report["attribution"] = {
            "status": attr_res2.status,
            "evidence": cast(list[JsonValue], cast(list[object], attr_evidence2)),
            "claims": attr_claims2,
            "details": attr_details2,
        }

    llm_synthesis_res2 = next(
        (r for r in rep.stage_results if r.stage == "llm_synthesis"), None
    )
    if llm_synthesis_res2 is None:
        report["llm_synthesis"] = {
            "status": "failed",
            "summary": {
                "input_artifacts": 0,
                "candidate_claims": 0,
                "claims_emitted": 0,
                "claims_dropped": 0,
                "max_claims": 0,
                "bounded_output": True,
            },
            "claims": [],
            "reason": "llm_synthesis stage did not run",
            "evidence": [
                {"path": "stages/llm_synthesis", "note": "did not run"},
            ],
        }
    else:
        _apply_stage_result_to_report(report, llm_synthesis_res2, budget_s=budget_s)

    endpoints_res2 = next(
        (r for r in rep.stage_results if r.stage == "endpoints"), None
    )
    if endpoints_res2 is None:
        report["endpoints"] = {
            "status": "failed",
            "evidence": [
                {"path": "stages/endpoints", "note": "did not run"},
            ],
            "summary": {
                "roots_scanned": 0,
                "files_scanned": 0,
                "endpoints": 0,
                "matches_seen": 0,
                "classification": "candidate",
                "observation": "static_reference",
            },
            "endpoints": [],
        }
    else:
        endpoints_details2 = dict(endpoints_res2.details)
        endpoints_evidence2 = normalize_evidence_list(
            endpoints_details2.get("evidence"),
            fallback=[{"path": "stages/endpoints", "note": "evidence missing"}],
        )
        endpoints_summary_any2 = endpoints_details2.get("summary")
        endpoints_summary2: dict[str, JsonValue]
        if isinstance(endpoints_summary_any2, dict):
            endpoints_summary2 = cast(dict[str, JsonValue], endpoints_summary_any2)
        else:
            endpoints_summary2 = {
                "roots_scanned": 0,
                "files_scanned": 0,
                "endpoints": 0,
                "matches_seen": 0,
                "classification": "candidate",
                "observation": "static_reference",
            }
        endpoints_any2 = endpoints_details2.get("endpoints")
        endpoints_payload2: list[JsonValue]
        if isinstance(endpoints_any2, list):
            endpoints_payload2 = cast(list[JsonValue], endpoints_any2)
        else:
            endpoints_payload2 = []
        report["endpoints"] = {
            "status": endpoints_res2.status,
            "evidence": cast(list[JsonValue], cast(list[object], endpoints_evidence2)),
            "summary": endpoints_summary2,
            "endpoints": endpoints_payload2,
        }

    surfaces_res2 = next((r for r in rep.stage_results if r.stage == "surfaces"), None)
    if surfaces_res2 is None:
        report["surfaces"] = {
            "status": "failed",
            "evidence": [
                {"path": "stages/surfaces", "note": "did not run"},
            ],
            "summary": {
                "service_candidates_seen": 0,
                "surfaces": 0,
                "unknowns": 0,
                "classification": "candidate",
                "observation": "static_reference",
            },
            "surfaces": [],
            "unknowns": [],
        }
    else:
        surfaces_details2 = dict(surfaces_res2.details)
        surfaces_evidence2 = normalize_evidence_list(
            surfaces_details2.get("evidence"),
            fallback=[{"path": "stages/surfaces", "note": "evidence missing"}],
        )
        surfaces_summary_any2 = surfaces_details2.get("summary")
        surfaces_summary2: dict[str, JsonValue]
        if isinstance(surfaces_summary_any2, dict):
            surfaces_summary2 = cast(dict[str, JsonValue], surfaces_summary_any2)
        else:
            surfaces_summary2 = {
                "service_candidates_seen": 0,
                "surfaces": 0,
                "unknowns": 0,
                "classification": "candidate",
                "observation": "static_reference",
            }
        surfaces_any2 = surfaces_details2.get("surfaces")
        surfaces_payload2: list[JsonValue]
        if isinstance(surfaces_any2, list):
            surfaces_payload2 = cast(list[JsonValue], surfaces_any2)
        else:
            surfaces_payload2 = []
        unknowns_any2 = surfaces_details2.get("unknowns")
        unknowns_payload2: list[JsonValue]
        if isinstance(unknowns_any2, list):
            unknowns_payload2 = cast(list[JsonValue], unknowns_any2)
        else:
            unknowns_payload2 = []
        report["surfaces"] = {
            "status": surfaces_res2.status,
            "evidence": cast(list[JsonValue], cast(list[object], surfaces_evidence2)),
            "summary": surfaces_summary2,
            "surfaces": surfaces_payload2,
            "unknowns": unknowns_payload2,
        }

    graph_res2 = next((r for r in rep.stage_results if r.stage == "graph"), None)
    if graph_res2 is None:
        report["graph"] = {
            "status": "failed",
            "evidence": [
                {"path": "stages/graph", "note": "did not run"},
            ],
            "summary": {
                "nodes": 0,
                "edges": 0,
                "components": 0,
                "endpoints": 0,
                "surfaces": 0,
                "vendors": 0,
                "classification": "candidate",
                "observation": "static_reference",
            },
            "nodes": [],
            "edges": [],
        }
    else:
        graph_details2 = dict(graph_res2.details)
        graph_evidence2 = normalize_evidence_list(
            graph_details2.get("evidence"),
            fallback=[{"path": "stages/graph", "note": "evidence missing"}],
        )
        graph_summary_any2 = graph_details2.get("summary")
        graph_summary2: dict[str, JsonValue]
        if isinstance(graph_summary_any2, dict):
            graph_summary2 = cast(dict[str, JsonValue], graph_summary_any2)
        else:
            graph_summary2 = {
                "nodes": 0,
                "edges": 0,
                "components": 0,
                "endpoints": 0,
                "surfaces": 0,
                "vendors": 0,
                "classification": "candidate",
                "observation": "static_reference",
            }
        graph_nodes_any2 = graph_details2.get("nodes")
        graph_nodes2: list[JsonValue]
        if isinstance(graph_nodes_any2, list):
            graph_nodes2 = cast(list[JsonValue], graph_nodes_any2)
        else:
            graph_nodes2 = []
        graph_edges_any2 = graph_details2.get("edges")
        graph_edges2: list[JsonValue]
        if isinstance(graph_edges_any2, list):
            graph_edges2 = cast(list[JsonValue], graph_edges_any2)
        else:
            graph_edges2 = []
        report["graph"] = {
            "status": graph_res2.status,
            "evidence": cast(list[JsonValue], cast(list[object], graph_evidence2)),
            "summary": graph_summary2,
            "nodes": graph_nodes2,
            "edges": graph_edges2,
            "details": graph_details2,
        }

    attack_surface_res2 = next(
        (r for r in rep.stage_results if r.stage == "attack_surface"), None
    )
    if attack_surface_res2 is None:
        report["attack_surface"] = {
            "status": "failed",
            "evidence": [
                {"path": "stages/attack_surface", "note": "did not run"},
            ],
            "summary": {
                "surfaces": 0,
                "endpoints": 0,
                "graph_nodes": 0,
                "graph_edges": 0,
                "attack_surface_items": 0,
                "unknowns": 0,
                "classification": "candidate",
                "observation": "static_reference",
            },
            "attack_surface": [],
            "unknowns": [],
        }
    else:
        attack_surface_details2 = dict(attack_surface_res2.details)
        attack_surface_evidence2 = normalize_evidence_list(
            attack_surface_details2.get("evidence"),
            fallback=[{"path": "stages/attack_surface", "note": "evidence missing"}],
        )
        attack_surface_summary_any2 = attack_surface_details2.get("summary")
        attack_surface_summary2: dict[str, JsonValue]
        if isinstance(attack_surface_summary_any2, dict):
            attack_surface_summary2 = cast(
                dict[str, JsonValue], attack_surface_summary_any2
            )
        else:
            attack_surface_summary2 = {
                "surfaces": 0,
                "endpoints": 0,
                "graph_nodes": 0,
                "graph_edges": 0,
                "attack_surface_items": 0,
                "unknowns": 0,
                "classification": "candidate",
                "observation": "static_reference",
            }
        attack_surface_items_any2 = attack_surface_details2.get("attack_surface")
        attack_surface_items2: list[JsonValue]
        if isinstance(attack_surface_items_any2, list):
            attack_surface_items2 = cast(list[JsonValue], attack_surface_items_any2)
        else:
            attack_surface_items2 = []
        attack_surface_unknowns_any2 = attack_surface_details2.get("unknowns")
        attack_surface_unknowns2: list[JsonValue]
        if isinstance(attack_surface_unknowns_any2, list):
            attack_surface_unknowns2 = cast(
                list[JsonValue], attack_surface_unknowns_any2
            )
        else:
            attack_surface_unknowns2 = []
        report["attack_surface"] = {
            "status": attack_surface_res2.status,
            "evidence": cast(
                list[JsonValue], cast(list[object], attack_surface_evidence2)
            ),
            "summary": attack_surface_summary2,
            "attack_surface": attack_surface_items2,
            "unknowns": attack_surface_unknowns2,
            "details": attack_surface_details2,
        }

    threat_model_res2 = next(
        (r for r in rep.stage_results if r.stage == "threat_model"), None
    )
    if threat_model_res2 is None:
        report["threat_model"] = {
            "status": "failed",
            "evidence": [
                {"path": "stages/threat_model", "note": "did not run"},
            ],
            "summary": {
                "taxonomy": [
                    "spoofing",
                    "tampering",
                    "repudiation",
                    "information_disclosure",
                    "denial_of_service",
                    "elevation_of_privilege",
                ],
                "attack_surface_items": 0,
                "threats": 0,
                "assumptions": 0,
                "mitigations": 0,
                "unknowns": 0,
                "classification": "candidate",
                "observation": "deterministic_static_inference",
            },
            "threats": [],
            "assumptions": [],
            "mitigations": [],
            "unknowns": [],
        }
    else:
        threat_model_details2 = dict(threat_model_res2.details)
        threat_model_evidence2 = normalize_evidence_list(
            threat_model_details2.get("evidence"),
            fallback=[{"path": "stages/threat_model", "note": "evidence missing"}],
        )
        threat_model_summary_any2 = threat_model_details2.get("summary")
        threat_model_summary2: dict[str, JsonValue]
        if isinstance(threat_model_summary_any2, dict):
            threat_model_summary2 = cast(
                dict[str, JsonValue], threat_model_summary_any2
            )
        else:
            threat_model_summary2 = {
                "taxonomy": [
                    "spoofing",
                    "tampering",
                    "repudiation",
                    "information_disclosure",
                    "denial_of_service",
                    "elevation_of_privilege",
                ],
                "attack_surface_items": 0,
                "threats": 0,
                "assumptions": 0,
                "mitigations": 0,
                "unknowns": 0,
                "classification": "candidate",
                "observation": "deterministic_static_inference",
            }
        threat_model_threats_any2 = threat_model_details2.get("threats")
        threat_model_threats2: list[JsonValue]
        if isinstance(threat_model_threats_any2, list):
            threat_model_threats2 = cast(list[JsonValue], threat_model_threats_any2)
        else:
            threat_model_threats2 = []
        threat_model_assumptions_any2 = threat_model_details2.get("assumptions")
        threat_model_assumptions2: list[JsonValue]
        if isinstance(threat_model_assumptions_any2, list):
            threat_model_assumptions2 = cast(
                list[JsonValue], threat_model_assumptions_any2
            )
        else:
            threat_model_assumptions2 = []
        threat_model_mitigations_any2 = threat_model_details2.get("mitigations")
        threat_model_mitigations2: list[JsonValue]
        if isinstance(threat_model_mitigations_any2, list):
            threat_model_mitigations2 = cast(
                list[JsonValue], threat_model_mitigations_any2
            )
        else:
            threat_model_mitigations2 = []
        threat_model_unknowns_any2 = threat_model_details2.get("unknowns")
        threat_model_unknowns2: list[JsonValue]
        if isinstance(threat_model_unknowns_any2, list):
            threat_model_unknowns2 = cast(list[JsonValue], threat_model_unknowns_any2)
        else:
            threat_model_unknowns2 = []
        report["threat_model"] = {
            "status": threat_model_res2.status,
            "evidence": cast(
                list[JsonValue], cast(list[object], threat_model_evidence2)
            ),
            "summary": threat_model_summary2,
            "threats": threat_model_threats2,
            "assumptions": threat_model_assumptions2,
            "mitigations": threat_model_mitigations2,
            "unknowns": threat_model_unknowns2,
            "details": threat_model_details2,
        }

    functional_spec_res2 = next(
        (r for r in rep.stage_results if r.stage == "functional_spec"), None
    )
    if functional_spec_res2 is None:
        report["functional_spec"] = {
            "status": "failed",
            "evidence": [
                {"path": "stages/functional_spec", "note": "did not run"},
            ],
            "summary": {
                "components": 0,
                "components_with_inputs": 0,
                "components_with_endpoints": 0,
                "classification": "candidate",
                "observation": "deterministic_static_inference",
            },
            "functional_spec": [],
        }
    else:
        functional_spec_details2 = dict(functional_spec_res2.details)
        functional_spec_evidence2 = normalize_evidence_list(
            functional_spec_details2.get("evidence"),
            fallback=[{"path": "stages/functional_spec", "note": "evidence missing"}],
        )
        functional_spec_summary_any2 = functional_spec_details2.get("summary")
        functional_spec_summary2: dict[str, JsonValue]
        if isinstance(functional_spec_summary_any2, dict):
            functional_spec_summary2 = cast(
                dict[str, JsonValue], functional_spec_summary_any2
            )
        else:
            functional_spec_summary2 = {
                "components": 0,
                "components_with_inputs": 0,
                "components_with_endpoints": 0,
                "classification": "candidate",
                "observation": "deterministic_static_inference",
            }
        functional_spec_any2 = functional_spec_details2.get("functional_spec")
        functional_spec_items2: list[JsonValue]
        if isinstance(functional_spec_any2, list):
            functional_spec_items2 = cast(list[JsonValue], functional_spec_any2)
        else:
            functional_spec_items2 = []
        report["functional_spec"] = {
            "status": functional_spec_res2.status,
            "evidence": cast(
                list[JsonValue], cast(list[object], functional_spec_evidence2)
            ),
            "summary": functional_spec_summary2,
            "functional_spec": functional_spec_items2,
            "details": functional_spec_details2,
        }

    emu_res2 = next((r for r in rep.stage_results if r.stage == "emulation"), None)
    if emu_res2 is None:
        report["emulation"] = {
            "status": "failed",
            "reason": "emulation stage did not run",
            "evidence": [{"path": "stages/emulation", "note": "did not run"}],
        }
    else:
        emu_details2 = dict(emu_res2.details)
        emu_evidence2 = normalize_evidence_list(
            emu_details2.get("evidence"),
            fallback=[{"path": "stages/emulation", "note": "evidence missing"}],
        )
        emu_reason_any2 = emu_details2.get("reason")
        emu_reason2 = (
            emu_reason_any2
            if isinstance(emu_reason_any2, str) and emu_reason_any2
            else ""
        )
        report["emulation"] = {
            "status": emu_res2.status,
            "reason": emu_reason2,
            "evidence": cast(list[JsonValue], cast(list[object], emu_evidence2)),
            "details": emu_details2,
        }

    for exploit_stage_name in (
        "exploit_gate",
        "exploit_chain",
        "poc_validation",
        "exploit_policy",
    ):
        exploit_stage_res = next(
            (r for r in rep.stage_results if r.stage == exploit_stage_name), None
        )
        if exploit_stage_res is not None:
            _apply_stage_result_to_report(
                report, exploit_stage_res, budget_s=budget_s
            )

    existing_limits = normalize_limitations_list(report.get("limitations"))
    report["limitations"] = cast(
        list[JsonValue],
        list(existing_limits) + list(budget_limits) + list(rep.limitations),
    )

    findings_res = run_findings(ctx)
    deduped_findings = _apply_duplicate_gate_to_findings(
        report=report,
        info=info,
        findings_any=findings_res.findings,
        force_retriage=force_retriage,
    )
    report["findings"] = cast(list[JsonValue], cast(list[object], deduped_findings))
    report["exploit_assessment"] = _build_exploit_assessment(
        profile=manifest_profile, report=report, run_dir=info.run_dir
    )
    report["llm"] = _apply_llm_exec_step(info=info, report=report, no_llm=no_llm)
    _set_report_completion(
        report,
        is_final=True,
        reason="full analyze_run completed",
        findings_executed=True,
    )
    _refresh_integrity_and_completeness(report, info, findings_executed=True)

    report_dir = info.run_dir / "report"
    _ = reporting.write_report_json(report_dir, report)
    _ = reporting.write_report_html(report_dir, report)
    try:
        _write_analyst_report_artifacts(report_dir, report)
    except Exception as exc:
        _mark_report_incomplete_due_to_digest(report=report, info=info, err=exc)
        _ = reporting.write_report_json(report_dir, report)
        _ = reporting.write_report_html(report_dir, report)
        raise

    extraction_status = cast(str, report["extraction"].get("status", "failed"))
    inventory_status = cast(str, report["inventory"].get("status", "failed"))
    emulation_status = cast(str, report["emulation"].get("status", "failed"))
    return combine_overall_status(extraction_status, inventory_status, emulation_status)
