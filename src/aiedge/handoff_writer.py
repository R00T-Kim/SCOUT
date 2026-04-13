"""firmware_handoff.json writer.

Extracted from run.py to separate handoff assembly from the rest of the
run orchestration. Behaviour is identical to the inline
``_write_firmware_handoff``/``_collect_handoff_bundles``/``_manifest_artifact_paths``
implementation that previously lived in run.py. No semantic changes.

Schema validation is performed via :func:`aiedge.schema.validate_handoff`;
validation failures are logged to stderr (warnings only), matching the
prior fail-open behaviour.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from .schema import JsonValue, validate_handoff

HANDOFF_SCHEMA_VERSION = 1


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_json_object(path: Path) -> dict[str, object] | None:
    try:
        data = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return cast(dict[str, object], data)


def _try_run_relative(path: Path, run_dir: Path) -> str | None:
    try:
        rel = path.resolve().relative_to(run_dir.resolve())
    except ValueError:
        return None
    return rel.as_posix()


def _manifest_artifact_paths(
    *,
    manifest: dict[str, object],
    run_dir: Path,
) -> list[str]:
    artifacts_any = manifest.get("artifacts")
    if not isinstance(artifacts_any, list):
        return []
    out: list[str] = []
    run_resolved = run_dir.resolve()
    for item_any in cast(list[object], artifacts_any):
        if not isinstance(item_any, dict):
            continue
        path_any = cast(dict[str, object], item_any).get("path")
        if not isinstance(path_any, str) or not path_any:
            continue
        rel_path = Path(path_any)
        if rel_path.is_absolute():
            continue
        candidate = (run_dir / rel_path).resolve()
        if not candidate.exists():
            continue
        try:
            _ = candidate.relative_to(run_resolved)
        except ValueError:
            continue
        rel = _try_run_relative(candidate, run_dir)
        if rel is not None:
            out.append(rel)
    return sorted(set(out))


def collect_handoff_bundles(run_dir: Path) -> list[dict[str, JsonValue]]:
    """Collect per-stage bundle manifests for the firmware handoff.

    Walks ``run_dir/stages/*`` and materialises one bundle entry per stage
    attempt manifest, plus a final ``findings-artifacts`` bundle for all
    files under ``stages/findings``. Returns the list (possibly empty).
    """
    bundles: list[dict[str, JsonValue]] = []
    stages_dir = run_dir / "stages"
    if not stages_dir.is_dir():
        return bundles

    for stage_dir in sorted(
        [p for p in stages_dir.iterdir() if p.is_dir()],
        key=lambda p: p.name,
    ):
        stage_name = stage_dir.name
        attempts_dir = stage_dir / "attempts"
        attempt_manifests: list[Path] = []
        if attempts_dir.is_dir():
            attempt_manifests = sorted(
                [
                    p / "stage.json"
                    for p in attempts_dir.iterdir()
                    if p.is_dir() and (p / "stage.json").is_file()
                ],
                key=lambda p: p.parent.name,
            )
        latest_manifest = stage_dir / "stage.json"
        if latest_manifest.is_file() and latest_manifest not in attempt_manifests:
            attempt_manifests.append(latest_manifest)

        for manifest_path in attempt_manifests:
            manifest_obj = _read_json_object(manifest_path)
            if manifest_obj is None:
                continue
            manifest = cast(dict[str, object], manifest_obj)
            attempt_any = manifest.get("attempt")
            attempt = int(attempt_any) if isinstance(attempt_any, int) else 0
            status_any = manifest.get("status")
            status = status_any if isinstance(status_any, str) else "unknown"
            artifacts = _manifest_artifact_paths(manifest=manifest, run_dir=run_dir)
            manifest_rel = _try_run_relative(manifest_path, run_dir)
            if manifest_rel is not None:
                artifacts = sorted(set([manifest_rel, *artifacts]))
            if not artifacts:
                continue
            bundle_id = f"{stage_name}-attempt-{attempt if attempt > 0 else 'latest'}"
            bundles.append(
                {
                    "id": bundle_id,
                    "stage": stage_name,
                    "attempt": attempt,
                    "status": status,
                    "artifacts": cast(list[JsonValue], cast(list[object], artifacts)),
                }
            )

    findings_dir = run_dir / "stages" / "findings"
    if findings_dir.is_dir():
        findings_paths = sorted(
            [
                rel
                for p in findings_dir.rglob("*")
                if p.is_file()
                for rel in [_try_run_relative(p, run_dir)]
                if isinstance(rel, str) and bool(rel)
            ]
        )
        if findings_paths:
            bundles.append(
                {
                    "id": "findings-artifacts",
                    "stage": "findings",
                    "attempt": 1,
                    "status": "ok",
                    "artifacts": cast(
                        list[JsonValue], cast(list[object], findings_paths)
                    ),
                }
            )

    return bundles


def write_firmware_handoff(
    *,
    info: object,
    profile: str,
    max_wallclock_per_run: int,
) -> None:
    """Build and write ``firmware_handoff.json`` for this run.

    ``info`` is a ``RunInfo`` instance (passed as ``object`` to avoid a
    circular import with ``run.py``). The function reads the run manifest
    for exploit gate state, assembles per-stage bundles, attaches the
    adversarial triage schema reference, optionally attaches the exploit
    gate snapshot, generates the Terminator feedback request (fail-open),
    validates the handoff against :func:`schema.validate_handoff`, and
    writes the final JSON to ``<run_dir>/firmware_handoff.json``.
    """
    # ``info`` is duck-typed as RunInfo; accessing attributes directly.
    manifest_path: Path = getattr(info, "manifest_path")  # type: ignore[assignment]
    run_dir: Path = getattr(info, "run_dir")  # type: ignore[assignment]
    run_id: str = getattr(info, "run_id")  # type: ignore[assignment]
    report_json_path: Path = getattr(info, "report_json_path")  # type: ignore[assignment]
    report_html_path: Path = getattr(info, "report_html_path")  # type: ignore[assignment]

    manifest_obj = _read_json_object(manifest_path) or {}
    exploit_gate_any = manifest_obj.get("exploit_gate")
    exploit_gate = (
        cast(dict[str, JsonValue], cast(dict[str, object], exploit_gate_any))
        if isinstance(exploit_gate_any, dict)
        else None
    )

    bundles = collect_handoff_bundles(run_dir)
    if not bundles:
        fallback_artifacts: list[str] = []
        report_json_rel = _try_run_relative(report_json_path, run_dir)
        if report_json_rel is not None and report_json_path.is_file():
            fallback_artifacts.append(report_json_rel)
        manifest_rel = _try_run_relative(manifest_path, run_dir)
        if manifest_rel is not None and manifest_path.is_file():
            fallback_artifacts.append(manifest_rel)
        if fallback_artifacts:
            bundles = [
                {
                    "id": "run-metadata",
                    "stage": "run",
                    "attempt": 1,
                    "status": "ok",
                    "artifacts": cast(
                        list[JsonValue], cast(list[object], sorted(fallback_artifacts))
                    ),
                }
            ]

    handoff: dict[str, JsonValue] = {
        "schema_version": HANDOFF_SCHEMA_VERSION,
        "generated_at": _iso_utc_now(),
        "profile": profile,
        "policy": {
            "max_reruns_per_stage": 3,
            "max_total_stage_attempts": 64,
            "max_wallclock_per_run": int(max(1, max_wallclock_per_run)),
        },
        "aiedge": {
            "run_id": run_id,
            "run_dir": str(run_dir.resolve()),
            "report_json": _try_run_relative(report_json_path, run_dir)
            or "report/report.json",
            "report_html": _try_run_relative(report_html_path, run_dir)
            or "report/report.html",
        },
        "bundles": cast(list[JsonValue], cast(list[object], bundles)),
    }

    # --- Adversarial triage schema reference for downstream consumers ---
    _adv_stage_json = (
        run_dir / "stages" / "adversarial_triage" / "triaged_findings.json"
    )
    if _adv_stage_json.is_file():
        try:
            _adv_data = json.loads(_adv_stage_json.read_text(encoding="utf-8"))
            _adv_summary = _adv_data.get("summary", {})
            handoff["adversarial_triage"] = {
                "artifact": "stages/adversarial_triage/triaged_findings.json",
                "schema": {
                    "version": _adv_data.get("schema_version", "adversarial-triage-v1"),
                    "findings_key": "triaged_findings",
                    "verdict_field": "triage_outcome",
                    "verdict_values": ["maintained", "downgraded", "below_threshold"],
                    "key_fields": [
                        "source_binary",
                        "sink_symbol",
                        "source_api",
                        "confidence",
                        "original_confidence",
                        "fp_verdict",
                        "fp_pattern",
                        "fp_rationale",
                        "no_xref_path",
                        "source_address",
                        "web_server",
                        "method",
                        "path_description",
                        "advocate_argument",
                        "critic_rebuttal",
                        "triage_outcome",
                        "trace_refs",
                    ],
                },
                "summary": (
                    cast(dict[str, JsonValue], _adv_summary)
                    if isinstance(_adv_summary, dict)
                    else {}
                ),
            }
        except Exception:
            pass  # fail-open

    if profile == "exploit" and exploit_gate is not None:
        handoff["exploit_gate"] = exploit_gate

    # --- Terminator feedback request ---
    try:
        from .terminator_feedback import generate_feedback_request as _gen_fb_req

        _candidates_for_fb: list[dict[str, JsonValue]] = []
        for bundle in bundles:
            if not isinstance(bundle, dict):
                continue
            stage_any = bundle.get("stage")
            if stage_any == "findings":
                artifacts_any = bundle.get("artifacts")
                if isinstance(artifacts_any, list):
                    for art_rel in artifacts_any:
                        if not isinstance(art_rel, str):
                            continue
                        if "exploit_candidates" in art_rel:
                            _ec_path = run_dir / art_rel
                            if _ec_path.is_file():
                                try:
                                    _ec_raw = json.loads(
                                        _ec_path.read_text(encoding="utf-8")
                                    )
                                    if isinstance(_ec_raw, dict):
                                        _ec_cands = _ec_raw.get("candidates")
                                        if isinstance(_ec_cands, list):
                                            _candidates_for_fb = cast(
                                                list[dict[str, JsonValue]],
                                                cast(list[object], _ec_cands),
                                            )
                                except Exception:
                                    pass
        handoff["feedback_request"] = _gen_fb_req(_candidates_for_fb)
    except Exception:
        pass  # fail-open: feedback request generation is best-effort

    handoff_errors = validate_handoff(handoff)
    if handoff_errors:
        import sys

        sys.stderr.write(
            f"[AIEDGE] WARNING: handoff validation errors: {handoff_errors}\n"
        )

    handoff_path = run_dir / "firmware_handoff.json"
    _ = handoff_path.write_text(
        json.dumps(handoff, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
