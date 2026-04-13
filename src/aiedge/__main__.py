"""Module entrypoint.

Allows: python -m aiedge
"""

from __future__ import annotations

import importlib
import json
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Callable, cast

from .cli_common import (
    _CANONICAL_8MB_SHA256,
    _CANONICAL_8MB_SIZE_BYTES,
    _resolve_tui_run_dir,
    _RunInfo,
    _RunReport,
    _sha256_file,
    _write_manifest_profile_marker,
    _write_manifest_rootfs_marker,
    _write_manifest_scan_limits_marker,
    _write_manifest_track_marker,
)
from .cli_parser import _build_parser
from .cli_serve import _serve_report_directory
from .cli_tui import _run_tui
from .codex_probe import resolve_llm_gate_input
from .corpus import (
    CorpusValidationError,
    corpus_summary,
    format_summary,
    load_corpus_manifest,
)
from .quality_metrics import (
    QualityMetricsError,
    build_quality_delta_report,
    evaluate_quality_metrics_harness,
    format_quality_metrics,
    write_quality_metrics,
)
from .quality_policy import (
    QUALITY_GATE_INVALID_METRICS,
    QUALITY_GATE_INVALID_REPORT,
    QUALITY_GATE_LLM_REQUIRED,
    QualityGateError,
    evaluate_quality_gate,
    format_quality_gate,
    load_json_object,
    write_quality_gate,
)
from .schema import JsonValue


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = _build_parser()
    try:
        args = parser.parse_args(list(argv))
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 20

    command = cast(str | None, getattr(args, "command", None))
    if command is None:
        parser.print_help()
        return 0

    def parse_stage_names(stages_raw: str | None) -> list[str] | None:
        if stages_raw is None:
            return None
        stage_names_local = [
            part.strip() for part in stages_raw.split(",") if part.strip()
        ]
        if not stage_names_local:
            print(
                "Invalid --stages value: provide at least one non-empty stage name.",
                file=sys.stderr,
            )
            return []
        return stage_names_local

    if command in ("analyze", "analyze-8mb"):
        input_firmware = cast(str, getattr(args, "input_firmware"))
        case_id = (
            cast(str, getattr(args, "case_id"))
            if getattr(args, "case_id")
            else f"auto-{int(time.time())}"
        )
        ack_authorization = bool(getattr(args, "ack_authorization", False))
        time_budget_s = cast(int, getattr(args, "time_budget_s"))
        open_egress = bool(getattr(args, "open_egress", False))
        egress_allow = cast(list[str], getattr(args, "egress_allow", []))
        no_llm = bool(getattr(args, "no_llm", False))
        stages_raw = cast(str | None, getattr(args, "stages", None))
        rootfs_raw = cast(str | None, getattr(args, "rootfs", None))
        max_files_raw = cast(int | None, getattr(args, "max_files", None))
        max_matches_raw = cast(int | None, getattr(args, "max_matches", None))
        ref_md = cast(str | None, getattr(args, "ref_md", None))
        require_ref_md = bool(getattr(args, "require_ref_md", False))
        force_retriage = bool(getattr(args, "force_retriage", False))
        profile = cast(str, getattr(args, "profile", "analysis"))
        exploit_flag = cast(str, getattr(args, "exploit_flag", ""))
        exploit_att = cast(str, getattr(args, "exploit_attestation", ""))
        exploit_scope = cast(str, getattr(args, "exploit_scope", ""))
        rootfs_path: Path | None = None
        if isinstance(rootfs_raw, str) and rootfs_raw.strip():
            candidate = Path(rootfs_raw).expanduser()
            if not candidate.is_dir():
                print(
                    f"Pre-extracted rootfs directory not found: {candidate}",
                    file=sys.stderr,
                )
                return 20
            rootfs_path = candidate.resolve()
        max_files: int | None = None
        if isinstance(max_files_raw, int):
            if max_files_raw <= 0:
                print("--max-files must be a positive integer.", file=sys.stderr)
                return 20
            max_files = int(max_files_raw)
        max_matches: int | None = None
        if isinstance(max_matches_raw, int):
            if max_matches_raw <= 0:
                print("--max-matches must be a positive integer.", file=sys.stderr)
                return 20
            max_matches = int(max_matches_raw)

        enforce_canonical_8mb = command == "analyze-8mb"
        if enforce_canonical_8mb:
            src = Path(input_firmware)
            if not src.is_file():
                print(f"Input firmware not found: {input_firmware}", file=sys.stderr)
                return 20
            if src.stat().st_size != _CANONICAL_8MB_SIZE_BYTES:
                print(
                    "8MB track requires the canonical snapshot (size mismatch)",
                    file=sys.stderr,
                )
                return 30
            if _sha256_file(src) != _CANONICAL_8MB_SHA256:
                print(
                    "8MB track requires the canonical snapshot (sha256 mismatch)",
                    file=sys.stderr,
                )
                return 30

        exploit_gate: dict[str, str] | None = None
        if profile == "exploit":
            if not (exploit_flag and exploit_att and exploit_scope):
                print(
                    "Exploit profile requires --exploit-flag, --exploit-attestation, and --exploit-scope",
                    file=sys.stderr,
                )
                return 30
            exploit_gate = {
                "flag": exploit_flag,
                "attestation": exploit_att,
                "scope": exploit_scope,
            }

        run_mod: ModuleType = importlib.import_module("aiedge.run")
        create_run = cast(Callable[..., object], getattr(run_mod, "create_run"))
        analyze_run = cast(
            Callable[..., object] | None, getattr(run_mod, "analyze_run", None)
        )
        run_subset = cast(
            Callable[..., object] | None, getattr(run_mod, "run_subset", None)
        )
        policy_exc = cast(
            type[BaseException],
            getattr(run_mod, "AIEdgePolicyViolation", RuntimeError),
        )

        stage_names = parse_stage_names(stages_raw)
        if stage_names == []:
            return 20

        try:
            info = create_run(
                input_firmware,
                case_id=case_id,
                ack_authorization=ack_authorization,
                open_egress=open_egress,
                egress_allowlist=egress_allow,
                ref_md_path=ref_md,
                require_ref_md=require_ref_md,
                runs_root=(
                    (Path.cwd() / "aiedge-8mb-runs") if enforce_canonical_8mb else None
                ),
            )

            if enforce_canonical_8mb:
                info_obj = info
                manifest_path_any = getattr(info_obj, "manifest_path", None)
                if not isinstance(manifest_path_any, Path):
                    raise RuntimeError("create_run did not return a manifest_path")
                _write_manifest_profile_marker(
                    manifest_path_any,
                    profile=profile,
                    exploit_gate=exploit_gate,
                )
                _write_manifest_track_marker(manifest_path_any)
            else:
                info_obj = info
                manifest_path_any = getattr(info_obj, "manifest_path", None)
                if isinstance(manifest_path_any, Path):
                    _write_manifest_profile_marker(
                        manifest_path_any,
                        profile=profile,
                        exploit_gate=exploit_gate,
                    )
            if isinstance(manifest_path_any, Path):
                _write_manifest_rootfs_marker(
                    manifest_path_any,
                    rootfs_path=rootfs_path,
                )
                _write_manifest_scan_limits_marker(
                    manifest_path_any,
                    max_files=max_files,
                    max_matches=max_matches,
                )

            experimental_parallel_raw = cast(
                int | None, getattr(args, "experimental_parallel", None)
            )
            experimental_parallel: int | None = None
            if (
                isinstance(experimental_parallel_raw, int)
                and experimental_parallel_raw > 0
            ):
                experimental_parallel = int(experimental_parallel_raw)

            # Progress tracker (--quiet suppresses)
            _progress = None
            if not getattr(args, "quiet", False):
                try:
                    from .progress import ProgressTracker

                    _progress = ProgressTracker(
                        out_of_order=experimental_parallel is not None
                    )
                except Exception:
                    pass

            _is_quiet = bool(getattr(args, "quiet", False))
            stage_status: str | None = None
            if stage_names is not None:
                if not callable(run_subset):
                    raise RuntimeError("run_subset is unavailable in aiedge.run")
                rep = cast(
                    _RunReport,
                    run_subset(
                        info,
                        stage_names,
                        time_budget_s=time_budget_s,
                        no_llm=no_llm,
                        on_progress=_progress,
                        quiet=_is_quiet,
                        experimental_parallel=experimental_parallel,
                    ),
                )
                stage_status = rep.status
            elif callable(analyze_run):
                stage_status = cast(
                    str,
                    analyze_run(
                        info,
                        time_budget_s=time_budget_s,
                        no_llm=no_llm,
                        force_retriage=force_retriage,
                        on_progress=_progress,
                        quiet=_is_quiet,
                        experimental_parallel=experimental_parallel,
                    ),
                )
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 20
        except policy_exc as e:
            print(str(e), file=sys.stderr)
            return 30
        except FileNotFoundError:
            print(f"Input firmware not found: {input_firmware}", file=sys.stderr)
            return 20
        except Exception as e:
            print(f"Fatal error: {e}", file=sys.stderr)
            return 20

        info_typed = cast(_RunInfo, info)
        print(str(info_typed.run_dir))
        if stage_status in ("partial", "failed"):
            return 10
        return 0

    if command == "stages":
        run_dir = cast(str, getattr(args, "run_dir"))
        time_budget_s = cast(int, getattr(args, "time_budget_s"))
        no_llm = bool(getattr(args, "no_llm", False))
        stages_raw = cast(str, getattr(args, "stages"))
        max_files_raw = cast(int | None, getattr(args, "max_files", None))
        max_matches_raw = cast(int | None, getattr(args, "max_matches", None))

        max_files: int | None = None
        if isinstance(max_files_raw, int):
            if max_files_raw <= 0:
                print("--max-files must be a positive integer.", file=sys.stderr)
                return 20
            max_files = int(max_files_raw)
        max_matches: int | None = None
        if isinstance(max_matches_raw, int):
            if max_matches_raw <= 0:
                print("--max-matches must be a positive integer.", file=sys.stderr)
                return 20
            max_matches = int(max_matches_raw)

        stage_names = parse_stage_names(stages_raw)
        if stage_names in (None, []):
            return 20

        run_mod_existing: ModuleType = importlib.import_module("aiedge.run")
        load_existing_run = cast(
            Callable[..., object] | None,
            getattr(run_mod_existing, "load_existing_run", None),
        )
        run_subset = cast(
            Callable[..., object] | None,
            getattr(run_mod_existing, "run_subset", None),
        )
        policy_exc = cast(
            type[BaseException],
            getattr(run_mod_existing, "AIEdgePolicyViolation", RuntimeError),
        )

        try:
            if not callable(load_existing_run):
                raise RuntimeError("load_existing_run is unavailable in aiedge.run")
            if not callable(run_subset):
                raise RuntimeError("run_subset is unavailable in aiedge.run")

            info = load_existing_run(run_dir)
            info_obj = cast(_RunInfo, info)
            if isinstance(info_obj.manifest_path, Path) and (
                max_files is not None or max_matches is not None
            ):
                _write_manifest_scan_limits_marker(
                    info_obj.manifest_path,
                    max_files=max_files,
                    max_matches=max_matches,
                )
            experimental_parallel_raw_stages = cast(
                int | None, getattr(args, "experimental_parallel", None)
            )
            experimental_parallel_stages: int | None = None
            if (
                isinstance(experimental_parallel_raw_stages, int)
                and experimental_parallel_raw_stages > 0
            ):
                experimental_parallel_stages = int(experimental_parallel_raw_stages)

            _progress_stages = None
            if not getattr(args, "quiet", False):
                try:
                    from .progress import ProgressTracker

                    _progress_stages = ProgressTracker(
                        out_of_order=experimental_parallel_stages is not None
                    )
                except Exception:
                    pass

            rep = cast(
                _RunReport,
                run_subset(
                    info,
                    stage_names,
                    time_budget_s=time_budget_s,
                    no_llm=no_llm,
                    on_progress=_progress_stages,
                    quiet=bool(getattr(args, "quiet", False)),
                    experimental_parallel=experimental_parallel_stages,
                ),
            )
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 20
        except policy_exc as e:
            print(str(e), file=sys.stderr)
            return 30
        except Exception as e:
            print(f"Fatal error: {e}", file=sys.stderr)
            return 20

        info_typed = cast(_RunInfo, info)
        print(str(info_typed.run_dir))
        if rep.status in ("partial", "failed"):
            return 10
        return 0

    if command == "mcp":
        from .mcp_server import main as mcp_main

        project_id = cast(str | None, getattr(args, "project_id", None))
        try:
            return mcp_main(project_id=project_id)
        except KeyboardInterrupt:
            return 0
        except Exception as e:
            print(f"MCP server error: {e}", file=sys.stderr)
            return 20

    if command == "serve":
        run_dir = cast(str, getattr(args, "run_dir"))
        host = cast(str, getattr(args, "host"))
        port = cast(int, getattr(args, "port"))
        once = bool(getattr(args, "once", False))
        duration_s = cast(float | None, getattr(args, "duration_s", None))

        try:
            return _serve_report_directory(
                run_dir_path=run_dir,
                host=host,
                port=port,
                once=once,
                duration_s=duration_s,
            )
        except Exception as e:
            print(f"Fatal error: {e}", file=sys.stderr)
            return 20

    if command == "tui":
        run_dir_raw = cast(str | None, getattr(args, "run_dir", None))
        run_dir_path = _resolve_tui_run_dir(run_dir_raw)
        if run_dir_path is None:
            print(
                (
                    "Run directory not found: provide <run_dir> or create at least one run under "
                    "./aiedge-runs (or set AIEDGE_RUNS_DIRS)."
                ),
                file=sys.stderr,
            )
            return 20
        limit = cast(int, getattr(args, "limit"))
        mode = cast(str, getattr(args, "mode", "auto"))
        watch = bool(getattr(args, "watch", False))
        interactive = bool(getattr(args, "interactive", False))
        interval_s = cast(float, getattr(args, "interval_s"))

        try:
            return _run_tui(
                run_dir_path=str(run_dir_path),
                limit=limit,
                mode=mode,
                watch=watch,
                interval_s=interval_s,
                interactive=interactive,
            )
        except Exception as e:
            print(f"Fatal error: {e}", file=sys.stderr)
            return 20

    if command == "corpus-validate":
        manifest_raw = cast(str, getattr(args, "manifest"))
        manifest_path = Path(manifest_raw)

        try:
            payload = load_corpus_manifest(manifest_path)
            summary = corpus_summary(payload)
        except FileNotFoundError:
            err = {
                "error_token": "CORPUS_INVALID_SAMPLE",
                "message": f"manifest file not found: {manifest_raw}",
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20
        except json.JSONDecodeError as e:
            err = {
                "error_token": "CORPUS_INVALID_SAMPLE",
                "message": f"manifest is not valid JSON: {e.msg}",
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20
        except CorpusValidationError as e:
            err = {
                "error_token": e.token,
                "message": str(e),
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20

        print(format_summary(summary), end="")
        return 0

    if command == "quality-metrics":
        manifest_raw = cast(str, getattr(args, "manifest"))
        baseline_raw = cast(str | None, getattr(args, "baseline", None))
        out_raw = cast(str, getattr(args, "out"))
        delta_out_raw = cast(str, getattr(args, "delta_out"))
        max_regression = cast(float, getattr(args, "max_regression"))
        manifest_path = Path(manifest_raw)
        baseline_path = Path(baseline_raw) if baseline_raw is not None else None
        out_path = Path(out_raw)
        delta_out_path = Path(delta_out_raw)

        try:
            if max_regression < 0.0:
                raise QualityMetricsError(
                    "QUALITY_METRICS_INVALID_THRESHOLD",
                    "max regression threshold must be >= 0.0",
                )

            payload, baseline_payload = evaluate_quality_metrics_harness(
                manifest_path=manifest_path,
                baseline_path=baseline_path,
            )
            write_quality_metrics(out_path, payload)

            if baseline_path is not None:
                if baseline_payload is None:
                    raise QualityMetricsError(
                        "QUALITY_METRICS_INVALID_BASELINE",
                        "baseline payload is required",
                    )
                delta_payload = build_quality_delta_report(
                    current_metrics=payload,
                    baseline_metrics=baseline_payload,
                    manifest_path=str(manifest_path),
                    baseline_path=str(baseline_path),
                    max_regression=max_regression,
                )
                write_quality_metrics(delta_out_path, delta_payload)
        except FileNotFoundError as e:
            missing_any = cast(object, getattr(e, "filename", None))
            missing = str(missing_any) if isinstance(missing_any, str) else manifest_raw
            err = {
                "error_token": "QUALITY_METRICS_INPUT_NOT_FOUND",
                "message": f"required input file not found: {missing}",
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20
        except json.JSONDecodeError as e:
            err = {
                "error_token": "QUALITY_METRICS_INVALID_BASELINE",
                "message": f"input JSON is invalid: {e.msg}",
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20
        except CorpusValidationError as e:
            err = {
                "error_token": e.token,
                "message": str(e),
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20
        except QualityMetricsError as e:
            err = {
                "error_token": e.token,
                "message": str(e),
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20

        print(format_quality_metrics(payload), end="")
        return 0

    if command in ("quality-gate", "release-quality-gate"):
        metrics_raw = cast(str, getattr(args, "metrics"))
        report_raw = cast(str | None, getattr(args, "report", None))
        llm_fixture_raw = cast(str | None, getattr(args, "llm_fixture", None))
        out_raw = cast(str, getattr(args, "out"))
        release_mode = command == "release-quality-gate" or bool(
            getattr(args, "release_mode", False)
        )
        llm_primary = command == "release-quality-gate" or bool(
            getattr(args, "llm_primary", False)
        )

        metrics_path = Path(metrics_raw)
        out_path = Path(out_raw)
        report_path = Path(report_raw) if report_raw is not None else None
        llm_fixture_path = (
            Path(llm_fixture_raw) if llm_fixture_raw is not None else None
        )

        verdict: dict[str, object]
        exit_code = 0
        try:
            metrics_payload = load_json_object(
                metrics_path,
                error_token=QUALITY_GATE_INVALID_METRICS,
                object_name="metrics",
            )
            report_payload: dict[str, object] | None = None
            if report_path is not None:
                report_payload = load_json_object(
                    report_path,
                    error_token=QUALITY_GATE_INVALID_REPORT,
                    object_name="report",
                )

            llm_gate_payload: dict[str, object] | None = None
            llm_gate_path: str | None = None
            if llm_primary:
                if report_payload is None:
                    raise QualityGateError(
                        QUALITY_GATE_LLM_REQUIRED,
                        "llm-primary policy requires --report",
                    )
                if llm_fixture_path is not None:
                    llm_gate_payload, llm_gate_path = resolve_llm_gate_input(
                        fixture_path=llm_fixture_path,
                        run_dir=Path.cwd(),
                        report=cast(dict[str, JsonValue], report_payload),
                    )
                else:
                    llm_status: str | None = None
                    llm_any = report_payload.get("llm")
                    if isinstance(llm_any, dict):
                        llm_status_any = cast(dict[str, object], llm_any).get("status")
                        if isinstance(llm_status_any, str):
                            llm_status = llm_status_any
                    llm_gate_payload = {
                        "verdict": "pass" if llm_status == "ok" else "fail"
                    }
                    llm_gate_path = "report.llm"

            verdict = evaluate_quality_gate(
                metrics_payload=metrics_payload,
                metrics_path=str(metrics_path),
                report_payload=report_payload,
                report_path=str(report_path) if report_path is not None else None,
                release_mode=release_mode,
                llm_primary=llm_primary,
                llm_gate_payload=llm_gate_payload,
                llm_gate_path=llm_gate_path,
            )
            if not bool(verdict.get("passed", False)):
                exit_code = 30
        except FileNotFoundError as e:
            missing_any = cast(object, getattr(e, "filename", None))
            missing = str(missing_any) if isinstance(missing_any, str) else metrics_raw
            err = {
                "error_token": "QUALITY_GATE_INPUT_NOT_FOUND",
                "message": f"required input file not found: {missing}",
            }
            verdict = {
                "schema_version": 1,
                "verdict": "fail",
                "passed": False,
                "metrics_path": str(metrics_path),
                "report_path": str(report_path) if report_path is not None else None,
                "errors": [err],
            }
            exit_code = 20
        except QualityGateError as e:
            err = {
                "error_token": e.token,
                "message": str(e),
            }
            verdict = {
                "schema_version": 1,
                "verdict": "fail",
                "passed": False,
                "metrics_path": str(metrics_path),
                "report_path": str(report_path) if report_path is not None else None,
                "errors": [err],
            }
            exit_code = 20

        write_quality_gate(out_path, verdict)
        if not bool(verdict.get("passed", False)):
            errors_any = verdict.get("errors")
            if isinstance(errors_any, list):
                for err_any in cast(list[object], errors_any):
                    if isinstance(err_any, dict):
                        print(
                            json.dumps(err_any, sort_keys=True, ensure_ascii=True),
                            file=sys.stderr,
                        )
        print(format_quality_gate(verdict), end="")
        return exit_code

    print(f"Unknown command: {command}", file=sys.stderr)
    return 20


if __name__ == "__main__":
    raise SystemExit(main())
