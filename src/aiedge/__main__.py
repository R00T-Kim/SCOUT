"""Module entrypoint.

Allows: python -m aiedge
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
import textwrap
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Callable, Protocol, cast

from . import __version__
from .corpus import (
    CorpusValidationError,
    corpus_summary,
    format_summary,
    load_corpus_manifest,
)
from .codex_probe import resolve_llm_gate_input
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


class _RunInfo(Protocol):
    run_dir: Path


class _RunReport(Protocol):
    status: str


_CANONICAL_8MB_SHA256 = (
    "387d97fd925125471691d5c565fcc0ff009e111bdbdfd2ddb057f9212a939c8a"
)
_CANONICAL_8MB_SIZE_BYTES = 8_388_608


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_manifest_track_marker(manifest_path: Path) -> None:
    obj_any = cast(object, json.loads(manifest_path.read_text(encoding="utf-8")))
    if not isinstance(obj_any, dict):
        raise ValueError("manifest.json is not an object")
    obj = cast(dict[str, object], obj_any)
    obj["track"] = {
        "track_id": "8mb",
        "canonical_sha256_prefix": _CANONICAL_8MB_SHA256[:12],
        "canonical_size_bytes": _CANONICAL_8MB_SIZE_BYTES,
    }
    _ = manifest_path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _write_manifest_profile_marker(
    manifest_path: Path,
    *,
    profile: str,
    exploit_gate: dict[str, str] | None,
) -> None:
    obj_any = cast(object, json.loads(manifest_path.read_text(encoding="utf-8")))
    if not isinstance(obj_any, dict):
        raise ValueError("manifest.json is not an object")
    obj = cast(dict[str, object], obj_any)
    obj["profile"] = profile
    if exploit_gate is not None:
        obj["exploit_gate"] = dict(exploit_gate)
    _ = manifest_path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _build_parser() -> argparse.ArgumentParser:
    epilog = textwrap.dedent(
        """\
        Exit codes:
          0   Success
          10  Partial success
          20  Fatal error
          30  Policy violation
        """
    )

    parser = argparse.ArgumentParser(
        prog="aiedge",
        description="Internal aiedge v1 scaffold",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = parser.add_argument(
        "--version",
        action="version",
        version=f"aiedge {__version__}",
        help="Print version and exit.",
    )
    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser(
        "analyze",
        help="Create a run directory for a firmware analysis (best-effort extraction).",
    )
    _ = analyze.add_argument(
        "input_firmware",
        help="Path to firmware binary to analyze.",
    )
    _ = analyze.add_argument(
        "--case-id",
        required=True,
        help="Case identifier recorded into the run manifest.",
    )
    _ = analyze.add_argument(
        "--ack-authorization",
        action="store_true",
        help="Acknowledge you are authorized to analyze this firmware.",
    )
    _ = analyze.add_argument(
        "--time-budget-s",
        type=int,
        default=3600,
        help="Overall pipeline time budget in seconds (default: 3600).",
    )
    _ = analyze.add_argument(
        "--open-egress",
        action="store_true",
        help="Record an override allowing full internet egress for this run.",
    )
    _ = analyze.add_argument(
        "--egress-allow",
        action="append",
        default=[],
        metavar="HOST",
        help="Add an allowed internet egress host; may be repeated.",
    )
    _ = analyze.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM probing and record deterministic skipped LLM report fields.",
    )
    _ = analyze.add_argument(
        "--profile",
        choices=["analysis", "exploit"],
        default="analysis",
        help="Execution profile (default: analysis).",
    )
    _ = analyze.add_argument(
        "--exploit-flag",
        default="",
        help="Exploit profile gate flag (required for --profile exploit).",
    )
    _ = analyze.add_argument(
        "--exploit-attestation",
        default="",
        help="Exploit profile attestation (required for --profile exploit).",
    )
    _ = analyze.add_argument(
        "--exploit-scope",
        default="",
        help="Exploit profile explicit scope string (required for --profile exploit).",
    )
    _ = analyze.add_argument(
        "--stages",
        default=None,
        help=("Comma-separated subset of stages to run (example: tooling,structure)."),
    )
    _ = analyze.add_argument(
        "--ref-md",
        default=None,
        metavar="PATH",
        help="Path to governed reference markdown context file.",
    )
    _ = analyze.add_argument(
        "--require-ref-md",
        action="store_true",
        help="Fail closed if --ref-md is missing or unreadable.",
    )
    _ = analyze.add_argument(
        "--force-retriage",
        action="store_true",
        help=(
            "Operator override: reopen duplicate-suppressed findings for retriage "
            "and emit deterministic duplicate-gate audit events."
        ),
    )

    analyze_8mb = sub.add_parser(
        "analyze-8mb",
        help=(
            "Analyze only the canonical 8MB firmware snapshot (sha256-locked); writes runs under aiedge-8mb-runs/."
        ),
    )
    _ = analyze_8mb.add_argument(
        "input_firmware",
        help=(
            "Path to firmware binary to analyze (must match canonical 8MB snapshot by sha256/size)."
        ),
    )
    _ = analyze_8mb.add_argument(
        "--case-id",
        required=True,
        help="Case identifier recorded into the run manifest.",
    )
    _ = analyze_8mb.add_argument(
        "--ack-authorization",
        action="store_true",
        help="Acknowledge you are authorized to analyze this firmware.",
    )
    _ = analyze_8mb.add_argument(
        "--time-budget-s",
        type=int,
        default=3600,
        help="Overall pipeline time budget in seconds (default: 3600).",
    )
    _ = analyze_8mb.add_argument(
        "--open-egress",
        action="store_true",
        help="Record an override allowing full internet egress for this run.",
    )
    _ = analyze_8mb.add_argument(
        "--egress-allow",
        action="append",
        default=[],
        metavar="HOST",
        help="Add an allowed internet egress host; may be repeated.",
    )
    _ = analyze_8mb.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM probing and record deterministic skipped LLM report fields.",
    )
    _ = analyze_8mb.add_argument(
        "--profile",
        choices=["analysis", "exploit"],
        default="analysis",
        help="Execution profile (default: analysis).",
    )
    _ = analyze_8mb.add_argument(
        "--exploit-flag",
        default="",
        help="Exploit profile gate flag (required for --profile exploit).",
    )
    _ = analyze_8mb.add_argument(
        "--exploit-attestation",
        default="",
        help="Exploit profile attestation (required for --profile exploit).",
    )
    _ = analyze_8mb.add_argument(
        "--exploit-scope",
        default="",
        help="Exploit profile explicit scope string (required for --profile exploit).",
    )
    _ = analyze_8mb.add_argument(
        "--stages",
        default=None,
        help=("Comma-separated subset of stages to run (example: tooling,structure)."),
    )
    _ = analyze_8mb.add_argument(
        "--ref-md",
        default=None,
        metavar="PATH",
        help="Path to governed reference markdown context file.",
    )
    _ = analyze_8mb.add_argument(
        "--require-ref-md",
        action="store_true",
        help="Fail closed if --ref-md is missing or unreadable.",
    )
    _ = analyze_8mb.add_argument(
        "--force-retriage",
        action="store_true",
        help=(
            "Operator override: reopen duplicate-suppressed findings for retriage "
            "and emit deterministic duplicate-gate audit events."
        ),
    )

    stages = sub.add_parser(
        "stages",
        help="Run a stage subset against an existing run directory.",
    )
    _ = stages.add_argument(
        "run_dir",
        help="Path to an existing run directory.",
    )
    _ = stages.add_argument(
        "--stages",
        required=True,
        help=("Comma-separated subset of stages to run (example: tooling,structure)."),
    )
    _ = stages.add_argument(
        "--time-budget-s",
        type=int,
        default=3600,
        help="Overall pipeline time budget in seconds (default: 3600).",
    )
    _ = stages.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM probing and record deterministic skipped LLM report fields.",
    )

    corpus_validate = sub.add_parser(
        "corpus-validate",
        help="Validate corpus manifest and print deterministic split summary.",
    )
    _ = corpus_validate.add_argument(
        "--manifest",
        default="benchmarks/corpus/manifest.json",
        metavar="PATH",
        help="Path to corpus manifest JSON (default: benchmarks/corpus/manifest.json).",
    )

    quality_metrics = sub.add_parser(
        "quality-metrics",
        help=(
            "Evaluate corpus labels with deterministic quality metrics and optional baseline delta output."
        ),
    )
    _ = quality_metrics.add_argument(
        "--manifest",
        default="benchmarks/corpus/manifest.json",
        metavar="PATH",
        help="Path to corpus manifest JSON (default: benchmarks/corpus/manifest.json).",
    )
    _ = quality_metrics.add_argument(
        "--baseline",
        default=None,
        metavar="PATH",
        help="Optional baseline metrics JSON for deterministic delta comparison.",
    )
    _ = quality_metrics.add_argument(
        "--out",
        default="metrics.json",
        metavar="PATH",
        help="Path for metrics report JSON output (default: metrics.json).",
    )
    _ = quality_metrics.add_argument(
        "--delta-out",
        default="metrics.delta.json",
        metavar="PATH",
        help="Path for baseline delta JSON output when --baseline is set (default: metrics.delta.json).",
    )
    _ = quality_metrics.add_argument(
        "--max-regression",
        type=float,
        default=0.01,
        metavar="FLOAT",
        help=(
            "Maximum allowed metric regression before flagging (default: 0.01). "
            "Regression is baseline-current for precision/recall/f1, and current-baseline for fpr/fnr."
        ),
    )

    quality_gate = sub.add_parser(
        "quality-gate",
        help=(
            "Enforce release-quality thresholds against metrics.json and emit a deterministic verdict artifact."
        ),
    )
    _ = quality_gate.add_argument(
        "--metrics",
        default="metrics.json",
        metavar="PATH",
        help="Path to quality metrics JSON (default: metrics.json).",
    )
    _ = quality_gate.add_argument(
        "--report",
        default=None,
        metavar="PATH",
        help="Optional report JSON for additive release-mode confirmed high/critical constraint.",
    )
    _ = quality_gate.add_argument(
        "--release-mode",
        action="store_true",
        help="Enable additive release constraint checks that consider report findings.",
    )
    _ = quality_gate.add_argument(
        "--llm-primary",
        action="store_true",
        help="Enable LLM-primary gating policy checks.",
    )
    _ = quality_gate.add_argument(
        "--llm-fixture",
        default=None,
        metavar="PATH",
        help=(
            "Optional LLM gate fixture JSON path; when omitted in llm-primary mode, "
            "a verdict is derived from report.llm.status."
        ),
    )
    _ = quality_gate.add_argument(
        "--out",
        default="quality_gate.json",
        metavar="PATH",
        help="Path for gate verdict JSON output artifact (default: quality_gate.json).",
    )

    release_quality_gate = sub.add_parser(
        "release-quality-gate",
        help=(
            "Alias for quality-gate with release-mode enabled by default for release CI policy checks."
        ),
    )
    _ = release_quality_gate.add_argument(
        "--metrics",
        default="metrics.json",
        metavar="PATH",
        help="Path to quality metrics JSON (default: metrics.json).",
    )
    _ = release_quality_gate.add_argument(
        "--report",
        default=None,
        metavar="PATH",
        help="Optional report JSON for additive release-mode confirmed high/critical constraint.",
    )
    _ = release_quality_gate.add_argument(
        "--llm-primary",
        action="store_true",
        help="Enable LLM-primary gating policy checks (release-quality-gate enables this by default).",
    )
    _ = release_quality_gate.add_argument(
        "--llm-fixture",
        default=None,
        metavar="PATH",
        help=(
            "Optional LLM gate fixture JSON path; when omitted in llm-primary mode, "
            "a verdict is derived from report.llm.status."
        ),
    )
    _ = release_quality_gate.add_argument(
        "--out",
        default="quality_gate.json",
        metavar="PATH",
        help="Path for gate verdict JSON output artifact (default: quality_gate.json).",
    )

    return parser


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
        case_id = cast(str, getattr(args, "case_id"))
        ack_authorization = bool(getattr(args, "ack_authorization", False))
        time_budget_s = cast(int, getattr(args, "time_budget_s"))
        open_egress = bool(getattr(args, "open_egress", False))
        egress_allow = cast(list[str], getattr(args, "egress_allow", []))
        no_llm = bool(getattr(args, "no_llm", False))
        stages_raw = cast(str | None, getattr(args, "stages", None))
        ref_md = cast(str | None, getattr(args, "ref_md", None))
        require_ref_md = bool(getattr(args, "require_ref_md", False))
        force_retriage = bool(getattr(args, "force_retriage", False))
        profile = cast(str, getattr(args, "profile", "analysis"))
        exploit_flag = cast(str, getattr(args, "exploit_flag", ""))
        exploit_att = cast(str, getattr(args, "exploit_attestation", ""))
        exploit_scope = cast(str, getattr(args, "exploit_scope", ""))

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

        if not ack_authorization:
            print(
                "Missing required acknowledgement: --ack-authorization",
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
                runs_root=(Path.cwd() / "aiedge-8mb-runs")
                if enforce_canonical_8mb
                else None,
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
            rep = cast(
                _RunReport,
                run_subset(
                    info,
                    stage_names,
                    time_budget_s=time_budget_s,
                    no_llm=no_llm,
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
