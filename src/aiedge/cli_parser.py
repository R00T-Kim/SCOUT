"""Argument parser construction for the ``aiedge`` CLI."""

from __future__ import annotations

import argparse
import textwrap

from . import __version__


def _build_parser() -> argparse.ArgumentParser:
    epilog = textwrap.dedent("""\
        Exit codes:
          0   Success
          10  Partial success
          20  Fatal error
          30  Policy violation
        """)

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
        required=False,
        default=None,
        help="Case identifier recorded into the run manifest (auto-generated if omitted).",
    )
    _ = analyze.add_argument(
        "--ack-authorization",
        action="store_true",
        default=True,
        help="Acknowledge you are authorized to analyze this firmware (default: True).",
    )
    _ = analyze.add_argument(
        "--time-budget-s",
        type=int,
        default=3600,
        help="Overall pipeline time budget in seconds (default: 3600).",
    )
    _ = analyze.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress stage progress output on stderr.",
    )
    _ = analyze.add_argument(
        "--open-egress",
        action="store_true",
        default=True,
        help="Record an override allowing full internet egress for this run (default: True).",
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
        default="exploit",
        help="Execution profile (default: exploit).",
    )
    _ = analyze.add_argument(
        "--exploit-flag",
        default="lab",
        help="Exploit profile gate flag (default: lab).",
    )
    _ = analyze.add_argument(
        "--exploit-attestation",
        default="authorized",
        help="Exploit profile attestation (default: authorized).",
    )
    _ = analyze.add_argument(
        "--exploit-scope",
        default="lab-only",
        help="Exploit profile explicit scope string (default: lab-only).",
    )
    _ = analyze.add_argument(
        "--stages",
        default=None,
        help=(
            "Comma-separated subset of stage names to run (example: tooling,structure). "
            "Note: findings is an integrated step in full analyze/analyze-8mb runs and is not a selectable stage."
        ),
    )
    _ = analyze.add_argument(
        "--rootfs",
        default=None,
        metavar="DIR",
        help=(
            "Path to a pre-extracted root filesystem directory. "
            "When provided, extraction stage ingests this directory instead of relying only on binwalk."
        ),
    )
    _ = analyze.add_argument(
        "--max-files",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Override scan file cap for inventory string-hit and endpoints stages. "
            "When omitted, SCOUT auto-scales by input firmware size."
        ),
    )
    _ = analyze.add_argument(
        "--max-matches",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Override match cap for inventory string-hit and endpoints stages. "
            "When omitted, SCOUT auto-scales by input firmware size."
        ),
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
    _ = analyze.add_argument(
        "--experimental-parallel",
        type=int,
        nargs="?",
        const=4,
        default=None,
        metavar="N",
        help=(
            "Enable DAG parallel stage execution (PoC). "
            "Optional max_workers, default 4."
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
        required=False,
        default=None,
        help="Case identifier recorded into the run manifest (auto-generated if omitted).",
    )
    _ = analyze_8mb.add_argument(
        "--ack-authorization",
        action="store_true",
        default=True,
        help="Acknowledge you are authorized to analyze this firmware (default: True).",
    )
    _ = analyze_8mb.add_argument(
        "--time-budget-s",
        type=int,
        default=3600,
        help="Overall pipeline time budget in seconds (default: 3600).",
    )
    _ = analyze_8mb.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress stage progress output on stderr.",
    )
    _ = analyze_8mb.add_argument(
        "--open-egress",
        action="store_true",
        default=True,
        help="Record an override allowing full internet egress for this run (default: True).",
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
        default="exploit",
        help="Execution profile (default: exploit).",
    )
    _ = analyze_8mb.add_argument(
        "--exploit-flag",
        default="lab",
        help="Exploit profile gate flag (default: lab).",
    )
    _ = analyze_8mb.add_argument(
        "--exploit-attestation",
        default="authorized",
        help="Exploit profile attestation (default: authorized).",
    )
    _ = analyze_8mb.add_argument(
        "--exploit-scope",
        default="lab-only",
        help="Exploit profile explicit scope string (default: lab-only).",
    )
    _ = analyze_8mb.add_argument(
        "--stages",
        default=None,
        help=(
            "Comma-separated subset of stage names to run (example: tooling,structure). "
            "Note: findings is an integrated step in full analyze/analyze-8mb runs and is not a selectable stage."
        ),
    )
    _ = analyze_8mb.add_argument(
        "--rootfs",
        default=None,
        metavar="DIR",
        help=(
            "Path to a pre-extracted root filesystem directory. "
            "When provided, extraction stage ingests this directory instead of relying only on binwalk."
        ),
    )
    _ = analyze_8mb.add_argument(
        "--max-files",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Override scan file cap for inventory string-hit and endpoints stages. "
            "When omitted, SCOUT auto-scales by input firmware size."
        ),
    )
    _ = analyze_8mb.add_argument(
        "--max-matches",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Override match cap for inventory string-hit and endpoints stages. "
            "When omitted, SCOUT auto-scales by input firmware size."
        ),
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
        help=(
            "Comma-separated subset of stage names to run (example: tooling,structure). "
            "Note: findings is an integrated step in full analyze/analyze-8mb runs and is not a selectable stage."
        ),
    )
    _ = stages.add_argument(
        "--time-budget-s",
        type=int,
        default=3600,
        help="Overall pipeline time budget in seconds (default: 3600).",
    )
    _ = stages.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress stage progress output on stderr.",
    )
    _ = stages.add_argument(
        "--max-files",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Override scan file cap for inventory string-hit and endpoints stages "
            "for this existing run."
        ),
    )
    _ = stages.add_argument(
        "--max-matches",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Override match cap for inventory string-hit and endpoints stages "
            "for this existing run."
        ),
    )
    _ = stages.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM probing and record deterministic skipped LLM report fields.",
    )
    _ = stages.add_argument(
        "--experimental-parallel",
        type=int,
        nargs="?",
        const=4,
        default=None,
        metavar="N",
        help=(
            "Enable DAG parallel stage execution (PoC). "
            "Optional max_workers, default 4."
        ),
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

    aeg_e2e_gate = sub.add_parser(
        "aeg-e2e-gate",
        help="Evaluate a completed SCOUT run against the fail-closed AEG E2E dynamic/FP gate.",
    )
    _ = aeg_e2e_gate.add_argument("run_dir", metavar="RUN_DIR")
    _ = aeg_e2e_gate.add_argument("--out", default=None, metavar="PATH")
    _ = aeg_e2e_gate.add_argument("--fpr-max", type=float, default=0.10)
    _ = aeg_e2e_gate.add_argument("--min-runner-pass", type=int, default=1)

    weaponization_readiness = sub.add_parser(
        "weaponization-readiness",
        help=(
            "Certify a private controlled weaponization package against a completed authorized SCOUT AEG run."
        ),
    )
    _ = weaponization_readiness.add_argument("run_dir", metavar="RUN_DIR")
    _ = weaponization_readiness.add_argument(
        "--package-manifest",
        required=True,
        metavar="PATH",
        help="Private package manifest JSON; exploit payload source is never loaded or executed.",
    )
    _ = weaponization_readiness.add_argument("--out", default=None, metavar="PATH")
    _ = weaponization_readiness.add_argument("--fpr-max", type=float, default=0.10)
    _ = weaponization_readiness.add_argument("--min-runner-pass", type=int, default=1)
    _ = weaponization_readiness.add_argument(
        "--allow-missing-control-pair",
        action="store_true",
        help="Treat missing vulnerable/control fail-closed proof as an explicit policy exception.",
    )
    _ = weaponization_readiness.add_argument(
        "--allow-missing-cleanup",
        action="store_true",
        help="Do not require cleanup strategy and verification metadata for this readiness check.",
    )

    weaponization_plan = sub.add_parser(
        "weaponization-plan",
        help="Build a controlled weaponization Plan IR from SCOUT run evidence and private package metadata.",
    )
    _ = weaponization_plan.add_argument("run_dir", metavar="RUN_DIR")
    _ = weaponization_plan.add_argument(
        "--package-manifest",
        default=None,
        metavar="PATH",
        help="Optional private package manifest JSON used for binding metadata.",
    )
    _ = weaponization_plan.add_argument("--chain-id", default=None)
    _ = weaponization_plan.add_argument("--repro-required", type=int, default=3)
    _ = weaponization_plan.add_argument("--out", default=None, metavar="PATH")

    weaponization_preflight = sub.add_parser(
        "weaponization-preflight",
        help="Fail-closed scope/profile/precondition gate before private controlled weaponization execution.",
    )
    _ = weaponization_preflight.add_argument("run_dir", metavar="RUN_DIR")
    _ = weaponization_preflight.add_argument("--plan", required=True, metavar="PATH")
    _ = weaponization_preflight.add_argument(
        "--package-manifest",
        default=None,
        metavar="PATH",
        help="Optional private package manifest JSON used for firmware binding checks.",
    )
    _ = weaponization_preflight.add_argument("--out", default=None, metavar="PATH")

    weaponization_ledger = sub.add_parser(
        "weaponization-ledger",
        help=(
            "Build the controlled weaponization execution ledger and optional L7 engagement approval record."
        ),
    )
    _ = weaponization_ledger.add_argument("run_dir", metavar="RUN_DIR")
    _ = weaponization_ledger.add_argument("--plan", required=True, metavar="PATH")
    _ = weaponization_ledger.add_argument("--preflight", required=True, metavar="PATH")
    _ = weaponization_ledger.add_argument("--readiness", required=True, metavar="PATH")
    _ = weaponization_ledger.add_argument(
        "--execution-evidence",
        action="append",
        default=None,
        metavar="PATH",
        help=(
            "exploit-evidence-v1 bundle path; may be repeated. Defaults to "
            "RUN_DIR/exploits/chain_*/evidence_bundle.json when omitted."
        ),
    )
    _ = weaponization_ledger.add_argument("--cleanup-log", default=None, metavar="PATH")
    _ = weaponization_ledger.add_argument(
        "--approval",
        default=None,
        metavar="PATH",
        help="Optional scout-engagement-approval-v1 manifest for L7 promotion.",
    )
    _ = weaponization_ledger.add_argument("--out", default=None, metavar="PATH")

    weaponization_execute = sub.add_parser(
        "weaponization-execute",
        help=(
            "Run a private plugin only after SCOUT-W plan/preflight/readiness gates pass, then write the ledger."
        ),
    )
    _ = weaponization_execute.add_argument("run_dir", metavar="RUN_DIR")
    _ = weaponization_execute.add_argument(
        "--exploit-dir",
        required=True,
        metavar="PATH",
        help="Private exploit package directory; public SCOUT never stores the payload source.",
    )
    _ = weaponization_execute.add_argument("--plan", required=True, metavar="PATH")
    _ = weaponization_execute.add_argument("--preflight", required=True, metavar="PATH")
    _ = weaponization_execute.add_argument("--readiness", required=True, metavar="PATH")
    _ = weaponization_execute.add_argument("--cleanup-log", required=True, metavar="PATH")
    _ = weaponization_execute.add_argument("--approval", default=None, metavar="PATH")
    _ = weaponization_execute.add_argument(
        "--vault-registry",
        default=None,
        metavar="PATH",
        help="Optional metadata-only package vault registry; package hash must be registered for this scope.",
    )
    _ = weaponization_execute.add_argument("--package-hash", default=None)
    _ = weaponization_execute.add_argument("--chain-id", default=None)
    _ = weaponization_execute.add_argument("--repro", default=None, type=int)
    _ = weaponization_execute.add_argument("--out-ledger", default=None, metavar="PATH")

    weaponization_package = sub.add_parser(
        "weaponization-package",
        help="Lint and register private controlled weaponization package metadata.",
    )
    package_sub = weaponization_package.add_subparsers(dest="package_command", required=True)
    package_lint = package_sub.add_parser("lint", help="Validate a private package manifest.")
    _ = package_lint.add_argument("--package-manifest", required=True, metavar="PATH")
    _ = package_lint.add_argument("--out", default=None, metavar="PATH")

    package_register = package_sub.add_parser(
        "register",
        help="Register a lint-passing package hash in a metadata-only vault registry.",
    )
    _ = package_register.add_argument("--registry", required=True, metavar="PATH")
    _ = package_register.add_argument("--package-manifest", required=True, metavar="PATH")
    _ = package_register.add_argument("--out", default=None, metavar="PATH")

    package_verify = package_sub.add_parser(
        "verify",
        help="Verify a package hash is registered for an optional firmware/pattern/chain scope.",
    )
    _ = package_verify.add_argument("--registry", required=True, metavar="PATH")
    _ = package_verify.add_argument("--package-hash", required=True)
    _ = package_verify.add_argument("--firmware-sha256", default=None)
    _ = package_verify.add_argument("--pattern-id", default=None)
    _ = package_verify.add_argument("--chain-id", default=None)
    _ = package_verify.add_argument("--out", default=None, metavar="PATH")

    aeg_readiness = sub.add_parser(
        "aeg-readiness",
        help=(
            "Audit AEG platform readiness from curated pattern evidence and stable real-firmware pair proof."
        ),
    )
    _ = aeg_readiness.add_argument(
        "--repo-root",
        default=None,
        metavar="PATH",
        help="Repository root for resolving stable evidence artifacts (default: current working directory).",
    )
    _ = aeg_readiness.add_argument(
        "--patterns-dir",
        default=None,
        metavar="PATH",
        help="Override exploit pattern-card directory (default: data/exploit_references/patterns).",
    )
    _ = aeg_readiness.add_argument(
        "--min-real-firmware-pairs",
        type=int,
        default=1,
        metavar="N",
        help="Minimum real known-vulnerable/patched firmware pairs required (default: 1).",
    )
    _ = aeg_readiness.add_argument(
        "--allow-unvalidated-patterns",
        action="store_true",
        help="Do not require every curated pattern card to have vulnerable/control evidence.",
    )
    _ = aeg_readiness.add_argument(
        "--out",
        default="docs/pov/aeg_platform_readiness.json",
        metavar="PATH",
        help="Path for readiness report JSON output artifact (default: docs/pov/aeg_platform_readiness.json).",
    )

    aeg_real_pair_gate = sub.add_parser(
        "aeg-real-pair-gate",
        help="Preflight a known-vulnerable/patched firmware pair for real_firmware_pair AEG promotion.",
    )
    _ = aeg_real_pair_gate.add_argument("--pairs", default="benchmarks/pair-eval/pairs.json", metavar="PATH")
    _ = aeg_real_pair_gate.add_argument("--pair-id", required=True)
    _ = aeg_real_pair_gate.add_argument("--results-dir", default="benchmark-results/aeg-real-pair", metavar="PATH")
    _ = aeg_real_pair_gate.add_argument("--vulnerable-run-dir", default=None, metavar="PATH")
    _ = aeg_real_pair_gate.add_argument("--control-run-dir", default=None, metavar="PATH")
    _ = aeg_real_pair_gate.add_argument("--patched-run-dir", default=None, metavar="PATH")
    _ = aeg_real_pair_gate.add_argument("--pattern-id", default=None)
    _ = aeg_real_pair_gate.add_argument("--out", default=None, metavar="PATH")
    _ = aeg_real_pair_gate.add_argument("--fpr-max", type=float, default=0.10)
    _ = aeg_real_pair_gate.add_argument("--min-runner-pass", type=int, default=1)

    aeg_real_pair = sub.add_parser(
        "aeg-real-pair",
        help=(
            "Run or reuse a known-vulnerable/patched firmware pair and emit real_firmware_pair AEG proof."
        ),
    )
    _ = aeg_real_pair.add_argument("--pairs", default="benchmarks/pair-eval/pairs.json", metavar="PATH")
    _ = aeg_real_pair.add_argument("--pair-id", required=True)
    _ = aeg_real_pair.add_argument("--results-dir", default="benchmark-results/aeg-real-pair", metavar="PATH")
    _ = aeg_real_pair.add_argument("--profile", default="exploit")
    _ = aeg_real_pair.add_argument("--driver", default="codex")
    _ = aeg_real_pair.add_argument("--time-budget-s", type=int, default=1800)
    _ = aeg_real_pair.add_argument("--no-llm", action="store_true")
    _ = aeg_real_pair.add_argument("--quiet", action="store_true", default=True)
    _ = aeg_real_pair.add_argument("--no-quiet", dest="quiet", action="store_false")
    _ = aeg_real_pair.add_argument("--fetch", action="store_true")
    _ = aeg_real_pair.add_argument("--force-fetch", action="store_true")
    _ = aeg_real_pair.add_argument("--dry-run", action="store_true")
    _ = aeg_real_pair.add_argument("--skip-analyze", action="store_true")
    _ = aeg_real_pair.add_argument(
        "--post-stages",
        default="fp_verification,exploit_autopoc,poc_validation,exploit_policy",
        help="Comma-separated stages to rerun after analysis/reuse before pair preflight.",
    )
    _ = aeg_real_pair.add_argument("--post-time-budget-s", type=int, default=1800)
    _ = aeg_real_pair.add_argument("--skip-post-stages", action="store_true")
    _ = aeg_real_pair.add_argument("--skip-quality-metrics", action="store_true")
    _ = aeg_real_pair.add_argument("--skip-verified-chain", action="store_true")
    _ = aeg_real_pair.add_argument("--vulnerable-run-dir", default=None, metavar="PATH")
    _ = aeg_real_pair.add_argument("--control-run-dir", default=None, metavar="PATH")
    _ = aeg_real_pair.add_argument("--patched-run-dir", default=None, metavar="PATH")
    _ = aeg_real_pair.add_argument("--pattern-id", default=None)
    _ = aeg_real_pair.add_argument("--out", default=None, metavar="PATH")
    _ = aeg_real_pair.add_argument("--fpr-max", type=float, default=0.10)
    _ = aeg_real_pair.add_argument("--min-runner-pass", type=int, default=1)

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

    serve = sub.add_parser(
        "serve",
        help=(
            "Serve an existing run report directory over local HTTP and print the viewer URL."
        ),
    )
    _ = serve.add_argument(
        "run_dir",
        help="Path to an existing run directory (must contain report/viewer.html).",
    )
    _ = serve.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host interface to bind (default: 127.0.0.1).",
    )
    _ = serve.add_argument(
        "--port",
        type=int,
        default=8000,
        help="TCP port to bind (default: 8000, use 0 for auto-assign).",
    )
    _ = serve.add_argument(
        "--once",
        action="store_true",
        help="Serve a single request and exit (useful for automation/tests).",
    )
    _ = serve.add_argument(
        "--duration-s",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Optional max runtime in seconds before auto-stop.",
    )

    mcp = sub.add_parser(
        "mcp",
        help="Start MCP (Model Context Protocol) stdio server for AI agent integration.",
    )
    _ = mcp.add_argument(
        "--project-id",
        default=None,
        help="Default run directory ID (e.g. aiedge-run-20260323-...). Optional.",
    )

    tui = sub.add_parser(
        "tui",
        help="Render an analyst-focused terminal dashboard for an existing run directory.",
    )
    _ = tui.add_argument(
        "run_dir",
        nargs="?",
        default="latest",
        help=(
            "Path to an existing run directory. Omit (or use 'latest') to auto-pick "
            "the most recent run from aiedge-runs/ or aiedge-8mb-runs/."
        ),
    )
    _ = tui.add_argument(
        "-m",
        "--mode",
        choices=("once", "watch", "interactive", "auto"),
        default="auto",
        help=(
            "Dashboard mode (default: auto). auto selects interactive on TTY, "
            "otherwise renders once."
        ),
    )
    _ = tui.add_argument(
        "-n",
        "--limit",
        type=int,
        default=12,
        help="Maximum number of exploit candidates to print (default: 12).",
    )
    _ = tui.add_argument(
        "-w",
        "--watch",
        action="store_true",
        help="Alias for --mode watch. Refresh dashboard continuously until Ctrl+C.",
    )
    _ = tui.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Alias for --mode interactive. Launch interactive terminal UI (keyboard navigation).",
    )
    _ = tui.add_argument(
        "-t",
        "--interval-s",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="Refresh interval for --watch mode (default: 2.0).",
    )

    return parser
