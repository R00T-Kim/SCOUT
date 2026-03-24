#!/usr/bin/env python3
"""benchmark_runner.py -- SCOUT benchmark runner for reproducible quality measurement.

Runs SCOUT analysis against a corpus of firmware samples with gold labels,
measures precision/recall/FPR, and tracks deterministic stage digest stability.

Usage:
    python3 scripts/benchmark_runner.py --corpus benchmarks/corpus/manifest.json \\
        --output benchmarks/results/ [--no-llm] [--stages STAGES]

The corpus manifest uses schema ``benchmark-corpus-v1``::

    {
      "schema_version": "benchmark-corpus-v1",
      "corpus_id": "scout-public-v0",
      "samples": [ ... ]
    }

Each sample carries an ``expected`` block with gold labels for unpack success,
services, SBOM components, known CVEs, and hardening flags.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, cast


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SampleExpected:
    """Gold-label expectations for a single corpus sample."""

    unpack_success: bool = True
    services: List[str] = field(default_factory=list)
    sbom_components: List[str] = field(default_factory=list)
    known_cves: List[str] = field(default_factory=list)
    hardening: Dict[str, bool] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "SampleExpected":
        if data is None:
            return cls()
        return cls(
            unpack_success=bool(data.get("unpack_success", True)),
            services=list(data.get("services", [])),
            sbom_components=list(data.get("sbom_components", [])),
            known_cves=list(data.get("known_cves", [])),
            hardening=dict(data.get("hardening", {})),
        )


@dataclass
class CorpusSample:
    """A single firmware sample in the benchmark corpus."""

    id: str
    name: str
    path: str
    sha256: str
    architecture: str
    source_url: str
    expected: SampleExpected

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CorpusSample":
        return cls(
            id=data["id"],
            name=data.get("name", data["id"]),
            path=data["path"],
            sha256=data.get("sha256", ""),
            architecture=data.get("architecture", "unknown"),
            source_url=data.get("source_url", ""),
            expected=SampleExpected.from_dict(data.get("expected")),
        )


@dataclass
class SampleResult:
    """Benchmark results for a single sample."""

    sample_id: str
    sample_name: str
    run_dir: str
    status: str  # "ok", "partial", "failed", "skipped", "error"
    error_message: str = ""
    unpack_success: bool = False
    services_found: List[str] = field(default_factory=list)
    services_precision: float = 0.0
    services_recall: float = 0.0
    sbom_components_found: List[str] = field(default_factory=list)
    sbom_precision: float = 0.0
    sbom_recall: float = 0.0
    cves_found: List[str] = field(default_factory=list)
    cve_detection_rate: float = 0.0
    findings_count: int = 0
    stage_digests: Dict[str, str] = field(default_factory=dict)
    total_duration_s: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "sample_name": self.sample_name,
            "run_dir": self.run_dir,
            "status": self.status,
            "error_message": self.error_message,
            "unpack_success": self.unpack_success,
            "services_found": self.services_found,
            "services_precision": round(self.services_precision, 6),
            "services_recall": round(self.services_recall, 6),
            "sbom_components_found": self.sbom_components_found,
            "sbom_precision": round(self.sbom_precision, 6),
            "sbom_recall": round(self.sbom_recall, 6),
            "cves_found": self.cves_found,
            "cve_detection_rate": round(self.cve_detection_rate, 6),
            "findings_count": self.findings_count,
            "stage_digests": self.stage_digests,
            "total_duration_s": round(self.total_duration_s, 3),
        }


# ---------------------------------------------------------------------------
# Metric helpers
# ---------------------------------------------------------------------------

def _safe_ratio(numerator: int, denominator: int) -> float:
    """Return numerator/denominator clamped to [0, 1], or 0 if denominator<=0."""
    if denominator <= 0:
        return 0.0
    return max(0.0, min(1.0, float(numerator) / float(denominator)))


def _precision_recall(
    predicted: Sequence[str], expected: Sequence[str]
) -> Tuple[float, float]:
    """Compute precision and recall using case-insensitive substring matching.

    A predicted item matches an expected item if either contains the other as a
    substring (case-insensitive).  This handles partial name matches common in
    firmware analysis (e.g. ``busybox-1.36`` matching gold label ``busybox``).
    """
    if not predicted and not expected:
        return 1.0, 1.0
    if not predicted:
        return 0.0, 0.0
    if not expected:
        # Nothing expected but items found -- precision=0, recall vacuously 1.
        return 0.0, 1.0

    pred_lower = [p.lower() for p in predicted]
    exp_lower = [e.lower() for e in expected]

    tp_pred = 0
    for p in pred_lower:
        for e in exp_lower:
            if p in e or e in p:
                tp_pred += 1
                break

    tp_exp = 0
    for e in exp_lower:
        for p in pred_lower:
            if e in p or p in e:
                tp_exp += 1
                break

    precision = _safe_ratio(tp_pred, len(pred_lower))
    recall = _safe_ratio(tp_exp, len(exp_lower))
    return precision, recall


def _f1(precision: float, recall: float) -> float:
    denom = precision + recall
    if denom <= 0.0:
        return 0.0
    return max(0.0, min(1.0, (2.0 * precision * recall) / denom))


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


# ---------------------------------------------------------------------------
# Corpus loading
# ---------------------------------------------------------------------------

def load_benchmark_corpus(manifest_path: Path) -> Tuple[Dict[str, Any], List[CorpusSample]]:
    """Load and validate the benchmark corpus manifest.

    Returns the raw manifest dict and the parsed list of samples.
    """
    text = manifest_path.read_text(encoding="utf-8")
    payload = json.loads(text)

    schema = payload.get("schema_version", "")
    if schema and schema != "benchmark-corpus-v1":
        _warn(f"unexpected schema_version {schema!r}, proceeding anyway")

    corpus_id = payload.get("corpus_id", "unknown")
    raw_samples = payload.get("samples", [])
    if not isinstance(raw_samples, list):
        _fatal("manifest 'samples' must be a list")

    samples: List[CorpusSample] = []
    for idx, raw in enumerate(raw_samples):
        if not isinstance(raw, dict):
            _warn(f"sample[{idx}] is not an object, skipping")
            continue
        if "id" not in raw:
            _warn(f"sample[{idx}] has no 'id', skipping")
            continue
        samples.append(CorpusSample.from_dict(raw))

    _info(f"loaded corpus {corpus_id!r} with {len(samples)} sample(s)")
    return payload, samples


# ---------------------------------------------------------------------------
# SCOUT invocation
# ---------------------------------------------------------------------------

def _find_scout_root(manifest_path: Path) -> Path:
    """Walk up from the manifest to find the SCOUT project root (where ./scout lives)."""
    candidate = manifest_path.resolve().parent
    for _ in range(10):
        if (candidate / "scout").is_file():
            return candidate
        parent = candidate.parent
        if parent == candidate:
            break
        candidate = parent
    # Fallback: assume cwd
    return Path.cwd()


def run_scout_analysis(
    sample: CorpusSample,
    scout_root: Path,
    *,
    no_llm: bool = True,
    stages: Optional[str] = None,
    timeout_s: int = 3600,
) -> Tuple[Optional[Path], float, str]:
    """Run SCOUT analysis on a single sample.

    Returns (run_dir_path, duration_seconds, error_message).
    run_dir_path is None if analysis completely failed to start.
    """
    firmware_path = scout_root / sample.path
    if not firmware_path.is_file():
        return None, 0.0, f"firmware file not found: {firmware_path}"

    cmd: List[str] = [
        sys.executable, "-m", "aiedge",
        "analyze", str(firmware_path),
        "--ack-authorization",
    ]
    if no_llm:
        cmd.append("--no-llm")
    if stages:
        cmd.extend(["--stages", stages])
    cmd.extend(["--time-budget-s", str(timeout_s)])

    env = os.environ.copy()
    src_path = str(scout_root / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path

    _info(f"  running: {' '.join(cmd[-6:])}")
    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(scout_root),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_s + 60,  # grace period above the internal budget
        )
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - start
        return None, elapsed, f"subprocess timed out after {timeout_s + 60}s"
    except Exception as exc:
        elapsed = time.monotonic() - start
        return None, elapsed, f"subprocess error: {exc}"

    elapsed = time.monotonic() - start

    # Find the run directory from stdout -- SCOUT prints it
    run_dir = _extract_run_dir(proc.stdout, proc.stderr, scout_root)

    if proc.returncode not in (0, 10):
        # 0=success, 10=partial success -- both acceptable
        error_msg = f"exit code {proc.returncode}"
        if proc.stderr:
            # Last 500 chars of stderr for context
            error_msg += f": {proc.stderr[-500:]}"
        return run_dir, elapsed, error_msg

    return run_dir, elapsed, ""


def _extract_run_dir(
    stdout: str, stderr: str, scout_root: Path
) -> Optional[Path]:
    """Try to find the run directory from SCOUT output.

    SCOUT typically creates run dirs under aiedge-runs/ or aiedge-8mb-runs/.
    Look for the most recently modified directory.
    """
    # Try to find run dir from output lines
    for line in (stdout + "\n" + stderr).splitlines():
        line = line.strip()
        if "aiedge-runs/" in line or "aiedge-8mb-runs/" in line:
            # Extract path-like substring
            for token in line.split():
                if "aiedge-runs/" in token or "aiedge-8mb-runs/" in token:
                    candidate = scout_root / token.strip("'\"")
                    if candidate.is_dir():
                        return candidate

    # Fallback: find most recent run directory
    for runs_parent in ("aiedge-runs", "aiedge-8mb-runs"):
        runs_dir = scout_root / runs_parent
        if not runs_dir.is_dir():
            continue
        subdirs = sorted(
            (d for d in runs_dir.iterdir() if d.is_dir()),
            key=lambda d: d.stat().st_mtime,
            reverse=True,
        )
        if subdirs:
            return subdirs[0]

    return None


# ---------------------------------------------------------------------------
# Result extraction from run directory
# ---------------------------------------------------------------------------

def _load_stage_json(run_dir: Path, stage_name: str) -> Optional[Dict[str, Any]]:
    """Load stages/<stage_name>/stage.json if it exists."""
    path = run_dir / "stages" / stage_name / "stage.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_json_file(path: Path) -> Optional[Any]:
    """Load any JSON file, returning None on failure."""
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _collect_stage_digests(run_dir: Path) -> Dict[str, str]:
    """Compute SHA-256 of each stage's normalized stage.json (volatile keys stripped)."""
    volatile_keys = {
        "created_at", "run_id", "started_at", "finished_at", "duration_s",
    }
    digests: Dict[str, str] = {}
    stages_dir = run_dir / "stages"
    if not stages_dir.is_dir():
        return digests

    for stage_dir in sorted(stages_dir.iterdir()):
        if not stage_dir.is_dir():
            continue
        stage_json = stage_dir / "stage.json"
        if not stage_json.is_file():
            continue
        try:
            data = json.loads(stage_json.read_text(encoding="utf-8"))
            normalized = _normalize_for_digest(data, volatile_keys)
            canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            digests[stage_dir.name] = _sha256_text(canonical)
        except Exception:
            digests[stage_dir.name] = "error"

    return digests


def _normalize_for_digest(value: Any, volatile_keys: set) -> Any:
    """Strip volatile keys and normalize floats for deterministic hashing."""
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        return float(round(value, 6))
    if isinstance(value, list):
        return [_normalize_for_digest(v, volatile_keys) for v in value]
    if isinstance(value, dict):
        return {
            k: _normalize_for_digest(v, volatile_keys)
            for k, v in value.items()
            if k not in volatile_keys
        }
    return str(value)


def extract_results(
    sample: CorpusSample,
    run_dir: Optional[Path],
    duration_s: float,
    error_message: str,
) -> SampleResult:
    """Extract benchmark metrics from a completed analysis run."""
    if run_dir is None or not run_dir.is_dir():
        return SampleResult(
            sample_id=sample.id,
            sample_name=sample.name,
            run_dir=str(run_dir or ""),
            status="error" if error_message else "skipped",
            error_message=error_message or "no run directory found",
            total_duration_s=duration_s,
        )

    result = SampleResult(
        sample_id=sample.id,
        sample_name=sample.name,
        run_dir=str(run_dir),
        status="ok",
        total_duration_s=duration_s,
        error_message=error_message,
    )

    # -- Unpack success --
    extraction = _load_stage_json(run_dir, "extraction")
    if extraction is not None:
        status = extraction.get("status", "failed")
        result.unpack_success = status in ("ok", "partial")
    else:
        result.unpack_success = False

    # -- Services found --
    inventory = _load_stage_json(run_dir, "inventory")
    if inventory is not None:
        result.services_found = _extract_services(run_dir)
    prec, rec = _precision_recall(result.services_found, sample.expected.services)
    result.services_precision = prec
    result.services_recall = rec

    # -- SBOM components --
    result.sbom_components_found = _extract_sbom_components(run_dir)
    prec, rec = _precision_recall(
        result.sbom_components_found, sample.expected.sbom_components
    )
    result.sbom_precision = prec
    result.sbom_recall = rec

    # -- CVE matches --
    result.cves_found = _extract_cves(run_dir)
    if sample.expected.known_cves:
        matched = 0
        for expected_cve in sample.expected.known_cves:
            exp_lower = expected_cve.lower()
            for found_cve in result.cves_found:
                if exp_lower in found_cve.lower() or found_cve.lower() in exp_lower:
                    matched += 1
                    break
        result.cve_detection_rate = _safe_ratio(matched, len(sample.expected.known_cves))
    else:
        result.cve_detection_rate = 1.0  # nothing to miss

    # -- Findings count --
    result.findings_count = _count_findings(run_dir)

    # -- Stage digests --
    result.stage_digests = _collect_stage_digests(run_dir)

    # -- Determine overall status --
    if error_message and result.unpack_success:
        result.status = "partial"
    elif error_message:
        result.status = "failed"

    return result


def _extract_services(run_dir: Path) -> List[str]:
    """Extract detected service names from inventory and endpoints stages."""
    services: List[str] = []

    # From inventory stage artifacts
    inventory_dir = run_dir / "stages" / "inventory"
    if inventory_dir.is_dir():
        for artifact in inventory_dir.iterdir():
            if artifact.suffix != ".json" or artifact.name == "stage.json":
                continue
            data = _load_json_file(artifact)
            if not isinstance(data, dict):
                continue
            # Look for service-related keys
            for key in ("services", "listening_services", "init_services"):
                items = data.get(key)
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            services.append(item)
                        elif isinstance(item, dict):
                            name = item.get("name") or item.get("service") or item.get("binary")
                            if isinstance(name, str):
                                services.append(name)

    # From endpoints stage
    endpoints_data = _load_stage_json(run_dir, "endpoints")
    if isinstance(endpoints_data, dict):
        artifacts = endpoints_data.get("artifacts", [])
        if isinstance(artifacts, list):
            for art in artifacts:
                if isinstance(art, dict) and isinstance(art.get("path"), str):
                    art_path = run_dir / art["path"]
                    data = _load_json_file(art_path)
                    if isinstance(data, dict):
                        svc_list = data.get("services", [])
                        if isinstance(svc_list, list):
                            for s in svc_list:
                                if isinstance(s, str):
                                    services.append(s)
                                elif isinstance(s, dict):
                                    name = s.get("name", "")
                                    if isinstance(name, str) and name:
                                        services.append(name)

    return sorted(set(services))


def _extract_sbom_components(run_dir: Path) -> List[str]:
    """Extract SBOM component names from the sbom stage."""
    components: List[str] = []

    sbom_dir = run_dir / "stages" / "sbom"
    if not sbom_dir.is_dir():
        return components

    for artifact in sbom_dir.iterdir():
        if artifact.suffix != ".json" or artifact.name == "stage.json":
            continue
        data = _load_json_file(artifact)
        if not isinstance(data, dict):
            continue
        # CycloneDX format
        comp_list = data.get("components", [])
        if isinstance(comp_list, list):
            for comp in comp_list:
                if isinstance(comp, dict):
                    name = comp.get("name", "")
                    if isinstance(name, str) and name:
                        components.append(name)

    return sorted(set(components))


def _extract_cves(run_dir: Path) -> List[str]:
    """Extract CVE IDs from the cve_scan stage."""
    cves: List[str] = []

    cve_dir = run_dir / "stages" / "cve_scan"
    if not cve_dir.is_dir():
        return cves

    for artifact in cve_dir.iterdir():
        if artifact.suffix != ".json" or artifact.name == "stage.json":
            continue
        data = _load_json_file(artifact)
        if not isinstance(data, dict):
            continue
        # Look for CVE lists in various formats
        for key in ("cves", "vulnerabilities", "matches", "results"):
            items = data.get(key)
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, str) and item.upper().startswith("CVE-"):
                        cves.append(item)
                    elif isinstance(item, dict):
                        cve_id = item.get("cve_id") or item.get("id") or item.get("cve")
                        if isinstance(cve_id, str) and cve_id.upper().startswith("CVE-"):
                            cves.append(cve_id)

    return sorted(set(cves))


def _count_findings(run_dir: Path) -> int:
    """Count total findings from the findings stage."""
    findings_dir = run_dir / "stages" / "findings"
    if not findings_dir.is_dir():
        return 0

    count = 0
    for artifact in findings_dir.iterdir():
        if artifact.suffix != ".json" or artifact.name == "stage.json":
            continue
        data = _load_json_file(artifact)
        if isinstance(data, list):
            count += len(data)
        elif isinstance(data, dict):
            findings_list = data.get("findings", [])
            if isinstance(findings_list, list):
                count += len(findings_list)

    return count


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def aggregate_results(
    results: List[SampleResult],
    corpus_payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Compute aggregate benchmark summary across all sample results."""
    total = len(results)
    if total == 0:
        return {
            "schema_version": "benchmark-summary-v1",
            "corpus_id": corpus_payload.get("corpus_id", "unknown"),
            "sample_count": 0,
            "error": "no samples processed",
        }

    # Status counts
    status_counts: Dict[str, int] = {}
    for r in results:
        status_counts[r.status] = status_counts.get(r.status, 0) + 1

    # Unpack success rate
    attempted = [r for r in results if r.status != "skipped"]
    unpack_ok = sum(1 for r in attempted if r.unpack_success)
    unpack_rate = _safe_ratio(unpack_ok, len(attempted)) if attempted else 0.0

    # SBOM precision/recall (macro-average over samples with expectations)
    sbom_samples = [r for r in results if r.status in ("ok", "partial")]
    sbom_prec_sum = sum(r.sbom_precision for r in sbom_samples)
    sbom_rec_sum = sum(r.sbom_recall for r in sbom_samples)
    sbom_count = len(sbom_samples) or 1
    sbom_precision_avg = sbom_prec_sum / sbom_count
    sbom_recall_avg = sbom_rec_sum / sbom_count

    # Service detection precision/recall (macro-average)
    svc_prec_sum = sum(r.services_precision for r in sbom_samples)
    svc_rec_sum = sum(r.services_recall for r in sbom_samples)
    svc_precision_avg = svc_prec_sum / sbom_count
    svc_recall_avg = svc_rec_sum / sbom_count

    # CVE detection rate (macro-average)
    cve_samples = [r for r in results if r.status in ("ok", "partial")]
    cve_rate_sum = sum(r.cve_detection_rate for r in cve_samples)
    cve_count = len(cve_samples) or 1
    cve_rate_avg = cve_rate_sum / cve_count

    # Timing
    durations = [r.total_duration_s for r in results if r.total_duration_s > 0]
    mean_duration = sum(durations) / len(durations) if durations else 0.0
    total_duration = sum(durations)

    # Findings
    total_findings = sum(r.findings_count for r in results)

    return {
        "schema_version": "benchmark-summary-v1",
        "corpus_id": corpus_payload.get("corpus_id", "unknown"),
        "sample_count": total,
        "status_counts": status_counts,
        "unpack_success_rate": round(unpack_rate, 6),
        "sbom": {
            "macro_precision": round(sbom_precision_avg, 6),
            "macro_recall": round(sbom_recall_avg, 6),
            "macro_f1": round(_f1(sbom_precision_avg, sbom_recall_avg), 6),
        },
        "services": {
            "macro_precision": round(svc_precision_avg, 6),
            "macro_recall": round(svc_recall_avg, 6),
            "macro_f1": round(_f1(svc_precision_avg, svc_recall_avg), 6),
        },
        "cve_detection_rate": round(cve_rate_avg, 6),
        "findings_total": total_findings,
        "timing": {
            "mean_duration_s": round(mean_duration, 3),
            "total_duration_s": round(total_duration, 3),
            "min_duration_s": round(min(durations), 3) if durations else 0.0,
            "max_duration_s": round(max(durations), 3) if durations else 0.0,
        },
    }


# ---------------------------------------------------------------------------
# Determinism checking
# ---------------------------------------------------------------------------

def build_digest_map(results: List[SampleResult]) -> Dict[str, Any]:
    """Build stage digest map for determinism verification across runs."""
    digest_map: Dict[str, Any] = {
        "schema_version": "benchmark-digests-v1",
        "samples": {},
    }

    for r in results:
        if r.stage_digests:
            digest_map["samples"][r.sample_id] = {
                "run_dir": r.run_dir,
                "stage_digests": r.stage_digests,
            }

    return digest_map


def check_determinism(
    all_run_results: List[List[SampleResult]],
) -> Dict[str, Any]:
    """Compare stage digests across repeated runs to check determinism.

    Returns a report with per-sample, per-stage determinism results.
    """
    if len(all_run_results) < 2:
        return {
            "deterministic": True,
            "runs_compared": len(all_run_results),
            "note": "need >= 2 runs for determinism comparison",
        }

    mismatches: List[Dict[str, Any]] = []
    num_runs = len(all_run_results)

    # Build sample->run->stage->digest index
    sample_ids: set = set()
    for run_results in all_run_results:
        for r in run_results:
            sample_ids.add(r.sample_id)

    for sid in sorted(sample_ids):
        # Collect digests for this sample across runs
        run_digests: List[Dict[str, str]] = []
        for run_results in all_run_results:
            matching = [r for r in run_results if r.sample_id == sid]
            if matching:
                run_digests.append(matching[0].stage_digests)
            else:
                run_digests.append({})

        # Compare each stage
        all_stages: set = set()
        for d in run_digests:
            all_stages.update(d.keys())

        for stage in sorted(all_stages):
            digests_for_stage = [d.get(stage, "missing") for d in run_digests]
            unique = set(digests_for_stage)
            if len(unique) > 1:
                mismatches.append({
                    "sample_id": sid,
                    "stage": stage,
                    "digests": digests_for_stage,
                })

    return {
        "deterministic": len(mismatches) == 0,
        "runs_compared": num_runs,
        "total_mismatches": len(mismatches),
        "mismatches": mismatches[:50],  # cap output size
    }


# ---------------------------------------------------------------------------
# Baseline comparison
# ---------------------------------------------------------------------------

def compare_with_baseline(
    summary: Dict[str, Any],
    baseline_path: Path,
) -> Dict[str, Any]:
    """Compare current summary against a baseline result file.

    Returns a delta report with regressions highlighted.
    """
    baseline_data = _load_json_file(baseline_path)
    if not isinstance(baseline_data, dict):
        return {"error": f"invalid baseline file: {baseline_path}"}

    delta: Dict[str, Any] = {
        "schema_version": "benchmark-delta-v1",
        "baseline_path": str(baseline_path),
        "regressions": [],
        "improvements": [],
    }

    # Metrics where higher is better
    higher_better = [
        ("unpack_success_rate", "unpack_success_rate"),
        ("sbom.macro_precision", "sbom.macro_precision"),
        ("sbom.macro_recall", "sbom.macro_recall"),
        ("sbom.macro_f1", "sbom.macro_f1"),
        ("services.macro_precision", "services.macro_precision"),
        ("services.macro_recall", "services.macro_recall"),
        ("services.macro_f1", "services.macro_f1"),
        ("cve_detection_rate", "cve_detection_rate"),
    ]

    for metric_path, label in higher_better:
        current_val = _get_nested_float(summary, metric_path)
        baseline_val = _get_nested_float(baseline_data, metric_path)
        diff = current_val - baseline_val

        entry = {
            "metric": label,
            "current": round(current_val, 6),
            "baseline": round(baseline_val, 6),
            "delta": round(diff, 6),
        }
        if diff < -0.01:  # regression threshold
            delta["regressions"].append(entry)
        elif diff > 0.01:
            delta["improvements"].append(entry)

    delta["has_regressions"] = len(delta["regressions"]) > 0
    return delta


def _get_nested_float(data: Dict[str, Any], path: str) -> float:
    """Traverse a dot-separated path and return a float value, defaulting to 0."""
    current: Any = data
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part, 0.0)
        else:
            return 0.0
    if isinstance(current, (int, float)):
        return float(current)
    return 0.0


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _write_json(path: Path, data: Any) -> None:
    """Write data as pretty-printed JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _info(msg: str) -> None:
    print(f"[benchmark] {msg}", file=sys.stderr, flush=True)


def _warn(msg: str) -> None:
    print(f"[benchmark] WARNING: {msg}", file=sys.stderr, flush=True)


def _fatal(msg: str) -> None:
    print(f"[benchmark] FATAL: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run_benchmark(
    corpus_path: Path,
    output_dir: Path,
    *,
    no_llm: bool = True,
    stages: Optional[str] = None,
    repeat: int = 1,
    timeout_s: int = 3600,
    baseline_path: Optional[Path] = None,
) -> int:
    """Execute the full benchmark suite.

    Returns exit code: 0 = all passed, 1 = some failures, 2 = fatal error.
    """
    corpus_payload, samples = load_benchmark_corpus(corpus_path)
    scout_root = _find_scout_root(corpus_path)
    _info(f"SCOUT root: {scout_root}")
    _info(f"output: {output_dir}")
    _info(f"repeat: {repeat}, no_llm: {no_llm}, timeout: {timeout_s}s")

    if not samples:
        _fatal("no samples in corpus")

    output_dir.mkdir(parents=True, exist_ok=True)
    all_run_results: List[List[SampleResult]] = []

    for run_idx in range(repeat):
        if repeat > 1:
            _info(f"=== Run {run_idx + 1}/{repeat} ===")

        run_results: List[SampleResult] = []
        for sample_idx, sample in enumerate(samples):
            _info(
                f"[{sample_idx + 1}/{len(samples)}] "
                f"sample={sample.id!r} ({sample.name})"
            )

            # Check firmware file exists
            firmware_path = scout_root / sample.path
            if not firmware_path.is_file():
                _warn(f"  skipping: file not found at {firmware_path}")
                run_results.append(SampleResult(
                    sample_id=sample.id,
                    sample_name=sample.name,
                    run_dir="",
                    status="skipped",
                    error_message=f"file not found: {firmware_path}",
                ))
                continue

            run_dir, duration, error = run_scout_analysis(
                sample,
                scout_root,
                no_llm=no_llm,
                stages=stages,
                timeout_s=timeout_s,
            )

            result = extract_results(sample, run_dir, duration, error)
            run_results.append(result)

            status_icon = {
                "ok": "OK", "partial": "PARTIAL",
                "failed": "FAIL", "skipped": "SKIP", "error": "ERR",
            }.get(result.status, "???")
            _info(
                f"  {status_icon} | unpack={'Y' if result.unpack_success else 'N'}"
                f" | services={len(result.services_found)}"
                f" | sbom={len(result.sbom_components_found)}"
                f" | cves={len(result.cves_found)}"
                f" | findings={result.findings_count}"
                f" | {result.total_duration_s:.1f}s"
            )

        all_run_results.append(run_results)

    # Use the last run for primary results
    primary_results = all_run_results[-1]

    # --- Write per-sample results ---
    results_payload = {
        "schema_version": "benchmark-results-v1",
        "corpus_id": corpus_payload.get("corpus_id", "unknown"),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "config": {
            "no_llm": no_llm,
            "stages": stages,
            "repeat": repeat,
            "timeout_s": timeout_s,
        },
        "results": [r.to_dict() for r in primary_results],
    }
    results_path = output_dir / "benchmark_results.json"
    _write_json(results_path, results_payload)
    _info(f"wrote {results_path}")

    # --- Write summary ---
    summary = aggregate_results(primary_results, corpus_payload)
    summary["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    summary_path = output_dir / "benchmark_summary.json"
    _write_json(summary_path, summary)
    _info(f"wrote {summary_path}")

    # --- Write digest map ---
    digests = build_digest_map(primary_results)
    digests_path = output_dir / "benchmark_digests.json"
    _write_json(digests_path, digests)
    _info(f"wrote {digests_path}")

    # --- Determinism check ---
    if repeat > 1:
        det_report = check_determinism(all_run_results)
        det_path = output_dir / "benchmark_determinism.json"
        _write_json(det_path, det_report)
        _info(f"wrote {det_path}")
        if det_report["deterministic"]:
            _info("determinism check: PASS")
        else:
            _warn(
                f"determinism check: FAIL "
                f"({det_report['total_mismatches']} mismatch(es))"
            )

    # --- Baseline comparison ---
    if baseline_path is not None:
        delta = compare_with_baseline(summary, baseline_path)
        delta_path = output_dir / "benchmark_delta.json"
        _write_json(delta_path, delta)
        _info(f"wrote {delta_path}")
        if delta.get("has_regressions"):
            _warn(f"baseline comparison: {len(delta['regressions'])} regression(s)")
            for reg in delta["regressions"]:
                _warn(
                    f"  {reg['metric']}: "
                    f"{reg['baseline']:.4f} -> {reg['current']:.4f} "
                    f"(delta={reg['delta']:+.4f})"
                )
        else:
            _info("baseline comparison: no regressions")

    # --- Print summary to stderr ---
    _info("--- Summary ---")
    _info(f"samples: {summary.get('sample_count', 0)}")
    _info(f"status: {summary.get('status_counts', {})}")
    _info(f"unpack rate: {summary.get('unpack_success_rate', 0):.1%}")
    sbom_info = summary.get("sbom", {})
    _info(
        f"SBOM: P={sbom_info.get('macro_precision', 0):.3f}"
        f" R={sbom_info.get('macro_recall', 0):.3f}"
        f" F1={sbom_info.get('macro_f1', 0):.3f}"
    )
    svc_info = summary.get("services", {})
    _info(
        f"services: P={svc_info.get('macro_precision', 0):.3f}"
        f" R={svc_info.get('macro_recall', 0):.3f}"
        f" F1={svc_info.get('macro_f1', 0):.3f}"
    )
    _info(f"CVE detection rate: {summary.get('cve_detection_rate', 0):.1%}")
    timing = summary.get("timing", {})
    _info(f"mean time: {timing.get('mean_duration_s', 0):.1f}s")
    _info(f"total findings: {summary.get('findings_total', 0)}")

    # Return code
    failed = sum(
        1 for r in primary_results if r.status in ("failed", "error")
    )
    if failed > 0:
        return 1
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="benchmark_runner",
        description=(
            "SCOUT benchmark runner -- run analysis against a labelled corpus "
            "and measure precision, recall, CVE detection, and determinism."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python3 scripts/benchmark_runner.py \\\n"
            "      --corpus benchmarks/corpus/manifest.json \\\n"
            "      --output benchmarks/results/\n"
            "\n"
            "  python3 scripts/benchmark_runner.py \\\n"
            "      --corpus benchmarks/corpus/manifest.json \\\n"
            "      --output benchmarks/results/ \\\n"
            "      --no-llm --repeat 3 --timeout 1800\n"
            "\n"
            "  python3 scripts/benchmark_runner.py \\\n"
            "      --corpus benchmarks/corpus/manifest.json \\\n"
            "      --output benchmarks/results/ \\\n"
            "      --baseline benchmarks/baseline/benchmark_summary.json\n"
        ),
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        required=True,
        help="path to benchmark corpus manifest JSON",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="directory for benchmark result files",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        default=False,
        help="pass --no-llm to SCOUT (deterministic analysis, no LLM calls)",
    )
    parser.add_argument(
        "--stages",
        type=str,
        default=None,
        help="comma-separated list of stages to run (default: all)",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        metavar="N",
        help="run each sample N times for determinism checking (default: 1)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=3600,
        metavar="SECONDS",
        help="per-sample timeout in seconds (default: 3600)",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        metavar="PATH",
        help="path to previous benchmark_summary.json for regression detection",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    corpus_path: Path = args.corpus
    if not corpus_path.is_file():
        _fatal(f"corpus manifest not found: {corpus_path}")

    if args.repeat < 1:
        _fatal("--repeat must be >= 1")
    if args.timeout < 1:
        _fatal("--timeout must be >= 1")

    if args.baseline is not None and not args.baseline.is_file():
        _fatal(f"baseline file not found: {args.baseline}")

    return run_benchmark(
        corpus_path=corpus_path,
        output_dir=args.output,
        no_llm=args.no_llm,
        stages=args.stages,
        repeat=args.repeat,
        timeout_s=args.timeout,
        baseline_path=args.baseline,
    )


if __name__ == "__main__":
    sys.exit(main())
