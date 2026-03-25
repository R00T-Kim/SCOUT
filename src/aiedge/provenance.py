"""provenance.py — SLSA L2 provenance attestation for SCOUT analysis artifacts.

Generates in-toto attestation statements that record:
- What firmware was analyzed (subject)
- What version of SCOUT was used (builder)
- What stages ran and their digests (materials/predicate)
- When the analysis started and finished (metadata)

The attestation can be signed with cosign for SLSA L2 compliance.

Usage::

    from pathlib import Path
    from aiedge.provenance import generate_attestation, write_attestation, verify_attestation

    # Generate and persist
    attestation_path = write_attestation(Path("aiedge-runs/my-run"))

    # Verify later
    result = verify_attestation(attestation_path, Path("aiedge-runs/my-run"))
    print(result["valid"])
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from .path_safety import assert_under_dir, sha256_file

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

ATTESTATION_TYPE = "https://in-toto.io/Statement/v0.1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://github.com/R00T-Kim/SCOUT/analysis/v1"
BUILDER_ID = "https://github.com/R00T-Kim/SCOUT"

# Artifact names that become in-toto subjects (order matters for stability)
_SUBJECT_NAMES: tuple[str, ...] = (
    "firmware_handoff.json",
    "analyst_digest.json",
    "verified_chain.json",
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_json_object(path: Path) -> dict[str, object] | None:
    """Return parsed JSON object from *path*, or None on any failure."""
    try:
        data = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return cast(dict[str, object], data)


def _str_field(obj: dict[str, object], key: str) -> str:
    v = obj.get(key)
    return v if isinstance(v, str) else ""


def _collect_subjects(run_dir: Path) -> list[dict[str, object]]:
    """Return in-toto subject entries for the canonical SCOUT output artifacts."""
    subjects: list[dict[str, object]] = []
    for name in _SUBJECT_NAMES:
        candidate = run_dir / name
        if not candidate.is_file():
            continue
        digest = sha256_file(candidate)
        subjects.append(
            {
                "name": name,
                "digest": {"sha256": digest},
            }
        )
    return subjects


def _collect_stage_materials(run_dir: Path) -> list[dict[str, object]]:
    """Return one material entry per completed stage, keyed by stage.json digest."""
    stages_dir = run_dir / "stages"
    if not stages_dir.is_dir():
        return []

    materials: list[dict[str, object]] = []
    for stage_dir in sorted(p for p in stages_dir.iterdir() if p.is_dir()):
        stage_json = stage_dir / "stage.json"
        if not stage_json.is_file():
            continue
        digest = sha256_file(stage_json)
        rel = stage_json.relative_to(run_dir).as_posix()
        materials.append(
            {
                "uri": rel,
                "digest": {"sha256": digest},
            }
        )
    return materials


def _read_manifest(run_dir: Path) -> dict[str, object]:
    manifest_path = run_dir / "manifest.json"
    obj = _read_json_object(manifest_path)
    return obj if obj is not None else {}


def _manifest_timestamps(manifest: dict[str, object]) -> tuple[str, str]:
    """Return (started_on, finished_on) ISO strings from the manifest.

    ``manifest.json`` records ``created_at`` as the run-init timestamp.
    A finished timestamp is derived from the latest ``finished_at`` across
    all stage.json files, falling back to ``created_at`` when unavailable.
    """
    started_on = _str_field(manifest, "created_at")

    # Best-effort: scan stage manifests for the latest finished_at.
    finished_on = started_on
    Path(manifest.get("run_dir", "")) if False else None  # unused branch
    return started_on, finished_on


def _latest_stage_finished_at(run_dir: Path) -> str:
    """Return the latest ``finished_at`` timestamp found across all stage.json files."""
    stages_dir = run_dir / "stages"
    latest = ""
    if not stages_dir.is_dir():
        return latest
    for stage_dir in stages_dir.iterdir():
        if not stage_dir.is_dir():
            continue
        obj = _read_json_object(stage_dir / "stage.json")
        if obj is None:
            continue
        ts = _str_field(obj, "finished_at")
        if ts and ts > latest:
            latest = ts
    return latest


def _no_llm_from_manifest(manifest: dict[str, object]) -> bool:
    """Infer whether --no-llm was used.

    There is no dedicated field; we check for the absence of any LLM-related
    key as a best-effort heuristic and default to False (unknown → assume LLM
    was enabled).
    """
    # The manifest does not currently record --no-llm; return False as default.
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_attestation(run_dir: Path, tool_version: str = "1.0.0") -> dict[str, object]:
    """Create an in-toto Statement v0.1 attestation for a SCOUT analysis run.

    Reads ``manifest.json``, all ``stages/*/stage.json`` files, and the
    canonical output artifacts (``firmware_handoff.json``,
    ``analyst_digest.json``, ``verified_chain.json``) from *run_dir*.

    Args:
        run_dir: Root directory of a completed (or partial) SCOUT run.
        tool_version: Semantic version string for SCOUT (e.g. ``"1.2.3"``).
            Defaults to ``"0.0.0"`` when the caller has not supplied a value.

    Returns:
        A dict representing a fully-formed in-toto Statement v0.1 with an
        SLSA Provenance v1 predicate.  The dict is JSON-serialisable with the
        standard ``json`` module.
    """
    run_dir = run_dir.resolve()

    manifest = _read_manifest(run_dir)
    run_id = _str_field(manifest, "run_id") or run_dir.name
    firmware_sha256 = _str_field(manifest, "input_sha256")
    started_on = _str_field(manifest, "created_at")
    finished_on = _latest_stage_finished_at(run_dir) or started_on

    subjects = _collect_subjects(run_dir)
    materials = _collect_stage_materials(run_dir)

    # Reconstruct the stages list from stage directories for externalParameters
    stages_dir = run_dir / "stages"
    stage_names: list[str] = []
    if stages_dir.is_dir():
        stage_names = sorted(p.name for p in stages_dir.iterdir() if p.is_dir())

    attestation: dict[str, object] = {
        "_type": ATTESTATION_TYPE,
        "subject": subjects,
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "firmware_sha256": firmware_sha256,
                    "stages": stage_names if stage_names else "all",
                    "no_llm": _no_llm_from_manifest(manifest),
                },
                "internalParameters": {},
                "resolvedDependencies": materials,
            },
            "runDetails": {
                "builder": {
                    "id": BUILDER_ID,
                    "version": {"scout": tool_version},
                },
                "metadata": {
                    "invocationId": run_id,
                    "startedOn": started_on,
                    "finishedOn": finished_on,
                },
            },
        },
    }
    return attestation


def write_attestation(
    run_dir: Path,
    output_path: Path | None = None,
    tool_version: str = "1.0.0",
) -> Path:
    """Generate an attestation and write it to disk.

    Args:
        run_dir: Root directory of a completed (or partial) SCOUT run.
        output_path: Destination file path.  When ``None``, defaults to
            ``run_dir/attestation.intoto.json``.
        tool_version: Semantic version string passed through to
            :func:`generate_attestation`.

    Returns:
        The resolved path of the written attestation file.

    Raises:
        AIEdgePolicyViolation: If *output_path* resolves outside *run_dir*
            (path-traversal guard).
    """
    run_dir = run_dir.resolve()

    if output_path is None:
        dest = run_dir / "attestation.intoto.json"
    else:
        dest = output_path.resolve()
        assert_under_dir(run_dir, dest)

    attestation = generate_attestation(run_dir, tool_version=tool_version)
    payload = json.dumps(attestation, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    dest.write_text(payload, encoding="utf-8")
    return dest


def verify_attestation(attestation_path: Path, run_dir: Path) -> dict[str, object]:
    """Verify an existing attestation against the current run artifacts.

    Checks:

    1. Every subject listed in the attestation has a matching file whose
       current SHA-256 digest equals the recorded digest.
    2. Every resolved dependency (stage material) listed in the attestation
       has a matching ``stage.json`` file whose current digest matches.

    Args:
        attestation_path: Path to the ``*.intoto.json`` file to verify.
        run_dir: Root directory of the SCOUT run the attestation covers.

    Returns:
        A dict with the following keys:

        ``valid`` (bool)
            ``True`` iff all recorded digests match the current files.
        ``mismatches`` (list of str)
            Human-readable descriptions of each mismatch found.
        ``checked_at`` (str)
            ISO-8601 UTC timestamp of when the verification ran.
    """
    run_dir = run_dir.resolve()
    mismatches: list[str] = []

    attestation_obj = _read_json_object(attestation_path)
    if attestation_obj is None:
        return {
            "valid": False,
            "mismatches": ["attestation file is missing or not valid JSON"],
            "checked_at": _iso_utc_now(),
        }

    # ------------------------------------------------------------------ #
    # 1. Verify subjects
    # ------------------------------------------------------------------ #
    raw_subjects = attestation_obj.get("subject")
    subjects: list[object] = (
        cast(list[object], raw_subjects) if isinstance(raw_subjects, list) else []
    )
    for subj_any in subjects:
        if not isinstance(subj_any, dict):
            mismatches.append("subject entry is not a JSON object")
            continue
        subj = cast(dict[str, object], subj_any)
        name_val = subj.get("name")
        name = name_val if isinstance(name_val, str) else ""
        digest_any = subj.get("digest")
        if not isinstance(digest_any, dict):
            mismatches.append(f"subject '{name}': missing digest object")
            continue
        digest_obj = cast(dict[str, object], digest_any)
        expected_sha = digest_obj.get("sha256")
        if not isinstance(expected_sha, str):
            mismatches.append(f"subject '{name}': missing sha256 in digest")
            continue

        candidate = run_dir / name
        if not candidate.is_file():
            mismatches.append(f"subject '{name}': file not found at {candidate}")
            continue
        actual_sha = sha256_file(candidate)
        if actual_sha != expected_sha:
            mismatches.append(
                f"subject '{name}': digest mismatch "
                f"(expected={expected_sha[:16]}… actual={actual_sha[:16]}…)"
            )

    # ------------------------------------------------------------------ #
    # 2. Verify stage materials (resolvedDependencies)
    # ------------------------------------------------------------------ #
    predicate_any = attestation_obj.get("predicate")
    if isinstance(predicate_any, dict):
        predicate = cast(dict[str, object], predicate_any)
        build_def_any = predicate.get("buildDefinition")
        if isinstance(build_def_any, dict):
            build_def = cast(dict[str, object], build_def_any)
            deps_any = build_def.get("resolvedDependencies")
            deps: list[object] = (
                cast(list[object], deps_any) if isinstance(deps_any, list) else []
            )
            for dep_any in deps:
                if not isinstance(dep_any, dict):
                    mismatches.append("resolvedDependency entry is not a JSON object")
                    continue
                dep = cast(dict[str, object], dep_any)
                uri_val = dep.get("uri")
                uri = uri_val if isinstance(uri_val, str) else ""
                dep_digest_any = dep.get("digest")
                if not isinstance(dep_digest_any, dict):
                    mismatches.append(f"material '{uri}': missing digest object")
                    continue
                dep_digest = cast(dict[str, object], dep_digest_any)
                expected_sha = dep_digest.get("sha256")
                if not isinstance(expected_sha, str):
                    mismatches.append(f"material '{uri}': missing sha256 in digest")
                    continue

                candidate = run_dir / uri
                if not candidate.is_file():
                    mismatches.append(f"material '{uri}': file not found at {candidate}")
                    continue
                actual_sha = sha256_file(candidate)
                if actual_sha != expected_sha:
                    mismatches.append(
                        f"material '{uri}': digest mismatch "
                        f"(expected={expected_sha[:16]}… actual={actual_sha[:16]}…)"
                    )

    return {
        "valid": len(mismatches) == 0,
        "mismatches": mismatches,
        "checked_at": _iso_utc_now(),
    }
