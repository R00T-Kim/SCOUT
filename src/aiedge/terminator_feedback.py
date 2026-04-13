from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, cast

from .path_safety import assert_under_dir
from .schema import JsonValue

FEEDBACK_SCHEMA_VERSION = "terminator-feedback-v1"

_VALID_VERDICTS = frozenset({"confirmed", "false_positive", "wont_fix", "needs_info"})
_VALID_HINT_PRIORITIES = frozenset({"low", "medium", "high"})


@dataclass(frozen=True)
class TerminatorVerdict:
    """A single Terminator verdict on a previously reported finding."""

    finding_fingerprint: str  # SHA-256 based similarity key (fingerprinting.py compat)
    verdict: str  # "confirmed"|"false_positive"|"wont_fix"|"needs_info"
    confidence_override: float | None  # New confidence value (None = no change)
    rationale: str  # Verdict rationale
    original_run_id: str  # Original run ID
    timestamp: str  # ISO 8601


def _resolve_feedback_dir() -> Path:
    """Resolve feedback directory from env var or default."""
    env_val = os.environ.get("AIEDGE_FEEDBACK_DIR")
    if env_val is not None and env_val.strip():
        return Path(env_val).expanduser().resolve()
    return Path("aiedge-feedback")


def load_feedback_registry(feedback_dir: Path | None = None) -> list[TerminatorVerdict]:
    """Load Terminator verdict registry from disk.

    File format (``feedback_dir/registry.json``)::

        {
            "schema_version": "terminator-feedback-v1",
            "verdicts": [ ... ]
        }

    Validation rules:
    - ``schema_version`` must match ``FEEDBACK_SCHEMA_VERSION``.
    - Each verdict must contain the required fields.
    - ``verdict`` value must be one of the valid values.
    - Invalid individual entries are skipped (the whole file does NOT fail).

    Returns an empty list when the file is missing or the top-level
    structure is invalid.
    """
    if feedback_dir is None:
        feedback_dir = _resolve_feedback_dir()

    registry_path = feedback_dir / "registry.json"
    if not registry_path.is_file():
        return []

    try:
        raw = json.loads(registry_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    if not isinstance(raw, dict):
        return []

    if raw.get("schema_version") != FEEDBACK_SCHEMA_VERSION:
        return []

    verdicts_any = raw.get("verdicts")
    if not isinstance(verdicts_any, list):
        return []

    result: list[TerminatorVerdict] = []
    for item_any in verdicts_any:
        if not isinstance(item_any, dict):
            continue
        item = cast(dict[str, object], item_any)

        fp = item.get("finding_fingerprint")
        verdict_val = item.get("verdict")
        rationale = item.get("rationale")
        original_run_id = item.get("original_run_id")
        timestamp = item.get("timestamp")

        if not isinstance(fp, str) or not fp:
            continue
        if not isinstance(verdict_val, str) or verdict_val not in _VALID_VERDICTS:
            continue
        if not isinstance(rationale, str):
            rationale = ""
        if not isinstance(original_run_id, str):
            original_run_id = ""
        if not isinstance(timestamp, str):
            timestamp = ""

        conf_override: float | None = None
        conf_any = item.get("confidence_override")
        if (
            isinstance(conf_any, (int, float))
            and conf_any is not True
            and conf_any is not False
        ):
            conf_override = float(max(0.0, min(1.0, float(conf_any))))

        result.append(
            TerminatorVerdict(
                finding_fingerprint=fp,
                verdict=verdict_val,
                confidence_override=conf_override,
                rationale=rationale,
                original_run_id=original_run_id,
                timestamp=timestamp,
            )
        )

    return result


def _fingerprint_prefix(fp: str, length: int = 16) -> str:
    """Return the first ``length`` characters of a fingerprint for prefix matching."""
    return fp[:length].lower()


def _find_matching_verdict(
    fingerprint: str,
    verdicts: list[TerminatorVerdict],
) -> TerminatorVerdict | None:
    """Find the most recent matching verdict by fingerprint prefix (first 16 chars)."""
    prefix = _fingerprint_prefix(fingerprint)
    best: TerminatorVerdict | None = None
    for v in verdicts:
        if _fingerprint_prefix(v.finding_fingerprint) == prefix:
            if best is None or v.timestamp > best.timestamp:
                best = v
    return best


def apply_scoring_calibration(
    candidates: list[dict[str, JsonValue]],
    verdicts: list[TerminatorVerdict],
    *,
    boost_factor: float = 1.15,
    suppress_factor: float = 0.5,
    max_score: float = 0.97,
) -> list[dict[str, JsonValue]]:
    """Calibrate candidate scores based on past Terminator verdicts.

    Rules:
    - ``confirmed`` -> similar finding score ``*= boost_factor`` (capped at *max_score*)
    - ``false_positive`` -> similar finding score ``*= suppress_factor``
    - ``wont_fix`` -> similar finding priority set to ``"low"``
    - ``needs_info`` -> no change

    Similarity matching uses the first 16 characters of the finding fingerprint
    (prefix match).

    If ``confidence_override`` is set on the verdict it is applied directly.

    Returns a **new** list (originals are not mutated).  Each calibrated
    candidate gains a ``"feedback_applied"`` annotation.
    """
    if not verdicts:
        return list(candidates)

    # Build prefix -> best verdict index for O(n) lookup.
    prefix_to_verdict: dict[str, TerminatorVerdict] = {}
    for v in verdicts:
        pfx = _fingerprint_prefix(v.finding_fingerprint)
        existing = prefix_to_verdict.get(pfx)
        if existing is None or v.timestamp > existing.timestamp:
            prefix_to_verdict[pfx] = v

    out: list[dict[str, JsonValue]] = []
    for candidate in candidates:
        c = dict(candidate)  # shallow copy

        # Try to match by candidate_id (which contains a sha256) or fingerprint fields
        candidate_id_any = c.get("candidate_id")
        fingerprint_any = c.get("fingerprint_sha256")

        matched_verdict: TerminatorVerdict | None = None

        for fp_source in (candidate_id_any, fingerprint_any):
            if not isinstance(fp_source, str) or not fp_source:
                continue
            # Strip "candidate:" prefix if present
            clean = fp_source
            if clean.startswith("candidate:"):
                clean = clean[len("candidate:") :]
            pfx = _fingerprint_prefix(clean)
            v = prefix_to_verdict.get(pfx)
            if v is not None:
                matched_verdict = v
                break

        if matched_verdict is None:
            out.append(c)
            continue

        score_any = c.get("score")
        score = float(score_any) if isinstance(score_any, (int, float)) else 0.0

        feedback_info: dict[str, JsonValue] = {
            "verdict": matched_verdict.verdict,
            "original_run_id": matched_verdict.original_run_id,
        }

        if matched_verdict.confidence_override is not None:
            score = matched_verdict.confidence_override
            c["score"] = round(min(max_score, score), 4)
            c["confidence"] = round(min(max_score, score), 4)
            feedback_info["override_applied"] = True
        elif matched_verdict.verdict == "confirmed":
            score = round(min(max_score, score * boost_factor), 4)
            c["score"] = score
            c["confidence"] = round(min(max_score, score), 4)
        elif matched_verdict.verdict == "false_positive":
            score = round(max(0.0, score * suppress_factor), 4)
            c["score"] = score
            c["confidence"] = round(max(0.0, score), 4)
        elif matched_verdict.verdict == "wont_fix":
            c["priority"] = "low"

        # needs_info -> no change

        c["feedback_applied"] = cast(JsonValue, feedback_info)
        out.append(c)

    return out


def generate_feedback_request(
    candidates: list[dict[str, JsonValue]],
    *,
    max_priority_findings: int = 10,
) -> dict[str, JsonValue]:
    """Generate a ``feedback_request`` section for ``firmware_handoff.json``.

    Selects findings most in need of review:
    - Confidence in the uncertain mid-range (0.4 -- 0.7)
    - Chain-backed candidates without prior feedback

    Returns a dict suitable for inclusion in the handoff payload.
    """
    scored: list[tuple[float, str]] = []
    for candidate in candidates:
        cid_any = candidate.get("candidate_id")
        if not isinstance(cid_any, str) or not cid_any:
            continue

        # Already has feedback -> skip
        if candidate.get("feedback_applied") is not None:
            continue

        conf_any = candidate.get("confidence")
        conf = float(conf_any) if isinstance(conf_any, (int, float)) else 0.5

        # Score by how close to the uncertain mid-range center (0.55)
        uncertainty = 1.0 - abs(conf - 0.55) / 0.55  # peaks at 0.55
        uncertainty = max(0.0, uncertainty)

        # Bonus for chain-backed candidates (more complex, more value in feedback)
        source_any = candidate.get("source")
        if isinstance(source_any, str) and source_any == "chain":
            uncertainty += 0.2

        scored.append((uncertainty, cid_any))

    scored.sort(key=lambda pair: (-pair[0], pair[1]))

    priority_ids: list[str] = [cid for _, cid in scored[:max_priority_findings]]

    return {
        "priority_findings": cast(list[JsonValue], cast(list[object], priority_ids)),
        "expected_feedback_path": "aiedge-feedback/registry.json",
        "feedback_schema_version": FEEDBACK_SCHEMA_VERSION,
    }


# ---------------------------------------------------------------------------
# PR #12 -- Analyst hint injection and verdict override (MCP-driven)
# ---------------------------------------------------------------------------
#
# The existing registry schema stores bulk Terminator verdicts under
# ``verdicts`` keyed by fingerprint. PR #12 adds a parallel ``findings`` map
# keyed by the human-readable finding ID (the MCP client's vocabulary) so
# analyst hints and per-finding verdict overrides can be pushed in at MCP
# call time without needing the fingerprint. ``load_feedback_registry``
# ignores unknown top-level keys, so adding ``findings`` is backwards-safe
# for the existing ``duplicate_gate.py`` consumer path.
#
# Registry shape after PR #12::
#
#     {
#       "schema_version": "terminator-feedback-v1",
#       "verdicts": [ ... existing bulk verdicts ... ],
#       "findings": {
#         "<finding_id>": {
#           "analyst_hints": [
#             {"text": "...", "priority": "medium",
#              "added_by": "analyst-a", "timestamp": "2025-01-01T..."}
#           ],
#           "verdict": "false_positive",
#           "rationale": "...",
#           "confidence_override": 0.12,
#           "last_updated": "2025-01-01T..."
#         }
#       }
#     }

_DEFAULT_HINT_PRIORITY = "medium"


def _iso_utc_now() -> str:
    """Return current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _resolve_and_prepare_feedback_dir(feedback_dir: Path | None) -> Path:
    """Resolve the feedback directory (env or default) and create it."""
    resolved = (feedback_dir or _resolve_feedback_dir()).resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def _load_registry_raw(registry_path: Path) -> dict[str, Any]:
    """Load the raw registry dict (empty skeleton when missing/invalid).

    Unlike :func:`load_feedback_registry`, this preserves *all* keys
    (including PR #12's new ``findings`` map) for in-place mutation.
    """
    if not registry_path.is_file():
        return {
            "schema_version": FEEDBACK_SCHEMA_VERSION,
            "verdicts": [],
            "findings": {},
        }
    try:
        raw = json.loads(registry_path.read_text(encoding="utf-8"))
    except Exception:
        return {
            "schema_version": FEEDBACK_SCHEMA_VERSION,
            "verdicts": [],
            "findings": {},
        }
    if not isinstance(raw, dict):
        return {
            "schema_version": FEEDBACK_SCHEMA_VERSION,
            "verdicts": [],
            "findings": {},
        }
    raw_dict = cast(dict[str, Any], raw)
    # Always normalise -- tolerate pre-PR-#12 registries that only have
    # "schema_version" + "verdicts".
    raw_dict.setdefault("schema_version", FEEDBACK_SCHEMA_VERSION)
    if not isinstance(raw_dict.get("verdicts"), list):
        raw_dict["verdicts"] = []
    findings_any = raw_dict.get("findings")
    if not isinstance(findings_any, dict):
        raw_dict["findings"] = {}
    return raw_dict


def _write_registry_atomic(registry_path: Path, payload: dict[str, Any]) -> None:
    """Atomic write: temp file + rename. Caller must already hold the lock."""
    tmp_path = registry_path.with_suffix(registry_path.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp_path, registry_path)


def _with_registry_lock(
    feedback_dir: Path | None,
    mutator: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """Load the registry under an exclusive flock, apply *mutator*, write back.

    Mirrors the ``fcntl.flock`` pattern used by ``duplicate_gate.py`` so that
    concurrent MCP calls serialise cleanly.

    Returns the post-mutation registry payload (useful for tests).
    """
    resolved_dir = _resolve_and_prepare_feedback_dir(feedback_dir)
    registry_path = resolved_dir / "registry.json"
    # Enforce path containment -- the registry must live inside the feedback dir.
    assert_under_dir(resolved_dir, registry_path)

    lock_path = resolved_dir / "registry.json.lock"
    assert_under_dir(resolved_dir, lock_path)
    lock_fd = open(lock_path, "w")  # noqa: SIM115 -- released in finally
    try:
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
        registry = _load_registry_raw(registry_path)
        updated = mutator(registry)
        _write_registry_atomic(registry_path, updated)
        return updated
    finally:
        try:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
        finally:
            lock_fd.close()


def _findings_map(registry: dict[str, Any]) -> dict[str, Any]:
    """Return the ``findings`` sub-dict, creating it if missing."""
    findings_any = registry.get("findings")
    if not isinstance(findings_any, dict):
        registry["findings"] = {}
        return cast(dict[str, Any], registry["findings"])
    return cast(dict[str, Any], findings_any)


def _finding_entry(findings_map: dict[str, Any], finding_id: str) -> dict[str, Any]:
    """Return the per-finding entry dict, creating it if missing."""
    entry_any = findings_map.get(finding_id)
    if not isinstance(entry_any, dict):
        findings_map[finding_id] = {}
        return cast(dict[str, Any], findings_map[finding_id])
    return cast(dict[str, Any], entry_any)


def add_analyst_hint(
    finding_id: str,
    hint_text: str,
    *,
    priority: str = _DEFAULT_HINT_PRIORITY,
    added_by: str | None = None,
    feedback_dir: Path | None = None,
) -> dict[str, Any]:
    """Append an analyst hint to the feedback registry for *finding_id*.

    Args:
        finding_id: Human-readable finding ID (MCP client vocabulary).
        hint_text: The analyst's guidance for next-run LLM triage.
        priority: One of ``low`` / ``medium`` / ``high``. Invalid values
            are coerced to the default (``medium``).
        added_by: Optional analyst identifier/name.
        feedback_dir: Optional override (defaults to ``AIEDGE_FEEDBACK_DIR``).

    Returns:
        The newly-appended hint dict (with ``timestamp`` populated).

    Raises:
        ValueError: When ``finding_id`` or ``hint_text`` are empty.
    """
    if not isinstance(finding_id, str) or not finding_id.strip():
        raise ValueError("finding_id must be a non-empty string")
    if not isinstance(hint_text, str) or not hint_text.strip():
        raise ValueError("hint_text must be a non-empty string")

    normalized_priority = (
        priority if priority in _VALID_HINT_PRIORITIES else _DEFAULT_HINT_PRIORITY
    )
    timestamp = _iso_utc_now()
    new_hint: dict[str, Any] = {
        "text": hint_text.strip(),
        "priority": normalized_priority,
        "added_by": added_by if isinstance(added_by, str) and added_by else None,
        "timestamp": timestamp,
    }

    def _mutator(registry: dict[str, Any]) -> dict[str, Any]:
        findings_map = _findings_map(registry)
        entry = _finding_entry(findings_map, finding_id.strip())
        hints_any = entry.get("analyst_hints")
        if not isinstance(hints_any, list):
            hints_list: list[Any] = []
            entry["analyst_hints"] = hints_list
        else:
            hints_list = cast(list[Any], hints_any)
        hints_list.append(dict(new_hint))
        entry["last_updated"] = timestamp
        return registry

    _with_registry_lock(feedback_dir, _mutator)
    return new_hint


def get_analyst_hints(
    finding_id: str,
    *,
    feedback_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Return the analyst hints recorded for *finding_id* (empty list if none).

    This is a read-only helper -- no lock required. Adversarial triage
    calls this on the hot path, so it must stay cheap.
    """
    if not isinstance(finding_id, str) or not finding_id.strip():
        return []
    resolved_dir = (feedback_dir or _resolve_feedback_dir()).resolve()
    registry_path = resolved_dir / "registry.json"
    if not registry_path.is_file():
        return []
    try:
        raw = json.loads(registry_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(raw, dict):
        return []
    findings_any = raw.get("findings")
    if not isinstance(findings_any, dict):
        return []
    entry_any = cast(dict[str, Any], findings_any).get(finding_id.strip())
    if not isinstance(entry_any, dict):
        return []
    hints_any = cast(dict[str, Any], entry_any).get("analyst_hints")
    if not isinstance(hints_any, list):
        return []
    out: list[dict[str, Any]] = []
    for item in cast(list[Any], hints_any):
        if isinstance(item, dict):
            out.append(dict(cast(dict[str, Any], item)))
    return out


def set_verdict_override(
    finding_id: str,
    verdict: str,
    *,
    rationale: str | None = None,
    confidence_override: float | None = None,
    feedback_dir: Path | None = None,
) -> dict[str, Any]:
    """Write a per-finding verdict override into the feedback registry.

    The override lives alongside the existing bulk ``verdicts`` list and
    shares the same allowed verdict vocabulary. Analysts using the MCP
    ``scout_override_verdict`` tool only know the finding ID (not the
    fingerprint), so this keyed-by-id surface is the write path.

    Args:
        finding_id: Human-readable finding ID.
        verdict: One of ``confirmed`` / ``false_positive`` / ``wont_fix`` /
            ``needs_info``.
        rationale: Optional analyst rationale.
        confidence_override: Optional explicit confidence replacement in
            ``[0.0, 1.0]``. Values outside the range are clamped.
        feedback_dir: Optional override (defaults to ``AIEDGE_FEEDBACK_DIR``).

    Returns:
        The updated finding entry dict.

    Raises:
        ValueError: When ``finding_id`` is empty or ``verdict`` is invalid.
    """
    if not isinstance(finding_id, str) or not finding_id.strip():
        raise ValueError("finding_id must be a non-empty string")
    if verdict not in _VALID_VERDICTS:
        raise ValueError(
            f"verdict must be one of {sorted(_VALID_VERDICTS)}, got {verdict!r}"
        )

    clamped_confidence: float | None = None
    if confidence_override is not None:
        if not isinstance(confidence_override, (int, float)):
            raise ValueError("confidence_override must be a float in [0.0, 1.0]")
        clamped_confidence = float(max(0.0, min(1.0, float(confidence_override))))

    timestamp = _iso_utc_now()

    def _mutator(registry: dict[str, Any]) -> dict[str, Any]:
        findings_map = _findings_map(registry)
        entry = _finding_entry(findings_map, finding_id.strip())
        entry["verdict"] = verdict
        if isinstance(rationale, str) and rationale.strip():
            entry["rationale"] = rationale.strip()
        if clamped_confidence is not None:
            entry["confidence_override"] = clamped_confidence
        entry["last_updated"] = timestamp
        return registry

    updated = _with_registry_lock(feedback_dir, _mutator)
    findings_map = updated.get("findings")
    if isinstance(findings_map, dict):
        entry_any = cast(dict[str, Any], findings_map).get(finding_id.strip())
        if isinstance(entry_any, dict):
            return dict(cast(dict[str, Any], entry_any))
    return {}
