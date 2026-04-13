"""Reasoning trail capture for LLM-driven finding adjustments.

Used by adversarial_triage and fp_verification to record advocate/critic
debate steps and verdict transitions in a structured, analyst-readable form.
Trail entries are attached to findings as an additive optional field;
existing consumers that ignore the field continue to work unchanged.

PR #11 of Phase 2B -- follows the additive-first pattern established by
PR #7a (`finding_categories.py`): new optional field on findings, no schema
bump, no downstream consumer touched. The 7 existing consumers of finding
dicts keep working because they simply do not look at `reasoning_trail`.

Entries carry:
- ``stage``: originating SCOUT stage name (e.g. ``"fp_verification"``,
  ``"adversarial_triage"``)
- ``step``: logical debate/verdict step (e.g. ``"sanitizer_detected"``,
  ``"advocate"``, ``"critic"``, ``"decision"``)
- ``verdict``: short verdict token (``"downgrade"``, ``"maintain"``,
  ``"exploit_path_plausible"``, etc.)
- ``rationale``: analyst-readable explanation
- ``delta``: confidence delta actually applied (negative = downgrade,
  ``0.0`` when the entry is informational only)
- ``timestamp``: ISO 8601 UTC timestamp captured at entry construction
- ``llm_model``: optional model identifier when the step was LLM-driven
- ``raw_response_excerpt``: optional LLM raw-response excerpt, capped at
  200 characters via :func:`redact_excerpt` to keep ``findings.json`` small
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "ReasoningEntry",
    "append_entry",
    "empty_trail",
    "redact_excerpt",
]

_MAX_EXCERPT_CHARS = 200


def _iso_utc_now() -> str:
    """Return current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def redact_excerpt(text: str | None, max_chars: int = _MAX_EXCERPT_CHARS) -> str | None:
    """Cap raw LLM excerpts so they never bloat ``findings.json``.

    Args:
        text: Raw LLM response text, or ``None``.
        max_chars: Maximum character count (default 200). Values <= 3 are
            clamped up to 4 so the ellipsis marker still fits.

    Returns:
        ``None`` if ``text`` is ``None``; the stripped ``text`` unchanged if
        short enough; otherwise a truncated prefix ending in ``"..."``.
    """
    if text is None:
        return None
    stripped = text.strip()
    if max_chars <= 3:
        max_chars = 4
    if len(stripped) <= max_chars:
        return stripped
    return stripped[: max_chars - 3] + "..."


@dataclass
class ReasoningEntry:
    """A single step in a finding's reasoning trail.

    ``raw_response_excerpt`` is capped at 200 chars via
    :func:`redact_excerpt` in :meth:`__post_init__` so callers cannot
    accidentally persist a multi-kilobyte LLM response inside
    ``findings.json``.
    """

    stage: str
    step: str
    verdict: str
    rationale: str
    delta: float = 0.0
    timestamp: str = field(default_factory=_iso_utc_now)
    llm_model: str | None = None
    raw_response_excerpt: str | None = None

    def __post_init__(self) -> None:
        # Always enforce the excerpt cap at construction time so that no
        # downstream code path can bypass it.
        if self.raw_response_excerpt is not None:
            self.raw_response_excerpt = redact_excerpt(self.raw_response_excerpt)


def append_entry(
    trail: list[dict[str, Any]] | None, entry: ReasoningEntry
) -> list[dict[str, Any]]:
    """Return a new trail list with ``entry`` (as a dict) appended.

    The caller's ``trail`` reference is never mutated -- a new list is
    returned so the additive field update pattern stays predictable.
    """
    new_trail: list[dict[str, Any]] = list(trail or [])
    new_trail.append(asdict(entry))
    return new_trail


def empty_trail() -> list[dict[str, Any]]:
    """Return an empty trail (helper for call sites that want an explicit init)."""
    return []
