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
    "format_trail_for_markdown",
    "format_trail_for_tui",
    "normalize_trail",
    "redact_excerpt",
]

_MAX_EXCERPT_CHARS = 200
_TUI_RATIONALE_MAX_CHARS = 80


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


def normalize_trail(trail: object) -> list[dict[str, Any]]:
    """Return only the dict entries from ``trail`` (or empty list).

    Used by viewer/markdown/TUI render sites that need to defensively read
    a finding's ``reasoning_trail`` field without trusting its shape. Any
    non-dict entry is silently dropped, matching the additive-first
    pattern from PR #11 (consumers that ignore malformed entries keep
    working).
    """
    if not isinstance(trail, list):
        return []
    out: list[dict[str, Any]] = []
    for entry in trail:
        if isinstance(entry, dict):
            out.append(entry)
    return out


def _entry_field(entry: dict[str, Any], key: str, default: str = "") -> str:
    value = entry.get(key, default)
    if value is None:
        return default
    return str(value)


def _entry_delta(entry: dict[str, Any]) -> float:
    delta = entry.get("delta", 0.0)
    if isinstance(delta, bool) or not isinstance(delta, (int, float)):
        return 0.0
    return float(delta)


def _format_delta(delta: float) -> str:
    """Render a non-zero delta as a signed two-decimal string ("+0.10", "-0.15").

    Returns an empty string when ``delta`` is zero so callers can branch on
    truthiness.
    """
    if delta == 0.0:
        return ""
    sign = "+" if delta > 0 else ""
    return f"{sign}{delta:.2f}"


def format_trail_for_markdown(trail: object) -> list[str]:
    """Render a reasoning trail as analyst-markdown lines.

    Returns the empty list when ``trail`` is missing/empty/malformed so
    callers can use it as a section gate. Each entry becomes one numbered
    line of the form ``"<idx>. <stage> <step> [(model)] [delta] -- <rationale>"``
    matching the example in the PR #13 plan. The leading
    ``**Reasoning Trail (N steps)**`` header is the caller's responsibility
    so this helper stays free of formatting opinions.
    """
    entries = normalize_trail(trail)
    if not entries:
        return []
    lines: list[str] = []
    for idx, entry in enumerate(entries, start=1):
        stage = _entry_field(entry, "stage")
        step = _entry_field(entry, "step")
        verdict = _entry_field(entry, "verdict")
        rationale = _entry_field(entry, "rationale")
        llm_model = _entry_field(entry, "llm_model")
        delta = _entry_delta(entry)
        delta_text = _format_delta(delta)

        head_parts: list[str] = []
        if stage:
            head_parts.append(stage)
        if step:
            head_parts.append(step)
        head = " ".join(head_parts) if head_parts else "(unknown step)"
        if llm_model:
            head = f"{head} ({llm_model})"

        suffix_parts: list[str] = []
        if verdict:
            suffix_parts.append(f"-> {verdict}")
        if delta_text:
            suffix_parts.append(delta_text)
        suffix = " ".join(suffix_parts)

        line = f"{idx}. {head}"
        if suffix:
            line = f"{line} {suffix}"
        if rationale:
            line = f"{line} -- {rationale}"
        lines.append(line)
    return lines


def format_trail_for_tui(
    trail: object,
    *,
    max_rationale_chars: int = _TUI_RATIONALE_MAX_CHARS,
    use_unicode: bool = True,
) -> list[str]:
    """Render a reasoning trail as compact TUI lines.

    Each line is one trail step indented under the caller-supplied header.
    Long rationales are truncated to ``max_rationale_chars`` with a
    ``"..."`` suffix so the TUI never breaks layout. When ``use_unicode``
    is False (e.g. ``AIEDGE_TUI_ASCII=1``), the arrow glyph degrades to
    the ASCII ``"->"`` form.

    Returns the empty list when ``trail`` is missing/empty/malformed.
    """
    entries = normalize_trail(trail)
    if not entries:
        return []
    arrow = "\u2192" if use_unicode else "->"
    lines: list[str] = []
    for idx, entry in enumerate(entries, start=1):
        stage = _entry_field(entry, "stage") or "?"
        step = _entry_field(entry, "step") or "?"
        verdict = _entry_field(entry, "verdict")
        rationale = _entry_field(entry, "rationale")
        llm_model = _entry_field(entry, "llm_model")
        delta = _entry_delta(entry)
        delta_text = _format_delta(delta)

        if max_rationale_chars > 3 and len(rationale) > max_rationale_chars:
            rationale_render = rationale[: max_rationale_chars - 3] + "..."
        else:
            rationale_render = rationale

        head_parts = [f"[{stage}]", step]
        if llm_model:
            head_parts.append(f"({llm_model})")
        head_parts.append(arrow)
        head_parts.append(verdict or "(no verdict)")
        if delta_text:
            head_parts.append(delta_text)
        line = f"  {idx}. " + " ".join(head_parts)
        if rationale_render:
            line = f"{line} -- {rationale_render}"
        lines.append(line)
    return lines
