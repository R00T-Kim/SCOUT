"""Type narrowing helpers for JsonValue -> numeric conversions.

SCOUT deserialises stage artefacts to ``dict[str, JsonValue]`` (where
``JsonValue`` is a recursive union of ``str | int | float | bool | None |
list[JsonValue] | dict[str, JsonValue]``). Downstream stages frequently need
numeric scalars from those payloads. Using ``float(value)`` or ``int(value)``
directly triggers pyright ``reportArgumentType`` because ``dict``/``list`` are
also valid ``JsonValue`` members which are not ``ConvertibleToFloat``.

This module provides defensive, type-narrowing helpers that:
  1. Satisfy pyright without ``# type: ignore`` comments.
  2. Preserve SCOUT's "fail-open" invariant: malformed payloads produce the
     caller-supplied ``default`` rather than raising.
  3. Avoid any business-logic side effects -- the returned value is
     numerically equivalent to ``float(x)``/``int(x)`` for well-formed inputs.

Usage:
    from aiedge._typing_helpers import safe_float, safe_int

    score = safe_float(finding.get("confidence"), default=0.0)
    count = safe_int(metrics.get("hits"), default=0)
"""

from __future__ import annotations

from typing import Any

__all__ = ["safe_float", "safe_int"]


def safe_float(value: Any, default: float = 0.0) -> float:
    """Convert ``value`` to ``float`` with defensive fallback.

    Accepts ``None``, ``bool``, ``int``, ``float`` and ``str``. Any other type
    (``dict``, ``list``, arbitrary objects) returns ``default`` without
    raising. Strings that cannot be parsed return ``default``.

    This is a pure function -- it never raises and has no side effects.

    Args:
        value: Arbitrary value (typically sourced from deserialised JSON).
        default: Fallback returned for ``None``, non-numeric, or unparseable
            inputs. Defaults to ``0.0``.

    Returns:
        ``float`` representation of ``value`` if possible, else ``default``.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        # ``bool`` is a subclass of ``int`` -- keep numeric equivalence.
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except (ValueError, TypeError):
            return default
    return default


def safe_int(value: Any, default: int = 0) -> int:
    """Convert ``value`` to ``int`` with defensive fallback.

    Accepts ``None``, ``bool``, ``int``, ``float`` and ``str``. For ``float``
    inputs the fractional component is truncated (``int(x)`` semantics).
    Strings that cannot be parsed as ``int`` fall back to ``float`` parsing
    before surrendering to ``default``.

    This is a pure function -- it never raises and has no side effects.

    Args:
        value: Arbitrary value (typically sourced from deserialised JSON).
        default: Fallback returned for ``None``, non-numeric, or unparseable
            inputs. Defaults to ``0``.

    Returns:
        ``int`` representation of ``value`` if possible, else ``default``.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except (ValueError, TypeError):
            pass
        try:
            return int(float(value))
        except (ValueError, TypeError):
            return default
    return default
