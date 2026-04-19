from __future__ import annotations

"""LATTE-inspired text-based backward slicing for taint LLM prompts.

The full LATTE technique (Liu et al., TOSEM 2025) builds a Code Slicing
Prompt Sequence on top of an actual program slice computed from
inter-procedural data-flow analysis. SCOUT's first-cut implementation is
deliberately simpler:

* it operates on Ghidra-decompiled function bodies as plain text;
* it walks bottom-up from the line that contains the sink call;
* it keeps any earlier line that mentions an identifier already known to
  influence the slice;
* it stops at ``max_lines`` or the function start.

The resulting slice is a strict subset of the function body, ordered as
in the source. Empty lines and comment-only lines are preserved as-is so
the LLM still sees structural cues. The slicing is therefore an
*over-approximation* of true backward dataflow, but it is much cheaper
than rebuilding a Ghidra-grade SSA / use-def graph and it already buys
the two properties that LATTE relies on for prompt quality:

1. **Token compression** -- LLM context is dominated by the sink path
   instead of the entire function;
2. **Locality** -- variables defined in the same function are visible to
   the LLM, so it can reason about taint provenance without losing the
   declaration site.

Future revisions can replace ``extract_backward_slice`` with a Ghidra
P-code SSA backend without changing the public API or the call sites in
``taint_propagation.py``.

The slicing is **opt-in** at the call site via ``AIEDGE_LATTE_SLICING=1``
because its over-approximation can occasionally cut a load-bearing line
that the regex heuristic does not recognise as relevant. Default-off
keeps the existing prompt behaviour byte-identical.
"""

import os
import re

# Identifier extraction. C identifiers are [a-zA-Z_][a-zA-Z0-9_]*.
_IDENT_PAT: re.Pattern[str] = re.compile(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b")

# Reserved identifiers we do *not* want to inflate the variable-of-interest
# set. These are C keywords or extremely common standard-library tokens whose
# presence on a line should not, by itself, pull every previous line into the
# slice. The list is intentionally conservative; specialised vendor tokens are
# not filtered because they often *are* the relevant variables.
_NOISE_IDENTIFIERS: frozenset[str] = frozenset(
    {
        # C keywords / type qualifiers
        "if",
        "else",
        "for",
        "while",
        "do",
        "switch",
        "case",
        "default",
        "break",
        "continue",
        "return",
        "goto",
        "sizeof",
        "void",
        "int",
        "long",
        "short",
        "char",
        "float",
        "double",
        "unsigned",
        "signed",
        "const",
        "volatile",
        "static",
        "extern",
        "inline",
        "auto",
        "register",
        "struct",
        "union",
        "enum",
        "typedef",
        # Common literals / boolean tokens
        "true",
        "false",
        "NULL",
        "null",
        "nullptr",
        "TRUE",
        "FALSE",
        # Frequently encountered macros that are not data variables
        "abs",
        "min",
        "max",
        "MIN",
        "MAX",
    }
)


def _line_identifiers(line: str) -> set[str]:
    """Return the set of C-style identifiers that appear in ``line``,
    excluding the ``_NOISE_IDENTIFIERS`` set."""
    return {tok for tok in _IDENT_PAT.findall(line) if tok not in _NOISE_IDENTIFIERS}


def latte_slicing_enabled() -> bool:
    """Return ``True`` when ``AIEDGE_LATTE_SLICING`` is set to a truthy value.

    Truthy = ``"1"``, ``"true"``, ``"yes"``, ``"on"`` (case-insensitive).
    Anything else, including unset, returns ``False``. Centralising the
    parse keeps call sites in ``taint_propagation`` short.
    """
    raw = os.environ.get("AIEDGE_LATTE_SLICING", "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def find_sink_line(function_body: str, sink_sym: str) -> int | None:
    """Return the 0-based line index of the first call to ``sink_sym`` in
    ``function_body``. Matches ``sink_sym(`` (optional whitespace) at a word
    boundary so ``open(`` matches but ``fopen(`` does not when ``sink_sym``
    is ``"open"``. Returns ``None`` when no call is found.
    """
    if not function_body or not sink_sym:
        return None
    pat = re.compile(r"\b" + re.escape(sink_sym) + r"\s*\(")
    for idx, line in enumerate(function_body.splitlines()):
        if pat.search(line):
            return idx
    return None


def extract_backward_slice(
    function_body: str,
    sink_line_idx: int,
    *,
    max_lines: int = 30,
) -> str:
    """Return a backward slice ending at ``sink_line_idx``.

    Algorithm: start from the sink line, collect its non-noise identifiers
    as the initial variable-of-interest set, then walk upward. For each
    earlier line, if its identifier set intersects the variable-of-interest
    set we include the line and union its identifiers into the interest
    set (data dependency may flow further back). Iteration stops when we
    accumulate ``max_lines`` lines or reach the function start.

    Lines are emitted in source order. When ``sink_line_idx`` is out of
    range the function returns ``function_body`` unchanged so callers can
    treat the slice as a *safe substitute* for the full body.
    """
    if not function_body:
        return function_body
    lines = function_body.splitlines()
    if sink_line_idx < 0 or sink_line_idx >= len(lines):
        return function_body
    if max_lines <= 0:
        return function_body

    sink_line = lines[sink_line_idx]
    vars_of_interest: set[str] = _line_identifiers(sink_line)
    # If the sink line itself has no usable identifier (rare), keep at
    # least the sink token so the slice is non-empty.
    if not vars_of_interest:
        vars_of_interest = set(_IDENT_PAT.findall(sink_line))

    included: list[int] = [sink_line_idx]
    for i in range(sink_line_idx - 1, -1, -1):
        if len(included) >= max_lines:
            break
        line = lines[i]
        line_ids = _line_identifiers(line)
        # Always preserve blank / comment lines that immediately precede an
        # included statement so the LLM sees the surrounding context block.
        if not line_ids:
            included.append(i)
            continue
        if line_ids & vars_of_interest:
            included.append(i)
            vars_of_interest |= line_ids

    included.sort()
    return "\n".join(lines[i] for i in included)


def extract_slice_around_sink(
    function_body: str,
    sink_sym: str,
    *,
    max_lines: int = 30,
) -> str | None:
    """Convenience wrapper: locate ``sink_sym`` then backward-slice.

    Returns ``None`` when ``sink_sym`` is not called in ``function_body``,
    so the caller can decide whether to skip the prompt entirely or fall
    back to the full body.
    """
    idx = find_sink_line(function_body, sink_sym)
    if idx is None:
        return None
    return extract_backward_slice(function_body, idx, max_lines=max_lines)


def maybe_slice(
    function_body: str,
    sink_sym: str,
    *,
    max_lines: int = 30,
) -> str:
    """Return a slice when ``AIEDGE_LATTE_SLICING`` is enabled, otherwise
    return ``function_body`` unchanged. This is the recommended entry
    point for ``taint_propagation`` since it bakes the env-gate decision
    in one place and never returns ``None``.
    """
    if not latte_slicing_enabled():
        return function_body
    sliced = extract_slice_around_sink(function_body, sink_sym, max_lines=max_lines)
    return sliced if sliced is not None else function_body


def slice_compression_ratio(original: str, sliced: str) -> float:
    """Return the fraction of original lines preserved in ``sliced``.

    Useful for telemetry: a value < 0.4 indicates aggressive compression
    (good for token cost) while a value approaching 1.0 means slicing
    barely helped (the function is mostly on the sink path). Returns
    ``1.0`` when the original is empty so callers do not need a special
    case.
    """
    orig_lines = original.splitlines()
    if not orig_lines:
        return 1.0
    sliced_lines = sliced.splitlines() if sliced else []
    return round(len(sliced_lines) / len(orig_lines), 6)
