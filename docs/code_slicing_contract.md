# LATTE Code Slicing Contract

> Phase 2C+.1 (Pivot 2026-04-19) — text-based backward slicing that the taint
> propagation stage uses to compress LLM prompts when
> `AIEDGE_LATTE_SLICING=1` is set.

## Why this exists

LATTE (Liu et al., "LATTE: LLM-Powered Static Binary Taint Analysis",
TOSEM 2025) reported that feeding the LLM the **sink-rooted backward
slice** instead of the full decompiled function body improved new-bug
discovery and reduced token usage. SCOUT's first-cut implementation
takes the same idea but stays conservative: it operates on plain text,
does not require a Ghidra-grade SSA backend, and is opt-in so the
existing prompt behaviour stays byte-identical when the env var is
unset.

The slicing is **over-approximate**: it keeps every earlier line whose
identifier set overlaps the already-tracked variables-of-interest. That
means the slice is a strict subset of the original body (ordering
preserved) but it may retain irrelevant lines that happen to mention a
tainted variable name in passing. In exchange, it never drops a line
that contains a real data dependency along the sink path, so the LLM
never has to reason about a variable whose definition disappeared.

## Public API

Source: `src/aiedge/code_slicing.py`.

| Function | Purpose |
|---|---|
| `latte_slicing_enabled()` | Returns `True` when `AIEDGE_LATTE_SLICING` is set to `1`/`true`/`yes`/`on` (case-insensitive). |
| `find_sink_line(body, sink_sym)` | 0-based line index of the first `sink_sym(` call, or `None`. |
| `extract_backward_slice(body, sink_line_idx, max_lines=30)` | Backward-walks from `sink_line_idx`, keeps lines whose identifiers overlap the tracked set. Returns a string of the retained lines in source order. |
| `extract_slice_around_sink(body, sink_sym, max_lines=30)` | Convenience: `find_sink_line` then `extract_backward_slice`. Returns `None` when the sink is absent. |
| `maybe_slice(body, sink_sym, max_lines=30)` | Recommended entry point for call sites: when the env gate is off it returns the body unchanged; when on it returns the slice (falling back to the full body if the sink is not found). Never returns `None`. |
| `slice_compression_ratio(original, sliced)` | Telemetry helper — ratio of kept lines to original lines. |

## Env gate

```
AIEDGE_LATTE_SLICING=1   # enable slicing (any of 1/true/yes/on)
```

Default (unset) means `maybe_slice` returns the input body verbatim, so
dropping the env var gives byte-identical prompts to every LLM call.

## Algorithm (first-cut)

```
1. Locate the sink line (first occurrence of `<sink_sym>(`).
2. Initial variables-of-interest = identifiers on the sink line
   (minus the noise set: C keywords, literals, common macros).
3. For each earlier line (bottom-up):
     a. If its identifier set intersects the variables-of-interest,
        include it and union its identifiers into the interest set.
     b. If the line has no usable identifier (blank, comment-only),
        include it so the LLM keeps structural context.
     c. Stop at `max_lines` or the function start.
4. Emit retained lines in source order.
```

Noise identifiers (`_NOISE_IDENTIFIERS`) are kept minimal on purpose: we
filter only what is guaranteed not to carry data (`if`, `int`, `NULL`,
`true`, ...). Vendor-specific tokens are *not* filtered because they
often *are* the relevant variables in router firmware decompilation.

## Over-approximation behaviour

Because the algorithm tracks identifiers and not their scopes, a slice
may include lines that merely reference a same-named variable elsewhere
in the function. This is acceptable for prompt compression but analysts
who need an exact data-flow trace should still consult the Ghidra
P-code SSA path (`pcode_taint.py`).

## Call site

The only caller today is `_build_taint_prompt()` in
`src/aiedge/taint_propagation.py`:

```python
body_raw = fb.get("body", "")
body_sliced = maybe_slice(body_raw, sink_symbol)
body = _truncate_text(body_sliced, max_chars=2000)
```

When `AIEDGE_LATTE_SLICING` is unset the call returns `body_raw`
unchanged and the subsequent `_truncate_text` path is byte-identical to
pre-2C+.1 behaviour.

## Phase 2D entry interaction

Phase 2D.1 (reasoning_trail + MCP loop validation) depends on the LLM
actually producing useful verdicts across diverse findings. Slicing is
the main lever we have today to let the LLM see *more* findings within
the same token budget — so even if Phase 2D.1 does not require slicing,
leaving it disabled in production runs means the analyst cycles through
a smaller effective corpus. Operators planning a Phase 2D.1 walkthrough
should enable `AIEDGE_LATTE_SLICING=1` for the run.

## Related artifacts

- `src/aiedge/code_slicing.py` — implementation
- `src/aiedge/taint_propagation.py` — call site in `_build_taint_prompt`
- `tests/test_code_slicing.py` — unit tests (32 cases) that pin:
  - sink-line location and word-boundary behaviour
  - slice invariants (subset, source order, sink kept, defining lines
    pulled in)
  - `max_lines` cap and degenerate inputs
  - env-gate parsing and byte-identical default-off
  - compression-ratio telemetry
