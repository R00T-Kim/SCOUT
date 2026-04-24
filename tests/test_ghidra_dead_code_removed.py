"""Phase 2C++.2 — guardrails for removed legacy Gap B code.

docs/upgrade_plz.md (v2.4.0 external review) flagged a byte-offset heuristic
(`addr_diff > 16`) in the P-code taint matching logic. Commit `3352783`
(v2.4.1) replaced that primary path with callee-name resolution but left two
residual artefacts in the tree:

- `ghidra_analysis.py` carried a standalone helper `trace_pcode_forward()`
  inside `_PYGHIDRA_SCRIPT` that was never invoked (dead function).
- `ghidra_scripts/pcode_taint.py` kept the `addr_diff` branch as an
  `else` fallback that `run()` could never reach (caller always passes
  `source_api_name`).

v2.7.2 (Phase 2C++.2) physically removed both. These tests pin that removal
so reviewers grepping the tree no longer find the old pattern, and so a
future refactor cannot silently reintroduce it.
"""

from __future__ import annotations

import re
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "aiedge"


def _read(rel: str) -> str:
    return (_SRC / rel).read_text(encoding="utf-8")


def _strip_comments(source: str) -> str:
    """Drop trailing and full-line `#` comments so pattern checks only look at
    executable code. Quoted `#` characters are rare in this codebase and this
    helper is only used by guard-rail tests, so a minimal line-based strip is
    sufficient."""
    out: list[str] = []
    for line in source.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        if "#" in line:
            # Drop inline comment; keep the code before it.
            out.append(line.split("#", 1)[0].rstrip())
        else:
            out.append(line)
    return "\n".join(out)


def test_ghidra_analysis_has_no_dead_trace_pcode_forward_helper() -> None:
    """The legacy helper used to sit inside `_PYGHIDRA_SCRIPT` with its own
    `diff > 16` gate even though nothing inside the script called it."""
    text = _read("ghidra_analysis.py")
    assert (
        "def trace_pcode_forward" not in text
    ), "legacy dead helper reintroduced in ghidra_analysis.py"


def test_ghidra_analysis_pyghidra_script_has_no_addr_diff_logic() -> None:
    """The pyghidra fallback's inline Strategy 1 loop must resolve CALL
    targets by name — no byte-offset proximity gate."""
    text = _read("ghidra_analysis.py")
    # The inline loop must still exist (positive check).
    assert "resolve_call_target(op, hf)" in text
    # Scan only executable code; the removal note retains the old pattern name
    # in a comment for reviewer discoverability.
    code = _strip_comments(text)
    assert not re.search(
        r"\bdiff\s*>\s*16\b", code
    ), "offset heuristic reappeared in ghidra_analysis.py"


def test_pcode_taint_script_has_no_addr_diff_fallback() -> None:
    """`ghidra_scripts/pcode_taint.py` previously carried an
    `else: addr_diff = abs(...)` fallback that was unreachable because
    `run()` always passed `source_api_name`. v2.7.2 removed it."""
    text = _read("ghidra_scripts/pcode_taint.py")
    code = _strip_comments(text)
    # Guard the executable form: no variable, no control flow.
    assert "addr_diff = abs(" not in code
    assert not re.search(r"\baddr_diff\s*>\s*16\b", code)
    # The fallback's legacy callee-name/else split must be gone from code.
    assert "# Fallback: address proximity (legacy behavior)" not in text


def test_pcode_taint_source_api_name_is_required() -> None:
    """`_trace_forward_pcode` must reject callers that omit
    `source_api_name`; without that parameter callee-name matching has no
    target and we would fall through to no candidates."""
    text = _read("ghidra_scripts/pcode_taint.py")
    # The signature line has no default for source_api_name.
    assert re.search(
        r"def\s+_trace_forward_pcode\([^)]*source_api_name\s*\)",
        text,
        flags=re.DOTALL,
    ), "source_api_name is no longer a required positional argument"
    # Sanity: default `= \"\"` must not reappear.
    assert 'source_api_name=""' not in text


def test_pcode_taint_run_always_passes_source_api_name() -> None:
    """Defensive: the only `_trace_forward_pcode(...)` call in `run()` must
    keep passing `source_api_name=source_api`. This is the invariant that
    makes the fallback removal safe."""
    text = _read("ghidra_scripts/pcode_taint.py")
    assert "source_api_name=source_api" in text
