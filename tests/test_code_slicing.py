"""Phase 2C+.1 — LATTE-inspired text-based backward slicing tests.

Locks the public surface of ``aiedge.code_slicing`` and the env-gated
``maybe_slice`` entry point that ``taint_propagation`` calls. The tests
intentionally exercise behavioural invariants (slice is a subset of the
function body, line order is preserved, opt-out is byte-identical, ...)
rather than the exact set of lines kept, so future swaps to a
Ghidra-grade backend do not require rewriting the suite.
"""

from __future__ import annotations

import pytest

from aiedge.code_slicing import (
    extract_backward_slice,
    extract_slice_around_sink,
    find_sink_line,
    latte_slicing_enabled,
    maybe_slice,
    slice_compression_ratio,
)

# ---------------------------------------------------------------------------
# Sample function bodies (Ghidra-decompile-flavoured)
# ---------------------------------------------------------------------------


_SIMPLE_BODY = """\
void handle_request(char *user_input, int len) {
    char buf[64];
    int rc;
    char *prefix = "/cmd: ";
    rc = check_auth(user_input);
    if (rc != 0) {
        return;
    }
    sprintf(buf, "%s%s", prefix, user_input);
    log_info("about to exec %s", buf);
    system(buf);
}
"""


_NO_SINK_BODY = """\
void counter(int n) {
    for (int i = 0; i < n; i++) {
        printf("tick\\n");
    }
}
"""


# ---------------------------------------------------------------------------
# find_sink_line
# ---------------------------------------------------------------------------


def test_find_sink_line_returns_first_match() -> None:
    idx = find_sink_line(_SIMPLE_BODY, "system")
    assert idx is not None
    line = _SIMPLE_BODY.splitlines()[idx]
    assert "system(buf)" in line


def test_find_sink_line_respects_word_boundary() -> None:
    """``open`` should not match ``fopen``."""
    body = "    rc = fopen(path, mode);\n    open(path, O_RDONLY);\n"
    idx = find_sink_line(body, "open")
    assert idx == 1  # the bare open() call, not fopen


def test_find_sink_line_returns_none_when_absent() -> None:
    assert find_sink_line(_NO_SINK_BODY, "system") is None
    assert find_sink_line("", "system") is None
    assert find_sink_line(_SIMPLE_BODY, "") is None


# ---------------------------------------------------------------------------
# extract_backward_slice -- behaviour invariants
# ---------------------------------------------------------------------------


def test_slice_includes_sink_line() -> None:
    sink_idx = find_sink_line(_SIMPLE_BODY, "system")
    assert sink_idx is not None
    sliced = extract_backward_slice(_SIMPLE_BODY, sink_idx)
    assert "system(buf)" in sliced


def test_slice_preserves_source_order() -> None:
    sink_idx = find_sink_line(_SIMPLE_BODY, "system")
    assert sink_idx is not None
    sliced = extract_backward_slice(_SIMPLE_BODY, sink_idx)
    sliced_lines = sliced.splitlines()
    body_lines = _SIMPLE_BODY.splitlines()
    line_to_first_index: dict[str, int] = {}
    for i, line in enumerate(body_lines):
        line_to_first_index.setdefault(line, i)
    indices = [line_to_first_index[line] for line in sliced_lines]
    assert indices == sorted(indices)


def test_slice_is_subset_of_original_lines() -> None:
    sink_idx = find_sink_line(_SIMPLE_BODY, "system")
    assert sink_idx is not None
    sliced_lines = set(extract_backward_slice(_SIMPLE_BODY, sink_idx).splitlines())
    body_lines = set(_SIMPLE_BODY.splitlines())
    assert sliced_lines <= body_lines


def test_slice_pulls_in_definition_of_sink_argument() -> None:
    """The line that *defines* ``buf`` (the sink argument) must be kept."""
    sink_idx = find_sink_line(_SIMPLE_BODY, "system")
    assert sink_idx is not None
    sliced = extract_backward_slice(_SIMPLE_BODY, sink_idx)
    assert "char buf[64];" in sliced


def test_slice_pulls_in_definition_chain_back_to_user_input() -> None:
    """``buf`` is filled by ``sprintf`` from ``user_input`` and ``prefix``;
    those defining lines must appear in the slice so the LLM can reason
    about the taint chain."""
    sink_idx = find_sink_line(_SIMPLE_BODY, "system")
    assert sink_idx is not None
    sliced = extract_backward_slice(_SIMPLE_BODY, sink_idx)
    assert "sprintf(buf" in sliced  # the assignment
    assert "user_input" in sliced  # taint source visible


def test_slice_respects_max_lines_cap() -> None:
    sink_idx = find_sink_line(_SIMPLE_BODY, "system")
    assert sink_idx is not None
    sliced = extract_backward_slice(_SIMPLE_BODY, sink_idx, max_lines=2)
    assert len(sliced.splitlines()) <= 2


def test_slice_returns_full_body_when_index_out_of_range() -> None:
    body = "int main(void) { return 0; }\n"
    assert extract_backward_slice(body, 999) == body
    assert extract_backward_slice(body, -1) == body


def test_slice_returns_full_body_when_max_lines_nonpositive() -> None:
    """``max_lines <= 0`` is treated as a no-op so callers cannot accidentally
    blank the prompt."""
    sink_idx = find_sink_line(_SIMPLE_BODY, "system")
    assert sink_idx is not None
    assert extract_backward_slice(_SIMPLE_BODY, sink_idx, max_lines=0) == _SIMPLE_BODY


def test_slice_handles_empty_body() -> None:
    assert extract_backward_slice("", 0) == ""


# ---------------------------------------------------------------------------
# extract_slice_around_sink convenience wrapper
# ---------------------------------------------------------------------------


def test_extract_slice_around_sink_returns_none_when_sink_absent() -> None:
    assert extract_slice_around_sink(_NO_SINK_BODY, "system") is None


def test_extract_slice_around_sink_combines_locator_and_slicer() -> None:
    sliced = extract_slice_around_sink(_SIMPLE_BODY, "system")
    assert sliced is not None
    assert "system(buf)" in sliced
    assert "char buf[64];" in sliced


# ---------------------------------------------------------------------------
# maybe_slice + env gate
# ---------------------------------------------------------------------------


def test_latte_slicing_enabled_default_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AIEDGE_LATTE_SLICING", raising=False)
    assert latte_slicing_enabled() is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "On"])
def test_latte_slicing_enabled_truthy_values(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("AIEDGE_LATTE_SLICING", value)
    assert latte_slicing_enabled() is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "garbage"])
def test_latte_slicing_enabled_falsy_values(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("AIEDGE_LATTE_SLICING", value)
    assert latte_slicing_enabled() is False


def test_maybe_slice_is_byte_identical_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AIEDGE_LATTE_SLICING", raising=False)
    assert maybe_slice(_SIMPLE_BODY, "system") == _SIMPLE_BODY


def test_maybe_slice_compresses_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AIEDGE_LATTE_SLICING", "1")
    sliced = maybe_slice(_SIMPLE_BODY, "system")
    assert sliced != _SIMPLE_BODY
    assert len(sliced.splitlines()) < len(_SIMPLE_BODY.splitlines())


def test_maybe_slice_falls_back_to_full_body_when_sink_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AIEDGE_LATTE_SLICING", "1")
    assert maybe_slice(_NO_SINK_BODY, "system") == _NO_SINK_BODY


# ---------------------------------------------------------------------------
# slice_compression_ratio
# ---------------------------------------------------------------------------


def test_compression_ratio_full_body_is_one() -> None:
    assert slice_compression_ratio(_SIMPLE_BODY, _SIMPLE_BODY) == 1.0


def test_compression_ratio_empty_original_is_one() -> None:
    assert slice_compression_ratio("", "anything") == 1.0


def test_compression_ratio_below_one_when_sliced() -> None:
    sink_idx = find_sink_line(_SIMPLE_BODY, "system")
    assert sink_idx is not None
    sliced = extract_backward_slice(_SIMPLE_BODY, sink_idx, max_lines=3)
    assert slice_compression_ratio(_SIMPLE_BODY, sliced) < 1.0
