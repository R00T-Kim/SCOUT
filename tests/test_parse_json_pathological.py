"""5-stage JSON parser pathological corpus test (PR #6).

Tests parse_json_from_llm_output() against 30+ malformed inputs to verify
deterministic behavior (success or explicit failure, never silent corruption).

Externally-facing claim: 'SCOUT's 5-stage JSON parser handles preamble,
fences, brace-counting, and common errors. Failure rate dropped from 68%
to 0% on R7000.' This file is the test that backs the claim against a
broad corpus, not just R7000.

Contract under test
-------------------
- Returns dict[str, object] on success.
- Returns None on irrecoverable parse failure.
- Never raises an unhandled exception.
- Same input always produces same output (deterministic).
- Returned values are always JSON-serializable.
"""

from __future__ import annotations

import json

import pytest

from aiedge.llm_driver import parse_json_from_llm_output

# ---------------------------------------------------------------------------
# Stage 0: preamble stripping
# ---------------------------------------------------------------------------


class TestParsePreamble:
    """Stage 0: LLM preamble stripping before first parse attempt."""

    def test_preamble_here_is_the_json(self):
        result = parse_json_from_llm_output('Here is the JSON: {"key": "value"}')
        assert result == {"key": "value"}

    def test_preamble_response(self):
        result = parse_json_from_llm_output('Response: {"key": "value"}')
        assert result == {"key": "value"}

    def test_preamble_output(self):
        result = parse_json_from_llm_output('Output: {"k": 99}')
        assert result == {"k": 99}

    def test_preamble_result(self):
        result = parse_json_from_llm_output('Result: {"status": "ok"}')
        assert result == {"status": "ok"}

    def test_preamble_case_insensitive(self):
        result = parse_json_from_llm_output('HERE IS THE JSON: {"k": 1}')
        assert result == {"k": 1}

    def test_preamble_long_prose_falls_through_to_brace_counting(self):
        # "Sure, I will provide..." doesn't match stage 0 regex, but brace
        # counting (stage 3) still finds the object.
        text = 'Sure, I will provide the analysis. Here\'s the result: {"k": 1}'
        result = parse_json_from_llm_output(text)
        assert result == {"k": 1}

    def test_preamble_with_newlines_before_object(self):
        text = 'Analysis complete.\n\nHere is the JSON output:\n{"status": "ok"}'
        result = parse_json_from_llm_output(text)
        assert result == {"status": "ok"}


# ---------------------------------------------------------------------------
# Stage 1: code fence extraction
# ---------------------------------------------------------------------------


class TestParseFences:
    """Stage 1: code fence extraction (json-tagged and plain)."""

    def test_json_fence(self):
        result = parse_json_from_llm_output('```json\n{"k": "v"}\n```')
        assert result == {"k": "v"}

    def test_plain_fence(self):
        result = parse_json_from_llm_output('```\n{"k": "v"}\n```')
        assert result == {"k": "v"}

    def test_fence_with_surrounding_text(self):
        text = 'Here is the data:\n```json\n{"k": 1}\n```\nDone.'
        result = parse_json_from_llm_output(text)
        assert result == {"k": 1}

    def test_fence_missing_close_still_attempted(self):
        # Lenient regex allows missing closing fence — if extractable, accept it.
        text = '```json\n{"k": "v"}'
        result = parse_json_from_llm_output(text)
        # Either valid parse or None — must not corrupt.
        assert result is None or result == {"k": "v"}

    def test_fence_json_case_insensitive(self):
        result = parse_json_from_llm_output('```JSON\n{"k": "v"}\n```')
        assert result == {"k": "v"}


# ---------------------------------------------------------------------------
# Stage 3: brace-counting object extraction
# ---------------------------------------------------------------------------


class TestParseBraceCounting:
    """Stage 3: outermost brace-counted extraction for nested / surrounded objects."""

    def test_nested_2_levels(self):
        result = parse_json_from_llm_output('{"a": {"b": {"c": 1}}}')
        assert result == {"a": {"b": {"c": 1}}}

    def test_nested_5_levels(self):
        result = parse_json_from_llm_output('{"a": {"b": {"c": {"d": {"e": 1}}}}}')
        assert result == {"a": {"b": {"c": {"d": {"e": 1}}}}}

    def test_nested_7_levels(self):
        obj = {"a": {"b": {"c": {"d": {"e": {"f": {"g": 42}}}}}}}
        text = json.dumps(obj)
        result = parse_json_from_llm_output(text)
        assert result == obj

    def test_trailing_garbage_after_object(self):
        result = parse_json_from_llm_output('{"k": "v"} <end>')
        assert result == {"k": "v"}

    def test_trailing_text_after_object(self):
        result = parse_json_from_llm_output('{"k": "v"} extra text')
        assert result == {"k": "v"}

    def test_first_object_when_multiple(self):
        result = parse_json_from_llm_output('{"k": 1} {"k": 2}')
        assert result == {"k": 1}

    def test_comment_after_object(self):
        result = parse_json_from_llm_output('{"k": "v"} // comment')
        assert result == {"k": "v"}

    def test_ansi_escape_stripped_by_brace_counting(self):
        # Brace-counting finds `{` ignoring leading ANSI bytes.
        text = '\x1b[31m{"k": "v"}\x1b[0m'
        result = parse_json_from_llm_output(text)
        # Stage 3 starts at first `{`, so ANSI suffix is harmless.
        assert result == {"k": "v"} or result is None


# ---------------------------------------------------------------------------
# Stage 4: common error fixes (trailing comma, single quotes)
# ---------------------------------------------------------------------------


class TestParseCommonErrors:
    """Stage 4: trailing commas and single-quote heuristic."""

    def test_trailing_comma_object(self):
        result = parse_json_from_llm_output('{"k": "v",}')
        assert result == {"k": "v"}

    def test_trailing_comma_array_value(self):
        result = parse_json_from_llm_output('{"items": [1, 2, 3,]}')
        assert result == {"items": [1, 2, 3]}

    def test_nested_trailing_comma(self):
        result = parse_json_from_llm_output('{"a": {"b": 1,}}')
        assert result == {"a": {"b": 1}}

    def test_single_quotes_no_double_quotes(self):
        # Single-quote swap only fires when no '"' present — pure single-quote input.
        result = parse_json_from_llm_output("{'k': 'v'}")
        assert result == {"k": "v"}

    def test_trailing_comma_then_single_quote(self):
        # Both fixes needed: trailing comma then quotes. Since single-quote
        # swap requires no '"' in string, use pure single-quote version.
        result = parse_json_from_llm_output("{'k': 'v',}")
        assert result == {"k": "v"}


# ---------------------------------------------------------------------------
# Explicit failure cases (must return None, never raise)
# ---------------------------------------------------------------------------


class TestParseExplicitFailure:
    """Inputs that are genuinely unrecoverable must return None, not raise."""

    def test_empty_string(self):
        assert parse_json_from_llm_output("") is None

    def test_only_whitespace(self):
        assert parse_json_from_llm_output("   \n\t  ") is None

    def test_random_text_no_json(self):
        assert parse_json_from_llm_output("just some random text without json") is None

    def test_truncated_string_value(self):
        # Brace-counting finds `{`, but json.loads fails; stage 4 cannot fix.
        assert parse_json_from_llm_output('{"k": "incomp') is None

    def test_truncated_object(self):
        assert parse_json_from_llm_output('{"k": "v"') is None

    def test_array_root_brace_counted(self):
        # Array root: json.loads('[{"k":"v"}]') returns a list (rejected by
        # _accept), but brace-counting (stage 3) finds the inner `{...}` and
        # returns the first element as a dict.  Parser succeeds with {"k":"v"}.
        result = parse_json_from_llm_output('[{"k": "v"}]')
        assert result == {"k": "v"}

    def test_number_root_rejected(self):
        assert parse_json_from_llm_output("42") is None

    def test_null_root_rejected(self):
        assert parse_json_from_llm_output("null") is None

    def test_bool_root_rejected(self):
        assert parse_json_from_llm_output("true") is None


# ---------------------------------------------------------------------------
# Whitespace, encoding, and CRLF edge cases
# ---------------------------------------------------------------------------


class TestParseEdgeCases:
    """Encoding, whitespace, CRLF, unicode, etc."""

    def test_crlf_newlines(self):
        result = parse_json_from_llm_output('{"k":\r\n"v"}')
        assert result == {"k": "v"}

    def test_unicode_escaped(self):
        result = parse_json_from_llm_output('{"name": "\\u00e9"}')
        assert result == {"name": "\u00e9"}

    def test_leading_whitespace(self):
        result = parse_json_from_llm_output('   \n  {"k": "v"}')
        assert result == {"k": "v"}

    def test_escaped_newline_in_value(self):
        result = parse_json_from_llm_output('{"k": "line1\\nline2"}')
        assert result == {"k": "line1\nline2"}

    def test_html_entity_in_string(self):
        # HTML entities are valid JSON string content.
        result = parse_json_from_llm_output('{"k": "v &amp; w"}')
        assert result == {"k": "v &amp; w"}

    def test_leading_tabs_before_object(self):
        result = parse_json_from_llm_output('\t\t{"k": 1}')
        assert result == {"k": 1}

    def test_bom_before_object(self):
        # UTF-8 BOM: \ufeff. Parser strips via .strip(); BOM is not whitespace
        # but brace-counting will find `{` regardless.
        text = '\ufeff{"k": 1}'
        result = parse_json_from_llm_output(text)
        # Either succeeds (brace-counting past BOM) or None — must not corrupt.
        assert result is None or result == {"k": 1}

    def test_deeply_nested_large_object(self):
        # Build a 7-deep object and verify round-trip.
        deep = {"level": 7}
        for i in range(6, 0, -1):
            deep = {"level": i, "child": deep}
        text = json.dumps(deep)
        result = parse_json_from_llm_output(text)
        assert result == deep

    def test_large_flat_object(self):
        # 100 keys — no nesting issues.
        big = {f"key_{i}": i for i in range(100)}
        text = json.dumps(big)
        result = parse_json_from_llm_output(text)
        assert result == big


# ---------------------------------------------------------------------------
# required_keys schema validation
# ---------------------------------------------------------------------------


class TestParseRequiredKeys:
    """required_keys parameter triggers schema validation on parsed dict."""

    def test_required_keys_all_present(self):
        text = '{"name": "x", "value": 1}'
        result = parse_json_from_llm_output(
            text, required_keys=frozenset({"name", "value"})
        )
        assert result == {"name": "x", "value": 1}

    def test_required_keys_missing_one(self):
        text = '{"name": "x"}'
        result = parse_json_from_llm_output(
            text, required_keys=frozenset({"name", "value"})
        )
        assert result is None

    def test_required_keys_all_missing(self):
        text = '{"other": "x"}'
        result = parse_json_from_llm_output(
            text, required_keys=frozenset({"name", "value"})
        )
        assert result is None

    def test_required_keys_with_extra_fields(self):
        text = '{"name": "x", "value": 1, "extra": "y"}'
        result = parse_json_from_llm_output(
            text, required_keys=frozenset({"name", "value"})
        )
        assert result == {"name": "x", "value": 1, "extra": "y"}

    def test_required_keys_empty_frozenset(self):
        # Empty frozenset means no constraint — should accept any dict.
        text = '{"k": "v"}'
        result = parse_json_from_llm_output(text, required_keys=frozenset())
        assert result == {"k": "v"}

    def test_required_keys_none_means_no_validation(self):
        text = '{"k": "v"}'
        result = parse_json_from_llm_output(text, required_keys=None)
        assert result == {"k": "v"}


# ---------------------------------------------------------------------------
# Full corpus integration: no unhandled exception, always JSON-serializable
# ---------------------------------------------------------------------------


class TestParseCorpusFromFixtures:
    """Run parser against the entire MALFORMED_JSON_CORPUS from PR #4 fixture."""

    def test_all_corpus_entries_no_exception(self, scout_malformed_corpus):
        """Parser must not raise on any corpus entry."""
        failures = []
        for label, raw in scout_malformed_corpus:
            try:
                parse_json_from_llm_output(raw)
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{label}: {type(exc).__name__}: {exc}")
        assert not failures, "Parser raised on corpus entries:\n" + "\n".join(failures)

    def test_all_corpus_entries_result_json_serializable(self, scout_malformed_corpus):
        """When parser returns a non-None result it must be JSON-serializable."""
        corrupt = []
        for label, raw in scout_malformed_corpus:
            result = parse_json_from_llm_output(raw)
            if result is not None:
                try:
                    json.dumps(result)
                except (TypeError, ValueError) as exc:
                    corrupt.append(f"{label}: {exc}")
        assert not corrupt, "Parser returned non-serializable for:\n" + "\n".join(
            corrupt
        )

    def test_all_corpus_entries_result_is_dict_or_none(self, scout_malformed_corpus):
        """Return value must be dict or None — never a bare list, int, str, etc."""
        wrong_type = []
        for label, raw in scout_malformed_corpus:
            result = parse_json_from_llm_output(raw)
            if result is not None and not isinstance(result, dict):
                wrong_type.append(f"{label}: got {type(result).__name__}")
        assert not wrong_type, "Parser returned non-dict for:\n" + "\n".join(wrong_type)


# ---------------------------------------------------------------------------
# Determinism: same input → same output on repeated calls
# ---------------------------------------------------------------------------


class TestParseDeterminism:
    """Idempotency: calling parser N times on same input must yield equal results."""

    @pytest.mark.parametrize(
        "input_text",
        [
            '{"a": 1}',
            'Here is the JSON: {"k": "v"}',
            '```json\n{"k": "v"}\n```',
            "{'a': 1,}",
            '{"a": {"b": {"c": 1}}}',
            '{"k": "v"} trailing garbage',
            "",
            "null",
            '[{"k": "v"}]',
        ],
    )
    def test_idempotent_three_calls(self, input_text):
        r1 = parse_json_from_llm_output(input_text)
        r2 = parse_json_from_llm_output(input_text)
        r3 = parse_json_from_llm_output(input_text)
        assert r1 == r2 == r3

    def test_corpus_idempotent(self, scout_malformed_corpus):
        """Every corpus entry is deterministic across two calls."""
        nondeterministic = []
        for label, raw in scout_malformed_corpus:
            r1 = parse_json_from_llm_output(raw)
            r2 = parse_json_from_llm_output(raw)
            if r1 != r2:
                nondeterministic.append(label)
        assert not nondeterministic, "Non-deterministic on: " + ", ".join(
            nondeterministic
        )
