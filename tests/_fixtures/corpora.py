"""Corpus of malformed LLM outputs for parser robustness testing."""

MALFORMED_JSON_CORPUS: list[tuple[str, str]] = [
    # (label, raw_text)
    ("preamble_simple", 'Here is the JSON: {"key": "value"}'),
    ("preamble_response", 'Response: {"key": "value"}'),
    (
        "preamble_long",
        'Sure, I will provide the analysis. Here\'s the result: {"k": 1}',
    ),
    ("fences_json", '```json\n{"k": "v"}\n```'),
    ("fences_plain", '```\n{"k": "v"}\n```'),
    ("fences_mixed_with_text", 'Here is the data:\n```json\n{"k": 1}\n```\nDone.'),
    ("trailing_comma_obj", '{"k": "v",}'),
    ("trailing_comma_arr", '{"items": [1, 2, 3,]}'),
    ("single_quotes", "{'k': 'v'}"),
    ("nested_brace_2", '{"a": {"b": {"c": 1}}}'),
    ("nested_brace_5", '{"a": {"b": {"c": {"d": {"e": 1}}}}}'),
    ("truncated_string", '{"k": "incomp'),
    ("truncated_object", '{"k": "v"'),
    ("empty_string", ""),
    ("only_whitespace", "   \n\t  "),
    ("ansi_color", '\x1b[31m{"k": "v"}\x1b[0m'),
    ("crlf", '{"k":\r\n"v"}'),
    ("unicode_escaped", '{"name": "\\u00e9"}'),
    ("leading_whitespace", '   \n  {"k": "v"}'),
    ("trailing_garbage", '{"k": "v"} <end>'),
    ("multiple_objects", '{"k": 1} {"k": 2}'),
    ("invalid_after_valid", '{"k": "v"} extra text'),
    ("nested_with_trailing_comma", '{"a": {"b": 1,}}'),
    ("array_root", '[{"k": "v"}]'),
    ("number_root", "42"),
    ("null_root", "null"),
    ("bool_root", "true"),
    ("escaped_newline", '{"k": "line1\\nline2"}'),
    ("comment_style", '{"k": "v"} // comment'),
    ("html_entities", '{"k": "v &amp; w"}'),
    # 30 cases total
]
