"""Unit tests for aiedge.normalize module."""

from __future__ import annotations

from aiedge.normalize import normalize_evidence_list, normalize_limitations_list

# ---------------------------------------------------------------------------
# normalize_evidence_list
# ---------------------------------------------------------------------------

FALLBACK: list[dict] = [{"path": "fallback/path.bin"}]


def test_evidence_empty_list_returns_fallback() -> None:
    result = normalize_evidence_list([], fallback=FALLBACK)
    assert result == FALLBACK


def test_evidence_none_returns_fallback() -> None:
    result = normalize_evidence_list(None, fallback=FALLBACK)
    assert result == FALLBACK


def test_evidence_dict_input_returns_fallback() -> None:
    result = normalize_evidence_list({"path": "x"}, fallback=FALLBACK)
    assert result == FALLBACK


def test_evidence_str_input_returns_fallback() -> None:
    result = normalize_evidence_list("some/path", fallback=FALLBACK)
    assert result == FALLBACK


def test_evidence_int_input_returns_fallback() -> None:
    result = normalize_evidence_list(42, fallback=FALLBACK)
    assert result == FALLBACK


def test_evidence_valid_dict_item_with_path() -> None:
    items = [{"path": "lib/libfoo.so"}]
    result = normalize_evidence_list(items, fallback=FALLBACK)
    assert result == [{"path": "lib/libfoo.so"}]


def test_evidence_dict_item_missing_path_excluded() -> None:
    items = [{"note": "no path here"}]
    result = normalize_evidence_list(items, fallback=FALLBACK)
    assert result == FALLBACK


def test_evidence_optional_fields_extracted() -> None:
    items = [
        {
            "path": "bin/httpd",
            "note": "stack overflow",
            "snippet": "gets(buf);",
            "snippet_sha256": "abc123",
        }
    ]
    result = normalize_evidence_list(items, fallback=FALLBACK)
    assert len(result) == 1
    ev = result[0]
    assert ev["path"] == "bin/httpd"
    assert ev["note"] == "stack overflow"
    assert ev["snippet"] == "gets(buf);"
    assert ev["snippet_sha256"] == "abc123"


def test_evidence_str_item_becomes_path_dict() -> None:
    items = ["etc/passwd"]
    result = normalize_evidence_list(items, fallback=FALLBACK)
    assert result == [{"path": "etc/passwd"}]


def test_evidence_mixed_list() -> None:
    items = [
        {"path": "bin/sh"},
        "etc/shadow",
        {"note": "no path"},  # invalid — excluded
        123,  # invalid — excluded
        {"path": ""},  # empty path — excluded
    ]
    result = normalize_evidence_list(items, fallback=FALLBACK)
    assert result == [{"path": "bin/sh"}, {"path": "etc/shadow"}]


def test_evidence_empty_optional_fields_not_included() -> None:
    items = [{"path": "bin/sh", "note": "", "snippet": ""}]
    result = normalize_evidence_list(items, fallback=FALLBACK)
    assert result == [{"path": "bin/sh"}]
    assert "note" not in result[0]
    assert "snippet" not in result[0]


def test_evidence_fallback_is_shallow_copied() -> None:
    # list(fallback) returns a new list object but shares the inner dict refs.
    fb: list[dict] = [{"path": "orig"}]
    result = normalize_evidence_list(None, fallback=fb)
    assert result is not fb  # different list object
    assert result == fb  # same contents


# ---------------------------------------------------------------------------
# normalize_limitations_list
# ---------------------------------------------------------------------------


def test_limitations_empty_list() -> None:
    assert normalize_limitations_list([]) == []


def test_limitations_none_returns_empty() -> None:
    assert normalize_limitations_list(None) == []


def test_limitations_non_list_returns_empty() -> None:
    assert normalize_limitations_list("a string") == []
    assert normalize_limitations_list({"key": "val"}) == []
    assert normalize_limitations_list(7) == []


def test_limitations_valid_strings() -> None:
    result = normalize_limitations_list(["limit A", "limit B"])
    assert result == ["limit A", "limit B"]


def test_limitations_empty_string_filtered() -> None:
    result = normalize_limitations_list(["ok", "", "also ok"])
    assert result == ["ok", "also ok"]


def test_limitations_non_string_items_filtered() -> None:
    result = normalize_limitations_list(["valid", 42, None, True, "also valid"])
    assert result == ["valid", "also valid"]
