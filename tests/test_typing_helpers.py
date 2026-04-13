"""Tests for :mod:`aiedge._typing_helpers`."""

from __future__ import annotations

import math

from aiedge._typing_helpers import safe_float, safe_int


class TestSafeFloat:
    def test_none_returns_default(self) -> None:
        assert safe_float(None) == 0.0
        assert safe_float(None, default=3.14) == 3.14

    def test_int_and_float(self) -> None:
        assert safe_float(42) == 42.0
        assert safe_float(3.14) == 3.14
        assert safe_float(-1) == -1.0

    def test_bool(self) -> None:
        assert safe_float(True) == 1.0
        assert safe_float(False) == 0.0

    def test_numeric_string(self) -> None:
        assert safe_float("2.5") == 2.5
        assert safe_float("7") == 7.0
        assert safe_float("-1.2") == -1.2

    def test_invalid_string_returns_default(self) -> None:
        assert safe_float("abc") == 0.0
        assert safe_float("abc", default=-1.0) == -1.0
        assert safe_float("") == 0.0

    def test_dict_and_list_return_default(self) -> None:
        assert safe_float({"a": 1}) == 0.0
        assert safe_float([1, 2, 3]) == 0.0
        assert safe_float({"a": 1}, default=9.9) == 9.9

    def test_arbitrary_object_returns_default(self) -> None:
        assert safe_float(object()) == 0.0

    def test_nan_passthrough(self) -> None:
        result = safe_float(float("nan"))
        assert math.isnan(result)


class TestSafeInt:
    def test_none_returns_default(self) -> None:
        assert safe_int(None) == 0
        assert safe_int(None, default=5) == 5

    def test_int(self) -> None:
        assert safe_int(42) == 42
        assert safe_int(-1) == -1
        assert safe_int(0) == 0

    def test_float_truncates(self) -> None:
        assert safe_int(3.7) == 3
        assert safe_int(-2.9) == -2
        assert safe_int(0.1) == 0

    def test_bool(self) -> None:
        assert safe_int(True) == 1
        assert safe_int(False) == 0

    def test_numeric_string(self) -> None:
        assert safe_int("42") == 42
        assert safe_int("-7") == -7

    def test_float_string_truncates(self) -> None:
        # ``int("3.14")`` raises; ``safe_int`` falls back to float parsing.
        assert safe_int("3.14") == 3
        assert safe_int("-2.9") == -2

    def test_invalid_string_returns_default(self) -> None:
        assert safe_int("abc") == 0
        assert safe_int("abc", default=-1) == -1
        assert safe_int("") == 0

    def test_dict_and_list_return_default(self) -> None:
        assert safe_int({"a": 1}) == 0
        assert safe_int([1, 2, 3]) == 0

    def test_arbitrary_object_returns_default(self) -> None:
        assert safe_int(object()) == 0
