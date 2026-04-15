from __future__ import annotations

from cerberus.util import safe_duration_to_float


def test_safe_duration_to_float_accepts_numeric_values():
    assert safe_duration_to_float(7) == 7.0
    assert safe_duration_to_float(2.75) == 2.75
    assert safe_duration_to_float("3.5") == 3.5


def test_safe_duration_to_float_parses_clock_strings():
    assert safe_duration_to_float("00:00:07") == 7.0
    assert safe_duration_to_float("01:02") == 62.0
    assert safe_duration_to_float("01:02:03") == 3723.0


def test_safe_duration_to_float_is_non_throwing_for_invalid_data():
    assert safe_duration_to_float(None) == 0.0
    assert safe_duration_to_float("") == 0.0
    assert safe_duration_to_float("not-a-duration") == 0.0
