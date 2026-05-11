"""Unit tests for project_04.core."""

from __future__ import annotations

import pytest

from project_04.core import (
    MIN_ENTROPY_BITS_FAIR,
    PasswordAnalysis,
    analyze_password,
)


class TestAnalyzePassword:
    def test_very_weak_password(self) -> None:
        result = analyze_password("abc")
        assert result.score == 0
        assert result.strength_label == "Very Weak"

    def test_strong_password(self) -> None:
        result = analyze_password("C0rrectH0rseB@tteryStaple!")
        assert result.score >= 3

    def test_detects_all_char_classes(self) -> None:
        result = analyze_password("Abc1!xyz")
        assert result.has_lower
        assert result.has_upper
        assert result.has_digits
        assert result.has_special

    def test_only_lowercase(self) -> None:
        result = analyze_password("abcdefgh")
        assert not result.has_upper
        assert not result.has_digits
        assert not result.has_special

    def test_entropy_increases_with_length(self) -> None:
        short = analyze_password("Abc1!")
        long = analyze_password("Abc1!" * 5)
        assert long.entropy_bits > short.entropy_bits

    def test_keyboard_walk_flagged(self) -> None:
        result = analyze_password("qwerty123")
        assert any("keyboard" in w.lower() for w in result.warnings)

    def test_repeated_chars_flagged(self) -> None:
        result = analyze_password("aaaaaaaabcde1!")
        assert any("repeat" in w.lower() for w in result.warnings)

    def test_empty_password(self) -> None:
        result = analyze_password("")
        assert result.score == 0
        assert result.entropy_bits == 0.0

    def test_suggestions_for_missing_classes(self) -> None:
        result = analyze_password("alllowercase")
        assert any("uppercase" in s.lower() for s in result.suggestions)
        assert any("digit" in s.lower() for s in result.suggestions)
        assert any("special" in s.lower() for s in result.suggestions)

    def test_password_analysis_is_frozen(self) -> None:
        result = analyze_password("Test1234!")
        with pytest.raises((TypeError, AttributeError)):
            result.score = 99  # type: ignore[misc]

    def test_entropy_bits_positive_for_non_empty(self) -> None:
        result = analyze_password("a")
        assert result.entropy_bits > 0.0

    def test_score_bounds(self) -> None:
        for pw in ["a", "password", "P@ssw0rd!", "C0rrectHorseBatteryStaple!X"]:
            result = analyze_password(pw)
            assert 0 <= result.score <= 4
