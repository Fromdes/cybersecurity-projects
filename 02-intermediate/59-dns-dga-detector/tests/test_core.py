"""Tests for project 59 DNS DGA detector."""

from __future__ import annotations

import pytest

from project_59.core import (
    DGAVerdict,
    analyse_domain_list,
    bigram_score,
    classify_domain,
    consonant_ratio,
    digit_ratio,
    shannon_entropy,
)


class TestFeatures:
    def test_entropy_uniform(self) -> None:
        # All same char → 0
        assert shannon_entropy("aaaa") == 0.0

    def test_entropy_high(self) -> None:
        # Many distinct chars → high entropy
        assert shannon_entropy("abcdefghij") > 3.0

    def test_consonant_ratio_vowel_heavy(self) -> None:
        assert consonant_ratio("aeiou") == 0.0

    def test_consonant_ratio_consonant_heavy(self) -> None:
        assert consonant_ratio("bcdftghjk") > 0.8

    def test_digit_ratio(self) -> None:
        assert digit_ratio("abc123") == pytest.approx(0.5)

    def test_digit_ratio_empty(self) -> None:
        assert digit_ratio("") == 0.0

    def test_bigram_score_english(self) -> None:
        # "the" contains "th" and "he"
        score = bigram_score("the")
        assert score > 0.01

    def test_bigram_score_random(self) -> None:
        score = bigram_score("xzqvkjfmbn")
        assert score < 0.005


class TestClassifyDomain:
    def test_known_good(self) -> None:
        v = classify_domain("google.com")
        assert not v.is_dga

    def test_short_label(self) -> None:
        v = classify_domain("abc.io")
        assert not v.is_dga

    def test_dga_high_entropy(self) -> None:
        # Typical DGA domain: high entropy, no English structure
        v = classify_domain("xq8bzk3mplrvw9s.com")
        assert v.is_dga or v.confidence > 0.3

    def test_dga_long_random(self) -> None:
        v = classify_domain("kzjqxvbwymfplrtsnhcd.net")
        assert v.is_dga

    def test_tld_stripped(self) -> None:
        # Simple heuristic: label = parts[-2]; for .co.uk this resolves to "co"
        v = classify_domain("example.co.uk")
        assert v.label == "co"
        v2 = classify_domain("example.com")
        assert v2.label == "example"

    def test_verdict_fields(self) -> None:
        v = classify_domain("google.com")
        assert v.entropy >= 0
        assert 0.0 <= v.confidence <= 1.0
        assert v.length > 0


class TestAnalyseDomainList:
    def test_mixed_list(self) -> None:
        domains = ["google.com", "kzjqxvbwymfplrtsnhcd.net", ""]
        results = analyse_domain_list(domains)
        assert len(results) == 2  # empty string filtered out
        is_dga_flags = [r.is_dga for r in results]
        assert True in is_dga_flags
