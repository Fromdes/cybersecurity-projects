"""Unit tests for project_06.core."""

from __future__ import annotations

from pathlib import Path

import pytest

from project_06._wordlist import DEMO_WORDLIST
from project_06.core import (
    DEFAULT_SEPARATOR,
    DEFAULT_WORD_COUNT,
    MIN_WORD_COUNT,
    entropy_warning,
    generate_passphrase,
    load_wordlist,
    passphrase_entropy,
)


class TestLoadWordlist:
    def test_loads_demo_wordlist_by_default(self) -> None:
        wl = load_wordlist()
        assert len(wl) >= 200

    def test_loads_custom_file(self, tmp_path: Path) -> None:
        f = tmp_path / "words.txt"
        f.write_text("apple\nbanana\ncherry\n", encoding="utf-8")
        wl = load_wordlist(f)
        assert "apple" in wl
        assert "banana" in wl

    def test_loads_eff_format(self, tmp_path: Path) -> None:
        f = tmp_path / "eff.txt"
        f.write_text("11111\tabacus\n11112\nabdomen\n", encoding="utf-8")
        wl = load_wordlist(f)
        assert "abacus" in wl
        assert "abdomen" in wl

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_wordlist(tmp_path / "no.txt")

    def test_too_few_words_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "tiny.txt"
        f.write_text("only\n", encoding="utf-8")
        with pytest.raises(ValueError, match="too small"):
            load_wordlist(f)

    def test_deduplicates_words(self, tmp_path: Path) -> None:
        f = tmp_path / "dupes.txt"
        f.write_text("word\nword\nother\n", encoding="utf-8")
        wl = load_wordlist(f)
        assert wl.count("word") == 1


class TestGeneratePassphrase:
    def test_correct_word_count(self) -> None:
        pp = generate_passphrase(word_count=5)
        assert len(pp.split(DEFAULT_SEPARATOR)) == 5

    def test_custom_separator(self) -> None:
        pp = generate_passphrase(word_count=4, separator=" ")
        assert " " in pp

    def test_words_from_wordlist(self) -> None:
        wl = ["alpha", "beta", "gamma", "delta"]
        pp = generate_passphrase(word_count=3, wordlist=wl)
        for word in pp.split(DEFAULT_SEPARATOR):
            assert word in wl

    def test_too_few_words_raises(self) -> None:
        with pytest.raises(ValueError):
            generate_passphrase(word_count=MIN_WORD_COUNT - 1)

    def test_default_word_count(self) -> None:
        pp = generate_passphrase()
        assert len(pp.split(DEFAULT_SEPARATOR)) == DEFAULT_WORD_COUNT

    def test_all_words_lowercase(self) -> None:
        pp = generate_passphrase()
        for word in pp.split(DEFAULT_SEPARATOR):
            assert word == word.lower()


class TestPassphraseEntropy:
    def test_known_value(self) -> None:
        entropy = passphrase_entropy(6, 7776)
        assert entropy == pytest.approx(77.55, abs=0.1)

    def test_zero_on_edge_cases(self) -> None:
        assert passphrase_entropy(0, 100) == 0.0
        assert passphrase_entropy(6, 1) == 0.0

    def test_demo_wordlist_entropy(self) -> None:
        entropy = passphrase_entropy(DEFAULT_WORD_COUNT, len(DEMO_WORDLIST))
        assert entropy > 0


class TestEntropyWarning:
    def test_low_entropy_produces_warning(self) -> None:
        warning = entropy_warning(40.0)
        assert warning is not None
        assert "bits" in warning

    def test_sufficient_entropy_returns_none(self) -> None:
        assert entropy_warning(80.0) is None
