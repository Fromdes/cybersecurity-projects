"""Unit tests for project_05.core."""

from __future__ import annotations

import string

import pytest

from project_05.core import (
    CHARS_SPECIAL,
    DEFAULT_LENGTH,
    PasswordConfig,
    generate_multiple,
    generate_password,
)


class TestPasswordConfig:
    def test_defaults_valid(self) -> None:
        cfg = PasswordConfig()
        assert cfg.length == DEFAULT_LENGTH

    def test_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="at least"):
            PasswordConfig(length=4)

    def test_too_long_raises(self) -> None:
        with pytest.raises(ValueError, match="exceed"):
            PasswordConfig(length=600)

    def test_no_classes_raises(self) -> None:
        with pytest.raises(ValueError, match="At least one"):
            PasswordConfig(
                use_lower=False, use_upper=False, use_digits=False, use_special=False
            )

    def test_alphabet_excludes_ambiguous(self) -> None:
        cfg = PasswordConfig(exclude_ambiguous=True)
        alpha = cfg.alphabet()
        for ch in "0O1lI":
            assert ch not in alpha

    def test_entropy_increases_with_length(self) -> None:
        short = PasswordConfig(length=8)
        long = PasswordConfig(length=32)
        assert long.entropy_bits() > short.entropy_bits()

    def test_entropy_zero_when_single_char_pool(self) -> None:
        cfg = PasswordConfig(
            use_lower=False, use_upper=False, use_special=False,
            use_digits=True, length=8
        )
        assert cfg.entropy_bits() > 0


class TestGeneratePassword:
    def test_correct_length(self) -> None:
        cfg = PasswordConfig(length=20)
        pw = generate_password(cfg)
        assert len(pw) == 20

    def test_all_chars_from_alphabet(self) -> None:
        cfg = PasswordConfig()
        alphabet = set(cfg.alphabet())
        pw = generate_password(cfg)
        assert all(c in alphabet for c in pw)

    def test_contains_all_required_classes(self) -> None:
        cfg = PasswordConfig(
            use_lower=True, use_upper=True, use_digits=True, use_special=True,
            require_each_class=True, length=20,
        )
        pw = generate_password(cfg)
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in CHARS_SPECIAL for c in pw)

    def test_digits_only(self) -> None:
        cfg = PasswordConfig(
            use_lower=False, use_upper=False, use_special=False, use_digits=True,
            require_each_class=False, length=10,
        )
        pw = generate_password(cfg)
        assert all(c in string.digits for c in pw)

    def test_default_config(self) -> None:
        pw = generate_password()
        assert len(pw) == DEFAULT_LENGTH

    def test_no_ambiguous_chars(self) -> None:
        cfg = PasswordConfig(length=100, exclude_ambiguous=True)
        for _ in range(20):
            pw = generate_password(cfg)
            assert not any(c in "0O1lI" for c in pw)


class TestGenerateMultiple:
    def test_generates_correct_count(self) -> None:
        passwords = generate_multiple(5)
        assert len(passwords) == 5

    def test_all_unique(self) -> None:
        passwords = generate_multiple(20)
        assert len(set(passwords)) == 20

    def test_count_zero_raises(self) -> None:
        with pytest.raises(ValueError):
            generate_multiple(0)
