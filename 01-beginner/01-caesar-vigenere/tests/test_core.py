"""Unit tests for project_01.core."""

from __future__ import annotations

import pytest

from project_01.core import (
    CaesarCipher,
    VigenereCipher,
    caesar_crack,
    entropy_bits,
    frequency_analysis,
    vigenere_key_length_hint,
)


class TestCaesarCipher:
    """Tests for CaesarCipher."""

    def test_encrypt_basic(self) -> None:
        # Arrange
        cipher = CaesarCipher(3)
        # Act
        result = cipher.encrypt("ABC")
        # Assert
        assert result == "DEF"

    def test_decrypt_roundtrip(self) -> None:
        cipher = CaesarCipher(13)
        original = "Hello, World!"
        assert cipher.decrypt(cipher.encrypt(original)) == original

    def test_preserves_non_alpha(self) -> None:
        cipher = CaesarCipher(1)
        assert cipher.encrypt("a1b!") == "b1c!"

    def test_wraps_around_alphabet(self) -> None:
        cipher = CaesarCipher(3)
        assert cipher.encrypt("XYZ") == "ABC"

    def test_lowercase_preserved(self) -> None:
        cipher = CaesarCipher(1)
        assert cipher.encrypt("abc") == "bcd"

    def test_zero_shift_is_identity(self) -> None:
        cipher = CaesarCipher(0)
        assert cipher.encrypt("Hello") == "Hello"

    def test_invalid_shift_raises(self) -> None:
        with pytest.raises(ValueError):
            CaesarCipher(26)

    def test_negative_shift_raises(self) -> None:
        with pytest.raises(ValueError):
            CaesarCipher(-1)

    def test_rot13(self) -> None:
        cipher = CaesarCipher(13)
        assert cipher.encrypt(cipher.encrypt("Secret")) == "Secret"


class TestVigenereCipher:
    """Tests for VigenereCipher."""

    def test_encrypt_basic(self) -> None:
        cipher = VigenereCipher("KEY")
        assert cipher.encrypt("ABC") == "KFA"

    def test_decrypt_roundtrip(self) -> None:
        cipher = VigenereCipher("SECRET")
        original = "Attack at dawn!"
        assert cipher.decrypt(cipher.encrypt(original)) == original

    def test_case_insensitive_key(self) -> None:
        c1 = VigenereCipher("key")
        c2 = VigenereCipher("KEY")
        assert c1.encrypt("Hello") == c2.encrypt("Hello")

    def test_invalid_key_raises(self) -> None:
        with pytest.raises(ValueError):
            VigenereCipher("key123")

    def test_non_alpha_preserved(self) -> None:
        cipher = VigenereCipher("A")
        assert cipher.encrypt("a, b!") == "a, b!"


class TestFrequencyAnalysis:
    """Tests for frequency_analysis."""

    def test_returns_all_letters(self) -> None:
        result = frequency_analysis("hello")
        assert len(result) == 26

    def test_empty_string(self) -> None:
        result = frequency_analysis("")
        assert all(v == 0.0 for v in result.values())

    def test_known_frequency(self) -> None:
        result = frequency_analysis("AAAB")
        assert result["A"] == pytest.approx(75.0)
        assert result["B"] == pytest.approx(25.0)

    def test_non_alpha_ignored(self) -> None:
        result = frequency_analysis("A1B2")
        assert result["A"] == pytest.approx(50.0)
        assert result["B"] == pytest.approx(50.0)


class TestCaesarCrack:
    """Tests for caesar_crack."""

    def test_crack_recovers_shift(self) -> None:
        original = "The quick brown fox jumps over the lazy dog"
        cipher = CaesarCipher(7)
        ciphertext = cipher.encrypt(original)
        results = caesar_crack(ciphertext)
        shifts = [s for s, _ in results]
        assert 7 in shifts[:3]

    def test_returns_25_candidates(self) -> None:
        results = caesar_crack("HELLO")
        assert len(results) == 25


class TestVigenereKeyLengthHint:
    """Tests for vigenere_key_length_hint."""

    def test_returns_results(self) -> None:
        hints = vigenere_key_length_hint("ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 5)
        assert len(hints) > 0

    def test_max_key_len_respected(self) -> None:
        hints = vigenere_key_length_hint("AAAA" * 10, max_key_len=3)
        assert all(length <= 3 for length, _ in hints)


class TestEntropyBits:
    """Tests for entropy_bits."""

    def test_empty_returns_zero(self) -> None:
        assert entropy_bits("") == 0.0

    def test_uniform_has_higher_entropy(self) -> None:
        high = entropy_bits("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        low = entropy_bits("AAAAAAAAAA")
        assert high > low

    def test_non_alpha_only_returns_zero(self) -> None:
        assert entropy_bits("123!@#") == 0.0
