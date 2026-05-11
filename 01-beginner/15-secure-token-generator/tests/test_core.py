"""Tests for project_15.core — Secure Token Generator."""
from __future__ import annotations

import re
import uuid

import pytest

from project_15.core import (
    DEFAULT_BYTE_LENGTH,
    MAX_BYTE_LENGTH,
    MIN_BYTE_LENGTH,
    TokenFormat,
    TokenResult,
    estimate_entropy,
    generate_token,
)

_HEX_RE = re.compile(r"^[0-9a-f]+$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9\-_]+$")
_ALPHANUM_RE = re.compile(r"^[A-Za-z0-9]+$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


class TestGenerateTokenHex:
    def test_returns_token_result(self) -> None:
        result = generate_token(fmt=TokenFormat.HEX)
        assert isinstance(result, TokenResult)

    def test_hex_format(self) -> None:
        result = generate_token(fmt=TokenFormat.HEX)
        assert _HEX_RE.match(result.token)

    def test_default_byte_length(self) -> None:
        result = generate_token(fmt=TokenFormat.HEX)
        assert result.byte_length == DEFAULT_BYTE_LENGTH
        assert len(result.token) == DEFAULT_BYTE_LENGTH * 2

    def test_custom_byte_length(self) -> None:
        result = generate_token(fmt=TokenFormat.HEX, byte_length=16)
        assert len(result.token) == 32

    def test_entropy_positive(self) -> None:
        result = generate_token(fmt=TokenFormat.HEX)
        assert result.entropy_bits > 0


class TestGenerateTokenBase64URL:
    def test_url_safe_chars(self) -> None:
        result = generate_token(fmt=TokenFormat.BASE64URL)
        assert _B64URL_RE.match(result.token)
        assert "=" not in result.token

    def test_entropy_equals_byte_bits(self) -> None:
        result = generate_token(fmt=TokenFormat.BASE64URL, byte_length=32)
        assert result.entropy_bits == 256.0


class TestGenerateTokenAlphanum:
    def test_alphanum_chars(self) -> None:
        result = generate_token(fmt=TokenFormat.ALPHANUM)
        assert _ALPHANUM_RE.match(result.token)

    def test_length_equals_byte_length(self) -> None:
        result = generate_token(fmt=TokenFormat.ALPHANUM, byte_length=24)
        assert len(result.token) == 24


class TestGenerateTokenUUID4:
    def test_valid_uuid4(self) -> None:
        result = generate_token(fmt=TokenFormat.UUID4)
        assert _UUID_RE.match(result.token)

    def test_entropy_is_122_bits(self) -> None:
        result = generate_token(fmt=TokenFormat.UUID4)
        assert result.entropy_bits == 122.0

    def test_ignores_byte_length(self) -> None:
        result = generate_token(fmt=TokenFormat.UUID4, byte_length=MIN_BYTE_LENGTH)
        # UUID4 is always valid regardless of byte_length
        assert _UUID_RE.match(result.token)


class TestValidation:
    def test_too_small_raises(self) -> None:
        with pytest.raises(ValueError, match="byte_length"):
            generate_token(fmt=TokenFormat.HEX, byte_length=MIN_BYTE_LENGTH - 1)

    def test_too_large_raises(self) -> None:
        with pytest.raises(ValueError, match="byte_length"):
            generate_token(fmt=TokenFormat.HEX, byte_length=MAX_BYTE_LENGTH + 1)


class TestEstimateEntropy:
    def test_hex_64_chars(self) -> None:
        bits = estimate_entropy(64, 16)
        assert abs(bits - 256.0) < 0.001

    def test_alphanum_32_chars(self) -> None:
        bits = estimate_entropy(32, 62)
        assert bits > 180

    def test_zero_length_raises(self) -> None:
        with pytest.raises(ValueError):
            estimate_entropy(0, 16)

    def test_charset_one_raises(self) -> None:
        with pytest.raises(ValueError):
            estimate_entropy(10, 1)
