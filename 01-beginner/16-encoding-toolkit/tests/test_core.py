"""Tests for project_16.core — Encoding Toolkit."""
from __future__ import annotations

import pytest

from project_16.core import (
    CodecResult,
    Encoding,
    decode,
    detect_encodings,
    encode,
)

PLAIN_TEXT: str = "Hello, World!"
PLAIN_UTF8_EXTRA: str = "café"


class TestEncode:
    def test_base64_returns_codec_result(self) -> None:
        result = encode(PLAIN_TEXT, Encoding.BASE64)
        assert isinstance(result, CodecResult)
        assert result.operation == "encode"

    def test_base64_value(self) -> None:
        result = encode("Hello", Encoding.BASE64)
        assert result.output == "SGVsbG8="

    def test_base64url_no_padding(self) -> None:
        result = encode(PLAIN_TEXT, Encoding.BASE64URL)
        assert "=" not in result.output

    def test_hex_lowercase(self) -> None:
        result = encode("AB", Encoding.HEX)
        assert result.output == "4142"

    def test_url_encoding(self) -> None:
        result = encode("hello world", Encoding.URL)
        assert result.output == "hello%20world"

    def test_html_escaping(self) -> None:
        result = encode("<script>", Encoding.HTML)
        assert "&lt;" in result.output and "&gt;" in result.output

    def test_rot13(self) -> None:
        result = encode("Hello", Encoding.ROT13)
        assert result.output == "Uryyb"

    def test_base32(self) -> None:
        result = encode("Hi", Encoding.BASE32)
        assert result.output.isalnum() or "=" in result.output

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            encode("", Encoding.BASE64)


class TestDecode:
    def test_base64_roundtrip(self) -> None:
        encoded = encode(PLAIN_TEXT, Encoding.BASE64).output
        result = decode(encoded, Encoding.BASE64)
        assert result.output == PLAIN_TEXT

    def test_base64url_roundtrip(self) -> None:
        encoded = encode(PLAIN_TEXT, Encoding.BASE64URL).output
        result = decode(encoded, Encoding.BASE64URL)
        assert result.output == PLAIN_TEXT

    def test_hex_roundtrip(self) -> None:
        encoded = encode(PLAIN_TEXT, Encoding.HEX).output
        result = decode(encoded, Encoding.HEX)
        assert result.output == PLAIN_TEXT

    def test_url_roundtrip(self) -> None:
        encoded = encode("hello world", Encoding.URL).output
        result = decode(encoded, Encoding.URL)
        assert result.output == "hello world"

    def test_html_roundtrip(self) -> None:
        encoded = encode("<b>ok</b>", Encoding.HTML).output
        result = decode(encoded, Encoding.HTML)
        assert result.output == "<b>ok</b>"

    def test_rot13_double(self) -> None:
        once = encode("Hello", Encoding.ROT13).output
        twice = decode(once, Encoding.ROT13).output
        assert twice == "Hello"

    def test_invalid_hex_raises(self) -> None:
        with pytest.raises(ValueError, match="Decode failed"):
            decode("ZZZZ", Encoding.HEX)

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            decode("", Encoding.BASE64)


class TestDetectEncodings:
    def test_detects_hex(self) -> None:
        candidates = detect_encodings("deadbeef")
        assert Encoding.HEX in candidates

    def test_detects_base64(self) -> None:
        candidates = detect_encodings("SGVsbG8=")
        assert Encoding.BASE64 in candidates

    def test_detects_url(self) -> None:
        candidates = detect_encodings("hello%20world")
        assert Encoding.URL in candidates

    def test_no_match(self) -> None:
        candidates = detect_encodings("plain text no encoding here!!")
        assert Encoding.HEX not in candidates
