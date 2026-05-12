"""Encode, decode, and detect common data encoding schemes."""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import urllib.parse
from dataclasses import dataclass
from enum import StrEnum


class Encoding(StrEnum):
    """Supported encoding schemes."""

    BASE64 = "base64"
    BASE64URL = "base64url"
    BASE32 = "base32"
    HEX = "hex"
    URL = "url"
    HTML = "html"
    ROT13 = "rot13"


@dataclass(frozen=True)
class CodecResult:
    """Result of an encode or decode operation."""

    output: str
    encoding: Encoding
    operation: str  # "encode" or "decode"


_HEX_RE: re.Pattern[str] = re.compile(r"^[0-9a-fA-F]+$")
_BASE64_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9+/]+=*$")
_BASE64URL_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9\-_]+=*$")
_BASE32_RE: re.Pattern[str] = re.compile(r"^[A-Z2-7]+=*$")

# Valid unpadded-length mod-8 remainders for Base32
_BASE32_VALID_MOD: frozenset[int] = frozenset({0, 2, 4, 5, 7})


def encode(data: str, encoding: Encoding) -> CodecResult:
    """Encode *data* using the specified encoding scheme.

    Args:
        data: UTF-8 plaintext to encode.
        encoding: Target encoding scheme.

    Returns:
        CodecResult with the encoded string.

    Raises:
        ValueError: If data is empty.
    """
    if not data:
        raise ValueError("Input data must not be empty")
    raw = data.encode("utf-8")
    output = _dispatch_encode(data, raw, encoding)
    return CodecResult(output=output, encoding=encoding, operation="encode")


def decode(data: str, encoding: Encoding) -> CodecResult:
    """Decode *data* from the specified encoding back to UTF-8.

    Args:
        data: Encoded string to decode.
        encoding: Source encoding scheme.

    Returns:
        CodecResult with the decoded string.

    Raises:
        ValueError: If data is empty or decoding fails.
    """
    if not data:
        raise ValueError("Input data must not be empty")
    output = _dispatch_decode(data, encoding)
    return CodecResult(output=output, encoding=encoding, operation="decode")


def detect_encodings(data: str) -> list[Encoding]:
    """Return encodings that *data* structurally matches.

    Args:
        data: String to analyse.

    Returns:
        List of candidate Encoding values (may be empty).
    """
    candidates: list[Encoding] = []
    _check_hex(data, candidates)
    _check_base32(data, candidates)
    _check_base64(data, candidates)
    _check_url(data, candidates)
    return candidates


# ---------------------------------------------------------------------------
# Internal dispatch helpers
# ---------------------------------------------------------------------------


def _dispatch_encode(data: str, raw: bytes, enc: Encoding) -> str:
    match enc:
        case Encoding.BASE64:
            return base64.b64encode(raw).decode("ascii")
        case Encoding.BASE64URL:
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        case Encoding.BASE32:
            return base64.b32encode(raw).decode("ascii")
        case Encoding.HEX:
            return raw.hex()
        case Encoding.URL:
            return urllib.parse.quote(data, safe="")
        case Encoding.HTML:
            return html.escape(data, quote=True)
        case Encoding.ROT13:
            return codecs.encode(data, "rot_13")
        case _:
            raise ValueError(f"Unsupported encoding: {enc}")


def _dispatch_decode(data: str, enc: Encoding) -> str:
    try:
        return _decode_inner(data, enc)
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"Decode failed for {enc.value!r}: {exc}") from exc


def _decode_inner(data: str, enc: Encoding) -> str:
    match enc:
        case Encoding.BASE64:
            return base64.b64decode(_pad(data, 4)).decode("utf-8")
        case Encoding.BASE64URL:
            return base64.urlsafe_b64decode(_pad(data, 4)).decode("utf-8")
        case Encoding.BASE32:
            return base64.b32decode(_pad(data, 8)).decode("utf-8")
        case Encoding.HEX:
            return bytes.fromhex(data).decode("utf-8")
        case Encoding.URL:
            return urllib.parse.unquote(data)
        case Encoding.HTML:
            return html.unescape(data)
        case Encoding.ROT13:
            return codecs.encode(data, "rot_13")
        case _:
            raise ValueError(f"Unsupported encoding: {enc}")


def _pad(data: str, block: int) -> str:
    remainder = len(data) % block
    return data + "=" * (block - remainder) if remainder else data


def _check_hex(data: str, out: list[Encoding]) -> None:
    if len(data) % 2 == 0 and _HEX_RE.match(data):
        out.append(Encoding.HEX)


def _check_base32(data: str, out: list[Encoding]) -> None:
    stripped = data.rstrip("=").upper()
    if _BASE32_RE.match(stripped) and len(stripped) % 8 in _BASE32_VALID_MOD:
        out.append(Encoding.BASE32)


def _check_base64(data: str, out: list[Encoding]) -> None:
    if _BASE64_RE.match(data):
        out.append(Encoding.BASE64)
    if _BASE64URL_RE.match(data):
        out.append(Encoding.BASE64URL)


def _check_url(data: str, out: list[Encoding]) -> None:
    if "%" in data:
        out.append(Encoding.URL)
