"""Cryptographically secure token generation utilities."""
from __future__ import annotations

import base64
import math
import secrets
import uuid
from dataclasses import dataclass
from enum import Enum

DEFAULT_BYTE_LENGTH: int = 32
MIN_BYTE_LENGTH: int = 16
MAX_BYTE_LENGTH: int = 512

CHARSET_HEX_SIZE: int = 16
CHARSET_ALPHANUM_SIZE: int = 62
CHARSET_ALPHANUM: str = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)
UUID4_ENTROPY_BITS: float = 122.0
UUID4_BYTE_LENGTH: int = 16


class TokenFormat(str, Enum):
    """Output format for generated tokens."""

    HEX = "hex"
    BASE64URL = "base64url"
    ALPHANUM = "alphanum"
    UUID4 = "uuid4"


@dataclass(frozen=True)
class TokenResult:
    """Result of a token generation operation."""

    token: str
    format: TokenFormat
    entropy_bits: float
    byte_length: int


def generate_token(
    fmt: TokenFormat = TokenFormat.HEX,
    byte_length: int = DEFAULT_BYTE_LENGTH,
) -> TokenResult:
    """Generate a cryptographically secure token.

    Args:
        fmt: Output encoding format.
        byte_length: Number of random bytes (ignored for UUID4).

    Returns:
        TokenResult with the token and entropy metadata.

    Raises:
        ValueError: If byte_length is outside the allowed range.
    """
    if fmt is not TokenFormat.UUID4:
        _validate_byte_length(byte_length)
    if fmt is TokenFormat.HEX:
        return _gen_hex(byte_length)
    if fmt is TokenFormat.BASE64URL:
        return _gen_base64url(byte_length)
    if fmt is TokenFormat.ALPHANUM:
        return _gen_alphanum(byte_length)
    return _gen_uuid4()


def estimate_entropy(token_length: int, charset_size: int) -> float:
    """Estimate entropy in bits for a token of given length and charset.

    Args:
        token_length: Number of characters in the token.
        charset_size: Number of distinct characters in the alphabet.

    Returns:
        Entropy in bits.

    Raises:
        ValueError: If either argument is not positive.
    """
    if token_length <= 0 or charset_size <= 1:
        raise ValueError("token_length must be > 0 and charset_size must be > 1")
    return token_length * math.log2(charset_size)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _validate_byte_length(n: int) -> None:
    if not (MIN_BYTE_LENGTH <= n <= MAX_BYTE_LENGTH):
        raise ValueError(
            f"byte_length must be between {MIN_BYTE_LENGTH} and {MAX_BYTE_LENGTH}"
        )


def _gen_hex(byte_length: int) -> TokenResult:
    raw = secrets.token_bytes(byte_length)
    token = raw.hex()
    entropy = estimate_entropy(len(token), CHARSET_HEX_SIZE)
    return TokenResult(
        token=token,
        format=TokenFormat.HEX,
        entropy_bits=entropy,
        byte_length=byte_length,
    )


def _gen_base64url(byte_length: int) -> TokenResult:
    raw = secrets.token_bytes(byte_length)
    token = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return TokenResult(
        token=token,
        format=TokenFormat.BASE64URL,
        entropy_bits=float(byte_length * 8),
        byte_length=byte_length,
    )


def _gen_alphanum(byte_length: int) -> TokenResult:
    token = "".join(secrets.choice(CHARSET_ALPHANUM) for _ in range(byte_length))
    entropy = estimate_entropy(byte_length, CHARSET_ALPHANUM_SIZE)
    return TokenResult(
        token=token,
        format=TokenFormat.ALPHANUM,
        entropy_bits=entropy,
        byte_length=byte_length,
    )


def _gen_uuid4() -> TokenResult:
    return TokenResult(
        token=str(uuid.uuid4()),
        format=TokenFormat.UUID4,
        entropy_bits=UUID4_ENTROPY_BITS,
        byte_length=UUID4_BYTE_LENGTH,
    )
