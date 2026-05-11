"""HMAC-SHA256/512 message authentication."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path

# Supported digest algorithms
SUPPORTED_ALGORITHMS: frozenset[str] = frozenset({"sha256", "sha512"})
DEFAULT_ALGORITHM: str = "sha256"

# Minimum key length (NIST SP 800-107 recommendation: ≥ hash output length)
MIN_KEY_BYTES: int = 32


@dataclass(frozen=True)
class HMACResult:
    """The result of an HMAC computation."""

    digest: str          # hex-encoded HMAC tag
    algorithm: str       # e.g. "sha256"
    key_length: int      # byte length of the key used


def compute_hmac(
    message: bytes,
    key: bytes,
    *,
    algorithm: str = DEFAULT_ALGORITHM,
) -> HMACResult:
    """Compute HMAC over *message* using *key*.

    Args:
        message: Arbitrary bytes to authenticate.
        key: Secret key bytes.
        algorithm: Digest algorithm — ``"sha256"`` or ``"sha512"``.

    Returns:
        :class:`HMACResult` with the hex-encoded tag.

    Raises:
        ValueError: If *algorithm* is not supported or *key* is empty.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. "
            f"Choose from: {sorted(SUPPORTED_ALGORITHMS)}"
        )
    if not key:
        raise ValueError("HMAC key must not be empty")
    tag = hmac.new(key, message, algorithm).hexdigest()
    return HMACResult(digest=tag, algorithm=algorithm, key_length=len(key))


def verify_hmac(
    message: bytes,
    key: bytes,
    expected_digest: str,
    *,
    algorithm: str = DEFAULT_ALGORITHM,
) -> bool:
    """Verify that *expected_digest* matches the HMAC of *message* under *key*.

    Uses :func:`hmac.compare_digest` for constant-time comparison.

    Args:
        message: The original message bytes.
        key: Secret key bytes.
        expected_digest: Hex-encoded HMAC tag to compare against.
        algorithm: Digest algorithm.

    Returns:
        ``True`` if the digest is valid.
    """
    result = compute_hmac(message, key, algorithm=algorithm)
    return hmac.compare_digest(result.digest, expected_digest.lower())


def sign_file(path: Path, key: bytes, *, algorithm: str = DEFAULT_ALGORITHM) -> HMACResult:
    """Compute the HMAC of a file's contents.

    Args:
        path: Path to the file to sign.
        key: Secret key bytes.
        algorithm: Digest algorithm.

    Returns:
        :class:`HMACResult` with the hex-encoded tag.

    Raises:
        FileNotFoundError: If *path* does not exist.
    """
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    data = path.read_bytes()
    return compute_hmac(data, key, algorithm=algorithm)


def verify_file(
    path: Path,
    key: bytes,
    expected_digest: str,
    *,
    algorithm: str = DEFAULT_ALGORITHM,
) -> bool:
    """Verify the HMAC of a file against *expected_digest*.

    Args:
        path: Path to the file to verify.
        key: Secret key bytes.
        expected_digest: Previously computed hex-encoded HMAC tag.
        algorithm: Digest algorithm.

    Returns:
        ``True`` if the digest is valid.

    Raises:
        FileNotFoundError: If *path* does not exist.
    """
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    data = path.read_bytes()
    return verify_hmac(data, key, expected_digest, algorithm=algorithm)


def derive_key_from_passphrase(passphrase: str, *, algorithm: str = DEFAULT_ALGORITHM) -> bytes:
    """Derive a fixed-length key from *passphrase* via SHA-256/512 hash.

    Not a KDF — for production use Argon2id (see Project 14). This helper
    allows the CLI to accept human-readable keys without external dependencies.

    Args:
        passphrase: UTF-8 passphrase string.
        algorithm: Hash algorithm to determine output length.

    Returns:
        32 or 64 bytes derived from the passphrase.
    """
    h = hashlib.new(algorithm, passphrase.encode("utf-8"))
    return h.digest()
