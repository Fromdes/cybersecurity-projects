"""Password hashing with Argon2id and PBKDF2-SHA256."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from enum import Enum

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# Argon2id OWASP-recommended parameters (2023)
ARGON2_TIME_COST: int = 2
ARGON2_MEMORY_COST: int = 65536   # 64 MiB
ARGON2_PARALLELISM: int = 1

# PBKDF2 NIST SP 800-132 minimum (OWASP recommends ≥210 000 for SHA-256)
PBKDF2_ITERATIONS: int = 210_000
PBKDF2_HASH_NAME: str = "sha256"
PBKDF2_KEY_LEN: int = 32          # 256-bit derived key
PBKDF2_SALT_LEN: int = 16         # 128-bit salt


class HashAlgorithm(str, Enum):
    """Supported password hashing algorithms."""

    ARGON2ID = "argon2id"
    PBKDF2 = "pbkdf2"


@dataclass(frozen=True)
class HashResult:
    """Result of a password hash operation."""

    encoded: str          # PHC string (Argon2) or hex-encoded tag (PBKDF2)
    algorithm: HashAlgorithm


def hash_password(
    password: str,
    *,
    algorithm: HashAlgorithm = HashAlgorithm.ARGON2ID,
) -> HashResult:
    """Hash *password* using the requested algorithm.

    Args:
        password: Plaintext password (UTF-8).
        algorithm: Hashing algorithm to use.

    Returns:
        :class:`HashResult` containing the encoded hash.

    Raises:
        ValueError: If *password* is empty.
    """
    if not password:
        raise ValueError("Password must not be empty")

    if algorithm is HashAlgorithm.ARGON2ID:
        return _hash_argon2id(password)
    return _hash_pbkdf2(password)


def verify_password(password: str, encoded: str, *, algorithm: HashAlgorithm) -> bool:
    """Verify *password* against a previously computed *encoded* hash.

    Args:
        password: Plaintext password to check.
        encoded: Stored hash (PHC string for Argon2; ``salt:dk`` hex for PBKDF2).
        algorithm: Algorithm that produced *encoded*.

    Returns:
        ``True`` if the password matches.
    """
    if algorithm is HashAlgorithm.ARGON2ID:
        return _verify_argon2id(password, encoded)
    return _verify_pbkdf2(password, encoded)


def needs_rehash(encoded: str) -> bool:
    """Return ``True`` if an Argon2id hash was created with outdated parameters.

    Useful for migrating stored hashes to stronger settings on next login.

    Args:
        encoded: Argon2id PHC string.

    Returns:
        ``True`` if the hash parameters no longer match the current defaults.
    """
    ph = _make_hasher()
    return ph.check_needs_rehash(encoded)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_hasher() -> PasswordHasher:
    return PasswordHasher(
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
    )


def _hash_argon2id(password: str) -> HashResult:
    ph = _make_hasher()
    encoded = ph.hash(password)
    return HashResult(encoded=encoded, algorithm=HashAlgorithm.ARGON2ID)


def _verify_argon2id(password: str, encoded: str) -> bool:
    ph = _make_hasher()
    try:
        return ph.verify(encoded, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _hash_pbkdf2(password: str) -> HashResult:
    salt = os.urandom(PBKDF2_SALT_LEN)
    dk = hashlib.pbkdf2_hmac(
        PBKDF2_HASH_NAME,
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=PBKDF2_KEY_LEN,
    )
    encoded = f"{salt.hex()}:{dk.hex()}"
    return HashResult(encoded=encoded, algorithm=HashAlgorithm.PBKDF2)


def _verify_pbkdf2(password: str, encoded: str) -> bool:
    try:
        salt_hex, dk_hex = encoded.split(":", 1)
    except ValueError:
        return False
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(dk_hex)
    actual = hashlib.pbkdf2_hmac(
        PBKDF2_HASH_NAME,
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=PBKDF2_KEY_LEN,
    )
    import hmac as _hmac
    return _hmac.compare_digest(actual, expected)
