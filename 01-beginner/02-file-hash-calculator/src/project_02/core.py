"""Core hashing logic for the File Hash Calculator."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

# Algorithms offered (subset of hashlib.algorithms_guaranteed)
SUPPORTED_ALGORITHMS: frozenset[str] = frozenset(
    {"md5", "sha1", "sha256", "sha512", "sha3_256", "sha3_512", "blake2b"}
)

# Stream read chunk size (1 MiB)
_CHUNK_SIZE: int = 1 << 20


def hash_file(path: Path, algorithm: str) -> str:
    """Compute the hex digest of a file using *algorithm*.

    Args:
        path: Path to the file to hash.
        algorithm: Hash algorithm name (e.g. ``"sha256"``).

    Returns:
        Lowercase hex digest string.

    Raises:
        ValueError: If *algorithm* is not supported.
        FileNotFoundError: If *path* does not exist.
    """
    _validate_algorithm(algorithm)
    h = hashlib.new(algorithm)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_text(text: str, algorithm: str, *, encoding: str = "utf-8") -> str:
    """Compute the hex digest of a UTF-8 encoded string.

    Args:
        text: Input string.
        algorithm: Hash algorithm name.
        encoding: Character encoding to use when converting *text* to bytes.

    Returns:
        Lowercase hex digest string.

    Raises:
        ValueError: If *algorithm* is not supported.
    """
    _validate_algorithm(algorithm)
    h = hashlib.new(algorithm)
    h.update(text.encode(encoding))
    return h.hexdigest()


def hash_file_all(path: Path) -> dict[str, str]:
    """Hash *path* with every supported algorithm simultaneously.

    Args:
        path: Path to the file.

    Returns:
        Mapping of algorithm name → hex digest.
    """
    hashers = {alg: hashlib.new(alg) for alg in SUPPORTED_ALGORITHMS}
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK_SIZE), b""):
            for h in hashers.values():
                h.update(chunk)
    return {alg: h.hexdigest() for alg, h in sorted(hashers.items())}


def verify_hash(path: Path, algorithm: str, expected: str) -> bool:
    """Constant-time compare the hash of *path* against *expected*.

    Uses :func:`hmac.compare_digest` to prevent timing side-channels.

    Args:
        path: Path to the file.
        algorithm: Hash algorithm name.
        expected: Expected hex digest (case-insensitive).

    Returns:
        ``True`` if hashes match, ``False`` otherwise.
    """
    computed = hash_file(path, algorithm)
    return hmac.compare_digest(computed.lower(), expected.lower().strip())


def hash_file_size(path: Path) -> int:
    """Return the byte-size of *path*.

    Args:
        path: Path to the file.

    Returns:
        File size in bytes.
    """
    return path.stat().st_size


def _validate_algorithm(algorithm: str) -> None:
    """Raise ValueError if *algorithm* is not in SUPPORTED_ALGORITHMS."""
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. "
            f"Choose from: {', '.join(sorted(SUPPORTED_ALGORITHMS))}"
        )
