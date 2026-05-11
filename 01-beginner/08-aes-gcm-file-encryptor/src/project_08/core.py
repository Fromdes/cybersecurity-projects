"""AES-256-GCM encryption with Scrypt key derivation."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# File format: MAGIC(4) + SALT(32) + NONCE(12) + CIPHERTEXT+TAG
MAGIC: bytes = b"AES1"
MAGIC_LEN: int = len(MAGIC)
SALT_LEN: int = 32
NONCE_LEN: int = 12
KEY_LEN: int = 32   # AES-256
TAG_LEN: int = 16   # GCM authentication tag (appended by AESGCM)

# Scrypt parameters (OWASP 2023 interactive login recommendation)
_SCRYPT_N: int = 2**17   # CPU/memory cost factor
_SCRYPT_R: int = 8       # block size
_SCRYPT_P: int = 1       # parallelism

ENCRYPTED_EXTENSION: str = ".enc"
_CHUNK_SIZE: int = 64 * 1024  # 64 KiB read buffer


class DecryptionError(Exception):
    """Raised when decryption fails — wrong password or corrupted file."""


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from *password* using Scrypt.

    Args:
        password: User-supplied passphrase.
        salt: 32-byte random salt.

    Returns:
        32-byte derived key.
    """
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(src: Path, dst: Path, password: str) -> None:
    """Encrypt *src* with AES-256-GCM and write to *dst*.

    File format::

        MAGIC(4) | SALT(32) | NONCE(12) | ciphertext+tag

    Args:
        src: Plaintext source file.
        dst: Encrypted output file (will be overwritten if it exists).
        password: Passphrase for key derivation.

    Raises:
        FileNotFoundError: If *src* does not exist.
        IsADirectoryError: If *src* is a directory.
    """
    if not src.exists():
        raise FileNotFoundError(f"Source file not found: {src}")
    if src.is_dir():
        raise IsADirectoryError(f"Source must be a file, not a directory: {src}")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    plaintext = src.read_bytes()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    dst.write_bytes(MAGIC + salt + nonce + ciphertext)


def decrypt_file(src: Path, dst: Path, password: str) -> None:
    """Decrypt *src* (AES-256-GCM) and write plaintext to *dst*.

    Args:
        src: Encrypted source file (must have the correct MAGIC header).
        dst: Plaintext output file (will be overwritten if it exists).
        password: Passphrase used during encryption.

    Raises:
        FileNotFoundError: If *src* does not exist.
        ValueError: If *src* is not a valid encrypted file or is truncated.
        DecryptionError: If decryption fails (wrong password or tampered data).
    """
    if not src.exists():
        raise FileNotFoundError(f"Encrypted file not found: {src}")

    raw = src.read_bytes()
    _validate_header(raw, src)

    offset = MAGIC_LEN
    salt = raw[offset: offset + SALT_LEN]
    offset += SALT_LEN
    nonce = raw[offset: offset + NONCE_LEN]
    offset += NONCE_LEN
    ciphertext = raw[offset:]

    if len(ciphertext) < TAG_LEN:
        raise ValueError(f"File too short to contain GCM tag: {src}")

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise DecryptionError(
            "Decryption failed: wrong password or file has been tampered with."
        ) from exc

    dst.write_bytes(plaintext)


def _validate_header(data: bytes, path: Path) -> None:
    """Raise ValueError if *data* does not start with the expected MAGIC."""
    min_size = MAGIC_LEN + SALT_LEN + NONCE_LEN + TAG_LEN
    if len(data) < min_size:
        raise ValueError(f"File too small to be a valid encrypted file: {path}")
    if data[:MAGIC_LEN] != MAGIC:
        raise ValueError(
            f"Not a valid encrypted file (bad magic bytes): {path}. "
            "Was it encrypted with this tool?"
        )
