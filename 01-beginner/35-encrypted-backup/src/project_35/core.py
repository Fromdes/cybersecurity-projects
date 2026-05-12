"""Encrypted backup: compress directory → AES-256-GCM → .encbak file."""
from __future__ import annotations

import hashlib
import io
import json
import logging
import secrets
import tarfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger(__name__)

KEY_LEN: int = 32
SALT_LEN: int = 16
NONCE_LEN: int = 12
CHUNK_SIZE: int = 65536

ARGON2_TIME_COST: int = 3
ARGON2_MEMORY_COST: int = 65536
ARGON2_PARALLELISM: int = 1

MAGIC: bytes = b"ENCBAK01"


@dataclass(frozen=True)
class BackupManifest:
    """Metadata describing a completed backup."""

    source_path: str
    created_at: str
    file_count: int
    uncompressed_size: int
    compressed_size: int
    content_hash: str


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive 32-byte AES key from *password* using Argon2id.

    Args:
        password: User-supplied passphrase.
        salt: 16-byte random salt.

    Returns:
        32-byte key bytes.
    """
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def create_backup(source: Path, output_path: Path, password: str) -> BackupManifest:
    """Create an encrypted compressed backup of *source*.

    Format: MAGIC(8) | salt(16) | nonce(12) | AESGCM(compressed_tar)

    Args:
        source: File or directory to back up.
        output_path: Destination .encbak file path.
        password: Encryption passphrase.

    Returns:
        :class:`BackupManifest` with backup metadata.

    Raises:
        FileNotFoundError: If *source* does not exist.
        ValueError: If password is empty.
    """
    if not source.exists():
        raise FileNotFoundError(f"Source not found: {source}")
    if not password:
        raise ValueError("password must not be empty")

    tar_buf = io.BytesIO()
    file_count = 0
    uncompressed_size = 0

    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tar:
        if source.is_dir():
            for file_path in sorted(source.rglob("*")):
                if file_path.is_file():
                    tar.add(file_path, arcname=str(file_path.relative_to(source.parent)))
                    uncompressed_size += file_path.stat().st_size
                    file_count += 1
        else:
            tar.add(source, arcname=source.name)
            uncompressed_size = source.stat().st_size
            file_count = 1

    compressed_data = tar_buf.getvalue()
    compressed_size = len(compressed_data)
    content_hash = hashlib.sha256(compressed_data).hexdigest()

    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, compressed_data, None)

    output_path.write_bytes(MAGIC + salt + nonce + ciphertext)
    output_path.chmod(0o600)

    manifest = BackupManifest(
        source_path=str(source),
        created_at=datetime.now(tz=UTC).isoformat(),
        file_count=file_count,
        uncompressed_size=uncompressed_size,
        compressed_size=compressed_size,
        content_hash=content_hash,
    )
    _write_manifest(output_path, manifest)
    log.info("Backup created: %s (%d files)", output_path, file_count)
    return manifest


def restore_backup(backup_path: Path, output_dir: Path, password: str) -> int:
    """Decrypt and restore files from *backup_path* into *output_dir*.

    Args:
        backup_path: .encbak file created by :func:`create_backup`.
        output_dir: Directory to extract files into.
        password: Decryption passphrase.

    Returns:
        Number of files restored.

    Raises:
        FileNotFoundError: If backup file not found.
        ValueError: If magic bytes don't match (wrong file type).
        cryptography.exceptions.InvalidTag: If password wrong or file tampered.
    """
    raw = backup_path.read_bytes()
    if raw[:8] != MAGIC:
        raise ValueError(f"Not a valid .encbak file: {backup_path}")

    salt = raw[8:24]
    nonce = raw[24:36]
    ciphertext = raw[36:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    output_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:gz") as tar:
        tar.extractall(output_dir)  # noqa: S202
        members = tar.getmembers()
        file_count = sum(1 for m in members if m.isfile())

    log.info("Restored %d files to %s", file_count, output_dir)
    return file_count


def verify_backup(backup_path: Path, password: str) -> bool:
    """Verify backup integrity by decrypting and checking content hash.

    Args:
        backup_path: .encbak file to verify.
        password: Passphrase used to create the backup.

    Returns:
        True if backup is intact, False if hash mismatch.
    """
    raw = backup_path.read_bytes()
    if raw[:8] != MAGIC:
        return False

    salt = raw[8:24]
    nonce = raw[24:36]
    ciphertext = raw[36:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    manifest_path = _manifest_path(backup_path)
    if not manifest_path.exists():
        return True

    manifest = _read_manifest(manifest_path)
    current_hash = hashlib.sha256(plaintext).hexdigest()
    return current_hash == manifest.content_hash


def _manifest_path(backup_path: Path) -> Path:
    return backup_path.with_suffix(".manifest.json")


def _write_manifest(backup_path: Path, manifest: BackupManifest) -> None:
    mp = _manifest_path(backup_path)
    mp.write_text(json.dumps({
        "source_path": manifest.source_path,
        "created_at": manifest.created_at,
        "file_count": manifest.file_count,
        "uncompressed_size": manifest.uncompressed_size,
        "compressed_size": manifest.compressed_size,
        "content_hash": manifest.content_hash,
    }, indent=2), encoding="utf-8")


def _read_manifest(manifest_path: Path) -> BackupManifest:
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    return BackupManifest(**data)
