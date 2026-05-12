"""Core validation and storage logic for secure file uploads."""

from __future__ import annotations

import hashlib
import logging
import mimetypes
import os
import re
import secrets
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_FILENAME_LENGTH: Final[int] = 200
SAFE_FILENAME_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_\-\.]+$")

# Magic bytes for common file types  {mime: bytes_prefix}
MAGIC_SIGNATURES: Final[dict[str, bytes]] = {
    "image/jpeg": b"\xff\xd8\xff",
    "image/png": b"\x89PNG\r\n\x1a\n",
    "image/gif": b"GIF8",
    "image/webp": b"RIFF",
    "application/pdf": b"%PDF",
    "application/zip": b"PK\x03\x04",
    "text/plain": b"",  # no magic, trust extension only
}

DEFAULT_ALLOWED_TYPES: Final[frozenset[str]] = frozenset({
    "image/jpeg", "image/png", "image/gif", "image/webp",
    "application/pdf", "text/plain",
})

DEFAULT_MAX_BYTES: Final[int] = 10 * 1024 * 1024  # 10 MiB


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class UploadError(Exception):
    """Base upload validation error."""


class FileTooLargeError(UploadError):
    """File exceeds the configured size limit."""


class DisallowedMimeTypeError(UploadError):
    """MIME type is not in the allowlist."""


class MagicMismatchError(UploadError):
    """File magic bytes don't match declared extension/MIME type."""


class UnsafeFilenameError(UploadError):
    """Filename contains path traversal or disallowed characters."""


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class UploadResult:
    """Metadata returned after a successful upload."""

    stored_name: str
    original_name: str
    mime_type: str
    size_bytes: int
    sha256: str
    storage_path: str


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

@dataclass
class UploadValidator:
    """Stateless file upload validator."""

    allowed_types: frozenset[str] = field(default_factory=lambda: DEFAULT_ALLOWED_TYPES)
    max_bytes: int = DEFAULT_MAX_BYTES

    def validate_filename(self, filename: str) -> str:
        """Return a sanitised base filename or raise UnsafeFilenameError."""
        base = Path(filename).name  # strip any directory components
        if not base or base in {".", ".."}:
            raise UnsafeFilenameError(f"Invalid filename: {filename!r}")
        if len(base) > MAX_FILENAME_LENGTH:
            raise UnsafeFilenameError(
                f"Filename too long: {len(base)} > {MAX_FILENAME_LENGTH}"
            )
        if not SAFE_FILENAME_RE.match(base):
            raise UnsafeFilenameError(
                f"Filename contains unsafe characters: {base!r}"
            )
        return base

    def validate_size(self, data: bytes) -> None:
        """Raise FileTooLargeError if data exceeds max_bytes."""
        if len(data) > self.max_bytes:
            raise FileTooLargeError(
                f"File size {len(data)} exceeds limit {self.max_bytes}"
            )

    def validate_mime(self, filename: str, data: bytes) -> str:
        """Validate MIME type against allowlist and magic bytes. Returns detected MIME."""
        # Guess from extension
        guessed, _ = mimetypes.guess_type(filename)
        mime = guessed or "application/octet-stream"

        if mime not in self.allowed_types:
            raise DisallowedMimeTypeError(
                f"MIME type {mime!r} is not allowed. Allowed: {sorted(self.allowed_types)}"
            )

        # Verify magic bytes
        expected_magic = MAGIC_SIGNATURES.get(mime)
        if expected_magic and not data.startswith(expected_magic):
            raise MagicMismatchError(
                f"File content does not match declared type {mime!r}"
            )

        return mime

    def validate(self, filename: str, data: bytes) -> str:
        """Run all validations. Returns detected MIME type."""
        self.validate_filename(filename)
        self.validate_size(data)
        return self.validate_mime(filename, data)


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

@dataclass
class UploadStorage:
    """Stores validated file uploads under a configurable root directory."""

    storage_root: Path
    validator: UploadValidator = field(default_factory=UploadValidator)

    def __post_init__(self) -> None:
        self.storage_root.mkdir(parents=True, exist_ok=True)

    def store(self, filename: str, data: bytes) -> UploadResult:
        """Validate and store *data* safely. Returns UploadResult."""
        safe_name = self.validator.validate_filename(filename)
        mime = self.validator.validate(filename, data)

        # Generate an unpredictable stored filename
        stored_name = f"{secrets.token_hex(16)}_{safe_name}"
        dest = self.storage_root / stored_name

        # Confirm no path traversal after resolution
        resolved = dest.resolve()
        if not str(resolved).startswith(str(self.storage_root.resolve())):
            raise UnsafeFilenameError("Path traversal detected in storage path")

        dest.write_bytes(data)
        # Restrict permissions: owner read/write only
        os.chmod(dest, stat.S_IRUSR | stat.S_IWUSR)

        sha256 = hashlib.sha256(data).hexdigest()
        logger.info(
            "Stored upload: %s → %s (%s, %d bytes, sha256=%s)",
            safe_name, stored_name, mime, len(data), sha256[:16],
        )
        return UploadResult(
            stored_name=stored_name,
            original_name=safe_name,
            mime_type=mime,
            size_bytes=len(data),
            sha256=sha256,
            storage_path=str(resolved),
        )

    def delete(self, stored_name: str) -> bool:
        """Delete a previously stored file. Returns True if deleted."""
        target = (self.storage_root / stored_name).resolve()
        if not str(target).startswith(str(self.storage_root.resolve())):
            raise UnsafeFilenameError("Path traversal in delete request")
        if target.exists():
            target.unlink()
            return True
        return False
