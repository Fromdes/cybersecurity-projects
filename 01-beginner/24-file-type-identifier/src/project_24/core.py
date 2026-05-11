"""File type identification via magic bytes with extension spoofing detection."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

READ_BYTES: int = 32

MAGIC_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b'\x89PNG\r\n\x1a\n', "image/png", ".png"),
    (b'\xff\xd8\xff', "image/jpeg", ".jpg"),
    (b'GIF89a', "image/gif", ".gif"),
    (b'GIF87a', "image/gif", ".gif"),
    (b'%PDF-', "application/pdf", ".pdf"),
    (b'PK\x03\x04', "application/zip", ".zip"),
    (b'PK\x05\x06', "application/zip", ".zip"),
    (b'\x7fELF', "application/x-elf", ".elf"),
    (b'MZ', "application/x-dosexec", ".exe"),
    (b'\x1f\x8b', "application/gzip", ".gz"),
    (b'BZh', "application/x-bzip2", ".bz2"),
    (b'\xfd7zXZ\x00', "application/x-xz", ".xz"),
    (b'Rar!\x1a\x07', "application/x-rar", ".rar"),
    (b'7z\xbc\xaf\x27\x1c', "application/x-7z-compressed", ".7z"),
    (b'ID3', "audio/mpeg", ".mp3"),
    (b'\xff\xfb', "audio/mpeg", ".mp3"),
    (b'RIFF', "audio/x-wav", ".wav"),
    (b'OggS', "audio/ogg", ".ogg"),
    (b'fLaC', "audio/flac", ".flac"),
    (b'\xcf\xfa\xed\xfe', "application/x-mach-binary", ".macho"),
    (b'\xce\xfa\xed\xfe', "application/x-mach-binary", ".macho"),
    (b'\xca\xfe\xba\xbe', "application/x-mach-binary", ".dylib"),
    (b'<!DOCTYPE', "text/html", ".html"),
    (b'<html', "text/html", ".html"),
    (b'<?xml', "text/xml", ".xml"),
)

BENIGN_MIME_GROUPS: frozenset[str] = frozenset({
    "text/plain", "text/csv", "application/json",
})

EXECUTABLE_MIMES: frozenset[str] = frozenset({
    "application/x-dosexec", "application/x-elf",
    "application/x-mach-binary", "application/x-shellscript",
})

EXT_TO_MIME: dict[str, str] = {
    ".txt": "text/plain",  ".pdf": "application/pdf",
    ".zip": "application/zip", ".exe": "application/x-dosexec",
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".png": "image/png", ".gif": "image/gif",
    ".gz": "application/gzip", ".bz2": "application/x-bzip2",
    ".mp3": "audio/mpeg", ".mp4": "video/mp4",
    ".html": "text/html", ".xml": "text/xml",
    ".rar": "application/x-rar", ".7z": "application/x-7z-compressed",
    ".elf": "application/x-elf", ".flac": "audio/flac",
}


@dataclass(frozen=True)
class FileTypeResult:
    """File type identification result."""

    path: str
    declared_extension: str
    detected_mime: str
    detected_extension: str
    is_extension_spoofed: bool
    confidence: str


def identify(path: str) -> FileTypeResult:
    """Identify the true file type of *path* by reading its magic bytes.

    Args:
        path: Absolute or relative path to the file.

    Returns:
        FileTypeResult with detected type and spoofing status.

    Raises:
        FileNotFoundError: If path does not exist.
        OSError: On read errors.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path!r}")
    magic = _read_magic(path)
    detected = _detect_from_magic(magic)
    declared_ext = Path(path).suffix.lower()
    if detected:
        detected_mime, detected_ext = detected
        confidence = "high"
    else:
        detected_mime, detected_ext = "application/octet-stream", ""
        confidence = "unknown"
    spoofed = _is_spoofed(declared_ext, detected_mime)
    return FileTypeResult(
        path=path,
        declared_extension=declared_ext,
        detected_mime=detected_mime,
        detected_extension=detected_ext,
        is_extension_spoofed=spoofed,
        confidence=confidence,
    )


def identify_bytes(data: bytes) -> tuple[str, str] | None:
    """Identify MIME type and extension from raw *data* bytes.

    Args:
        data: At least the first 32 bytes of a file.

    Returns:
        Tuple of (mime_type, extension) or None if unknown.
    """
    return _detect_from_magic(data)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _read_magic(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(READ_BYTES)


def _detect_from_magic(data: bytes) -> tuple[str, str] | None:
    for sig, mime, ext in sorted(MAGIC_SIGNATURES, key=lambda t: len(t[0]), reverse=True):
        if data.startswith(sig):
            return mime, ext
    return None


def _is_spoofed(declared_ext: str, detected_mime: str) -> bool:
    if not declared_ext or detected_mime == "application/octet-stream":
        return False
    expected_mime = EXT_TO_MIME.get(declared_ext)
    if expected_mime is None:
        return False
    return expected_mime != detected_mime
