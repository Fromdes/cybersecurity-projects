"""File Quarantine Service — safely isolate suspicious files with hash tracking and audit trail."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

QUARANTINE_MANIFEST: Final[str] = "manifest.json"
QUARANTINE_PERMISSIONS: Final[int] = 0o600    # owner read/write only for quarantined files
DIR_PERMISSIONS: Final[int] = 0o700           # quarantine dir: owner only
HASH_ALGORITHM: Final[str] = "sha256"
CHUNK_SIZE: Final[int] = 65536


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class QuarantineEntry:
    """Metadata for a file held in quarantine."""

    original_path: str
    quarantine_name: str     # filename inside quarantine dir (uuid-based)
    sha256: str
    size_bytes: int
    quarantined_at: float    # Unix timestamp
    reason: str
    released: bool = False
    released_at: float | None = None
    release_path: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialise to a JSON-compatible dict."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "QuarantineEntry":
        """Deserialise from a JSON-compatible dict."""
        return cls(**data)  # type: ignore[arg-type]


@dataclass
class QuarantineResult:
    """Result of a quarantine operation."""

    success: bool
    entry: QuarantineEntry | None = None
    error: str = ""


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def hash_file(path: Path) -> str:
    """Compute SHA-256 hash of a file.

    Args:
        path: Path to the file.

    Returns:
        Hex-encoded SHA-256 digest.

    Raises:
        OSError: If the file cannot be read.
    """
    h = hashlib.new(HASH_ALGORITHM)
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Quarantine store
# ---------------------------------------------------------------------------

class QuarantineStore:
    """Manages a directory of quarantined files with a JSON manifest.

    Args:
        quarantine_dir: Directory where quarantined files are stored.
    """

    def __init__(self, quarantine_dir: Path | str) -> None:
        self._dir = Path(quarantine_dir)
        self._manifest_path = self._dir / QUARANTINE_MANIFEST
        self._entries: dict[str, QuarantineEntry] = {}
        self._ensure_dir()
        self._load_manifest()

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _ensure_dir(self) -> None:
        """Create quarantine directory with strict permissions."""
        self._dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self._dir, DIR_PERMISSIONS)

    def _load_manifest(self) -> None:
        """Load existing manifest from disk if present."""
        if self._manifest_path.exists():
            try:
                with self._manifest_path.open() as fh:
                    raw = json.load(fh)
                self._entries = {k: QuarantineEntry.from_dict(v) for k, v in raw.items()}
            except (json.JSONDecodeError, KeyError, TypeError):
                self._entries = {}

    def _save_manifest(self) -> None:
        """Persist manifest to disk."""
        data = {k: v.to_dict() for k, v in self._entries.items()}
        with self._manifest_path.open("w") as fh:
            json.dump(data, fh, indent=2)
        os.chmod(self._manifest_path, QUARANTINE_PERMISSIONS)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def quarantine(self, source: Path | str, reason: str) -> QuarantineResult:
        """Move a file into quarantine.

        Args:
            source: Path of the file to quarantine.
            reason: Human-readable reason for quarantining.

        Returns:
            QuarantineResult with success status and entry metadata.
        """
        src = Path(source).resolve()

        if not src.exists():
            return QuarantineResult(success=False, error=f"File not found: {src}")
        if not src.is_file():
            return QuarantineResult(success=False, error=f"Not a regular file: {src}")

        try:
            file_hash = hash_file(src)
        except OSError as exc:
            return QuarantineResult(success=False, error=f"Cannot hash file: {exc}")

        size = src.stat().st_size
        # Use hash as quarantine filename to deduplicate identical files
        quarantine_name = f"{file_hash[:16]}_{src.name}"
        dest = self._dir / quarantine_name

        try:
            shutil.move(str(src), str(dest))
            os.chmod(dest, QUARANTINE_PERMISSIONS)
        except OSError as exc:
            return QuarantineResult(success=False, error=f"Move failed: {exc}")

        entry = QuarantineEntry(
            original_path=str(src),
            quarantine_name=quarantine_name,
            sha256=file_hash,
            size_bytes=size,
            quarantined_at=time.time(),
            reason=reason,
        )
        self._entries[file_hash] = entry
        self._save_manifest()

        return QuarantineResult(success=True, entry=entry)

    def release(self, file_hash: str, release_to: Path | str) -> QuarantineResult:
        """Release a quarantined file to a specified path.

        Args:
            file_hash: SHA-256 hash of the quarantined file.
            release_to: Destination path for the released file.

        Returns:
            QuarantineResult with success status.
        """
        entry = self._entries.get(file_hash)
        if entry is None:
            return QuarantineResult(success=False, error=f"No quarantine entry for hash {file_hash}")
        if entry.released:
            return QuarantineResult(success=False, error="File already released")

        src = self._dir / entry.quarantine_name
        dest = Path(release_to).resolve()

        if not src.exists():
            return QuarantineResult(success=False, error="Quarantined file missing from store")

        # Verify hash before releasing
        actual_hash = hash_file(src)
        if actual_hash != file_hash:
            return QuarantineResult(success=False, error="Hash mismatch — file may be tampered")

        try:
            shutil.move(str(src), str(dest))
        except OSError as exc:
            return QuarantineResult(success=False, error=f"Release failed: {exc}")

        entry.released = True
        entry.released_at = time.time()
        entry.release_path = str(dest)
        self._save_manifest()

        return QuarantineResult(success=True, entry=entry)

    def delete(self, file_hash: str) -> QuarantineResult:
        """Permanently delete a quarantined file.

        Args:
            file_hash: SHA-256 hash of the quarantined file.

        Returns:
            QuarantineResult with success status.
        """
        entry = self._entries.get(file_hash)
        if entry is None:
            return QuarantineResult(success=False, error=f"No entry for hash {file_hash}")

        src = self._dir / entry.quarantine_name
        if src.exists():
            try:
                # Overwrite with zeros before deleting (basic wipe)
                size = src.stat().st_size
                with src.open("r+b") as fh:
                    fh.write(b"\x00" * size)
                src.unlink()
            except OSError as exc:
                return QuarantineResult(success=False, error=f"Delete failed: {exc}")

        del self._entries[file_hash]
        self._save_manifest()
        return QuarantineResult(success=True)

    def list_entries(self, *, include_released: bool = False) -> list[QuarantineEntry]:
        """Return a list of quarantine entries.

        Args:
            include_released: If True, include already-released entries.

        Returns:
            List of QuarantineEntry objects.
        """
        return [
            e for e in self._entries.values()
            if include_released or not e.released
        ]

    def get_entry(self, file_hash: str) -> QuarantineEntry | None:
        """Return the entry for a given hash, or None."""
        return self._entries.get(file_hash)

    def verify_integrity(self) -> list[str]:
        """Check that all quarantined files still match their recorded hashes.

        Returns:
            List of error strings (empty = all OK).
        """
        errors: list[str] = []
        for file_hash, entry in self._entries.items():
            if entry.released:
                continue
            path = self._dir / entry.quarantine_name
            if not path.exists():
                errors.append(f"MISSING: {entry.quarantine_name} (hash={file_hash[:12]}…)")
                continue
            actual = hash_file(path)
            if actual != file_hash:
                errors.append(
                    f"TAMPERED: {entry.quarantine_name} expected={file_hash[:12]}… got={actual[:12]}…"
                )
        return errors
