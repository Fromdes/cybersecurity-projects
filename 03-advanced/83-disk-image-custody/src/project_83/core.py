"""Disk Image Hash & Chain-of-Custody — forensic hashing and custody record management."""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CHUNK_SIZE = 1024 * 1024  # 1 MB
SUPPORTED_ALGORITHMS: tuple[str, ...] = ("md5", "sha1", "sha256", "sha512")
CUSTODY_FILE_VERSION = 1


# ── Hash result ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class HashResult:
    """Result of hashing a single file."""

    file_path: str
    file_size: int
    md5: str
    sha1: str
    sha256: str
    sha512: str
    computed_at: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "sha512": self.sha512,
            "computed_at": self.computed_at,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "HashResult":
        """Deserialize from dict."""
        return HashResult(
            file_path=d["file_path"],
            file_size=d["file_size"],
            md5=d["md5"],
            sha1=d["sha1"],
            sha256=d["sha256"],
            sha512=d["sha512"],
            computed_at=d["computed_at"],
        )


# ── Custody entry ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CustodyEntry:
    """A single chain-of-custody event."""

    action: str
    actor: str
    timestamp: str
    location: str
    notes: str
    hash_at_time: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "action": self.action,
            "actor": self.actor,
            "timestamp": self.timestamp,
            "location": self.location,
            "notes": self.notes,
            "hash_at_time": self.hash_at_time,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "CustodyEntry":
        """Deserialize from dict."""
        return CustodyEntry(
            action=d["action"],
            actor=d["actor"],
            timestamp=d["timestamp"],
            location=d["location"],
            notes=d.get("notes", ""),
            hash_at_time=d.get("hash_at_time", ""),
        )


# ── Chain of custody record ────────────────────────────────────────────────────

@dataclass
class CustodyRecord:
    """Full chain-of-custody record for a disk image."""

    version: int
    hash_result: HashResult
    chain: list[CustodyEntry] = field(default_factory=list)

    def add_entry(self, action: str, notes: str = "", current_sha256: str = "") -> CustodyEntry:
        """Add a new custody event. Captures actor and location automatically."""
        entry = CustodyEntry(
            action=action,
            actor=_get_actor(),
            timestamp=datetime.now(timezone.utc).isoformat(),
            location=socket.gethostname(),
            notes=notes,
            hash_at_time=current_sha256,
        )
        self.chain.append(entry)
        return entry

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "version": self.version,
            "hash_result": self.hash_result.to_dict(),
            "chain": [e.to_dict() for e in self.chain],
        }

    def save(self, output: Path) -> None:
        """Save custody record to JSON file."""
        output.write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: Path) -> "CustodyRecord":
        """Load custody record from JSON file."""
        data = json.loads(path.read_text())
        return cls(
            version=data.get("version", 1),
            hash_result=HashResult.from_dict(data["hash_result"]),
            chain=[CustodyEntry.from_dict(e) for e in data.get("chain", [])],
        )


def _get_actor() -> str:
    """Return current user@hostname."""
    try:
        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USER", "unknown")
    return f"{user}@{socket.gethostname()}"


# ── Hasher ─────────────────────────────────────────────────────────────────────

def hash_image(file_path: Path, progress_callback: Any = None) -> HashResult:
    """Compute MD5, SHA1, SHA256, SHA512 of a file in a single streaming pass.

    Args:
        file_path: Path to the disk image.
        progress_callback: Optional callable(bytes_read, total) for progress.

    Returns:
        HashResult with all four digests.
    """
    md5 = hashlib.md5()  # noqa: S324
    sha1 = hashlib.sha1()  # noqa: S324
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    file_size = file_path.stat().st_size
    bytes_read = 0

    with file_path.open("rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)
            bytes_read += len(chunk)
            if progress_callback:
                progress_callback(bytes_read, file_size)

    return HashResult(
        file_path=str(file_path),
        file_size=file_size,
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        sha512=sha512.hexdigest(),
        computed_at=datetime.now(timezone.utc).isoformat(),
    )


def verify_image(file_path: Path, expected_sha256: str) -> tuple[bool, str]:
    """Recompute SHA-256 and compare to expected. Returns (matches, actual_hash)."""
    result = hash_image(file_path)
    matches = result.sha256.lower() == expected_sha256.lower()
    return matches, result.sha256


def create_custody_record(image_path: Path, notes: str = "") -> CustodyRecord:
    """Hash a disk image and create an initial chain-of-custody record."""
    hash_result = hash_image(image_path)
    record = CustodyRecord(version=CUSTODY_FILE_VERSION, hash_result=hash_result)
    record.add_entry("ACQUIRED", notes=notes or "Initial acquisition", current_sha256=hash_result.sha256)
    return record
