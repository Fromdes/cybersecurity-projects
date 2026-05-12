"""File integrity monitoring via SHA-256 baseline snapshots."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from enum import Enum

HASH_ALGORITHM: str = "sha256"
CHUNK_SIZE: int = 65_536  # 64 KiB read buffer
BASELINE_VERSION: str = "1"


class ChangeType(str, Enum):
    """Type of detected file integrity change."""

    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"


@dataclass(frozen=True)
class FileSnapshot:
    """Point-in-time snapshot of a file's identity."""

    path: str
    size: int
    mtime: float
    sha256: str


@dataclass(frozen=True)
class IntegrityChange:
    """A detected change between two snapshots."""

    path: str
    change_type: ChangeType
    old_hash: str | None
    new_hash: str | None
    old_size: int | None
    new_size: int | None


def snapshot_file(path: str) -> FileSnapshot:
    """Compute a FileSnapshot for *path*.

    Args:
        path: File path to snapshot.

    Returns:
        FileSnapshot with hash, size, and mtime.

    Raises:
        FileNotFoundError: If *path* does not exist.
        OSError: On read errors.
    """
    stat = os.stat(path)
    digest = _compute_sha256(path)
    return FileSnapshot(path=path, size=stat.st_size, mtime=stat.st_mtime, sha256=digest)


def snapshot_directory(root: str, recursive: bool = True) -> dict[str, FileSnapshot]:
    """Snapshot all files under *root*.

    Args:
        root: Directory path to walk.
        recursive: Whether to recurse into subdirectories.

    Returns:
        Dict mapping absolute path to FileSnapshot.
    """
    snapshots: dict[str, FileSnapshot] = {}
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            try:
                snapshots[fpath] = snapshot_file(fpath)
            except OSError:
                pass
        if not recursive:
            break
    return snapshots


def check_integrity(
    baseline: dict[str, FileSnapshot],
    current: dict[str, FileSnapshot],
) -> list[IntegrityChange]:
    """Compute changes between *baseline* and *current* snapshots.

    Args:
        baseline: Previously saved snapshot dict.
        current: Freshly computed snapshot dict.

    Returns:
        List of IntegrityChange objects (created, modified, deleted).
    """
    changes: list[IntegrityChange] = []
    for path, snap in current.items():
        if path not in baseline:
            changes.append(IntegrityChange(path, ChangeType.CREATED, None, snap.sha256, None, snap.size))
        elif snap.sha256 != baseline[path].sha256:
            old = baseline[path]
            changes.append(IntegrityChange(path, ChangeType.MODIFIED, old.sha256, snap.sha256, old.size, snap.size))
    for path, old in baseline.items():
        if path not in current:
            changes.append(IntegrityChange(path, ChangeType.DELETED, old.sha256, None, old.size, None))
    return sorted(changes, key=lambda c: c.path)


def save_baseline(baseline: dict[str, FileSnapshot], output_path: str) -> None:
    """Serialise *baseline* to a JSON file at *output_path*.

    Args:
        baseline: Snapshot dict to save.
        output_path: Destination file path.
    """
    payload = {"version": BASELINE_VERSION, "files": {k: asdict(v) for k, v in baseline.items()}}
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def load_baseline(input_path: str) -> dict[str, FileSnapshot]:
    """Load a baseline JSON file from *input_path*.

    Args:
        input_path: Path to a previously saved baseline file.

    Returns:
        Dict mapping file path to FileSnapshot.

    Raises:
        OSError: If the file cannot be read.
        ValueError: If the file format is invalid.
    """
    with open(input_path, encoding="utf-8") as fh:
        payload = json.load(fh)
    if "files" not in payload:
        raise ValueError("Invalid baseline file: missing 'files' key")
    return {k: FileSnapshot(**v) for k, v in payload["files"].items()}


def _compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()
