"""Core logic: baseline creation, integrity checking, and report generation."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC
from pathlib import Path

logger = logging.getLogger(__name__)

HASH_ALGORITHM: str = "sha256"
BASELINE_FILENAME: str = ".integrity_baseline.json"
_CHUNK_SIZE: int = 1 << 20  # 1 MiB


@dataclass(frozen=True)
class IntegrityReport:
    """Summary of an integrity check run."""

    baseline_path: Path
    checked_at: str
    new_files: list[str] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)
    modified_files: list[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        """Return True if no changes were detected."""
        return not (self.new_files or self.deleted_files or self.modified_files)

    def summary(self) -> str:
        """Return a human-readable one-line summary."""
        if self.is_clean:
            return "CLEAN — no changes detected"
        parts = []
        if self.new_files:
            parts.append(f"{len(self.new_files)} new")
        if self.deleted_files:
            parts.append(f"{len(self.deleted_files)} deleted")
        if self.modified_files:
            parts.append(f"{len(self.modified_files)} modified")
        return "CHANGED — " + ", ".join(parts)


def _hash_file(path: Path) -> str:
    """Compute SHA-256 hex digest of *path*."""
    h = hashlib.new(HASH_ALGORITHM)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def create_baseline(directory: Path, *, exclude: set[str] | None = None) -> dict[str, str]:
    """Walk *directory* and compute a SHA-256 hash for every file.

    Args:
        directory: Root directory to scan.
        exclude: Set of filename patterns to skip (exact names).

    Returns:
        Mapping of relative path string → SHA-256 hex digest.

    Raises:
        NotADirectoryError: If *directory* is not a directory.
    """
    if not directory.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")
    skip = exclude or set()
    baseline: dict[str, str] = {}
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        if path.name in skip or path.name == BASELINE_FILENAME:
            continue
        rel = path.relative_to(directory).as_posix()
        try:
            baseline[rel] = _hash_file(path)
        except OSError as exc:
            logger.warning("Skipping %s: %s", path, exc)
    return baseline


def check_integrity(
    directory: Path, baseline: dict[str, str], *, exclude: set[str] | None = None
) -> IntegrityReport:
    """Compare current directory state against *baseline*.

    Args:
        directory: Root directory to scan.
        baseline: Previously computed baseline mapping.
        exclude: Filenames to skip.

    Returns:
        :class:`IntegrityReport` describing changes found.
    """
    from datetime import datetime

    current = create_baseline(directory, exclude=exclude)
    baseline_keys = set(baseline.keys())
    current_keys = set(current.keys())

    new_files = sorted(current_keys - baseline_keys)
    deleted_files = sorted(baseline_keys - current_keys)
    modified_files = sorted(
        k for k in baseline_keys & current_keys if baseline[k] != current[k]
    )

    return IntegrityReport(
        baseline_path=directory,
        checked_at=datetime.now(UTC).isoformat(),
        new_files=new_files,
        deleted_files=deleted_files,
        modified_files=modified_files,
    )


def save_baseline(baseline: dict[str, str], path: Path) -> None:
    """Persist *baseline* to a JSON file at *path*.

    Args:
        baseline: Mapping of relative path → hash.
        path: Destination file path.
    """
    path.write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")
    logger.info("Baseline saved: %s (%d entries)", path, len(baseline))


def load_baseline(path: Path) -> dict[str, str]:
    """Load a baseline JSON file.

    Args:
        path: Path to the baseline JSON file.

    Returns:
        Mapping of relative path → hash.

    Raises:
        FileNotFoundError: If *path* does not exist.
        ValueError: If the file is not valid JSON or has wrong structure.
    """
    if not path.exists():
        raise FileNotFoundError(f"Baseline file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid baseline JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Baseline must be a JSON object, got {type(data).__name__}")
    return {str(k): str(v) for k, v in data.items()}
