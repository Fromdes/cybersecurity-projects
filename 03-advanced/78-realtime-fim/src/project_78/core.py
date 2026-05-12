"""Real-Time FIM — inotify/watchdog-based file integrity monitoring."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

HASH_ALGO = "sha256"
BASELINE_VERSION = 1


class EventType(str, Enum):
    """File system event types."""

    CREATED = "CREATED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    MOVED = "MOVED"


# ── File record ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class FileRecord:
    """Baseline record for a single file."""

    path: str
    sha256: str
    size: int
    mtime: float
    recorded_at: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "mtime": self.mtime,
            "recorded_at": self.recorded_at,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> FileRecord:
        """Deserialize from dict."""
        return FileRecord(
            path=d["path"],
            sha256=d["sha256"],
            size=d["size"],
            mtime=d["mtime"],
            recorded_at=d["recorded_at"],
        )


@dataclass(frozen=True)
class FIMEvent:
    """A file integrity event (deviation from baseline or real-time change)."""

    event_type: EventType
    path: str
    timestamp: datetime
    old_hash: str = ""
    new_hash: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "event_type": self.event_type.value,
            "path": self.path,
            "timestamp": self.timestamp.isoformat(),
            "old_hash": self.old_hash,
            "new_hash": self.new_hash,
            "details": self.details,
        }


# ── Hashing ────────────────────────────────────────────────────────────────────

def hash_file(path: Path) -> str:
    """Compute SHA-256 of a file. Return empty string on error."""
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


# ── Baseline ───────────────────────────────────────────────────────────────────

class Baseline:
    """Stores and manages file integrity baseline."""

    def __init__(self) -> None:
        self._records: dict[str, FileRecord] = {}

    def build(self, paths: list[Path], recursive: bool = True) -> int:
        """Scan paths and build baseline. Returns number of files recorded."""
        count = 0
        for root in paths:
            if root.is_file():
                self._record_file(root)
                count += 1
            elif root.is_dir():
                pattern = "**/*" if recursive else "*"
                for p in root.glob(pattern):
                    if p.is_file():
                        self._record_file(p)
                        count += 1
        logger.info("Baseline built: %d files", count)
        return count

    def _record_file(self, path: Path) -> None:
        try:
            stat = path.stat()
            digest = hash_file(path)
            self._records[str(path)] = FileRecord(
                path=str(path),
                sha256=digest,
                size=stat.st_size,
                mtime=stat.st_mtime,
                recorded_at=datetime.now(UTC).isoformat(),
            )
        except OSError as exc:
            logger.warning("Cannot record %s: %s", path, exc)

    def get(self, path: str) -> FileRecord | None:
        """Return baseline record for path."""
        return self._records.get(path)

    def all_records(self) -> dict[str, FileRecord]:
        """Return all records."""
        return dict(self._records)

    def save(self, output: Path) -> None:
        """Persist baseline to JSON file."""
        data = {
            "version": BASELINE_VERSION,
            "created_at": datetime.now(UTC).isoformat(),
            "records": {k: v.to_dict() for k, v in self._records.items()},
        }
        output.write_text(json.dumps(data, indent=2))
        logger.info("Baseline saved to %s (%d records)", output, len(self._records))

    @classmethod
    def load(cls, path: Path) -> Baseline:
        """Load baseline from JSON file."""
        data = json.loads(path.read_text())
        b = cls()
        for record_dict in data["records"].values():
            rec = FileRecord.from_dict(record_dict)
            b._records[rec.path] = rec
        logger.info("Baseline loaded: %d records from %s", len(b._records), path)
        return b

    def verify(self) -> list[FIMEvent]:
        """Compare current filesystem state to baseline. Return deviations."""
        events: list[FIMEvent] = []
        for path_str, record in self._records.items():
            p = Path(path_str)
            if not p.exists():
                events.append(FIMEvent(
                    event_type=EventType.DELETED,
                    path=path_str,
                    timestamp=datetime.now(UTC),
                    old_hash=record.sha256,
                    details={"baseline_size": record.size},
                ))
            else:
                current_hash = hash_file(p)
                if current_hash != record.sha256:
                    events.append(FIMEvent(
                        event_type=EventType.MODIFIED,
                        path=path_str,
                        timestamp=datetime.now(UTC),
                        old_hash=record.sha256,
                        new_hash=current_hash,
                    ))
        return events


# ── Real-time watcher (watchdog-based) ────────────────────────────────────────

try:
    from watchdog.events import (
        FileCreatedEvent,
        FileDeletedEvent,
        FileModifiedEvent,
        FileMovedEvent,
        FileSystemEvent,
        FileSystemEventHandler,
    )
    from watchdog.observers import Observer

    WATCHDOG_AVAILABLE = True

    class _FIMEventHandler(FileSystemEventHandler):
        """Watchdog event handler that produces FIMEvent objects."""

        def __init__(
            self,
            baseline: Baseline,
            callback: Callable[[FIMEvent], None],
        ) -> None:
            super().__init__()
            self._baseline = baseline
            self._callback = callback

        def on_created(self, event: FileSystemEvent) -> None:
            if event.is_directory:
                return
            path = str(event.src_path)
            new_hash = hash_file(Path(path))
            fim_event = FIMEvent(
                event_type=EventType.CREATED,
                path=path,
                timestamp=datetime.now(UTC),
                new_hash=new_hash,
            )
            self._callback(fim_event)

        def on_modified(self, event: FileSystemEvent) -> None:
            if event.is_directory:
                return
            path = str(event.src_path)
            old_record = self._baseline.get(path)
            new_hash = hash_file(Path(path))
            fim_event = FIMEvent(
                event_type=EventType.MODIFIED,
                path=path,
                timestamp=datetime.now(UTC),
                old_hash=old_record.sha256 if old_record else "",
                new_hash=new_hash,
            )
            self._callback(fim_event)

        def on_deleted(self, event: FileSystemEvent) -> None:
            if event.is_directory:
                return
            path = str(event.src_path)
            old_record = self._baseline.get(path)
            fim_event = FIMEvent(
                event_type=EventType.DELETED,
                path=path,
                timestamp=datetime.now(UTC),
                old_hash=old_record.sha256 if old_record else "",
            )
            self._callback(fim_event)

        def on_moved(self, event: FileSystemEvent) -> None:
            if event.is_directory:
                return
            fim_event = FIMEvent(
                event_type=EventType.MOVED,
                path=str(event.src_path),
                timestamp=datetime.now(UTC),
                details={"dest": str(event.dest_path)},
            )
            self._callback(fim_event)

except ImportError:
    WATCHDOG_AVAILABLE = False


class FIMWatcher:
    """Wraps watchdog observer for real-time FIM."""

    def __init__(
        self,
        baseline: Baseline,
        watch_paths: list[Path],
        callback: Callable[[FIMEvent], None],
        recursive: bool = True,
    ) -> None:
        if not WATCHDOG_AVAILABLE:
            raise RuntimeError("watchdog package not installed; run: pip install watchdog")
        self._baseline = baseline
        self._watch_paths = watch_paths
        self._callback = callback
        self._recursive = recursive
        self._observer: Any = None

    def start(self) -> None:
        """Start the watchdog observer."""
        from watchdog.observers import Observer as _Observer

        handler = _FIMEventHandler(self._baseline, self._callback)
        self._observer = _Observer()
        for path in self._watch_paths:
            self._observer.schedule(handler, str(path), recursive=self._recursive)
        self._observer.start()
        logger.info("FIM watcher started on %s", self._watch_paths)

    def stop(self) -> None:
        """Stop the watchdog observer."""
        if self._observer:
            self._observer.stop()
            self._observer.join()
            logger.info("FIM watcher stopped")


# ── Event log ─────────────────────────────────────────────────────────────────

class FIMEventLog:
    """Thread-safe log of FIM events with optional JSONL persistence."""

    def __init__(self, output_path: Path | None = None) -> None:
        self._events: list[FIMEvent] = []
        self._lock = threading.Lock()
        self._output_path = output_path

    def record(self, event: FIMEvent) -> None:
        """Record a FIM event."""
        with self._lock:
            self._events.append(event)
        if self._output_path:
            with self._output_path.open("a") as fh:
                fh.write(json.dumps(event.to_dict()) + "\n")
        logger.warning("[FIM %s] %s", event.event_type.value, event.path)

    def get_all(self) -> list[FIMEvent]:
        """Return a snapshot of all events."""
        with self._lock:
            return list(self._events)
