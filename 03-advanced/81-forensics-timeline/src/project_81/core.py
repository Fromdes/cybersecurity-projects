"""Forensics Timeline Builder — collects timestamps from multiple sources into a unified timeline."""

from __future__ import annotations

import csv
import json
import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Timeline event ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TimelineEvent:
    """A single timestamped event in the forensic timeline."""

    timestamp: datetime
    source: str
    event_type: str
    description: str
    artifact: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type,
            "description": self.description,
            "artifact": self.artifact,
            "details": self.details,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> TimelineEvent:
        """Deserialize from dict."""
        return TimelineEvent(
            timestamp=datetime.fromisoformat(d["timestamp"]),
            source=d["source"],
            event_type=d["event_type"],
            description=d["description"],
            artifact=d["artifact"],
            details=d.get("details", {}),
        )


# ── Sources ────────────────────────────────────────────────────────────────────

def collect_filesystem_events(path: Path, recursive: bool = True) -> Iterator[TimelineEvent]:
    """Yield timeline events from file mtime/atime/ctime."""
    if path.is_file():
        yield from _file_events(path)
        return
    if path.is_dir():
        pattern = "**/*" if recursive else "*"
        for p in path.glob(pattern):
            if p.is_file():
                yield from _file_events(p)


def _file_events(path: Path) -> Iterator[TimelineEvent]:
    """Emit mtime, atime, ctime events for a single file."""
    try:
        s = path.stat()
        for ts_attr, event_type, description in (
            (s.st_mtime, "FILE_MODIFIED", "File last modified"),
            (s.st_atime, "FILE_ACCESSED", "File last accessed"),
            (s.st_ctime, "FILE_CHANGED", "File metadata changed"),
        ):
            yield TimelineEvent(
                timestamp=datetime.fromtimestamp(ts_attr, tz=UTC),
                source="filesystem",
                event_type=event_type,
                description=f"{description}: {path.name}",
                artifact=str(path),
                details={"size": s.st_size, "mode": oct(s.st_mode)},
            )
    except OSError as exc:
        logger.warning("Cannot stat %s: %s", path, exc)


# Syslog timestamp pattern: "May 12 10:00:01"
_SYSLOG_TS = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^:]+):\s*(?P<msg>.+)$"
)
_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def collect_syslog_events(log_path: Path, year: int | None = None) -> Iterator[TimelineEvent]:
    """Parse syslog-format log file into timeline events."""
    if year is None:
        year = datetime.now(UTC).year
    with log_path.open(errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            m = _SYSLOG_TS.match(line)
            if not m:
                continue
            try:
                month = _MONTH_MAP.get(m.group("month"), 1)
                day = int(m.group("day"))
                h, mi, s = map(int, m.group("time").split(":"))
                ts = datetime(year, month, day, h, mi, s, tzinfo=UTC)
            except (ValueError, KeyError):
                continue
            yield TimelineEvent(
                timestamp=ts,
                source="syslog",
                event_type="LOG_ENTRY",
                description=m.group("msg")[:120],
                artifact=str(log_path),
                details={"host": m.group("host"), "process": m.group("proc")},
            )


# ISO8601 / common timestamp pattern for generic logs
_ISO_TS = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")


def collect_generic_log_events(log_path: Path) -> Iterator[TimelineEvent]:
    """Parse any log file containing ISO8601 timestamps."""
    with log_path.open(errors="replace") as fh:
        for line in fh:
            line = line.strip()
            m = _ISO_TS.search(line)
            if not m:
                continue
            try:
                ts_str = m.group(1).replace(" ", "T")
                if ts_str.endswith("Z"):
                    ts_str = ts_str[:-1] + "+00:00"
                ts = datetime.fromisoformat(ts_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)
            except ValueError:
                continue
            yield TimelineEvent(
                timestamp=ts,
                source="generic_log",
                event_type="LOG_ENTRY",
                description=line[:120],
                artifact=str(log_path),
            )


# ── Timeline ───────────────────────────────────────────────────────────────────

class ForensicsTimeline:
    """Aggregates events from multiple sources and exports sorted timelines."""

    def __init__(self) -> None:
        self._events: list[TimelineEvent] = []

    def add_events(self, events: Iterator[TimelineEvent]) -> int:
        """Add events from an iterator. Returns count added."""
        count = 0
        for event in events:
            self._events.append(event)
            count += 1
        return count

    def sorted_events(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        source_filter: str | None = None,
    ) -> list[TimelineEvent]:
        """Return events sorted by timestamp, optionally filtered."""
        result = self._events
        if start:
            result = [e for e in result if e.timestamp >= start]
        if end:
            result = [e for e in result if e.timestamp <= end]
        if source_filter:
            result = [e for e in result if e.source == source_filter]
        return sorted(result, key=lambda e: e.timestamp)

    def to_jsonl(self, output: Path) -> int:
        """Write all events sorted to a JSONL file. Returns event count."""
        events = self.sorted_events()
        with output.open("w") as fh:
            for event in events:
                fh.write(json.dumps(event.to_dict()) + "\n")
        return len(events)

    def to_csv(self, output: Path) -> int:
        """Write all events sorted to a CSV file. Returns event count."""
        events = self.sorted_events()
        with output.open("w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["timestamp", "source", "event_type", "description", "artifact"])
            for event in events:
                writer.writerow([
                    event.timestamp.isoformat(),
                    event.source,
                    event.event_type,
                    event.description,
                    event.artifact,
                ])
        return len(events)

    def summary(self) -> dict[str, Any]:
        """Return summary statistics."""
        if not self._events:
            return {"total": 0}
        by_source: dict[str, int] = {}
        by_type: dict[str, int] = {}
        for e in self._events:
            by_source[e.source] = by_source.get(e.source, 0) + 1
            by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
        sorted_events = sorted(self._events, key=lambda e: e.timestamp)
        return {
            "total": len(self._events),
            "earliest": sorted_events[0].timestamp.isoformat(),
            "latest": sorted_events[-1].timestamp.isoformat(),
            "by_source": by_source,
            "by_event_type": by_type,
        }
