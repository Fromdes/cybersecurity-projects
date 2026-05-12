"""Tests for Forensics Timeline Builder core."""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path

from project_81.core import (
    ForensicsTimeline,
    TimelineEvent,
    collect_filesystem_events,
    collect_generic_log_events,
    collect_syslog_events,
)


def make_event(ts: datetime, source: str = "test", event_type: str = "TEST") -> TimelineEvent:
    return TimelineEvent(
        timestamp=ts,
        source=source,
        event_type=event_type,
        description="Test event",
        artifact="/test/artifact",
    )


class TestTimelineEvent:
    def test_round_trip(self) -> None:
        ts = datetime(2024, 5, 12, 10, 0, 0, tzinfo=UTC)
        ev = TimelineEvent(
            timestamp=ts,
            source="fs",
            event_type="FILE_MODIFIED",
            description="Test",
            artifact="/etc/hosts",
            details={"size": 100},
        )
        d = ev.to_dict()
        restored = TimelineEvent.from_dict(d)
        assert restored.timestamp == ts
        assert restored.source == "fs"


class TestCollectFilesystemEvents:
    def test_collects_events_from_file(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_text("content")
        events = list(collect_filesystem_events(f))
        assert len(events) >= 1
        assert all(e.source == "filesystem" for e in events)
        assert all(e.artifact == str(f) for e in events)

    def test_collects_events_from_directory(self, tmp_path: Path) -> None:
        for i in range(3):
            (tmp_path / f"f{i}.txt").write_text(f"content{i}")
        events = list(collect_filesystem_events(tmp_path))
        assert len(events) >= 3

    def test_non_recursive(self, tmp_path: Path) -> None:
        subdir = tmp_path / "sub"
        subdir.mkdir()
        (subdir / "nested.txt").write_text("nested")
        (tmp_path / "top.txt").write_text("top")
        events_flat = list(collect_filesystem_events(tmp_path, recursive=False))
        events_rec = list(collect_filesystem_events(tmp_path, recursive=True))
        assert len(events_rec) > len(events_flat)


class TestCollectSyslogEvents:
    def test_parses_valid_syslog(self, tmp_path: Path) -> None:
        log = tmp_path / "auth.log"
        log.write_text(
            "May 12 10:00:01 myhost sshd[1234]: Failed password for root\n"
            "May 12 10:00:02 myhost sshd[1234]: Accepted publickey for user\n"
        )
        events = list(collect_syslog_events(log, year=2024))
        assert len(events) == 2
        assert events[0].source == "syslog"
        assert "Failed password" in events[0].description

    def test_skips_invalid_lines(self, tmp_path: Path) -> None:
        log = tmp_path / "test.log"
        log.write_text("invalid line\n\n   \n")
        events = list(collect_syslog_events(log))
        assert events == []


class TestCollectGenericLogEvents:
    def test_parses_iso8601(self, tmp_path: Path) -> None:
        log = tmp_path / "app.log"
        log.write_text(
            "2024-05-12T10:00:00Z INFO application started\n"
            "2024-05-12T10:01:00+00:00 ERROR something failed\n"
        )
        events = list(collect_generic_log_events(log))
        assert len(events) == 2
        assert events[0].source == "generic_log"

    def test_skips_lines_without_timestamp(self, tmp_path: Path) -> None:
        log = tmp_path / "notime.log"
        log.write_text("line without timestamp\nanother line\n")
        assert list(collect_generic_log_events(log)) == []


class TestForensicsTimeline:
    def test_add_events_count(self) -> None:
        timeline = ForensicsTimeline()
        ts = datetime.now(UTC)
        events = [make_event(ts) for _ in range(5)]
        count = timeline.add_events(iter(events))
        assert count == 5

    def test_sorted_order(self) -> None:
        timeline = ForensicsTimeline()
        t1 = datetime(2024, 1, 1, tzinfo=UTC)
        t2 = datetime(2024, 6, 1, tzinfo=UTC)
        t3 = datetime(2024, 3, 1, tzinfo=UTC)
        for ts in (t2, t1, t3):
            timeline._events.append(make_event(ts))
        sorted_ev = timeline.sorted_events()
        timestamps = [e.timestamp for e in sorted_ev]
        assert timestamps == sorted(timestamps)

    def test_to_jsonl(self, tmp_path: Path) -> None:
        timeline = ForensicsTimeline()
        ts = datetime.now(UTC)
        timeline._events.append(make_event(ts))
        out = tmp_path / "timeline.jsonl"
        count = timeline.to_jsonl(out)
        assert count == 1
        assert out.exists()
        obj = json.loads(out.read_text().strip())
        assert "timestamp" in obj

    def test_to_csv(self, tmp_path: Path) -> None:
        timeline = ForensicsTimeline()
        ts = datetime.now(UTC)
        timeline._events.append(make_event(ts))
        out = tmp_path / "timeline.csv"
        count = timeline.to_csv(out)
        assert count == 1
        rows = list(csv.reader(out.open()))
        assert len(rows) == 2  # header + 1 row

    def test_summary_empty(self) -> None:
        timeline = ForensicsTimeline()
        s = timeline.summary()
        assert s["total"] == 0

    def test_summary_populated(self) -> None:
        timeline = ForensicsTimeline()
        t1 = datetime(2024, 1, 1, tzinfo=UTC)
        t2 = datetime(2024, 6, 1, tzinfo=UTC)
        timeline._events.extend([
            make_event(t1, source="filesystem"),
            make_event(t2, source="syslog"),
        ])
        s = timeline.summary()
        assert s["total"] == 2
        assert s["by_source"]["filesystem"] == 1
        assert s["by_source"]["syslog"] == 1

    def test_source_filter(self) -> None:
        timeline = ForensicsTimeline()
        ts = datetime.now(UTC)
        timeline._events.extend([
            make_event(ts, source="filesystem"),
            make_event(ts, source="syslog"),
        ])
        fs_events = timeline.sorted_events(source_filter="filesystem")
        assert all(e.source == "filesystem" for e in fs_events)
        assert len(fs_events) == 1
