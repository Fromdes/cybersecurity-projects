"""Tests for Real-Time FIM core."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from project_78.core import (
    Baseline,
    EventType,
    FileRecord,
    FIMEvent,
    FIMEventLog,
    hash_file,
)


class TestHashFile:
    def test_hash_known_content(self, tmp_path: Path) -> None:
        import hashlib
        f = tmp_path / "test.txt"
        f.write_bytes(b"hello world")
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert hash_file(f) == expected

    def test_hash_missing_file(self, tmp_path: Path) -> None:
        result = hash_file(tmp_path / "nonexistent.txt")
        assert result == ""

    def test_hash_empty_file(self, tmp_path: Path) -> None:
        import hashlib
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        assert hash_file(f) == hashlib.sha256(b"").hexdigest()


class TestFileRecord:
    def test_round_trip(self) -> None:
        rec = FileRecord(
            path="/etc/passwd",
            sha256="abc123",
            size=1024,
            mtime=1700000000.0,
            recorded_at="2024-01-01T00:00:00+00:00",
        )
        d = rec.to_dict()
        restored = FileRecord.from_dict(d)
        assert restored == rec


class TestBaseline:
    def test_build_single_file(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_text("content")
        b = Baseline()
        count = b.build([f])
        assert count == 1
        rec = b.get(str(f))
        assert rec is not None
        assert len(rec.sha256) == 64

    def test_build_directory(self, tmp_path: Path) -> None:
        for i in range(3):
            (tmp_path / f"file{i}.txt").write_text(f"content{i}")
        b = Baseline()
        count = b.build([tmp_path])
        assert count == 3

    def test_save_and_load(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_text("hello")
        b = Baseline()
        b.build([f])
        baseline_file = tmp_path / "baseline.json"
        b.save(baseline_file)
        b2 = Baseline.load(baseline_file)
        rec = b2.get(str(f))
        assert rec is not None
        assert rec.sha256 == hash_file(f)

    def test_verify_no_changes(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_text("hello")
        b = Baseline()
        b.build([f])
        events = b.verify()
        assert events == []

    def test_verify_modified_file(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_text("original")
        b = Baseline()
        b.build([f])
        f.write_text("modified")
        events = b.verify()
        assert len(events) == 1
        assert events[0].event_type == EventType.MODIFIED

    def test_verify_deleted_file(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_text("content")
        b = Baseline()
        b.build([f])
        f.unlink()
        events = b.verify()
        assert len(events) == 1
        assert events[0].event_type == EventType.DELETED

    def test_verify_returns_old_hash(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_text("original")
        b = Baseline()
        b.build([f])
        original_hash = b.get(str(f)).sha256  # type: ignore[union-attr]
        f.write_text("changed")
        events = b.verify()
        assert events[0].old_hash == original_hash

    def test_get_missing_returns_none(self) -> None:
        b = Baseline()
        assert b.get("/nonexistent/path") is None


class TestFIMEvent:
    def test_to_dict(self) -> None:
        ev = FIMEvent(
            event_type=EventType.MODIFIED,
            path="/etc/hosts",
            timestamp=datetime.now(UTC),
            old_hash="aaa",
            new_hash="bbb",
        )
        d = ev.to_dict()
        assert d["event_type"] == "MODIFIED"
        assert d["old_hash"] == "aaa"
        assert d["new_hash"] == "bbb"


class TestFIMEventLog:
    def test_record_and_get(self) -> None:
        log = FIMEventLog()
        ev = FIMEvent(EventType.CREATED, "/tmp/new.txt", datetime.now(UTC))
        log.record(ev)
        all_events = log.get_all()
        assert len(all_events) == 1

    def test_persistence(self, tmp_path: Path) -> None:
        out = tmp_path / "events.jsonl"
        log = FIMEventLog(output_path=out)
        ev = FIMEvent(EventType.DELETED, "/tmp/del.txt", datetime.now(UTC))
        log.record(ev)
        assert out.exists()
        obj = json.loads(out.read_text().strip())
        assert obj["event_type"] == "DELETED"
