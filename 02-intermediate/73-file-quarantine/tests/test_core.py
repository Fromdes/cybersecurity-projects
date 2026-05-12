"""Tests for project 73 File Quarantine Service."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from project_73.core import (
    QuarantineEntry,
    QuarantineStore,
    hash_file,
)

# ---------------------------------------------------------------------------
# hash_file
# ---------------------------------------------------------------------------

class TestHashFile:
    def test_known_content(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_bytes(b"hello")
        # sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert hash_file(f).startswith("2cf24dba")

    def test_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        h = hash_file(f)
        assert len(h) == 64

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(OSError):
            hash_file(tmp_path / "nonexistent.txt")


# ---------------------------------------------------------------------------
# QuarantineEntry serialization
# ---------------------------------------------------------------------------

class TestQuarantineEntry:
    def _entry(self) -> QuarantineEntry:
        return QuarantineEntry(
            original_path="/tmp/evil.exe",
            quarantine_name="abc123_evil.exe",
            sha256="deadbeef" * 8,
            size_bytes=1024,
            quarantined_at=1700000000.0,
            reason="suspicious",
        )

    def test_roundtrip(self) -> None:
        e = self._entry()
        recovered = QuarantineEntry.from_dict(e.to_dict())
        assert recovered.sha256 == e.sha256
        assert recovered.original_path == e.original_path

    def test_released_default_false(self) -> None:
        assert not self._entry().released


# ---------------------------------------------------------------------------
# QuarantineStore
# ---------------------------------------------------------------------------

class TestQuarantineStore:
    def test_quarantine_moves_file(self, tmp_path: Path) -> None:
        src = tmp_path / "malware.txt"
        src.write_bytes(b"evil content")
        store = QuarantineStore(tmp_path / "q")
        result = store.quarantine(src, reason="test")
        assert result.success
        assert not src.exists()  # moved
        assert result.entry is not None
        assert result.entry.reason == "test"

    def test_quarantine_nonexistent_fails(self, tmp_path: Path) -> None:
        store = QuarantineStore(tmp_path / "q")
        result = store.quarantine(tmp_path / "ghost.txt", reason="test")
        assert not result.success
        assert "not found" in result.error.lower()

    def test_quarantine_dir_permissions(self, tmp_path: Path) -> None:
        store = QuarantineStore(tmp_path / "q")
        mode = os.stat(tmp_path / "q").st_mode & 0o777
        assert mode == 0o700

    def test_file_permissions_after_quarantine(self, tmp_path: Path) -> None:
        src = tmp_path / "evil.txt"
        src.write_bytes(b"data")
        store = QuarantineStore(tmp_path / "q")
        result = store.quarantine(src, reason="test")
        assert result.entry is not None
        qfile = tmp_path / "q" / result.entry.quarantine_name
        mode = os.stat(qfile).st_mode & 0o777
        assert mode == 0o600

    def test_release_restores_file(self, tmp_path: Path) -> None:
        src = tmp_path / "evil.txt"
        src.write_bytes(b"safe now")
        store = QuarantineStore(tmp_path / "q")
        q_result = store.quarantine(src, reason="test")
        assert q_result.entry is not None
        dest = tmp_path / "restored.txt"
        r_result = store.release(q_result.entry.sha256, dest)
        assert r_result.success
        assert dest.exists()
        assert dest.read_bytes() == b"safe now"

    def test_release_marks_entry_released(self, tmp_path: Path) -> None:
        src = tmp_path / "evil.txt"
        src.write_bytes(b"data")
        store = QuarantineStore(tmp_path / "q")
        q_result = store.quarantine(src, reason="test")
        assert q_result.entry is not None
        file_hash = q_result.entry.sha256
        store.release(file_hash, tmp_path / "out.txt")
        entry = store.get_entry(file_hash)
        assert entry is not None
        assert entry.released

    def test_release_unknown_hash_fails(self, tmp_path: Path) -> None:
        store = QuarantineStore(tmp_path / "q")
        result = store.release("deadbeef" * 8, tmp_path / "out.txt")
        assert not result.success

    def test_release_already_released_fails(self, tmp_path: Path) -> None:
        src = tmp_path / "evil.txt"
        src.write_bytes(b"data")
        store = QuarantineStore(tmp_path / "q")
        q_result = store.quarantine(src, reason="test")
        assert q_result.entry is not None
        store.release(q_result.entry.sha256, tmp_path / "out1.txt")
        result = store.release(q_result.entry.sha256, tmp_path / "out2.txt")
        assert not result.success

    def test_delete_removes_file(self, tmp_path: Path) -> None:
        src = tmp_path / "evil.txt"
        src.write_bytes(b"data")
        store = QuarantineStore(tmp_path / "q")
        q_result = store.quarantine(src, reason="test")
        assert q_result.entry is not None
        file_hash = q_result.entry.sha256
        store.delete(file_hash)
        assert store.get_entry(file_hash) is None

    def test_list_entries_excludes_released(self, tmp_path: Path) -> None:
        src1 = tmp_path / "a.txt"
        src1.write_bytes(b"aaa")
        src2 = tmp_path / "b.txt"
        src2.write_bytes(b"bbb")
        store = QuarantineStore(tmp_path / "q")
        q1 = store.quarantine(src1, reason="r1")
        q2 = store.quarantine(src2, reason="r2")
        assert q1.entry is not None and q2.entry is not None
        store.release(q1.entry.sha256, tmp_path / "out.txt")
        active = store.list_entries(include_released=False)
        assert len(active) == 1

    def test_manifest_persistence(self, tmp_path: Path) -> None:
        src = tmp_path / "evil.txt"
        src.write_bytes(b"data")
        store1 = QuarantineStore(tmp_path / "q")
        q_result = store1.quarantine(src, reason="persist")
        assert q_result.entry is not None
        # Create a new store instance pointing to the same dir
        store2 = QuarantineStore(tmp_path / "q")
        entries = store2.list_entries(include_released=True)
        assert len(entries) == 1
        assert entries[0].reason == "persist"

    def test_verify_integrity_pass(self, tmp_path: Path) -> None:
        src = tmp_path / "evil.txt"
        src.write_bytes(b"data")
        store = QuarantineStore(tmp_path / "q")
        store.quarantine(src, reason="test")
        assert store.verify_integrity() == []

    def test_verify_integrity_tampered(self, tmp_path: Path) -> None:
        src = tmp_path / "evil.txt"
        src.write_bytes(b"data")
        store = QuarantineStore(tmp_path / "q")
        q_result = store.quarantine(src, reason="test")
        assert q_result.entry is not None
        # Tamper with file
        qfile = tmp_path / "q" / q_result.entry.quarantine_name
        qfile.write_bytes(b"tampered!")
        errors = store.verify_integrity()
        assert len(errors) == 1
        assert "TAMPERED" in errors[0]
