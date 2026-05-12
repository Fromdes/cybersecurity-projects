"""Tests for project_33.core — Browser History Privacy Cleaner."""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from project_33.core import (
    TRACKER_PATTERNS,
    ScanResult,
    _chrome_time_to_dt,
    _firefox_time_to_dt,
    _read_chrome_history,
    _read_firefox_history,
    delete_entries,
    scan_profile,
)


def _create_chrome_db(profile_path: Path) -> Path:
    db = profile_path / "History"
    with sqlite3.connect(db) as conn:
        conn.execute(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)"
        )
        conn.execute(
            "CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)"
        )
        conn.execute(
            "INSERT INTO urls VALUES (1, 'https://google.com/search?q=test', 'Google', 3)"
        )
        conn.execute(
            "INSERT INTO urls VALUES (2, 'https://example.com', 'Example', 1)"
        )
        conn.execute("INSERT INTO visits VALUES (1, 1, 13_296_009_600_000_000)")
        conn.execute("INSERT INTO visits VALUES (2, 2, 13_296_009_600_000_000)")
    return db


def _create_firefox_db(profile_path: Path) -> Path:
    db = profile_path / "places.sqlite"
    with sqlite3.connect(db) as conn:
        conn.execute(
            "CREATE TABLE moz_places "
            "(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)"
        )
        conn.execute(
            "CREATE TABLE moz_historyvisits "
            "(id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER)"
        )
        conn.execute(
            "INSERT INTO moz_places VALUES (1, 'https://google.com/search?q=test', 'Google', 2)"
        )
        conn.execute(
            "INSERT INTO moz_places VALUES (2, 'https://example.com', 'Example', 1)"
        )
        conn.execute("INSERT INTO moz_historyvisits VALUES (1, 1, 1_672_531_200_000_000)")
        conn.execute("INSERT INTO moz_historyvisits VALUES (2, 2, 1_672_531_200_000_000)")
    return db


class TestChromeTimeConversion:
    def test_zero_returns_epoch(self) -> None:
        dt = _chrome_time_to_dt(0)
        assert dt == datetime(1970, 1, 1, tzinfo=UTC)

    def test_nonzero_returns_datetime(self) -> None:
        dt = _chrome_time_to_dt(13_296_009_600_000_000)
        assert isinstance(dt, datetime)
        assert dt.tzinfo is not None


class TestFirefoxTimeConversion:
    def test_zero_returns_epoch(self) -> None:
        dt = _firefox_time_to_dt(0)
        assert dt == datetime(1970, 1, 1, tzinfo=UTC)

    def test_nonzero_returns_datetime(self) -> None:
        dt = _firefox_time_to_dt(1_672_531_200_000_000)
        assert isinstance(dt, datetime)
        assert dt.year == 2023


class TestReadChromeHistory:
    def test_reads_entries(self, tmp_path: Path) -> None:
        _create_chrome_db(tmp_path)
        entries = _read_chrome_history(tmp_path)
        assert len(entries) == 2

    def test_missing_db_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            _read_chrome_history(tmp_path)

    def test_entry_fields(self, tmp_path: Path) -> None:
        _create_chrome_db(tmp_path)
        entries = _read_chrome_history(tmp_path)
        urls = [e.url for e in entries]
        assert any("google.com" in u for u in urls)


class TestReadFirefoxHistory:
    def test_reads_entries(self, tmp_path: Path) -> None:
        _create_firefox_db(tmp_path)
        entries = _read_firefox_history(tmp_path)
        assert len(entries) == 2

    def test_missing_db_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            _read_firefox_history(tmp_path)


class TestScanProfile:
    def test_chrome_scan_matches_tracker(self, tmp_path: Path) -> None:
        _create_chrome_db(tmp_path)
        result = scan_profile(tmp_path, "chrome", TRACKER_PATTERNS)
        assert result.matched_entries >= 1
        assert any("google.com" in e.url for e in result.entries)

    def test_firefox_scan_matches_tracker(self, tmp_path: Path) -> None:
        _create_firefox_db(tmp_path)
        result = scan_profile(tmp_path, "firefox", TRACKER_PATTERNS)
        assert result.matched_entries >= 1

    def test_no_match_returns_zero(self, tmp_path: Path) -> None:
        _create_chrome_db(tmp_path)
        result = scan_profile(tmp_path, "chrome", (r"totally-not-in-db\.xyz",))
        assert result.matched_entries == 0

    def test_result_is_scan_result(self, tmp_path: Path) -> None:
        _create_chrome_db(tmp_path)
        result = scan_profile(tmp_path, "chrome", TRACKER_PATTERNS)
        assert isinstance(result, ScanResult)


class TestDeleteEntries:
    def test_chrome_delete_reduces_count(self, tmp_path: Path) -> None:
        _create_chrome_db(tmp_path)
        deleted = delete_entries(tmp_path, "chrome", (r"google\.com",))
        assert deleted >= 1
        with sqlite3.connect(tmp_path / "History") as conn:
            remaining = conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
        assert remaining == 1

    def test_firefox_delete_reduces_count(self, tmp_path: Path) -> None:
        _create_firefox_db(tmp_path)
        deleted = delete_entries(tmp_path, "firefox", (r"google\.com",))
        assert deleted >= 1

    def test_no_match_returns_zero(self, tmp_path: Path) -> None:
        _create_chrome_db(tmp_path)
        deleted = delete_entries(tmp_path, "chrome", (r"nowhere\.xyz",))
        assert deleted == 0

    def test_missing_db_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            delete_entries(tmp_path, "chrome", TRACKER_PATTERNS)
