"""Tests for project_33.cli — Browser History Privacy Cleaner CLI."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from project_33.cli import main


def _create_chrome_db(profile_path: Path) -> None:
    with sqlite3.connect(profile_path / "History") as conn:
        conn.execute(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)"
        )
        conn.execute(
            "CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)"
        )
        conn.execute(
            "INSERT INTO urls VALUES (1, 'https://google.com/search?q=test', 'G', 1)"
        )
        conn.execute("INSERT INTO visits VALUES (1, 1, 13_296_009_600_000_000)")


class TestCLIScan:
    def test_scan_finds_entries(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _create_chrome_db(tmp_path)
        with patch("sys.argv", ["history-cleaner", "--browser", "chrome",
                                "--profile", str(tmp_path), "scan"]):
            main()
        captured = capsys.readouterr()
        assert "Matched" in captured.out

    def test_no_profiles_exits(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch("project_33.cli.find_profiles", return_value={}):
            with patch("sys.argv", ["history-cleaner", "scan"]):
                with pytest.raises(SystemExit) as exc_info:
                    main()
        assert exc_info.value.code == 1


class TestCLIClean:
    def test_clean_deletes_entries(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _create_chrome_db(tmp_path)
        with patch("sys.argv", ["history-cleaner", "--browser", "chrome",
                                "--profile", str(tmp_path), "clean"]):
            main()
        captured = capsys.readouterr()
        assert "deleted" in captured.out

    def test_clean_missing_db_warns(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        with patch("sys.argv", ["history-cleaner", "--browser", "chrome",
                                "--profile", str(tmp_path), "clean"]):
            main()
        captured = capsys.readouterr()
        assert "Warning" in captured.err or "Error" in captured.err
