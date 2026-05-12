"""Browser history scanning and selective purging for Chrome/Chromium/Firefox."""
from __future__ import annotations

import logging
import re
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger(__name__)

CHROME_EPOCH_OFFSET: int = 11_644_473_600_000_000
FIREFOX_EPOCH_DIVISOR: int = 1_000_000

BROWSER_PATHS: dict[str, list[str]] = {
    "chrome": [
        "~/.config/google-chrome",
        "~/.config/chromium",
    ],
    "firefox": [
        "~/.mozilla/firefox",
    ],
}

TRACKER_PATTERNS: tuple[str, ...] = (
    r"google\.com/search",
    r"bing\.com/search",
    r"yahoo\.com/search",
    r"doubleclick\.net",
    r"facebook\.com",
    r"analytics\.",
    r"tracking\.",
    r"telemetry\.",
)


@dataclass(frozen=True)
class HistoryEntry:
    """A single browser history visit record."""

    url: str
    title: str
    visit_time: datetime
    visit_count: int
    browser: str
    profile: str


@dataclass(frozen=True)
class ScanResult:
    """Summary of a history scan operation."""

    browser: str
    profile: str
    total_entries: int
    matched_entries: int
    entries: tuple[HistoryEntry, ...]


def find_profiles() -> dict[str, list[Path]]:
    """Discover installed browser profile directories.

    Returns:
        Dict mapping browser name to list of found profile paths.
    """
    found: dict[str, list[Path]] = {}
    for browser, paths in BROWSER_PATHS.items():
        profile_list: list[Path] = []
        for raw_path in paths:
            base = Path(raw_path).expanduser()
            if not base.exists():
                continue
            if browser == "firefox":
                for profile_dir in base.iterdir():
                    if profile_dir.is_dir() and (profile_dir / "places.sqlite").exists():
                        profile_list.append(profile_dir)
            else:
                history_file = base / "Default" / "History"
                if history_file.exists():
                    profile_list.append(base / "Default")
                for profile_dir in base.glob("Profile *"):
                    if (profile_dir / "History").exists():
                        profile_list.append(profile_dir)
        if profile_list:
            found[browser] = profile_list
    return found


def scan_profile(profile_path: Path, browser: str, patterns: tuple[str, ...] = TRACKER_PATTERNS) -> ScanResult:
    """Read history from *profile_path* and filter by *patterns*.

    Args:
        profile_path: Browser profile directory.
        browser: One of ``"chrome"``/``"chromium"`` or ``"firefox"``.
        patterns: Regex URL patterns to match.

    Returns:
        :class:`ScanResult` with matched entries.
    """
    if browser in ("chrome", "chromium"):
        entries = _read_chrome_history(profile_path)
    else:
        entries = _read_firefox_history(profile_path)

    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
    matched = [e for e in entries if any(rx.search(e.url) for rx in compiled)]

    return ScanResult(
        browser=browser,
        profile=str(profile_path),
        total_entries=len(entries),
        matched_entries=len(matched),
        entries=tuple(matched),
    )


def delete_entries(profile_path: Path, browser: str, patterns: tuple[str, ...] = TRACKER_PATTERNS) -> int:
    """Delete history entries matching *patterns* from *profile_path*.

    The browser must be closed before calling this function.

    Args:
        profile_path: Browser profile directory.
        browser: ``"chrome"``/``"chromium"`` or ``"firefox"``.
        patterns: Regex URL patterns to remove.

    Returns:
        Number of rows deleted.

    Raises:
        FileNotFoundError: If the history database is not found.
        sqlite3.OperationalError: If the database is locked (browser open).
    """
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]

    if browser in ("chrome", "chromium"):
        return _delete_chrome_entries(profile_path, compiled)
    return _delete_firefox_entries(profile_path, compiled)


def _read_chrome_history(profile_path: Path) -> list[HistoryEntry]:
    db_path = profile_path / "History"
    if not db_path.exists():
        raise FileNotFoundError(f"Chrome History database not found: {db_path}")

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    shutil.copy2(db_path, tmp_path)

    entries: list[HistoryEntry] = []
    try:
        with sqlite3.connect(tmp_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT u.url, u.title, u.visit_count, v.visit_time "
                "FROM urls u JOIN visits v ON u.id = v.url"
            ).fetchall()
            for row in rows:
                visit_time = _chrome_time_to_dt(row["visit_time"])
                entries.append(HistoryEntry(
                    url=row["url"] or "",
                    title=row["title"] or "",
                    visit_time=visit_time,
                    visit_count=row["visit_count"] or 0,
                    browser="chrome",
                    profile=str(profile_path),
                ))
    finally:
        tmp_path.unlink(missing_ok=True)
    return entries


def _read_firefox_history(profile_path: Path) -> list[HistoryEntry]:
    db_path = profile_path / "places.sqlite"
    if not db_path.exists():
        raise FileNotFoundError(f"Firefox places.sqlite not found: {db_path}")

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    shutil.copy2(db_path, tmp_path)

    entries: list[HistoryEntry] = []
    try:
        with sqlite3.connect(tmp_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT p.url, p.title, p.visit_count, h.visit_date "
                "FROM moz_places p JOIN moz_historyvisits h ON p.id = h.place_id"
            ).fetchall()
            for row in rows:
                visit_time = _firefox_time_to_dt(row["visit_date"] or 0)
                entries.append(HistoryEntry(
                    url=row["url"] or "",
                    title=row["title"] or "",
                    visit_time=visit_time,
                    visit_count=row["visit_count"] or 0,
                    browser="firefox",
                    profile=str(profile_path),
                ))
    finally:
        tmp_path.unlink(missing_ok=True)
    return entries


def _delete_chrome_entries(profile_path: Path, compiled: list[re.Pattern[str]]) -> int:
    db_path = profile_path / "History"
    if not db_path.exists():
        raise FileNotFoundError(f"Chrome History not found: {db_path}")

    with sqlite3.connect(db_path, timeout=3) as conn:
        urls = conn.execute("SELECT id, url FROM urls").fetchall()
        to_delete = [row[0] for row in urls if any(rx.search(row[1] or "") for rx in compiled)]
        if not to_delete:
            return 0
        placeholders = ",".join("?" * len(to_delete))
        conn.execute(f"DELETE FROM visits WHERE url IN ({placeholders})", to_delete)
        conn.execute(f"DELETE FROM urls WHERE id IN ({placeholders})", to_delete)
        conn.execute("VACUUM")
        return len(to_delete)


def _delete_firefox_entries(profile_path: Path, compiled: list[re.Pattern[str]]) -> int:
    db_path = profile_path / "places.sqlite"
    if not db_path.exists():
        raise FileNotFoundError(f"Firefox places.sqlite not found: {db_path}")

    with sqlite3.connect(db_path, timeout=3) as conn:
        places = conn.execute("SELECT id, url FROM moz_places").fetchall()
        to_delete = [row[0] for row in places if any(rx.search(row[1] or "") for rx in compiled)]
        if not to_delete:
            return 0
        placeholders = ",".join("?" * len(to_delete))
        conn.execute(f"DELETE FROM moz_historyvisits WHERE place_id IN ({placeholders})", to_delete)
        conn.execute(f"DELETE FROM moz_places WHERE id IN ({placeholders})", to_delete)
        conn.execute("VACUUM")
        return len(to_delete)


def _chrome_time_to_dt(chrome_ts: int) -> datetime:
    if not chrome_ts:
        return datetime(1970, 1, 1, tzinfo=UTC)
    unix_us = chrome_ts - CHROME_EPOCH_OFFSET
    return datetime.fromtimestamp(unix_us / 1_000_000, tz=UTC)


def _firefox_time_to_dt(ff_ts: int) -> datetime:
    if not ff_ts:
        return datetime(1970, 1, 1, tzinfo=UTC)
    return datetime.fromtimestamp(ff_ts / FIREFOX_EPOCH_DIVISOR, tz=UTC)
