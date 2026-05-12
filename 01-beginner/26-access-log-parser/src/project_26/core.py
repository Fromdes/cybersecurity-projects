"""Apache/Nginx access log parsing and summarisation."""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime

COMBINED_LOG_RE: re.Pattern[str] = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)
DATE_FORMAT: str = "%d/%b/%Y:%H:%M:%S %z"
UNKNOWN: str = "-"
TOP_N_DEFAULT: int = 10


@dataclass(frozen=True)
class LogEntry:
    """Single parsed access log record."""

    ip: str
    timestamp: datetime
    method: str
    path: str
    status_code: int
    bytes_sent: int
    user_agent: str
    referer: str


@dataclass(frozen=True)
class LogSummary:
    """Aggregated statistics for a set of log entries."""

    total_requests: int
    unique_ips: int
    error_rate: float
    top_ips: tuple[tuple[str, int], ...]
    top_paths: tuple[tuple[str, int], ...]
    status_distribution: dict[int, int]


def parse_line(line: str) -> LogEntry | None:
    """Parse a single *line* of combined or common log format.

    Args:
        line: A single access log line.

    Returns:
        LogEntry if the line matches, or None if it does not.
    """
    m = COMBINED_LOG_RE.match(line.strip())
    if not m:
        return None
    ts = _parse_timestamp(m.group("time"))
    if ts is None:
        return None
    bytes_str = m.group("bytes")
    return LogEntry(
        ip=m.group("ip"),
        timestamp=ts,
        method=m.group("method"),
        path=m.group("path"),
        status_code=int(m.group("status")),
        bytes_sent=int(bytes_str) if bytes_str.isdigit() else 0,
        user_agent=m.group("ua") or UNKNOWN,
        referer=m.group("referer") or UNKNOWN,
    )


def parse_file(path: str) -> list[LogEntry]:
    """Parse all valid lines in the log file at *path*.

    Args:
        path: Path to an Apache/Nginx access log file.

    Returns:
        List of parsed LogEntry objects (invalid lines are skipped).

    Raises:
        OSError: If *path* cannot be opened.
    """
    with open(path, encoding="utf-8", errors="replace") as fh:
        return [e for line in fh if (e := parse_line(line)) is not None]


def parse_string(content: str) -> list[LogEntry]:
    """Parse all valid lines in the log string *content*.

    Args:
        content: Multi-line log content.

    Returns:
        List of parsed LogEntry objects.
    """
    return [e for line in content.splitlines() if (e := parse_line(line)) is not None]


def summarize(entries: list[LogEntry], top_n: int = TOP_N_DEFAULT) -> LogSummary:
    """Compute aggregate statistics over *entries*.

    Args:
        entries: List of LogEntry objects.
        top_n: Number of top entries to return.

    Returns:
        LogSummary with counts, rates, and top-N rankings.
    """
    if not entries:
        return LogSummary(0, 0, 0.0, (), (), {})
    total = len(entries)
    ip_counts: Counter[str] = Counter(e.ip for e in entries)
    path_counts: Counter[str] = Counter(e.path for e in entries)
    status_counts: Counter[int] = Counter(e.status_code for e in entries)
    errors = sum(v for k, v in status_counts.items() if k >= 400)
    return LogSummary(
        total_requests=total,
        unique_ips=len(ip_counts),
        error_rate=errors / total,
        top_ips=tuple(ip_counts.most_common(top_n)),
        top_paths=tuple(path_counts.most_common(top_n)),
        status_distribution=dict(status_counts),
    )


def _parse_timestamp(ts_str: str) -> datetime | None:
    try:
        return datetime.strptime(ts_str, DATE_FORMAT)
    except ValueError:
        return None
