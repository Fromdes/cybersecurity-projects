"""SSH brute-force detection from auth.log / syslog lines."""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Final

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_THRESHOLD: Final[int] = 5
DEFAULT_WINDOW: Final[int] = 60  # seconds

_FAILED_RE: Final[re.Pattern[str]] = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\d.]+)"
)
_ACCEPTED_RE: Final[re.Pattern[str]] = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)"
)
_INVALID_USER_RE: Final[re.Pattern[str]] = re.compile(
    r"Invalid user (\S+) from ([\d.]+)"
)
_DISCONNECT_RE: Final[re.Pattern[str]] = re.compile(
    r"Disconnected from (?:invalid user )?(?:\S+ )?([\d.]+)"
)
_TIMESTAMP_RE: Final[re.Pattern[str]] = re.compile(
    r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)"
)

# Month abbreviations for timestamp parsing
MONTHS: Final[dict[str, int]] = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class LoginAttempt:
    """A single SSH login attempt parsed from a log line."""

    timestamp: float
    src_ip: str
    username: str
    success: bool
    raw_line: str


@dataclass(frozen=True)
class BruteForceAlert:
    """Detected SSH brute-force attack."""

    src_ip: str
    attempt_count: int
    window_seconds: float
    usernames: tuple[str, ...]
    first_attempt: float
    last_attempt: float
    severity: str


# ---------------------------------------------------------------------------
# Log line parser
# ---------------------------------------------------------------------------

def parse_syslog_timestamp(line: str, year: int | None = None) -> float:
    """Parse syslog timestamp to epoch float. Returns 0.0 on failure."""
    import time as _time
    m = _TIMESTAMP_RE.match(line)
    if not m:
        return 0.0
    ts_str = m.group(1)
    try:
        parts = ts_str.split()
        month = MONTHS.get(parts[0], 1)
        day = int(parts[1])
        h, mi, s = (int(x) for x in parts[2].split(":"))
        yr = year or _time.localtime().tm_year
        return _time.mktime((yr, month, day, h, mi, s, 0, 0, -1))
    except (ValueError, IndexError):
        return 0.0


def parse_line(line: str, base_timestamp: float = 0.0) -> LoginAttempt | None:
    """Parse an auth.log line into a LoginAttempt."""
    ts = parse_syslog_timestamp(line) or base_timestamp

    m = _FAILED_RE.search(line)
    if m:
        return LoginAttempt(
            timestamp=ts, src_ip=m.group(2),
            username=m.group(1), success=False, raw_line=line,
        )

    m = _INVALID_USER_RE.search(line)
    if m:
        return LoginAttempt(
            timestamp=ts, src_ip=m.group(2),
            username=m.group(1), success=False, raw_line=line,
        )

    m = _ACCEPTED_RE.search(line)
    if m:
        return LoginAttempt(
            timestamp=ts, src_ip=m.group(2),
            username=m.group(1), success=True, raw_line=line,
        )

    return None


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

@dataclass
class BruteForceDetector:
    """Sliding-window SSH brute-force detector."""

    threshold: int = DEFAULT_THRESHOLD
    window: int = DEFAULT_WINDOW

    # ip → list of (timestamp, username)
    _attempts: dict[str, list[tuple[float, str]]] = field(
        default_factory=lambda: defaultdict(list), repr=False
    )
    _alerted: set[str] = field(default_factory=set, repr=False)

    def record(self, attempt: LoginAttempt) -> None:
        if not attempt.success:
            self._attempts[attempt.src_ip].append(
                (attempt.timestamp, attempt.username)
            )

    def analyse(self, current_time: float | None = None) -> list[BruteForceAlert]:
        now = current_time if current_time is not None else time.time()
        window_start = now - self.window
        alerts: list[BruteForceAlert] = []

        for ip, entries in self._attempts.items():
            recent = [(ts, user) for ts, user in entries if ts >= window_start]
            if len(recent) >= self.threshold:
                usernames = tuple({u for _, u in recent})
                ts_values = [ts for ts, _ in recent]
                severity = "high" if len(recent) >= self.threshold * 3 else "medium"
                alerts.append(BruteForceAlert(
                    src_ip=ip,
                    attempt_count=len(recent),
                    window_seconds=float(self.window),
                    usernames=usernames,
                    first_attempt=min(ts_values),
                    last_attempt=max(ts_values),
                    severity=severity,
                ))

        return sorted(alerts, key=lambda a: a.attempt_count, reverse=True)

    def reset_ip(self, ip: str) -> None:
        self._attempts.pop(ip, None)


# ---------------------------------------------------------------------------
# File analyser
# ---------------------------------------------------------------------------

def analyse_auth_log(
    lines: list[str],
    *,
    threshold: int = DEFAULT_THRESHOLD,
    window: int = DEFAULT_WINDOW,
) -> list[BruteForceAlert]:
    """Analyse a list of auth.log lines and return brute-force alerts."""
    detector = BruteForceDetector(threshold=threshold, window=window)
    base_ts = 1700000000.0
    for i, line in enumerate(lines):
        attempt = parse_line(line, base_timestamp=base_ts + i)
        if attempt:
            detector.record(attempt)
    max_ts = base_ts + len(lines)
    return detector.analyse(current_time=max_ts)
