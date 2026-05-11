"""Auth log parsing and brute-force attempt detection."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

FAILED_PASSWORD_RE: re.Pattern[str] = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port"
)
INVALID_USER_RE: re.Pattern[str] = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+) port"
)
AUTH_FAILURE_RE: re.Pattern[str] = re.compile(
    r"authentication failure.*?(?:user=(?P<user>\S+))?.*rhost=(?P<ip>\S+)"
)
TIMESTAMP_RE: re.Pattern[str] = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
)
DEFAULT_THRESHOLD: int = 5
UNKNOWN: str = "unknown"


@dataclass(frozen=True)
class FailedAttempt:
    """A single failed authentication attempt extracted from a log line."""

    timestamp: str
    ip: str
    username: str
    service: str


@dataclass(frozen=True)
class BruteForceAlert:
    """Summary of repeated failed logins from a single IP."""

    ip: str
    attempt_count: int
    targeted_users: tuple[str, ...]
    is_alert: bool


def parse_log(path: str) -> list[FailedAttempt]:
    """Parse *path* for failed authentication events.

    Args:
        path: Path to an auth log file (e.g. /var/log/auth.log).

    Returns:
        List of FailedAttempt records.

    Raises:
        OSError: If *path* cannot be opened.
    """
    with open(path, encoding="utf-8", errors="replace") as fh:
        return parse_string(fh.read())


def parse_string(content: str) -> list[FailedAttempt]:
    """Parse auth log *content* for failed authentication events.

    Args:
        content: Multi-line auth log content.

    Returns:
        List of FailedAttempt records.
    """
    return [a for line in content.splitlines() if (a := _parse_line(line)) is not None]


def detect_brute_force(
    attempts: list[FailedAttempt],
    threshold: int = DEFAULT_THRESHOLD,
) -> list[BruteForceAlert]:
    """Group *attempts* by IP and flag those exceeding *threshold*.

    Args:
        attempts: List of FailedAttempt records.
        threshold: Minimum attempt count to generate an alert.

    Returns:
        List of BruteForceAlert sorted by attempt count (descending).
    """
    ip_users: dict[str, set[str]] = defaultdict(set)
    ip_count: dict[str, int] = defaultdict(int)
    for attempt in attempts:
        ip_count[attempt.ip] += 1
        ip_users[attempt.ip].add(attempt.username)
    alerts = [
        BruteForceAlert(
            ip=ip,
            attempt_count=count,
            targeted_users=tuple(sorted(ip_users[ip])),
            is_alert=count >= threshold,
        )
        for ip, count in ip_count.items()
    ]
    return sorted(alerts, key=lambda a: a.attempt_count, reverse=True)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_line(line: str) -> FailedAttempt | None:
    ts_m = TIMESTAMP_RE.match(line)
    ts = ts_m.group("ts") if ts_m else ""
    for pattern in (FAILED_PASSWORD_RE, INVALID_USER_RE, AUTH_FAILURE_RE):
        m = pattern.search(line)
        if m:
            user = (m.groupdict().get("user") or UNKNOWN).strip()
            ip = (m.groupdict().get("ip") or UNKNOWN).strip()
            service = _extract_service(line)
            return FailedAttempt(timestamp=ts, ip=ip, username=user, service=service)
    return None


def _extract_service(line: str) -> str:
    m = re.search(r"\b(sshd|su|sudo|login|vsftpd|ftpd|passwd)\b", line)
    return m.group(1) if m else UNKNOWN
