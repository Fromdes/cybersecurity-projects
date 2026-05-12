"""Login anomaly detector — baseline user behaviour and flag deviations in login events."""

from __future__ import annotations

import datetime
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_FAILED_LOGINS: Final[int] = 5       # consecutive failures before alarm
UNUSUAL_HOUR_START: Final[int] = 0      # midnight
UNUSUAL_HOUR_END: Final[int] = 5        # 5 AM — logins between 00:00–04:59 are unusual
NEW_COUNTRY_WEIGHT: Final[float] = 0.40
NEW_IP_WEIGHT: Final[float] = 0.15
UNUSUAL_HOUR_WEIGHT: Final[float] = 0.20
CREDENTIAL_STUFFING_WEIGHT: Final[float] = 0.30
IMPOSSIBLE_TRAVEL_WEIGHT: Final[float] = 0.50
BRUTE_FORCE_WEIGHT: Final[float] = 0.35

# Simplified GeoIP mapping for testing — real implementation uses a GeoIP DB
_COUNTRY_IP_PREFIXES: Final[dict[str, str]] = {
    "10.": "private",
    "192.168.": "private",
    "172.": "private",
}

# Log line format: "2024-01-15T10:30:00 username src_ip status [country]"
_LOG_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+"
    r"(?P<user>\S+)\s+"
    r"(?P<ip>\S+)\s+"
    r"(?P<status>success|failure|locked)\s*"
    r"(?P<country>\S+)?$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LoginEvent:
    """A single parsed login event."""

    timestamp: datetime.datetime
    username: str
    src_ip: str
    status: str   # "success" | "failure" | "locked"
    country: str  # "" if unknown


@dataclass(frozen=True)
class LoginAnomaly:
    """A detected anomaly in login activity."""

    username: str
    anomaly_type: str
    description: str
    severity: str    # "critical" | "high" | "medium" | "low"
    timestamp: datetime.datetime
    confidence: float   # 0.0–1.0


@dataclass
class UserProfile:
    """Baseline behaviour profile for a single user."""

    username: str
    known_ips: set[str] = field(default_factory=set)
    known_countries: set[str] = field(default_factory=set)
    typical_hours: set[int] = field(default_factory=set)   # hours 0–23
    total_logins: int = 0
    total_failures: int = 0

    def update(self, event: LoginEvent) -> None:
        """Update profile from a successful login event."""
        if event.status == "success":
            self.known_ips.add(event.src_ip)
            if event.country:
                self.known_countries.add(event.country)
            self.typical_hours.add(event.timestamp.hour)
            self.total_logins += 1
        elif event.status == "failure":
            self.total_failures += 1


@dataclass
class AnomalyDetectorState:
    """Running state for login anomaly detection."""

    profiles: dict[str, UserProfile] = field(default_factory=dict)
    anomalies: list[LoginAnomaly] = field(default_factory=list)
    _consecutive_failures: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _last_success: dict[str, LoginEvent] = field(default_factory=dict)

    def get_profile(self, username: str) -> UserProfile:
        """Return (creating if needed) the profile for a user."""
        if username not in self.profiles:
            self.profiles[username] = UserProfile(username=username)
        return self.profiles[username]


# ---------------------------------------------------------------------------
# Log parser
# ---------------------------------------------------------------------------

def parse_login_line(line: str) -> LoginEvent | None:
    """Parse a single log line into a LoginEvent.

    Args:
        line: Log line in format: ``YYYY-MM-DDTHH:MM:SS user ip status [country]``.

    Returns:
        LoginEvent or None if the line does not match.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = _LOG_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.datetime.fromisoformat(m.group("ts"))
    except ValueError:
        return None
    return LoginEvent(
        timestamp=ts,
        username=m.group("user").lower(),
        src_ip=m.group("ip"),
        status=m.group("status").lower(),
        country=m.group("country") or "",
    )


def parse_log_file(lines: list[str]) -> list[LoginEvent]:
    """Parse a list of log lines into LoginEvents.

    Args:
        lines: Raw log lines.

    Returns:
        List of successfully parsed LoginEvent objects.
    """
    events: list[LoginEvent] = []
    for line in lines:
        event = parse_login_line(line)
        if event is not None:
            events.append(event)
    return sorted(events, key=lambda e: e.timestamp)


# ---------------------------------------------------------------------------
# Anomaly detection checks
# ---------------------------------------------------------------------------

def _check_brute_force(
    event: LoginEvent,
    state: AnomalyDetectorState,
    threshold: int,
) -> LoginAnomaly | None:
    """Detect consecutive login failures (brute force)."""
    if event.status == "failure":
        state._consecutive_failures[event.username] += 1
        count = state._consecutive_failures[event.username]
        if count >= threshold:
            return LoginAnomaly(
                username=event.username,
                anomaly_type="BRUTE_FORCE",
                description=f"{count} consecutive login failures from {event.src_ip}",
                severity="high" if count < threshold * 2 else "critical",
                timestamp=event.timestamp,
                confidence=min(1.0, BRUTE_FORCE_WEIGHT + (count - threshold) * 0.05),
            )
    else:
        state._consecutive_failures[event.username] = 0
    return None


def _check_new_country(
    event: LoginEvent,
    profile: UserProfile,
) -> LoginAnomaly | None:
    """Detect login from a new/unseen country."""
    if (
        event.status == "success"
        and event.country
        and profile.known_countries
        and event.country not in profile.known_countries
    ):
        return LoginAnomaly(
            username=event.username,
            anomaly_type="NEW_COUNTRY",
            description=f"Login from new country {event.country!r} (known: {sorted(profile.known_countries)})",
            severity="high",
            timestamp=event.timestamp,
            confidence=NEW_COUNTRY_WEIGHT,
        )
    return None


def _check_new_ip(
    event: LoginEvent,
    profile: UserProfile,
) -> LoginAnomaly | None:
    """Detect login from a new/unseen IP address."""
    if (
        event.status == "success"
        and profile.known_ips
        and event.src_ip not in profile.known_ips
    ):
        return LoginAnomaly(
            username=event.username,
            anomaly_type="NEW_IP",
            description=f"Login from new IP {event.src_ip}",
            severity="low",
            timestamp=event.timestamp,
            confidence=NEW_IP_WEIGHT,
        )
    return None


def _check_unusual_hour(
    event: LoginEvent,
    profile: UserProfile,
) -> LoginAnomaly | None:
    """Detect logins during unusual hours (midnight–5 AM)."""
    hour = event.timestamp.hour
    if (
        event.status == "success"
        and UNUSUAL_HOUR_START <= hour < UNUSUAL_HOUR_END
        and profile.total_logins >= 5   # only flag if we have a baseline
        and hour not in profile.typical_hours
    ):
        return LoginAnomaly(
            username=event.username,
            anomaly_type="UNUSUAL_HOUR",
            description=f"Login at unusual hour {hour:02d}:00",
            severity="medium",
            timestamp=event.timestamp,
            confidence=UNUSUAL_HOUR_WEIGHT,
        )
    return None


def _check_impossible_travel(
    event: LoginEvent,
    profile: UserProfile,
    state: AnomalyDetectorState,
) -> LoginAnomaly | None:
    """Detect logically impossible rapid country changes (impossible travel)."""
    if event.status != "success" or not event.country:
        return None

    last = state._last_success.get(event.username)
    if last is None or not last.country:
        return None

    if last.country == event.country:
        return None

    # Time delta in hours
    delta_hours = (event.timestamp - last.timestamp).total_seconds() / 3600

    # If different countries within 2 hours, flag as impossible travel
    if delta_hours < 2.0:
        return LoginAnomaly(
            username=event.username,
            anomaly_type="IMPOSSIBLE_TRAVEL",
            description=(
                f"Country changed from {last.country!r} to {event.country!r} "
                f"in {delta_hours:.1f} hours"
            ),
            severity="critical",
            timestamp=event.timestamp,
            confidence=IMPOSSIBLE_TRAVEL_WEIGHT,
        )
    return None


def _check_credential_stuffing(
    events: list[LoginEvent],
) -> list[LoginAnomaly]:
    """Detect credential stuffing: single IP targeting many users.

    Args:
        events: All events to check (scanned once for IP → users mapping).

    Returns:
        List of anomalies for IPs that failed against many users.
    """
    ip_users: dict[str, set[str]] = defaultdict(set)
    ip_failures: dict[str, int] = defaultdict(int)

    for e in events:
        if e.status == "failure":
            ip_users[e.src_ip].add(e.username)
            ip_failures[e.src_ip] += 1

    anomalies: list[LoginAnomaly] = []
    for ip, users in ip_users.items():
        if len(users) >= 5:
            ts = max(e.timestamp for e in events if e.src_ip == ip and e.status == "failure")
            anomalies.append(LoginAnomaly(
                username="<multiple>",
                anomaly_type="CREDENTIAL_STUFFING",
                description=(
                    f"IP {ip} attempted {ip_failures[ip]} failures against "
                    f"{len(users)} distinct users"
                ),
                severity="critical",
                timestamp=ts,
                confidence=CREDENTIAL_STUFFING_WEIGHT,
            ))
    return anomalies


# ---------------------------------------------------------------------------
# Main analyser
# ---------------------------------------------------------------------------

def analyse_events(
    events: list[LoginEvent],
    *,
    brute_force_threshold: int = MAX_FAILED_LOGINS,
    baseline_events: list[LoginEvent] | None = None,
) -> AnomalyDetectorState:
    """Analyse a list of login events and detect anomalies.

    Args:
        events: Login events to analyse (chronological).
        brute_force_threshold: Consecutive failures before brute-force alarm.
        baseline_events: Historical events to build user profiles before analysis.

    Returns:
        AnomalyDetectorState with profiles and anomalies.
    """
    state = AnomalyDetectorState()

    # Build baseline profiles from historical events
    for event in (baseline_events or []):
        profile = state.get_profile(event.username)
        profile.update(event)
        if event.status == "success":
            state._last_success[event.username] = event

    # Analyse new events
    for event in events:
        profile = state.get_profile(event.username)

        anomaly = _check_brute_force(event, state, brute_force_threshold)
        if anomaly:
            state.anomalies.append(anomaly)

        if event.status == "success":
            country_anomaly = _check_new_country(event, profile)
            if country_anomaly:
                state.anomalies.append(country_anomaly)

            ip_anomaly = _check_new_ip(event, profile)
            if ip_anomaly:
                state.anomalies.append(ip_anomaly)

            hour_anomaly = _check_unusual_hour(event, profile)
            if hour_anomaly:
                state.anomalies.append(hour_anomaly)

            travel_anomaly = _check_impossible_travel(event, profile, state)
            if travel_anomaly:
                state.anomalies.append(travel_anomaly)

            state._last_success[event.username] = event

        profile.update(event)

    # Batch check for credential stuffing
    stuffing = _check_credential_stuffing(events)
    state.anomalies.extend(stuffing)

    return state


def analyse_log_file(lines: list[str], **kwargs: object) -> AnomalyDetectorState:
    """Parse and analyse login log lines.

    Args:
        lines: Raw log file lines.
        **kwargs: Passed to ``analyse_events``.

    Returns:
        AnomalyDetectorState.
    """
    events = parse_log_file(lines)
    return analyse_events(events, **kwargs)  # type: ignore[arg-type]
