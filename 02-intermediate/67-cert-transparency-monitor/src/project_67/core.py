"""Certificate Transparency log monitor — watches crt.sh for new certificates issued for domains."""

from __future__ import annotations

import datetime
import fnmatch
import json
import re
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import urlencode
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CRTSH_API_URL: Final[str] = "https://crt.sh/"
DEFAULT_TIMEOUT: Final[int] = 15
_DOMAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CTLogEntry:
    """A single certificate found in Certificate Transparency logs."""

    id: int
    logged_at: datetime.datetime
    not_before: datetime.datetime
    not_after: datetime.datetime
    common_name: str
    name_value: str  # may contain multiple SANs separated by newlines
    issuer_name: str
    serial_number: str

    @property
    def domains(self) -> list[str]:
        """Return list of unique domains from name_value."""
        seen: set[str] = set()
        result: list[str] = []
        for line in self.name_value.splitlines():
            d = line.strip().lower()
            if d and d not in seen:
                seen.add(d)
                result.append(d)
        return result

    @property
    def is_wildcard(self) -> bool:
        """Return True if any domain in this cert is a wildcard."""
        return any(d.startswith("*.") for d in self.domains)

    @property
    def is_expired(self) -> bool:
        """Return True if the certificate is currently expired."""
        now = datetime.datetime.now(tz=datetime.UTC)
        expiry = self.not_after
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=datetime.UTC)
        return now > expiry

    @property
    def days_until_expiry(self) -> int:
        """Days until certificate expires (negative if already expired)."""
        now = datetime.datetime.now(tz=datetime.UTC)
        expiry = self.not_after
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=datetime.UTC)
        return (expiry - now).days


@dataclass
class CTMonitorResult:
    """Results from a CT log monitoring query."""

    domain: str
    queried_at: datetime.datetime = field(default_factory=lambda: datetime.datetime.now(tz=datetime.UTC))
    entries: list[CTLogEntry] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        """Total number of certificates found."""
        return len(self.entries)

    @property
    def wildcard_count(self) -> int:
        """Number of wildcard certificates."""
        return sum(1 for e in self.entries if e.is_wildcard)

    @property
    def expired_count(self) -> int:
        """Number of expired certificates."""
        return sum(1 for e in self.entries if e.is_expired)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

_DT_FORMATS: Final[list[str]] = [
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
]


def _parse_dt(value: str) -> datetime.datetime:
    """Parse a datetime string from crt.sh JSON.

    Args:
        value: ISO-ish datetime string.

    Returns:
        Timezone-aware datetime in UTC.

    Raises:
        ValueError: If the string cannot be parsed.
    """
    if not value:
        raise ValueError("Empty datetime string")
    value = value.rstrip("Z")
    for fmt in _DT_FORMATS:
        try:
            dt = datetime.datetime.strptime(value, fmt)
            return dt.replace(tzinfo=datetime.UTC)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse datetime: {value!r}")


def parse_crtsh_response(data: list[dict]) -> list[CTLogEntry]:  # type: ignore[type-arg]
    """Parse the JSON list returned by crt.sh into CTLogEntry objects.

    Args:
        data: Parsed JSON list from crt.sh API.

    Returns:
        List of CTLogEntry, deduplicated by (id).
    """
    seen_ids: set[int] = set()
    entries: list[CTLogEntry] = []
    for item in data:
        entry_id = int(item.get("id", 0))
        if entry_id in seen_ids:
            continue
        seen_ids.add(entry_id)
        try:
            entry = CTLogEntry(
                id=entry_id,
                logged_at=_parse_dt(item.get("entry_timestamp", "") or item.get("logged_at", "")),
                not_before=_parse_dt(item.get("not_before", "")),
                not_after=_parse_dt(item.get("not_after", "")),
                common_name=item.get("common_name", ""),
                name_value=item.get("name_value", ""),
                issuer_name=item.get("issuer_name", ""),
                serial_number=item.get("serial_number", ""),
            )
        except (ValueError, KeyError):
            continue
        entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# CT log query
# ---------------------------------------------------------------------------

def query_crtsh(domain: str, *, timeout: int = DEFAULT_TIMEOUT) -> list[dict]:  # type: ignore[type-arg]
    """Query crt.sh for certificates matching domain.

    Args:
        domain: Domain name (wildcards like %.example.com are supported).
        timeout: HTTP timeout in seconds.

    Returns:
        Parsed JSON list from crt.sh.

    Raises:
        ValueError: If domain is syntactically invalid.
        OSError: On network failure.
    """
    if not _DOMAIN_RE.match(domain.lstrip("*.")):
        # Allow wildcard queries (%.example.com) but validate the base
        base = domain.lstrip("%.*")
        if not _DOMAIN_RE.match(base) and not re.match(r"^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", base):
            raise ValueError(f"Invalid domain: {domain!r}")

    params = urlencode({"q": domain, "output": "json"})
    url = f"{CRTSH_API_URL}?{params}"
    req = Request(url, headers={"User-Agent": "ct-monitor/1.0 (defensive-security)"})
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return json.loads(raw)  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

def detect_anomalies(result: CTMonitorResult, *, watched_issuers: list[str] | None = None) -> None:
    """Populate result.anomalies with suspicious findings.

    Args:
        result: A CTMonitorResult with entries already populated.
        watched_issuers: Optional list of issuer substrings to flag if NOT present.
    """
    if not result.entries:
        return

    issuer_counts: dict[str, int] = {}
    for entry in result.entries:
        issuer = entry.issuer_name or "unknown"
        issuer_counts[issuer] = issuer_counts.get(issuer, 0) + 1

    if watched_issuers:
        for entry in result.entries:
            known = any(w.lower() in entry.issuer_name.lower() for w in watched_issuers)
            if not known:
                result.anomalies.append(
                    f"UNEXPECTED_ISSUER: {entry.common_name} issued by {entry.issuer_name!r} (id={entry.id})"
                )

    # Flag certificates issued very recently (within 24 h) for monitoring
    recent_cutoff = datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(hours=24)
    recent = [e for e in result.entries if e.logged_at >= recent_cutoff]
    if len(recent) >= 5:
        result.anomalies.append(
            f"ISSUANCE_SPIKE: {len(recent)} certificates issued/logged in the last 24 h"
        )

    # Flag unexpected subdomain patterns
    for entry in result.entries:
        for domain in entry.domains:
            parts = domain.lstrip("*.").split(".")
            if len(parts) > 5:
                result.anomalies.append(
                    f"DEEP_SUBDOMAIN: {domain} in cert id={entry.id}"
                )
                break


def monitor(
    domain: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    watched_issuers: list[str] | None = None,
) -> CTMonitorResult:
    """Run a full CT log monitor query and anomaly check.

    Args:
        domain: Domain to monitor (e.g. 'example.com' or '%.example.com').
        timeout: HTTP timeout in seconds.
        watched_issuers: Issuer substrings to consider trusted.

    Returns:
        CTMonitorResult with entries and anomalies.
    """
    data = query_crtsh(domain, timeout=timeout)
    entries = parse_crtsh_response(data)
    result = CTMonitorResult(domain=domain, entries=entries)
    detect_anomalies(result, watched_issuers=watched_issuers)
    return result


def filter_entries(
    entries: list[CTLogEntry],
    *,
    since: datetime.datetime | None = None,
    domain_glob: str | None = None,
    include_expired: bool = True,
) -> list[CTLogEntry]:
    """Filter a list of CT entries by date, domain pattern, or expiry status.

    Args:
        entries: Input list.
        since: Only entries logged after this datetime.
        domain_glob: Unix-style glob pattern matched against common_name.
        include_expired: If False, excludes expired certificates.

    Returns:
        Filtered list of CTLogEntry.
    """
    result = entries
    if since is not None:
        result = [e for e in result if e.logged_at >= since]
    if domain_glob is not None:
        result = [e for e in result if fnmatch.fnmatch(e.common_name.lower(), domain_glob.lower())]
    if not include_expired:
        result = [e for e in result if not e.is_expired]
    return result
