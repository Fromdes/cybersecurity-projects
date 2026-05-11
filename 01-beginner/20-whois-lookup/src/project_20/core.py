"""WHOIS lookup and parsing for domain names and IP addresses."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import whois  # python-whois

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class WhoisResult:
    """Parsed WHOIS record for a domain or IP query."""

    query: str
    registrar: str
    creation_date: datetime | None
    expiration_date: datetime | None
    updated_date: datetime | None
    name_servers: tuple[str, ...]
    status: tuple[str, ...]
    emails: tuple[str, ...]
    country: str
    dnssec: str


def lookup(query: str) -> WhoisResult:
    """Perform a WHOIS query for *query*.

    Args:
        query: Domain name (e.g. ``"example.com"``) or IP address string.

    Returns:
        WhoisResult with parsed registration metadata.

    Raises:
        ValueError: If *query* is empty.
        whois.parser.PywhoisError: On WHOIS lookup failure.
    """
    if not query.strip():
        raise ValueError("query must not be empty")
    log.debug("WHOIS lookup: %s", query)
    data: Any = whois.whois(query)
    return _parse(query, data)


def _parse(query: str, data: Any) -> WhoisResult:
    return WhoisResult(
        query=query,
        registrar=_str_or_empty(data.registrar),
        creation_date=_first_date(data.creation_date),
        expiration_date=_first_date(data.expiration_date),
        updated_date=_first_date(data.updated_date),
        name_servers=tuple(
            s.lower() for s in _list_of_str(data.name_servers)
        ),
        status=tuple(_list_of_str(data.status)),
        emails=tuple(_list_of_str(data.emails)),
        country=_str_or_empty(data.country),
        dnssec=_str_or_empty(data.dnssec),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _str_or_empty(val: object) -> str:
    return str(val).strip() if val else ""


def _first_date(val: object) -> datetime | None:
    if isinstance(val, list):
        return val[0] if val else None
    return val if isinstance(val, datetime) else None


def _list_of_str(val: object) -> list[str]:
    if isinstance(val, list):
        return [str(v) for v in val if v]
    return [str(val)] if val else []
