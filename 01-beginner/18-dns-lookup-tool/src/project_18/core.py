"""DNS record lookup and reverse-resolution utilities."""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import dns.exception
import dns.resolver
import dns.reversename

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT: float = 5.0


class RecordType(StrEnum):
    """Supported DNS record types."""

    A = "A"
    AAAA = "AAAA"
    MX = "MX"
    TXT = "TXT"
    NS = "NS"
    CNAME = "CNAME"
    SOA = "SOA"
    PTR = "PTR"


@dataclass(frozen=True)
class DNSRecord:
    """A single DNS resource record."""

    name: str
    record_type: RecordType
    ttl: int
    value: str


def lookup(
    hostname: str,
    record_type: RecordType,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[DNSRecord]:
    """Resolve DNS records for *hostname*.

    Args:
        hostname: FQDN or short name to resolve.
        record_type: DNS record type to query.
        timeout: Query timeout in seconds.

    Returns:
        List of DNSRecord instances.

    Raises:
        ValueError: If hostname is empty.
        dns.exception.DNSException: On resolution failure.
    """
    if not hostname.strip():
        raise ValueError("hostname must not be empty")
    resolver = _make_resolver(timeout)
    try:
        answer = resolver.resolve(hostname, record_type.value)
    except dns.resolver.NXDOMAIN as exc:
        raise dns.exception.DNSException(f"No such domain: {hostname}") from exc
    except dns.resolver.NoAnswer as exc:
        raise dns.exception.DNSException(
            f"No {record_type.value} records for: {hostname}"
        ) from exc
    ttl = answer.rrset.ttl if answer.rrset else 0
    return [
        DNSRecord(
            name=str(answer.qname),
            record_type=record_type,
            ttl=ttl,
            value=_rdata_str(rdata),
        )
        for rdata in answer
    ]


def reverse_lookup(ip: str, timeout: float = DEFAULT_TIMEOUT) -> list[DNSRecord]:
    """Perform a reverse DNS lookup (PTR query) for *ip*.

    Args:
        ip: IPv4 or IPv6 address string.
        timeout: Query timeout in seconds.

    Returns:
        List of PTR DNSRecord instances.

    Raises:
        ValueError: If *ip* is not a valid IP address.
        dns.exception.DNSException: On resolution failure.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {ip!r}") from exc
    ptr_name = dns.reversename.from_address(ip)
    resolver = _make_resolver(timeout)
    try:
        answer = resolver.resolve(ptr_name, "PTR")
    except dns.resolver.NXDOMAIN as exc:
        raise dns.exception.DNSException(f"No PTR record for: {ip}") from exc
    ttl = answer.rrset.ttl if answer.rrset else 0
    return [
        DNSRecord(
            name=str(ptr_name),
            record_type=RecordType.PTR,
            ttl=ttl,
            value=str(rdata),
        )
        for rdata in answer
    ]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _make_resolver(timeout: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def _rdata_str(rdata: Any) -> str:
    return str(rdata)
