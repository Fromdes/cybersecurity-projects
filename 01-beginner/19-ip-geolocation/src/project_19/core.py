"""IP geolocation and ASN lookup via ip-api.com (free tier)."""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

import requests

log = logging.getLogger(__name__)

API_BASE_URL: str = "https://ip-api.com/json/{ip}"
REQUEST_TIMEOUT: float = 10.0
SUCCESS_STATUS: str = "success"
CALLER_SENTINEL: str = "me"

API_FIELDS: str = (
    "status,message,country,countryCode,regionName,"
    "city,lat,lon,isp,org,as,proxy,hosting,query,timezone"
)


@dataclass(frozen=True)
class GeoResult:
    """Geolocation and ASN information for a single IP address."""

    ip: str
    country: str
    country_code: str
    region: str
    city: str
    latitude: float
    longitude: float
    isp: str
    org: str
    asn: str
    timezone: str
    is_proxy: bool
    is_hosting: bool


def lookup_ip(ip: str) -> GeoResult:
    """Geolocate *ip* and return ASN/ownership metadata.

    Args:
        ip: IPv4 or IPv6 address. Use ``"me"`` to look up the caller's IP.

    Returns:
        GeoResult with location and network context.

    Raises:
        ValueError: If *ip* is not a valid address (and not ``"me"``).
        requests.RequestException: On HTTP/network errors.
        RuntimeError: If the API returns a failure status.
    """
    if ip != CALLER_SENTINEL:
        _validate_ip(ip)
    url = API_BASE_URL.format(ip=ip)
    response = requests.get(url, params={"fields": API_FIELDS}, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    data: dict[str, object] = response.json()
    if data.get("status") != SUCCESS_STATUS:
        raise RuntimeError(f"API error: {data.get('message', 'unknown error')}")
    return _parse_result(data)


def _validate_ip(ip: str) -> None:
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {ip!r}") from exc


def _parse_result(data: dict[str, object]) -> GeoResult:
    return GeoResult(
        ip=str(data.get("query", "")),
        country=str(data.get("country", "")),
        country_code=str(data.get("countryCode", "")),
        region=str(data.get("regionName", "")),
        city=str(data.get("city", "")),
        latitude=float(data.get("lat", 0.0)),  # type: ignore[arg-type]
        longitude=float(data.get("lon", 0.0)),  # type: ignore[arg-type]
        isp=str(data.get("isp", "")),
        org=str(data.get("org", "")),
        asn=str(data.get("as", "")),
        timezone=str(data.get("timezone", "")),
        is_proxy=bool(data.get("proxy", False)),
        is_hosting=bool(data.get("hosting", False)),
    )
