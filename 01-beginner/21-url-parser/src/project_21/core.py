"""URL parsing, validation, and structural analysis."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import ParseResult, parse_qs, urlparse

ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https", "ftp", "ftps"})
SUSPICIOUS_SCHEMES: frozenset[str] = frozenset({"javascript", "vbscript", "data", "file"})
PRIVATE_PORTS: frozenset[int] = frozenset({21, 22, 23, 25, 53, 110, 143, 3306, 3389, 5432, 5900})
MAX_URL_LENGTH: int = 2048
MAX_SUBDOMAIN_DEPTH: int = 5
MAX_QUERY_PARAMS: int = 20


@dataclass(frozen=True)
class URLComponents:
    """Parsed URL with validation warnings."""

    scheme: str
    host: str
    port: int | None
    path: str
    query_params: dict[str, list[str]]
    fragment: str
    is_ip_host: bool
    is_valid: bool
    warnings: tuple[str, ...]


def parse_url(url: str) -> URLComponents:
    """Parse *url* into components and collect structural warnings.

    Args:
        url: URL string to parse.

    Returns:
        URLComponents with parsed fields and any warnings.

    Raises:
        ValueError: If url is empty.
    """
    if not url.strip():
        raise ValueError("URL must not be empty")
    parsed = urlparse(url)
    host = parsed.hostname or ""
    is_ip = _is_ip_host(host)
    warnings = _collect_warnings(url, parsed, is_ip)
    is_valid = bool(parsed.scheme and parsed.netloc)
    return URLComponents(
        scheme=parsed.scheme,
        host=host,
        port=parsed.port,
        path=parsed.path,
        query_params=parse_qs(parsed.query),
        fragment=parsed.fragment,
        is_ip_host=is_ip,
        is_valid=is_valid,
        warnings=tuple(warnings),
    )


def validate_url(url: str) -> tuple[bool, list[str]]:
    """Check whether *url* is valid and return a list of issues.

    Args:
        url: URL string to validate.

    Returns:
        Tuple of (is_valid, list_of_issue_strings).
    """
    try:
        components = parse_url(url)
    except ValueError as exc:
        return False, [str(exc)]
    return components.is_valid, list(components.warnings)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _collect_warnings(url: str, parsed: ParseResult, is_ip: bool) -> list[str]:
    warnings: list[str] = []
    if not parsed.scheme:
        warnings.append("missing URL scheme")
    elif parsed.scheme in SUSPICIOUS_SCHEMES:
        warnings.append(f"dangerous scheme: {parsed.scheme!r}")
    elif parsed.scheme not in ALLOWED_SCHEMES:
        warnings.append(f"non-standard scheme: {parsed.scheme!r}")
    if not parsed.netloc:
        warnings.append("missing host")
    if is_ip:
        warnings.append("IP address used as host (no domain name)")
    if parsed.username or parsed.password:
        warnings.append("credentials embedded in URL")
    if len(url) > MAX_URL_LENGTH:
        warnings.append(f"URL exceeds {MAX_URL_LENGTH} characters")
    if parsed.port and parsed.port in PRIVATE_PORTS:
        warnings.append(f"connection to sensitive port {parsed.port}")
    _check_subdomain_depth(parsed.hostname or "", warnings)
    _check_query_count(parsed.query, warnings)
    return warnings


def _check_subdomain_depth(host: str, warnings: list[str]) -> None:
    parts = host.split(".")
    if len(parts) > MAX_SUBDOMAIN_DEPTH:
        warnings.append(f"excessive subdomain depth: {len(parts)} labels")


def _check_query_count(query: str, warnings: list[str]) -> None:
    params = parse_qs(query)
    if len(params) > MAX_QUERY_PARAMS:
        warnings.append(f"unusually many query parameters: {len(params)}")
