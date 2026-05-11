"""Heuristic phishing URL detection via scoring indicators."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import ParseResult, urlparse

SCORE_IP_HOST: int = 25
SCORE_AT_SYMBOL: int = 30
SCORE_DOUBLE_SLASH_REDIRECT: int = 20
SCORE_LONG_URL: int = 10
SCORE_MANY_SUBDOMAINS: int = 15
SCORE_MANY_HYPHENS: int = 10
SCORE_URL_SHORTENER: int = 25
SCORE_SUSPICIOUS_KEYWORD: int = 15
SCORE_SUSPICIOUS_TLD: int = 15
SCORE_NON_STANDARD_PORT: int = 10

LONG_URL_THRESHOLD: int = 75
MAX_SUBDOMAIN_LABELS: int = 4
MAX_HYPHENS: int = 3

RISK_CRITICAL: str = "CRITICAL"
RISK_HIGH: str = "HIGH"
RISK_MEDIUM: str = "MEDIUM"
RISK_LOW: str = "LOW"

SCORE_THRESHOLDS: tuple[tuple[int, str], ...] = (
    (70, RISK_CRITICAL),
    (45, RISK_HIGH),
    (20, RISK_MEDIUM),
    (0, RISK_LOW),
)

SUSPICIOUS_KEYWORDS: frozenset[str] = frozenset({
    "login", "signin", "verify", "secure", "account",
    "update", "confirm", "password", "credential",
    "banking", "paypal", "apple", "microsoft",
    "amazon", "netflix", "facebook", "webscr",
})

URL_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "rb.gy", "shorturl.at",
})

SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    ".xyz", ".top", ".club", ".work", ".click", ".link",
    ".online", ".site", ".space", ".download", ".gq",
})

SAFE_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443})


@dataclass(frozen=True)
class PhishingResult:
    """Heuristic phishing analysis for a single URL."""

    url: str
    score: int
    risk_level: str
    indicators: tuple[str, ...]


def analyze(url: str) -> PhishingResult:
    """Score *url* for phishing indicators.

    Args:
        url: URL string to analyse.

    Returns:
        PhishingResult with a 0–100 score, risk level, and indicators.

    Raises:
        ValueError: If url is empty.
    """
    if not url.strip():
        raise ValueError("URL must not be empty")
    parsed = urlparse(url)
    host = parsed.hostname or ""
    checks = [
        _check_ip_host(host),
        _check_at_symbol(url),
        _check_double_slash(url, parsed),
        _check_url_length(url),
        _check_subdomain_depth(host),
        _check_hyphens(host),
        _check_shortener(host),
        _check_keywords(url.lower()),
        _check_tld(host),
        _check_port(parsed.port),
    ]
    score = 0
    indicators: list[str] = []
    for pts, indicator in checks:
        score += pts
        if indicator:
            indicators.append(indicator)
    return PhishingResult(
        url=url,
        score=min(score, 100),
        risk_level=_score_to_risk(min(score, 100)),
        indicators=tuple(indicators),
    )


# ---------------------------------------------------------------------------
# Individual checks — each returns (score_delta, indicator_text | None)
# ---------------------------------------------------------------------------


def _score_to_risk(score: int) -> str:
    for threshold, level in SCORE_THRESHOLDS:
        if score >= threshold:
            return level
    return RISK_LOW


def _check_ip_host(host: str) -> tuple[int, str | None]:
    try:
        ipaddress.ip_address(host)
        return SCORE_IP_HOST, "IP address used as host"
    except ValueError:
        return 0, None


def _check_at_symbol(url: str) -> tuple[int, str | None]:
    if "@" in url:
        return SCORE_AT_SYMBOL, "@ symbol in URL (credential embedding)"
    return 0, None


def _check_double_slash(url: str, parsed: ParseResult) -> tuple[int, str | None]:
    path = parsed.path or ""
    if "//" in path:
        return SCORE_DOUBLE_SLASH_REDIRECT, "double-slash redirect in path"
    return 0, None


def _check_url_length(url: str) -> tuple[int, str | None]:
    if len(url) > LONG_URL_THRESHOLD:
        return SCORE_LONG_URL, f"long URL ({len(url)} chars)"
    return 0, None


def _check_subdomain_depth(host: str) -> tuple[int, str | None]:
    labels = host.split(".")
    if len(labels) > MAX_SUBDOMAIN_LABELS:
        return SCORE_MANY_SUBDOMAINS, f"many subdomain labels ({len(labels)})"
    return 0, None


def _check_hyphens(host: str) -> tuple[int, str | None]:
    domain = host.split(".")[0] if "." in host else host
    count = domain.count("-")
    if count >= MAX_HYPHENS:
        return SCORE_MANY_HYPHENS, f"multiple hyphens in domain ({count})"
    return 0, None


def _check_shortener(host: str) -> tuple[int, str | None]:
    if host in URL_SHORTENERS:
        return SCORE_URL_SHORTENER, f"URL shortener: {host}"
    return 0, None


def _check_keywords(url_lower: str) -> tuple[int, str | None]:
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if found:
        return SCORE_SUSPICIOUS_KEYWORD, f"suspicious keywords: {', '.join(found[:3])}"
    return 0, None


def _check_tld(host: str) -> tuple[int, str | None]:
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            return SCORE_SUSPICIOUS_TLD, f"suspicious TLD: {tld}"
    return 0, None


def _check_port(port: int | None) -> tuple[int, str | None]:
    if port and port not in SAFE_PORTS:
        return SCORE_NON_STANDARD_PORT, f"non-standard port: {port}"
    return 0, None
