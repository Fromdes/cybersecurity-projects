"""k-Anonymity HIBP password check — only the first 5 SHA-1 hex chars leave this machine."""

from __future__ import annotations

import hashlib
import logging

import requests

logger = logging.getLogger(__name__)

HIBP_API_BASE: str = "https://api.pwnedpasswords.com/range/"
K_ANON_PREFIX_LEN: int = 5
_REQUEST_TIMEOUT: int = 10  # seconds
_USER_AGENT: str = "defensive-cybersecurity-portfolio/0.1 (educational)"


def hash_password(password: str) -> str:
    """Return the uppercase SHA-1 hex digest of *password* (UTF-8 encoded).

    Args:
        password: The plaintext password.

    Returns:
        40-character uppercase hex SHA-1 digest.
    """
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324


def query_range(prefix: str, session: requests.Session) -> dict[str, int]:
    """Query the HIBP k-anonymity range endpoint for *prefix*.

    Only the first :const:`K_ANON_PREFIX_LEN` characters of the hash are
    sent to the server; the full hash never leaves this machine.

    Args:
        prefix: First 5 uppercase hex characters of the SHA-1 hash.
        session: Requests session (allows mocking in tests).

    Returns:
        Mapping of uppercase hash suffix (chars 6–40) → breach count.

    Raises:
        requests.HTTPError: If the API returns a non-2xx status.
        requests.Timeout: If the request exceeds the timeout.
        requests.ConnectionError: If the server is unreachable.
    """
    url = HIBP_API_BASE + prefix
    response = session.get(
        url,
        timeout=_REQUEST_TIMEOUT,
        headers={"User-Agent": _USER_AGENT, "Add-Padding": "true"},
    )
    response.raise_for_status()
    results: dict[str, int] = {}
    for line in response.text.splitlines():
        if ":" not in line:
            continue
        suffix, _, count_str = line.partition(":")
        try:
            results[suffix.upper()] = int(count_str.strip())
        except ValueError:
            logger.warning("Unexpected HIBP response line: %r", line)
    return results


def check_password(password: str, session: requests.Session | None = None) -> int:
    """Check if *password* has appeared in known data breaches.

    Uses k-anonymity: only the first 5 hex characters of the SHA-1 hash are
    sent to the HIBP API. The server never sees the full hash or password.

    Args:
        password: The plaintext password to check.
        session: Optional pre-configured requests Session (useful for testing).

    Returns:
        Number of times the password appeared in known breaches (0 = not found).

    Raises:
        requests.RequestException: On network or API errors.
    """
    sess = session or requests.Session()
    full_hash = hash_password(password)
    prefix = full_hash[:K_ANON_PREFIX_LEN]
    suffix = full_hash[K_ANON_PREFIX_LEN:]
    logger.debug("Querying HIBP with prefix %s (hash suffix never transmitted)", prefix)
    hashes = query_range(prefix, sess)
    return hashes.get(suffix, 0)


def check_hash(sha1_hash: str, session: requests.Session | None = None) -> int:
    """Check a pre-computed SHA-1 hash against HIBP (for privacy-sensitive callers).

    Args:
        sha1_hash: 40-character hex SHA-1 hash (upper or lower case).
        session: Optional requests Session.

    Returns:
        Breach count (0 = not found).

    Raises:
        ValueError: If *sha1_hash* is not a valid 40-character hex string.
    """
    clean = sha1_hash.strip().upper()
    if len(clean) != 40 or not all(c in "0123456789ABCDEF" for c in clean):
        raise ValueError(f"Invalid SHA-1 hash: {sha1_hash!r}")
    sess = session or requests.Session()
    prefix = clean[:K_ANON_PREFIX_LEN]
    suffix = clean[K_ANON_PREFIX_LEN:]
    hashes = query_range(prefix, sess)
    return hashes.get(suffix, 0)
