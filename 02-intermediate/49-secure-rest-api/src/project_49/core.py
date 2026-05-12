"""Security middleware and utilities for the REST API template."""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Final

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

API_KEY_BYTES: Final[int] = 32
RATE_LIMIT_WINDOW: Final[int] = 60  # seconds
RATE_LIMIT_MAX: Final[int] = 100    # requests per window


# ---------------------------------------------------------------------------
# API Key store
# ---------------------------------------------------------------------------

@dataclass
class APIKeyStore:
    """In-memory API key registry."""

    _keys: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)

    def create_key(self, owner: str, scopes: list[str]) -> str:
        """Generate a new API key for *owner* with *scopes*."""
        key = f"sk_{secrets.token_urlsafe(API_KEY_BYTES)}"
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        self._keys[key_hash] = {
            "owner": owner,
            "scopes": scopes,
            "created_at": time.time(),
            "active": True,
        }
        logger.info("API key created for owner=%s scopes=%s", owner, scopes)
        return key

    def validate_key(self, key: str, required_scope: str | None = None) -> dict[str, Any]:
        """Validate key and optional scope. Raises ValueError on failure."""
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        meta = self._keys.get(key_hash)
        if not meta:
            raise ValueError("Invalid API key")
        if not meta["active"]:
            raise ValueError("API key has been revoked")
        if required_scope and required_scope not in meta["scopes"]:
            raise ValueError(
                f"Scope {required_scope!r} not granted to this key"
            )
        return meta

    def revoke_key(self, key: str) -> bool:
        """Revoke a key. Returns True if found and revoked."""
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        meta = self._keys.get(key_hash)
        if meta:
            meta["active"] = False
            return True
        return False


# ---------------------------------------------------------------------------
# Rate limiter (token bucket per identifier)
# ---------------------------------------------------------------------------

@dataclass
class RateLimiter:
    """Simple fixed-window rate limiter."""

    window: int = RATE_LIMIT_WINDOW
    max_requests: int = RATE_LIMIT_MAX
    _windows: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list), repr=False)

    def is_allowed(self, identifier: str) -> bool:
        """Return True if *identifier* is within the rate limit."""
        now = time.time()
        window_start = now - self.window
        requests = self._windows[identifier]
        # Remove expired timestamps
        self._windows[identifier] = [t for t in requests if t > window_start]
        if len(self._windows[identifier]) >= self.max_requests:
            return False
        self._windows[identifier].append(now)
        return True

    def remaining(self, identifier: str) -> int:
        """Return remaining requests in the current window."""
        now = time.time()
        window_start = now - self.window
        count = sum(1 for t in self._windows[identifier] if t > window_start)
        return max(0, self.max_requests - count)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

SECURITY_HEADERS: Final[dict[str, str]] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "0",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


def get_security_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Return the standard security header set, optionally extended."""
    headers = dict(SECURITY_HEADERS)
    if extra:
        headers.update(extra)
    return headers


# ---------------------------------------------------------------------------
# Request signing (HMAC-SHA256)
# ---------------------------------------------------------------------------

def sign_request(
    method: str, path: str, body: bytes, timestamp: str, secret: bytes
) -> str:
    """Compute HMAC-SHA256 signature for a request."""
    msg = f"{method.upper()}\n{path}\n{timestamp}\n".encode() + body
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def verify_request_signature(
    method: str,
    path: str,
    body: bytes,
    timestamp: str,
    submitted_sig: str,
    secret: bytes,
    max_age_seconds: int = 300,
) -> None:
    """Verify request signature and timestamp. Raises ValueError on failure."""
    try:
        ts = float(timestamp)
    except ValueError as err:
        raise ValueError("Invalid timestamp format") from err

    age = abs(time.time() - ts)
    if age > max_age_seconds:
        raise ValueError(f"Request timestamp too old: {age:.0f}s > {max_age_seconds}s")

    expected = sign_request(method, path, body, timestamp, secret)
    if not hmac.compare_digest(expected, submitted_sig):
        raise ValueError("Request signature verification failed")
