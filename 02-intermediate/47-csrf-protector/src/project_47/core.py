"""Core CSRF token generation, storage, and validation logic."""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Final

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOKEN_BYTES: Final[int] = 32
DEFAULT_TTL: Final[int] = 3600  # seconds
HEADER_NAME: Final[str] = "X-CSRF-Token"
FORM_FIELD_NAME: Final[str] = "csrf_token"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class CSRFError(Exception):
    """Base CSRF protection error."""


class TokenExpiredError(CSRFError):
    """Token has exceeded its TTL."""


class TokenInvalidError(CSRFError):
    """Token signature or value is invalid."""


class TokenNotFoundError(CSRFError):
    """Token not found for this session."""


# ---------------------------------------------------------------------------
# Token store (in-memory; replace with Redis/DB in production)
# ---------------------------------------------------------------------------

@dataclass
class _TokenEntry:
    token: str
    issued_at: float
    hmac_sig: str


class TokenStore:
    """Thread-unsafe in-memory store. Use a persistent backend in production."""

    def __init__(self) -> None:
        self._store: dict[str, _TokenEntry] = {}

    def put(self, session_id: str, entry: _TokenEntry) -> None:
        self._store[session_id] = entry

    def get(self, session_id: str) -> _TokenEntry | None:
        return self._store.get(session_id)

    def delete(self, session_id: str) -> None:
        self._store.pop(session_id, None)

    def purge_expired(self, ttl: int) -> int:
        """Remove expired entries, return count removed."""
        now = time.time()
        expired = [sid for sid, e in self._store.items() if now - e.issued_at > ttl]
        for sid in expired:
            del self._store[sid]
        return len(expired)


# ---------------------------------------------------------------------------
# CSRF service
# ---------------------------------------------------------------------------

@dataclass
class CSRFService:
    """Stateful CSRF token manager with HMAC-signed double-submit support."""

    secret: bytes
    ttl: int = DEFAULT_TTL
    _store: TokenStore = field(default_factory=TokenStore, repr=False)

    # ------------------------------------------------------------------
    # Token generation
    # ------------------------------------------------------------------

    def generate_token(self, session_id: str) -> str:
        """Generate and store a new CSRF token for *session_id*."""
        raw = secrets.token_urlsafe(TOKEN_BYTES)
        sig = self._sign(session_id, raw)
        entry = _TokenEntry(token=raw, issued_at=time.time(), hmac_sig=sig)
        self._store.put(session_id, entry)
        logger.debug("CSRF token generated for session %s", session_id[:8])
        return raw

    # ------------------------------------------------------------------
    # Token validation
    # ------------------------------------------------------------------

    def validate_token(self, session_id: str, submitted_token: str) -> None:
        """Validate *submitted_token* for *session_id*.

        Raises CSRFError subclass on any failure.
        """
        entry = self._store.get(session_id)
        if entry is None:
            raise TokenNotFoundError(f"No CSRF token for session {session_id[:8]!r}")

        elapsed = time.time() - entry.issued_at
        if elapsed > self.ttl:
            self._store.delete(session_id)
            raise TokenExpiredError(
                f"CSRF token expired ({elapsed:.0f}s > {self.ttl}s TTL)"
            )

        expected_sig = self._sign(session_id, entry.token)
        if not hmac.compare_digest(entry.hmac_sig, expected_sig):
            raise TokenInvalidError("CSRF token HMAC verification failed (store tampered)")

        if not hmac.compare_digest(entry.token, submitted_token):
            raise TokenInvalidError("Submitted CSRF token does not match stored token")

        logger.debug("CSRF token validated for session %s", session_id[:8])

    # ------------------------------------------------------------------
    # Rotation
    # ------------------------------------------------------------------

    def rotate_token(self, session_id: str) -> str:
        """Invalidate the current token and issue a fresh one."""
        self._store.delete(session_id)
        return self.generate_token(session_id)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _sign(self, session_id: str, token: str) -> str:
        msg = f"{session_id}:{token}".encode()
        return hmac.new(self.secret, msg, hashlib.sha256).hexdigest()

    def purge_expired(self) -> int:
        """Purge expired tokens; return count removed."""
        return self._store.purge_expired(self.ttl)


# ---------------------------------------------------------------------------
# Utility: extract token from request dict (framework-agnostic)
# ---------------------------------------------------------------------------

def extract_token(
    headers: dict[str, str],
    form: dict[str, str],
    *,
    prefer_header: bool = True,
) -> str | None:
    """Extract CSRF token from headers or form data."""
    if prefer_header:
        return headers.get(HEADER_NAME) or form.get(FORM_FIELD_NAME)
    return form.get(FORM_FIELD_NAME) or headers.get(HEADER_NAME)
