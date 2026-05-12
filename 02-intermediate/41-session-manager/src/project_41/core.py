"""Session Manager Service — secure session lifecycle management.

Defends against: T1550.004 (Web Session Cookie), T1185 (Browser Session Hijacking),
T1539 (Steal Web Session Cookie), T1078 (Valid Accounts).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SESSION_ID_BYTES: int = 32
CSRF_TOKEN_BYTES: int = 32
DEFAULT_TTL_SECONDS: int = 3600          # 1 hour
DEFAULT_IDLE_TIMEOUT: int = 900          # 15 minutes
MAX_SESSIONS_PER_USER: int = 5
ROTATION_GRACE_SECONDS: int = 5          # old token valid this long after rotation


class SessionStatus(str, Enum):
    """Lifecycle state of a session."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    ROTATED = "rotated"


# ---------------------------------------------------------------------------
# Session dataclass
# ---------------------------------------------------------------------------

@dataclass
class Session:
    """An authenticated session record."""

    session_id: str
    user_id: str
    created_at: float
    last_accessed: float
    expires_at: float
    idle_timeout: int
    csrf_token: str
    status: SessionStatus = SessionStatus.ACTIVE
    metadata: dict[str, Any] = field(default_factory=dict)
    ip_address: str | None = None
    user_agent: str | None = None

    # After rotation the old ID stays briefly valid
    superseded_by: str | None = None
    superseded_at: float | None = None

    @property
    def is_expired(self) -> bool:
        """True if the absolute expiry has passed."""
        return time.time() > self.expires_at

    @property
    def is_idle(self) -> bool:
        """True if the idle timeout has passed since last access."""
        return (time.time() - self.last_accessed) > self.idle_timeout

    @property
    def is_valid(self) -> bool:
        """True only when active, not expired, and not idle."""
        return (
            self.status == SessionStatus.ACTIVE
            and not self.is_expired
            and not self.is_idle
        )


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ValidationResult:
    """Outcome of a session lookup."""

    valid: bool
    session: Session | None
    reason: str


# ---------------------------------------------------------------------------
# Session store
# ---------------------------------------------------------------------------

class SessionStore:
    """In-memory session store with full lifecycle management."""

    def __init__(
        self,
        ttl: int = DEFAULT_TTL_SECONDS,
        idle_timeout: int = DEFAULT_IDLE_TIMEOUT,
        max_per_user: int = MAX_SESSIONS_PER_USER,
    ) -> None:
        self._sessions: dict[str, Session] = {}
        self._ttl = ttl
        self._idle_timeout = idle_timeout
        self._max_per_user = max_per_user

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create(
        self,
        user_id: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Session:
        """Create a new session for a user.

        Args:
            user_id: Authenticated user identifier.
            ip_address: Remote IP for audit purposes.
            user_agent: Browser / client user-agent string.
            metadata: Optional extra data to attach to the session.

        Returns:
            Newly created Session.
        """
        self._enforce_session_cap(user_id)

        now = time.time()
        session = Session(
            session_id=secrets.token_urlsafe(SESSION_ID_BYTES),
            user_id=user_id,
            created_at=now,
            last_accessed=now,
            expires_at=now + self._ttl,
            idle_timeout=self._idle_timeout,
            csrf_token=secrets.token_urlsafe(CSRF_TOKEN_BYTES),
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=dict(metadata or {}),
        )
        self._sessions[session.session_id] = session
        logger.info("Session created user_id=%s session_id=%.16s", user_id, session.session_id)
        return session

    # ------------------------------------------------------------------
    # Validate
    # ------------------------------------------------------------------

    def validate(self, session_id: str) -> ValidationResult:
        """Validate a session token and refresh its last-accessed timestamp.

        Args:
            session_id: Session token from client cookie.

        Returns:
            ValidationResult with valid flag and reason.
        """
        session = self._sessions.get(session_id)
        if session is None:
            logger.warning("Session not found session_id=%.16s", session_id)
            return ValidationResult(valid=False, session=None, reason="not_found")

        if session.status == SessionStatus.REVOKED:
            return ValidationResult(valid=False, session=session, reason="revoked")

        if session.status == SessionStatus.ROTATED:
            # Allow grace period for the old token
            if session.superseded_at and (time.time() - session.superseded_at) <= ROTATION_GRACE_SECONDS:
                session.last_accessed = time.time()
                return ValidationResult(valid=True, session=session, reason="rotated_grace")
            return ValidationResult(valid=False, session=session, reason="rotated")

        if session.is_expired:
            session.status = SessionStatus.EXPIRED
            return ValidationResult(valid=False, session=session, reason="expired")

        if session.is_idle:
            session.status = SessionStatus.EXPIRED
            return ValidationResult(valid=False, session=session, reason="idle_timeout")

        session.last_accessed = time.time()
        return ValidationResult(valid=True, session=session, reason="ok")

    # ------------------------------------------------------------------
    # Rotate
    # ------------------------------------------------------------------

    def rotate(self, session_id: str) -> Session:
        """Issue a new session token while invalidating the old one (post-privilege change).

        Args:
            session_id: Existing valid session token.

        Returns:
            New Session with fresh token and CSRF token.

        Raises:
            KeyError: If session not found.
            ValueError: If session is not active.
        """
        result = self.validate(session_id)
        if not result.valid and result.reason not in ("ok", "rotated_grace"):
            raise ValueError(f"Cannot rotate invalid session: {result.reason}")

        old = self._sessions[session_id]
        now = time.time()
        new_session = Session(
            session_id=secrets.token_urlsafe(SESSION_ID_BYTES),
            user_id=old.user_id,
            created_at=now,
            last_accessed=now,
            expires_at=old.expires_at,
            idle_timeout=old.idle_timeout,
            csrf_token=secrets.token_urlsafe(CSRF_TOKEN_BYTES),
            ip_address=old.ip_address,
            user_agent=old.user_agent,
            metadata=dict(old.metadata),
        )
        old.status = SessionStatus.ROTATED
        old.superseded_by = new_session.session_id
        old.superseded_at = now
        self._sessions[new_session.session_id] = new_session
        logger.info("Session rotated user_id=%s old=%.16s new=%.16s", old.user_id, session_id, new_session.session_id)
        return new_session

    # ------------------------------------------------------------------
    # Revoke
    # ------------------------------------------------------------------

    def revoke(self, session_id: str) -> bool:
        """Revoke a single session (logout).

        Args:
            session_id: Session token to revoke.

        Returns:
            True if the session existed and was revoked.
        """
        session = self._sessions.get(session_id)
        if session is None:
            return False
        session.status = SessionStatus.REVOKED
        logger.info("Session revoked user_id=%s session_id=%.16s", session.user_id, session_id)
        return True

    def revoke_all(self, user_id: str) -> int:
        """Revoke all active sessions for a user (force logout everywhere).

        Args:
            user_id: User whose sessions should be revoked.

        Returns:
            Number of sessions revoked.
        """
        count = 0
        for session in self._sessions.values():
            if session.user_id == user_id and session.status == SessionStatus.ACTIVE:
                session.status = SessionStatus.REVOKED
                count += 1
        logger.info("All sessions revoked user_id=%s count=%d", user_id, count)
        return count

    # ------------------------------------------------------------------
    # CSRF
    # ------------------------------------------------------------------

    def verify_csrf(self, session_id: str, csrf_token: str) -> bool:
        """Constant-time CSRF token verification.

        Args:
            session_id: Session token.
            csrf_token: CSRF token submitted with the form/request.

        Returns:
            True if the CSRF token matches the session's stored token.
        """
        result = self.validate(session_id)
        if not result.valid or result.session is None:
            return False
        return hmac.compare_digest(result.session.csrf_token, csrf_token)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _enforce_session_cap(self, user_id: str) -> None:
        """Revoke oldest sessions when user hits the per-user cap."""
        user_sessions = sorted(
            [s for s in self._sessions.values() if s.user_id == user_id and s.status == SessionStatus.ACTIVE],
            key=lambda s: s.created_at,
        )
        while len(user_sessions) >= self._max_per_user:
            oldest = user_sessions.pop(0)
            oldest.status = SessionStatus.REVOKED
            logger.warning("Session cap enforced, revoked oldest user_id=%s", user_id)

    def purge_expired(self) -> int:
        """Remove expired/revoked sessions from memory.

        Returns:
            Number of sessions purged.
        """
        before = len(self._sessions)
        self._sessions = {
            sid: s for sid, s in self._sessions.items()
            if s.status == SessionStatus.ACTIVE
        }
        purged = before - len(self._sessions)
        if purged:
            logger.info("Purged %d stale sessions", purged)
        return purged

    def list_user_sessions(self, user_id: str) -> list[Session]:
        """Return all sessions for a user.

        Args:
            user_id: User identifier.

        Returns:
            List of Session objects (all statuses).
        """
        return [s for s in self._sessions.values() if s.user_id == user_id]

    def fingerprint(self, session_id: str) -> str:
        """SHA-256 fingerprint of a session ID for safe logging.

        Args:
            session_id: Raw session token.

        Returns:
            Hex digest string.
        """
        return hashlib.sha256(session_id.encode()).hexdigest()
