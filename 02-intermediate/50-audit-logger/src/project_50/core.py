"""Core audit log event definitions, storage, and query engine."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Final

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CHAIN_HMAC_KEY: Final[bytes] = b"audit-chain-integrity-key"


# ---------------------------------------------------------------------------
# Event model
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class AuditEvent:
    """Immutable audit log event."""

    event_id: str
    timestamp: float
    actor: str
    action: str
    resource: str
    outcome: str       # "success" | "failure" | "error"
    severity: str
    details: dict[str, Any]
    ip_address: str = ""
    session_id: str = ""
    prev_hash: str = ""  # hash of previous event for chain integrity

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    def compute_hash(self) -> str:
        """SHA-256 hash of this event's canonical JSON representation."""
        return hashlib.sha256(self.to_json().encode()).hexdigest()


def make_event(
    actor: str,
    action: str,
    resource: str,
    outcome: str,
    severity: Severity = Severity.INFO,
    details: dict[str, Any] | None = None,
    ip_address: str = "",
    session_id: str = "",
    prev_hash: str = "",
) -> AuditEvent:
    """Construct a new AuditEvent with auto-generated ID and timestamp."""
    return AuditEvent(
        event_id=str(uuid.uuid4()),
        timestamp=time.time(),
        actor=actor,
        action=action,
        resource=resource,
        outcome=outcome,
        severity=severity.value,
        details=details or {},
        ip_address=ip_address,
        session_id=session_id,
        prev_hash=prev_hash,
    )


# ---------------------------------------------------------------------------
# Append-only log store
# ---------------------------------------------------------------------------

@dataclass
class AuditLog:
    """Append-only, hash-chained audit log backed by a JSONL file."""

    log_path: Path
    _last_hash: str = field(default="", init=False, repr=False)

    def __post_init__(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if self.log_path.exists():
            self._last_hash = self._read_last_hash()

    # ------------------------------------------------------------------

    def append(
        self,
        actor: str,
        action: str,
        resource: str,
        outcome: str,
        severity: Severity = Severity.INFO,
        details: dict[str, Any] | None = None,
        ip_address: str = "",
        session_id: str = "",
    ) -> AuditEvent:
        """Append an event and return it."""
        event = make_event(
            actor=actor,
            action=action,
            resource=resource,
            outcome=outcome,
            severity=severity,
            details=details,
            ip_address=ip_address,
            session_id=session_id,
            prev_hash=self._last_hash,
        )
        line = event.to_json() + "\n"
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
        self._last_hash = event.compute_hash()
        logger.debug(
            "Audit: actor=%s action=%s resource=%s outcome=%s",
            actor, action, resource, outcome,
        )
        return event

    # ------------------------------------------------------------------

    def read_all(self) -> list[AuditEvent]:
        """Read all events from the log file."""
        if not self.log_path.exists():
            return []
        events: list[AuditEvent] = []
        with self.log_path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                events.append(AuditEvent(**data))
        return events

    def query(
        self,
        actor: str | None = None,
        action: str | None = None,
        resource: str | None = None,
        outcome: str | None = None,
        severity: str | None = None,
        since: float | None = None,
        until: float | None = None,
    ) -> list[AuditEvent]:
        """Filter events by field values and/or time range."""
        events = self.read_all()
        if actor:
            events = [e for e in events if e.actor == actor]
        if action:
            events = [e for e in events if e.action == action]
        if resource:
            events = [e for e in events if e.resource == resource]
        if outcome:
            events = [e for e in events if e.outcome == outcome]
        if severity:
            events = [e for e in events if e.severity == severity]
        if since is not None:
            events = [e for e in events if e.timestamp >= since]
        if until is not None:
            events = [e for e in events if e.timestamp <= until]
        return events

    # ------------------------------------------------------------------
    # Chain integrity verification
    # ------------------------------------------------------------------

    def verify_chain(self) -> tuple[bool, str]:
        """Verify hash-chain integrity. Returns (ok, message)."""
        events = self.read_all()
        if not events:
            return True, "Log is empty — chain intact."

        prev_hash = ""
        for i, event in enumerate(events):
            if event.prev_hash != prev_hash:
                return False, (
                    f"Chain broken at event #{i} (id={event.event_id}): "
                    f"expected prev_hash={prev_hash!r}, got {event.prev_hash!r}"
                )
            prev_hash = event.compute_hash()

        return True, f"Chain intact — {len(events)} events verified."

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _read_last_hash(self) -> str:
        last_line = ""
        with self.log_path.open(encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    last_line = stripped
        if not last_line:
            return ""
        data = json.loads(last_line)
        event = AuditEvent(**data)
        return event.compute_hash()
