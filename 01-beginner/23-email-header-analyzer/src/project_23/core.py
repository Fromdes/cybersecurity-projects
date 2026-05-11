"""Email header parsing with SPF/DKIM/DMARC result extraction."""
from __future__ import annotations

import re
from dataclasses import dataclass
from email.parser import HeaderParser

AUTH_FIELD_RE: re.Pattern[str] = re.compile(
    r"(spf|dkim|dmarc)=(pass|fail|neutral|softfail|none|permerror|temperror)",
    re.IGNORECASE,
)
IP_RE: re.Pattern[str] = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)
MANY_HOPS_THRESHOLD: int = 5
AUTH_RESULT_HEADER: str = "Authentication-Results"


@dataclass(frozen=True)
class AuthResult:
    """Extracted SPF/DKIM/DMARC authentication results."""

    spf: str | None
    dkim: str | None
    dmarc: str | None


@dataclass(frozen=True)
class EmailAnalysis:
    """Analysis result for a raw email header block."""

    from_addr: str
    reply_to: str | None
    subject: str
    date: str
    message_id: str
    received_hops: int
    auth: AuthResult
    x_mailer: str | None
    x_originating_ip: str | None
    warnings: tuple[str, ...]


def analyze(raw_headers: str) -> EmailAnalysis:
    """Analyse *raw_headers* and extract authentication and routing metadata.

    Args:
        raw_headers: Raw email header block (RFC 2822 format).

    Returns:
        EmailAnalysis with parsed fields and warnings.

    Raises:
        ValueError: If raw_headers is empty.
    """
    if not raw_headers.strip():
        raise ValueError("raw_headers must not be empty")
    msg = HeaderParser().parsestr(raw_headers)
    received = msg.get_all("Received") or []
    auth = _parse_auth_results(msg.get(AUTH_RESULT_HEADER) or "")
    warnings = _collect_warnings(msg, received, auth)
    return EmailAnalysis(
        from_addr=msg.get("From", ""),
        reply_to=msg.get("Reply-To"),
        subject=msg.get("Subject", ""),
        date=msg.get("Date", ""),
        message_id=msg.get("Message-ID", ""),
        received_hops=len(received),
        auth=auth,
        x_mailer=msg.get("X-Mailer"),
        x_originating_ip=msg.get("X-Originating-IP"),
        warnings=tuple(warnings),
    )


def _parse_auth_results(value: str) -> AuthResult:
    results: dict[str, str] = {}
    for match in AUTH_FIELD_RE.finditer(value):
        field, result = match.group(1).lower(), match.group(2).lower()
        results.setdefault(field, result)
    return AuthResult(
        spf=results.get("spf"),
        dkim=results.get("dkim"),
        dmarc=results.get("dmarc"),
    )


def _collect_warnings(msg: object, received: list[str], auth: AuthResult) -> list[str]:
    from email.message import Message
    assert isinstance(msg, Message)
    warnings: list[str] = []
    from_addr = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    if reply_to and reply_to != from_addr:
        warnings.append("Reply-To differs from From address")
    if not msg.get("Message-ID"):
        warnings.append("missing Message-ID header")
    if not msg.get("Date"):
        warnings.append("missing Date header")
    if len(received) > MANY_HOPS_THRESHOLD:
        warnings.append(f"unusually many Received hops: {len(received)}")
    _check_auth_warnings(auth, warnings)
    return warnings


def _check_auth_warnings(auth: AuthResult, warnings: list[str]) -> None:
    if auth.spf is None:
        warnings.append("no SPF result in Authentication-Results")
    elif auth.spf in ("fail", "softfail"):
        warnings.append(f"SPF {auth.spf}")
    if auth.dkim is None:
        warnings.append("no DKIM result in Authentication-Results")
    elif auth.dkim == "fail":
        warnings.append("DKIM fail")
    if auth.dmarc is None:
        warnings.append("no DMARC result in Authentication-Results")
    elif auth.dmarc == "fail":
        warnings.append("DMARC fail")
