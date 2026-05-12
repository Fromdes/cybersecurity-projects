"""Input Sanitization Library — detect and strip dangerous patterns from untrusted input.

Defends against: T1059.007 (JavaScript), T1190 (Exploit Public-Facing App — SQLi),
T1083 (File and Directory Discovery — path traversal), T1059 (Command Injection).
"""

from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Threat categories
# ---------------------------------------------------------------------------

class ThreatType(str, Enum):
    """Category of detected threat."""

    XSS = "xss"
    SQLI = "sqli"
    PATH_TRAVERSAL = "path_traversal"
    CMD_INJECTION = "cmd_injection"
    NULL_BYTE = "null_byte"
    UNICODE_HOMOGLYPH = "unicode_homoglyph"
    OVERSIZED = "oversized"


@dataclass(frozen=True)
class ThreatMatch:
    """A single detected threat within an input string."""

    threat_type: ThreatType
    pattern: str
    position: int


@dataclass
class SanitizationResult:
    """Result of a sanitization pass."""

    original: str
    sanitized: str
    threats: list[ThreatMatch] = field(default_factory=list)
    truncated: bool = False

    @property
    def is_clean(self) -> bool:
        """True if no threats were found."""
        return len(self.threats) == 0


# ---------------------------------------------------------------------------
# Pattern constants
# ---------------------------------------------------------------------------

MAX_DEFAULT_LENGTH: int = 8192

_XSS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"<\s*script\b", re.IGNORECASE),
    re.compile(r"</\s*script\s*>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"vbscript\s*:", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),          # onerror=, onclick=, etc.
    re.compile(r"<\s*iframe\b", re.IGNORECASE),
    re.compile(r"<\s*object\b", re.IGNORECASE),
    re.compile(r"<\s*embed\b", re.IGNORECASE),
    re.compile(r"expression\s*\(", re.IGNORECASE),    # CSS expression()
    re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
]

_SQLI_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"('\s*(or|and)\s*'?\d)", re.IGNORECASE),
    re.compile(r"(--|#)\s*$", re.MULTILINE),
    re.compile(r";\s*(drop|alter|truncate|delete|insert|update)\s+", re.IGNORECASE),
    re.compile(r"\bunion\s+(all\s+)?select\b", re.IGNORECASE),
    re.compile(r"\bselect\b.+\bfrom\b", re.IGNORECASE),
    re.compile(r"'\s*=\s*'", re.IGNORECASE),           # ' = ' tautology
    re.compile(r"\bwaitfor\s+delay\b", re.IGNORECASE),  # MSSQL time-based
    re.compile(r"\bsleep\s*\(", re.IGNORECASE),          # MySQL time-based
    re.compile(r"\bload_file\s*\(", re.IGNORECASE),
    re.compile(r"\binto\s+(outfile|dumpfile)\b", re.IGNORECASE),
]

_PATH_TRAVERSAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.[/\\]"),
    re.compile(r"%2e%2e[%2f%5c]", re.IGNORECASE),   # URL-encoded ../
    re.compile(r"\.\.%2f", re.IGNORECASE),
    re.compile(r"%252e%252e", re.IGNORECASE),         # double URL-encoded
]

_CMD_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"[;&|`$]"),
    re.compile(r"\$\("),                                # command substitution
    re.compile(r"`[^`]+`"),                             # backtick substitution
    re.compile(r"\|\s*(cat|ls|id|whoami|uname|wget|curl|bash|sh|nc|python)\b", re.IGNORECASE),
    re.compile(r">\s*/dev/", re.IGNORECASE),
    re.compile(r"\bnc\b.*-e\b", re.IGNORECASE),
]

# Characters that look like ASCII but aren't (homoglyph attack detection)
_CONFUSABLE_PATTERN: re.Pattern[str] = re.compile(
    r"[аеорсхір"   # Cyrillic lookalikes
    r"αεο"                                   # Greek lookalikes
    r"’‘“”]"                            # Smart quotes
)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

def detect_threats(text: str) -> list[ThreatMatch]:
    """Scan text for all known threat patterns without modifying it.

    Args:
        text: Raw input string to analyze.

    Returns:
        List of ThreatMatch objects (empty when clean).
    """
    threats: list[ThreatMatch] = []

    if "\x00" in text:
        threats.append(ThreatMatch(ThreatType.NULL_BYTE, "\\x00", text.index("\x00")))

    for pat in _XSS_PATTERNS:
        m = pat.search(text)
        if m:
            threats.append(ThreatMatch(ThreatType.XSS, pat.pattern, m.start()))

    for pat in _SQLI_PATTERNS:
        m = pat.search(text)
        if m:
            threats.append(ThreatMatch(ThreatType.SQLI, pat.pattern, m.start()))

    for pat in _PATH_TRAVERSAL_PATTERNS:
        m = pat.search(text)
        if m:
            threats.append(ThreatMatch(ThreatType.PATH_TRAVERSAL, pat.pattern, m.start()))

    for pat in _CMD_INJECTION_PATTERNS:
        m = pat.search(text)
        if m:
            threats.append(ThreatMatch(ThreatType.CMD_INJECTION, pat.pattern, m.start()))

    if _CONFUSABLE_PATTERN.search(text):
        threats.append(ThreatMatch(ThreatType.UNICODE_HOMOGLYPH, "confusable_chars", 0))

    if threats:
        logger.warning("Input threats detected count=%d types=%s", len(threats), [t.threat_type.value for t in threats])

    return threats


# ---------------------------------------------------------------------------
# Sanitizers
# ---------------------------------------------------------------------------

def strip_null_bytes(text: str) -> str:
    """Remove all null bytes from input.

    Args:
        text: Input string.

    Returns:
        String with \\x00 removed.
    """
    return text.replace("\x00", "")


def strip_html_tags(text: str) -> str:
    """Remove all HTML tags using a conservative regex.

    Args:
        text: Input string possibly containing HTML.

    Returns:
        Text with all <...> blocks removed.
    """
    return re.sub(r"<[^>]*>", "", text)


def normalize_unicode(text: str) -> str:
    """NFC-normalize and remove non-ASCII non-printable characters.

    Args:
        text: Potentially malformed Unicode string.

    Returns:
        NFC-normalized string with control characters stripped.
    """
    normalized = unicodedata.normalize("NFC", text)
    return "".join(c for c in normalized if unicodedata.category(c) not in ("Cc", "Cf"))


def sanitize_filename(name: str) -> str:
    """Strip path traversal sequences and dangerous filename characters.

    Args:
        name: User-supplied filename.

    Returns:
        Safe filename component (no directory separators or special chars).
    """
    # Remove directory separators and null bytes
    cleaned = re.sub(r"[/\\]", "_", name)
    cleaned = cleaned.replace("\x00", "")
    # Remove leading dots (hidden files on Unix)
    cleaned = cleaned.lstrip(".")
    # Keep only safe characters
    cleaned = re.sub(r"[^\w.\-]", "_", cleaned)
    # Collapse path traversal after separator removal
    cleaned = cleaned.replace("..", "__")
    return cleaned or "_"


def sanitize_text(
    text: str,
    *,
    max_length: int = MAX_DEFAULT_LENGTH,
    strip_html: bool = True,
    normalize: bool = True,
) -> SanitizationResult:
    """Apply a full sanitization pipeline to untrusted text input.

    Args:
        text: Raw untrusted input.
        max_length: Hard cap on output length (excess is truncated).
        strip_html: Remove HTML tags from output.
        normalize: Apply Unicode NFC normalization.

    Returns:
        SanitizationResult with sanitized text and threat list.
    """
    threats = detect_threats(text)
    sanitized = text

    sanitized = strip_null_bytes(sanitized)

    if normalize:
        sanitized = normalize_unicode(sanitized)

    if strip_html:
        sanitized = strip_html_tags(sanitized)

    truncated = False
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
        truncated = True
        threats.append(ThreatMatch(ThreatType.OVERSIZED, f">{max_length} chars", max_length))

    return SanitizationResult(
        original=text,
        sanitized=sanitized,
        threats=threats,
        truncated=truncated,
    )


def validate_email(email: str) -> bool:
    """Basic structural email validation (not RFC 5322 complete).

    Args:
        email: Email string to validate.

    Returns:
        True if the string looks like a valid email.
    """
    pattern = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
    return bool(pattern.match(email)) and len(email) <= 254  # noqa: PLR2004


def validate_integer(value: str, *, min_val: int | None = None, max_val: int | None = None) -> int:
    """Parse and range-check an integer from untrusted string input.

    Args:
        value: String representation of the integer.
        min_val: Optional minimum value (inclusive).
        max_val: Optional maximum value (inclusive).

    Returns:
        Parsed integer.

    Raises:
        ValueError: If value is not a valid integer or outside range.
    """
    stripped = value.strip()
    if not re.match(r"^-?\d+$", stripped):
        raise ValueError(f"Not a valid integer: {value!r}")
    n = int(stripped)
    if min_val is not None and n < min_val:
        raise ValueError(f"Value {n} below minimum {min_val}")
    if max_val is not None and n > max_val:
        raise ValueError(f"Value {n} above maximum {max_val}")
    return n
