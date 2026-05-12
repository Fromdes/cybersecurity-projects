"""Core CSP policy builder, validator, and violation report parser."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NONE_VALUE = "'none'"
SELF_VALUE = "'self'"
UNSAFE_INLINE = "'unsafe-inline'"
UNSAFE_EVAL = "'unsafe-eval'"
STRICT_DYNAMIC = "'strict-dynamic'"
REPORT_SAMPLE = "'report-sample'"

KEYWORD_VALUES: frozenset[str] = frozenset(
    {NONE_VALUE, SELF_VALUE, UNSAFE_INLINE, UNSAFE_EVAL, STRICT_DYNAMIC, REPORT_SAMPLE,
     "'wasm-unsafe-eval'", "'unsafe-hashes'"}
)

_NONCE_RE = re.compile(r"^'nonce-[A-Za-z0-9+/=]+={0,2}'$")
_HASH_RE = re.compile(r"^'(sha256|sha384|sha512)-[A-Za-z0-9+/=]+={0,2}'$")
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+\-.]*:$")
_HOST_RE = re.compile(
    r"^(\*\.)?[a-zA-Z0-9\-]+(\.([a-zA-Z0-9\-]+))*(/.*)?$"
)


class FetchDirective(str, Enum):
    """Fetch directives controlling resource loading."""

    DEFAULT_SRC = "default-src"
    SCRIPT_SRC = "script-src"
    SCRIPT_SRC_ELEM = "script-src-elem"
    SCRIPT_SRC_ATTR = "script-src-attr"
    STYLE_SRC = "style-src"
    STYLE_SRC_ELEM = "style-src-elem"
    STYLE_SRC_ATTR = "style-src-attr"
    IMG_SRC = "img-src"
    CONNECT_SRC = "connect-src"
    FONT_SRC = "font-src"
    OBJECT_SRC = "object-src"
    MEDIA_SRC = "media-src"
    FRAME_SRC = "frame-src"
    CHILD_SRC = "child-src"
    WORKER_SRC = "worker-src"
    MANIFEST_SRC = "manifest-src"
    PREFETCH_SRC = "prefetch-src"
    BASE_URI = "base-uri"
    FORM_ACTION = "form-action"


class NavigationDirective(str, Enum):
    """Navigation directives."""

    NAVIGATE_TO = "navigate-to"
    FORM_ACTION = "form-action"


class ReportingDirective(str, Enum):
    """Reporting directives."""

    REPORT_URI = "report-uri"
    REPORT_TO = "report-to"


class OtherDirective(str, Enum):
    """Miscellaneous directives."""

    SANDBOX = "sandbox"
    UPGRADE_INSECURE_REQUESTS = "upgrade-insecure-requests"
    BLOCK_ALL_MIXED_CONTENT = "block-all-mixed-content"
    REQUIRE_TRUSTED_TYPES_FOR = "require-trusted-types-for"
    TRUSTED_TYPES = "trusted-types"


@dataclass
class CSPViolationReport:
    """Parsed CSP violation report (report-uri POST body)."""

    document_uri: str
    violated_directive: str
    effective_directive: str
    blocked_uri: str
    original_policy: str
    referrer: str = ""
    status_code: int = 0
    source_file: str = ""
    line_number: int = 0
    column_number: int = 0
    script_sample: str = ""

    @classmethod
    def from_json(cls, raw: str | bytes | dict[str, Any]) -> "CSPViolationReport":
        """Parse a CSP violation report from JSON."""
        if isinstance(raw, (str, bytes)):
            data: dict[str, Any] = json.loads(raw)
        else:
            data = raw
        report = data.get("csp-report", data)
        return cls(
            document_uri=str(report.get("document-uri", "")),
            violated_directive=str(report.get("violated-directive", "")),
            effective_directive=str(report.get("effective-directive", "")),
            blocked_uri=str(report.get("blocked-uri", "")),
            original_policy=str(report.get("original-policy", "")),
            referrer=str(report.get("referrer", "")),
            status_code=int(report.get("status-code", 0)),
            source_file=str(report.get("source-file", "")),
            line_number=int(report.get("line-number", 0)),
            column_number=int(report.get("column-number", 0)),
            script_sample=str(report.get("script-sample", "")),
        )


@dataclass
class PolicyWarning:
    """A security warning found during policy analysis."""

    severity: str  # "high" | "medium" | "low"
    directive: str
    message: str


@dataclass
class CSPPolicy:
    """Content Security Policy represented as structured data."""

    directives: dict[str, list[str]] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def set(self, directive: str, *values: str) -> "CSPPolicy":
        """Replace all values for a directive."""
        self.directives[directive] = list(values)
        return self

    def add(self, directive: str, *values: str) -> "CSPPolicy":
        """Append values to a directive (creates if absent)."""
        existing = self.directives.setdefault(directive, [])
        for v in values:
            if v not in existing:
                existing.append(v)
        return self

    def remove(self, directive: str) -> "CSPPolicy":
        """Remove a directive entirely."""
        self.directives.pop(directive, None)
        return self

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def build(self) -> str:
        """Serialise the policy to a valid CSP header value string."""
        parts: list[str] = []
        for directive, values in self.directives.items():
            if values:
                parts.append(f"{directive} {' '.join(values)}")
            else:
                parts.append(directive)
        return "; ".join(parts)

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyse(self) -> list[PolicyWarning]:
        """Return a list of security warnings for this policy."""
        warnings: list[PolicyWarning] = []

        for directive, values in self.directives.items():
            if UNSAFE_INLINE in values:
                warnings.append(PolicyWarning(
                    severity="high",
                    directive=directive,
                    message=f"'{UNSAFE_INLINE}' allows inline script/style execution — "
                            "use nonces or hashes instead.",
                ))
            if UNSAFE_EVAL in values:
                warnings.append(PolicyWarning(
                    severity="high",
                    directive=directive,
                    message=f"'{UNSAFE_EVAL}' allows eval() — "
                            "avoid dynamic code execution.",
                ))
            wildcard_hosts = [v for v in values if v == "*"]
            if wildcard_hosts:
                warnings.append(PolicyWarning(
                    severity="high",
                    directive=directive,
                    message="Wildcard (*) source allows any origin.",
                ))
            http_sources = [v for v in values if v.startswith("http://")]
            for src in http_sources:
                warnings.append(PolicyWarning(
                    severity="medium",
                    directive=directive,
                    message=f"Insecure HTTP source: {src}",
                ))

        if FetchDirective.DEFAULT_SRC.value not in self.directives and \
                FetchDirective.SCRIPT_SRC.value not in self.directives:
            warnings.append(PolicyWarning(
                severity="medium",
                directive="(none)",
                message="No default-src or script-src — all scripts implicitly allowed.",
            ))

        object_src = self.directives.get(FetchDirective.OBJECT_SRC.value, [])
        if NONE_VALUE not in object_src:
            warnings.append(PolicyWarning(
                severity="medium",
                directive=FetchDirective.OBJECT_SRC.value,
                message="object-src should be 'none' to block Flash/plugin exploitation.",
            ))

        return warnings


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class CSPBuilder:
    """Fluent builder for Content Security Policies."""

    def __init__(self) -> None:
        self._policy = CSPPolicy()

    # ------------------------------------------------------------------
    # Preset helpers
    # ------------------------------------------------------------------

    def strict(self) -> "CSPBuilder":
        """Apply a strict modern baseline (nonce-ready, no unsafe-*)."""
        self._policy.set(FetchDirective.DEFAULT_SRC.value, NONE_VALUE)
        self._policy.set(FetchDirective.SCRIPT_SRC.value, SELF_VALUE, STRICT_DYNAMIC)
        self._policy.set(FetchDirective.STYLE_SRC.value, SELF_VALUE)
        self._policy.set(FetchDirective.IMG_SRC.value, SELF_VALUE, "data:")
        self._policy.set(FetchDirective.FONT_SRC.value, SELF_VALUE)
        self._policy.set(FetchDirective.CONNECT_SRC.value, SELF_VALUE)
        self._policy.set(FetchDirective.OBJECT_SRC.value, NONE_VALUE)
        self._policy.set(FetchDirective.BASE_URI.value, NONE_VALUE)
        self._policy.set(FetchDirective.FORM_ACTION.value, SELF_VALUE)
        self._policy.set(OtherDirective.UPGRADE_INSECURE_REQUESTS.value)
        return self

    def report_only(self, endpoint: str) -> "CSPBuilder":
        """Add report-uri (use for CSP-Report-Only mode)."""
        self._policy.set(ReportingDirective.REPORT_URI.value, endpoint)
        return self

    def report_to(self, group: str) -> "CSPBuilder":
        """Add report-to group name (Reporting API v1)."""
        self._policy.set(ReportingDirective.REPORT_TO.value, group)
        return self

    def allow_nonce(self, directive: str, nonce: str) -> "CSPBuilder":
        """Add a nonce source to a directive."""
        nonce_val = f"'nonce-{nonce}'"
        self._policy.add(directive, nonce_val)
        return self

    def allow_hash(self, directive: str, algorithm: str, digest: str) -> "CSPBuilder":
        """Add a hash source to a directive."""
        self._policy.add(directive, f"'{algorithm}-{digest}'")
        return self

    def add(self, directive: str, *values: str) -> "CSPBuilder":
        """Add arbitrary values to a directive."""
        self._policy.add(directive, *values)
        return self

    def set(self, directive: str, *values: str) -> "CSPBuilder":
        """Replace a directive."""
        self._policy.set(directive, *values)
        return self

    def build(self) -> CSPPolicy:
        """Return the finalised CSPPolicy."""
        return self._policy

    def header_value(self) -> str:
        """Return the serialised header string."""
        return self._policy.build()


# ---------------------------------------------------------------------------
# Parser (string → CSPPolicy)
# ---------------------------------------------------------------------------

def parse_policy(header_value: str) -> CSPPolicy:
    """Parse a CSP header string into a CSPPolicy object."""
    policy = CSPPolicy()
    for part in header_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        directive = tokens[0].lower()
        values = tokens[1:]
        policy.directives[directive] = values
    return policy


# ---------------------------------------------------------------------------
# Source validation
# ---------------------------------------------------------------------------

def is_valid_source_value(value: str) -> bool:
    """Return True if *value* is a syntactically valid CSP source expression."""
    if value in KEYWORD_VALUES:
        return True
    if _NONCE_RE.match(value):
        return True
    if _HASH_RE.match(value):
        return True
    if _SCHEME_RE.match(value):
        return True
    if _HOST_RE.match(value):
        return True
    if value == "*":
        return True
    return False
