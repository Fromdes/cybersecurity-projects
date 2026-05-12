"""Snort/Suricata IDS rule builder and validator."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_ACTIONS: Final[frozenset[str]] = frozenset({"alert", "log", "pass", "drop", "reject"})
VALID_PROTOCOLS: Final[frozenset[str]] = frozenset({"tcp", "udp", "icmp", "ip"})
_SID_COUNTER: int = 1000000

_CONTENT_SPECIAL_RE: Final[re.Pattern[str]] = re.compile(r'[|;\\"]')


class Direction(str, Enum):
    UNIDIRECTIONAL = "->"
    BIDIRECTIONAL = "<>"


# ---------------------------------------------------------------------------
# Rule options
# ---------------------------------------------------------------------------

@dataclass
class ContentOption:
    """A content match option."""

    pattern: str
    nocase: bool = False
    offset: int | None = None
    depth: int | None = None
    http_uri: bool = False
    http_header: bool = False
    http_method: bool = False

    def render(self) -> str:
        parts = [f'content:"{self.pattern}"']
        if self.nocase:
            parts.append("nocase")
        if self.offset is not None:
            parts.append(f"offset:{self.offset}")
        if self.depth is not None:
            parts.append(f"depth:{self.depth}")
        if self.http_uri:
            parts.append("http_uri")
        if self.http_header:
            parts.append("http_header")
        if self.http_method:
            parts.append("http_method")
        return "; ".join(parts)


@dataclass
class PcreOption:
    """A PCRE regex match option."""

    pattern: str
    flags: str = ""

    def render(self) -> str:
        return f'pcre:"/{self.pattern}/{self.flags}"'


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------

@dataclass
class SnortRule:
    """A Snort/Suricata IDS rule."""

    action: str
    protocol: str
    src_addr: str
    src_port: str
    direction: Direction
    dst_addr: str
    dst_port: str
    msg: str
    sid: int
    rev: int = 1
    classtype: str = "misc-activity"
    priority: int = 2
    content_options: list[ContentOption] = field(default_factory=list)
    pcre_options: list[PcreOption] = field(default_factory=list)
    flow: str = ""
    reference: str = ""
    metadata: str = ""
    threshold_type: str = ""
    threshold_count: int = 0
    threshold_seconds: int = 0

    def render(self) -> str:
        """Serialise to a valid Snort/Suricata rule string."""
        header = (
            f"{self.action} {self.protocol} "
            f"{self.src_addr} {self.src_port} "
            f"{self.direction.value} "
            f"{self.dst_addr} {self.dst_port}"
        )
        options: list[str] = [f'msg:"{self.msg}"']

        if self.flow:
            options.append(f"flow:{self.flow}")

        for co in self.content_options:
            options.append(co.render())

        for po in self.pcre_options:
            options.append(po.render())

        options.append(f"classtype:{self.classtype}")
        options.append(f"sid:{self.sid}")
        options.append(f"rev:{self.rev}")
        options.append(f"priority:{self.priority}")

        if self.reference:
            options.append(f"reference:{self.reference}")
        if self.metadata:
            options.append(f"metadata:{self.metadata}")
        if self.threshold_type and self.threshold_count and self.threshold_seconds:
            options.append(
                f"threshold:type {self.threshold_type},"
                f"track by_src,"
                f"count {self.threshold_count},"
                f"seconds {self.threshold_seconds}"
            )

        return f"{header} ({'; '.join(options)};)"


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

@dataclass
class RuleValidationError:
    field: str
    message: str


def validate_rule(rule: SnortRule) -> list[RuleValidationError]:
    """Return a list of validation errors; empty list means valid."""
    errors: list[RuleValidationError] = []

    if rule.action not in VALID_ACTIONS:
        errors.append(RuleValidationError("action", f"Unknown action: {rule.action!r}"))

    if rule.protocol not in VALID_PROTOCOLS:
        errors.append(RuleValidationError("protocol", f"Unknown protocol: {rule.protocol!r}"))

    if rule.sid < 1:
        errors.append(RuleValidationError("sid", "SID must be >= 1"))

    if not rule.msg:
        errors.append(RuleValidationError("msg", "msg cannot be empty"))

    if '"' in rule.msg:
        errors.append(RuleValidationError("msg", 'msg cannot contain double quotes'))

    return errors


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class RuleBuilder:
    """Fluent builder for Snort/Suricata rules."""

    _sid_counter: int = 1_000_001

    def __init__(self) -> None:
        self._action = "alert"
        self._proto = "tcp"
        self._src_addr = "any"
        self._src_port = "any"
        self._direction = Direction.UNIDIRECTIONAL
        self._dst_addr = "any"
        self._dst_port = "any"
        self._msg = ""
        self._classtype = "misc-activity"
        self._priority = 2
        self._rev = 1
        self._flow = ""
        self._reference = ""
        self._metadata = ""
        self._content_options: list[ContentOption] = []
        self._pcre_options: list[PcreOption] = []
        self._threshold_type = ""
        self._threshold_count = 0
        self._threshold_seconds = 0
        RuleBuilder._sid_counter += 1
        self._sid = RuleBuilder._sid_counter

    def action(self, action: str) -> RuleBuilder:
        self._action = action
        return self

    def protocol(self, proto: str) -> RuleBuilder:
        self._proto = proto
        return self

    def src(self, addr: str, port: str = "any") -> RuleBuilder:
        self._src_addr = addr
        self._src_port = port
        return self

    def dst(self, addr: str, port: str = "any") -> RuleBuilder:
        self._dst_addr = addr
        self._dst_port = port
        return self

    def bidirectional(self) -> RuleBuilder:
        self._direction = Direction.BIDIRECTIONAL
        return self

    def msg(self, message: str) -> RuleBuilder:
        self._msg = message
        return self

    def content(
        self, pattern: str, nocase: bool = False,
        offset: int | None = None, depth: int | None = None,
        http_uri: bool = False, http_header: bool = False,
    ) -> RuleBuilder:
        self._content_options.append(ContentOption(
            pattern=pattern, nocase=nocase, offset=offset, depth=depth,
            http_uri=http_uri, http_header=http_header,
        ))
        return self

    def pcre(self, pattern: str, flags: str = "") -> RuleBuilder:
        self._pcre_options.append(PcreOption(pattern=pattern, flags=flags))
        return self

    def flow(self, flow: str) -> RuleBuilder:
        self._flow = flow
        return self

    def classtype(self, ct: str) -> RuleBuilder:
        self._classtype = ct
        return self

    def priority(self, p: int) -> RuleBuilder:
        self._priority = p
        return self

    def reference(self, ref: str) -> RuleBuilder:
        self._reference = ref
        return self

    def threshold(self, kind: str, count: int, seconds: int) -> RuleBuilder:
        self._threshold_type = kind
        self._threshold_count = count
        self._threshold_seconds = seconds
        return self

    def build(self) -> SnortRule:
        """Construct and return the SnortRule."""
        return SnortRule(
            action=self._action,
            protocol=self._proto,
            src_addr=self._src_addr,
            src_port=self._src_port,
            direction=self._direction,
            dst_addr=self._dst_addr,
            dst_port=self._dst_port,
            msg=self._msg,
            sid=self._sid,
            rev=self._rev,
            classtype=self._classtype,
            priority=self._priority,
            content_options=list(self._content_options),
            pcre_options=list(self._pcre_options),
            flow=self._flow,
            reference=self._reference,
            metadata=self._metadata,
            threshold_type=self._threshold_type,
            threshold_count=self._threshold_count,
            threshold_seconds=self._threshold_seconds,
        )


# ---------------------------------------------------------------------------
# Preset rule templates
# ---------------------------------------------------------------------------

def sql_injection_rule() -> SnortRule:
    """Return a rule detecting common SQL injection patterns in HTTP."""
    return (
        RuleBuilder()
        .action("alert")
        .protocol("tcp")
        .src("any", "any")
        .dst("$HTTP_SERVERS", "$HTTP_PORTS")
        .msg("POSSIBLE SQL Injection Attempt")
        .flow("to_server,established")
        .content("SELECT", nocase=True, http_uri=True)
        .pcre(r"(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|--)", "i")
        .classtype("web-application-attack")
        .priority(1)
        .reference("url,owasp.org/www-community/attacks/SQL_Injection")
        .build()
    )


def xss_rule() -> SnortRule:
    """Return a rule detecting basic XSS payloads in HTTP."""
    return (
        RuleBuilder()
        .action("alert")
        .protocol("tcp")
        .src("any", "any")
        .dst("$HTTP_SERVERS", "$HTTP_PORTS")
        .msg("POSSIBLE XSS Attempt")
        .flow("to_server,established")
        .content("<script", nocase=True, http_uri=True)
        .pcre(r"<script[^>]*>", "i")
        .classtype("web-application-attack")
        .priority(1)
        .build()
    )


def ssh_brute_force_rule() -> SnortRule:
    """Return a rule detecting SSH brute-force (threshold-based)."""
    return (
        RuleBuilder()
        .action("alert")
        .protocol("tcp")
        .src("any", "any")
        .dst("$HOME_NET", "22")
        .msg("POSSIBLE SSH Brute Force Attempt")
        .flow("to_server,established")
        .content("SSH-", offset=0, depth=4)
        .classtype("attempted-admin")
        .priority(2)
        .threshold("both", count=5, seconds=60)
        .build()
    )
