"""Zero Trust Network Gateway — policy evaluation engine with audit logging."""

from __future__ import annotations

import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Policy model ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class NetworkRule:
    """A single network access rule in a Zero Trust policy."""

    rule_id: str
    description: str
    principals: frozenset[str]
    source_cidrs: frozenset[str]
    destinations: frozenset[str]
    ports: frozenset[int]
    protocols: frozenset[str]
    action: str
    require_mfa: bool = False
    max_risk_score: int = 100


@dataclass(frozen=True)
class AccessRequest:
    """An inbound network access request to be evaluated."""

    request_id: str
    principal: str
    source_ip: str
    destination: str
    port: int
    protocol: str
    mfa_verified: bool = False
    risk_score: int = 0
    labels: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AccessDecision:
    """The result of evaluating an access request against policy."""

    request_id: str
    allowed: bool
    matched_rule_id: str | None
    reason: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "request_id": self.request_id,
            "allowed": self.allowed,
            "matched_rule_id": self.matched_rule_id,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }


# ── IP / CIDR helpers ─────────────────────────────────────────────────────────

def _ip_in_cidrs(ip: str, cidrs: frozenset[str]) -> bool:
    """Return True if *ip* falls within any of *cidrs*."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs:
        if cidr == "*":
            return True
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _destination_matches(destination: str, patterns: frozenset[str]) -> bool:
    """Return True if *destination* matches any pattern (glob-style * suffix)."""
    for pat in patterns:
        if pat == "*":
            return True
        if pat.startswith("*") and destination.endswith(pat[1:]):
            return True
        if destination == pat:
            return True
        # CIDR match for IP destinations
        try:
            ipaddress.ip_address(destination)
            if "/" in pat:
                if _ip_in_cidrs(destination, frozenset({pat})):
                    return True
        except ValueError:
            pass
    return False


# ── Risk scoring ──────────────────────────────────────────────────────────────

_HIGH_RISK_PORTS: frozenset[int] = frozenset({21, 23, 445, 1433, 3306, 3389, 5432, 6379, 27017})
_PRIVATE_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def calculate_risk_score(request: AccessRequest) -> int:
    """Calculate a 0-100 risk score for an access request."""
    score = 0
    # High-risk destination ports
    if request.port in _HIGH_RISK_PORTS:
        score += 30
    # External source IP
    try:
        addr = ipaddress.ip_address(request.source_ip)
        if not any(addr in net for net in _PRIVATE_RANGES):
            score += 25
    except ValueError:
        score += 20
    # No MFA
    if not request.mfa_verified:
        score += 20
    # High port number (ephemeral/non-standard)
    if request.port > 49151:
        score += 10
    # Non-standard protocol
    if request.protocol.lower() not in ("tcp", "udp", "icmp"):
        score += 15
    return min(score, 100)


# ── Policy engine ─────────────────────────────────────────────────────────────

@dataclass
class ZeroTrustPolicy:
    """Zero Trust policy containing ordered rules."""

    rules: list[NetworkRule]
    default_action: str = "DENY"

    def evaluate(self, request: AccessRequest) -> AccessDecision:
        """Evaluate an access request against all rules in order."""
        effective_risk = max(request.risk_score, calculate_risk_score(request))

        for rule in self.rules:
            if not _principal_matches(request.principal, rule.principals):
                continue
            if not _ip_in_cidrs(request.source_ip, rule.source_cidrs):
                continue
            if not _destination_matches(request.destination, rule.destinations):
                continue
            if rule.ports and request.port not in rule.ports:
                continue
            if rule.protocols and request.protocol.lower() not in rule.protocols:
                continue
            # MFA check
            if rule.require_mfa and not request.mfa_verified:
                return AccessDecision(
                    request_id=request.request_id,
                    allowed=False,
                    matched_rule_id=rule.rule_id,
                    reason=f"Rule {rule.rule_id}: MFA required but not verified",
                )
            # Risk score check
            if effective_risk > rule.max_risk_score:
                return AccessDecision(
                    request_id=request.request_id,
                    allowed=False,
                    matched_rule_id=rule.rule_id,
                    reason=f"Rule {rule.rule_id}: Risk score {effective_risk} exceeds max {rule.max_risk_score}",
                )
            allowed = rule.action.upper() == "ALLOW"
            return AccessDecision(
                request_id=request.request_id,
                allowed=allowed,
                matched_rule_id=rule.rule_id,
                reason=f"Rule {rule.rule_id}: {rule.action} — {rule.description}",
            )

        allowed = self.default_action.upper() == "ALLOW"
        return AccessDecision(
            request_id=request.request_id,
            allowed=allowed,
            matched_rule_id=None,
            reason=f"Default policy: {self.default_action}",
        )


def _principal_matches(principal: str, patterns: frozenset[str]) -> bool:
    """Return True if principal matches any pattern."""
    for pat in patterns:
        if pat == "*":
            return True
        if re.fullmatch(re.escape(pat).replace(r"\*", ".*"), principal):
            return True
    return False


# ── Policy loader ─────────────────────────────────────────────────────────────

def load_policy_file(path: Path) -> ZeroTrustPolicy:
    """Load a Zero Trust policy from a JSON file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    rules: list[NetworkRule] = []
    for r in data.get("rules", []):
        rules.append(NetworkRule(
            rule_id=r["rule_id"],
            description=r.get("description", ""),
            principals=frozenset(r.get("principals", ["*"])),
            source_cidrs=frozenset(r.get("source_cidrs", ["0.0.0.0/0"])),
            destinations=frozenset(r.get("destinations", ["*"])),
            ports=frozenset(int(p) for p in r.get("ports", [])),
            protocols=frozenset(p.lower() for p in r.get("protocols", ["tcp"])),
            action=r.get("action", "DENY"),
            require_mfa=r.get("require_mfa", False),
            max_risk_score=r.get("max_risk_score", 100),
        ))
    return ZeroTrustPolicy(rules=rules, default_action=data.get("default_action", "DENY"))


# ── Audit log ─────────────────────────────────────────────────────────────────

@dataclass
class AuditLog:
    """Append-only audit log of access decisions."""

    _entries: list[dict[str, Any]] = field(default_factory=list)

    def record(self, request: AccessRequest, decision: AccessDecision) -> None:
        """Record a request+decision pair."""
        self._entries.append({
            "request_id": request.request_id,
            "principal": request.principal,
            "source_ip": request.source_ip,
            "destination": request.destination,
            "port": request.port,
            "protocol": request.protocol,
            "mfa_verified": request.mfa_verified,
            "risk_score": request.risk_score,
            "allowed": decision.allowed,
            "matched_rule_id": decision.matched_rule_id,
            "reason": decision.reason,
            "timestamp": decision.timestamp,
        })

    def to_jsonl(self) -> str:
        """Serialize log to JSONL string."""
        return "\n".join(json.dumps(e) for e in self._entries)

    def denied_count(self) -> int:
        """Return count of denied decisions."""
        return sum(1 for e in self._entries if not e["allowed"])

    def allowed_count(self) -> int:
        """Return count of allowed decisions."""
        return sum(1 for e in self._entries if e["allowed"])

    def __len__(self) -> int:
        return len(self._entries)
