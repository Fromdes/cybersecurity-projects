"""Firewall rule auditor — parses iptables/nftables rules and detects misconfigurations."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DANGEROUS_PORTS: Final[frozenset[int]] = frozenset({
    21, 22, 23, 25, 53, 80, 110, 111, 135, 137, 139, 143,
    389, 443, 445, 512, 513, 514, 1433, 1521, 2181, 3306,
    3389, 5432, 5900, 6379, 8080, 8443, 27017,
})

MANAGEMENT_PORTS: Final[frozenset[int]] = frozenset({22, 23, 3389, 5900, 8080, 8443})

ANY_ADDR: Final[frozenset[str]] = frozenset({"0.0.0.0/0", "::/0", "any", "0.0.0.0", ""})

# iptables -L -n (non-verbose): target proto opt src dst [rest]
_IPTABLES_NV_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<target>ACCEPT|DROP|REJECT|LOG|RETURN|MASQUERADE|SNAT|DNAT|REDIRECT|MARK|QUEUE)\s+"
    r"(?P<proto>\S+)\s+"
    r"(?P<opt>--)\s+"
    r"(?P<src>\S+)\s+"
    r"(?P<dst>\S+)"
    r"(?P<rest>.*)$"
)

# iptables -L -n -v (verbose): pkts bytes target proto opt in out src dst [rest]
_IPTABLES_V_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*\d+\s+\d+\w*\s+"
    r"(?P<target>\S+)\s+"
    r"(?P<proto>\S+)\s+"
    r"(?P<opt>\S+)\s+"
    r"(?P<in_iface>\S+)\s+"
    r"(?P<out_iface>\S+)\s+"
    r"(?P<src>\S+)\s+"
    r"(?P<dst>\S+)"
    r"(?P<rest>.*)$"
)

_PORT_RE: Final[re.Pattern[str]] = re.compile(r"(?:dpt:|dports? )(\d+)(?::(\d+))?")
_COMMENT_RE: Final[re.Pattern[str]] = re.compile(r"/\*.*?\*/|--comment\s+\"[^\"]*\"")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FirewallRule:
    """A single parsed firewall rule."""

    chain: str
    target: str          # ACCEPT, DROP, REJECT, LOG, etc.
    protocol: str        # tcp, udp, all, icmp
    source: str          # CIDR or 'anywhere'
    destination: str
    dst_port: int | None
    dst_port_end: int | None  # for port ranges
    raw: str             # original rule text

    @property
    def allows_any_source(self) -> bool:
        """Return True if the rule accepts traffic from any source address."""
        return self.source.lower() in ANY_ADDR or self.source == "anywhere"

    @property
    def is_accept(self) -> bool:
        """Return True if this rule ACCEPTs traffic."""
        return self.target.upper() in {"ACCEPT", "RETURN"}

    @property
    def port_range_size(self) -> int | None:
        """Return number of ports covered, or None if no port specified."""
        if self.dst_port is None:
            return None
        end = self.dst_port_end or self.dst_port
        return end - self.dst_port + 1


@dataclass(frozen=True)
class AuditFinding:
    """A single firewall audit finding."""

    severity: str   # critical, high, medium, low, info
    rule_index: int
    message: str
    raw_rule: str


@dataclass
class FirewallAuditResult:
    """Complete firewall audit result."""

    rules: list[FirewallRule] = field(default_factory=list)
    findings: list[AuditFinding] = field(default_factory=list)
    default_policies: dict[str, str] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        """Count of critical findings."""
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        """Count of high findings."""
        return sum(1 for f in self.findings if f.severity == "high")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _parse_port(rest: str) -> tuple[int | None, int | None]:
    """Extract destination port (and end of range) from rule remainder text."""
    m = _PORT_RE.search(rest)
    if not m:
        return None, None
    start = int(m.group(1))
    end = int(m.group(2)) if m.group(2) else None
    return start, end


def parse_iptables_line(line: str, chain_context: str = "") -> FirewallRule | None:
    """Parse a single line from `iptables -L -n -v` output.

    Args:
        line: A single rule line (not a header/Chain line).
        chain_context: Chain name from the section header if available.

    Returns:
        FirewallRule or None if the line is not a rule.
    """
    line = line.strip()
    if not line or line.startswith("Chain") or line.startswith("target") or line.startswith("pkts"):
        return None

    m = _IPTABLES_NV_RE.match(line) or _IPTABLES_V_RE.match(line)
    if not m:
        return None

    rest = m.group("rest") or ""
    dst_port, dst_port_end = _parse_port(rest)

    return FirewallRule(
        chain=chain_context or "UNKNOWN",
        target=m.group("target"),
        protocol=m.group("proto"),
        source=m.group("src"),
        destination=m.group("dst"),
        dst_port=dst_port,
        dst_port_end=dst_port_end,
        raw=line,
    )


def parse_iptables_output(output: str) -> tuple[list[FirewallRule], dict[str, str]]:
    """Parse full `iptables -L -n -v` or `iptables-save` output.

    Args:
        output: Full text of iptables listing.

    Returns:
        Tuple of (rules list, default_policies dict).
    """
    rules: list[FirewallRule] = []
    policies: dict[str, str] = {}
    current_chain = ""

    for line in output.splitlines():
        stripped = line.strip()

        # Chain header: "Chain INPUT (policy ACCEPT 1234 packets, 56789 bytes)"
        if stripped.startswith("Chain "):
            parts = stripped.split()
            if len(parts) >= 2:
                current_chain = parts[1]
            if "policy" in stripped:
                policy_match = re.search(r"policy\s+(\w+)", stripped)
                if policy_match:
                    policies[current_chain] = policy_match.group(1)
            continue

        rule = parse_iptables_line(stripped, chain_context=current_chain)
        if rule:
            rules.append(rule)

    return rules, policies


# ---------------------------------------------------------------------------
# Live capture
# ---------------------------------------------------------------------------

def get_live_rules(table: str = "filter") -> tuple[str, str]:
    """Run iptables -L -n -v and return (output, error).

    Args:
        table: iptables table name (filter, nat, mangle).

    Returns:
        Tuple of (stdout text, stderr text).
    """
    try:
        proc = subprocess.run(
            ["iptables", "-L", "-n", "-v", "-t", table],
            capture_output=True, text=True, timeout=10,
        )
        return proc.stdout, proc.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return "", str(exc)


# ---------------------------------------------------------------------------
# Auditor
# ---------------------------------------------------------------------------

def audit_rules(
    rules: list[FirewallRule],
    default_policies: dict[str, str] | None = None,
) -> FirewallAuditResult:
    """Audit a list of firewall rules and return findings.

    Args:
        rules: Parsed FirewallRule objects.
        default_policies: Dict mapping chain name → default policy.

    Returns:
        FirewallAuditResult with findings.
    """
    result = FirewallAuditResult(rules=rules, default_policies=default_policies or {})

    _check_default_policies(result)

    for idx, rule in enumerate(rules):
        _check_any_source_accept(result, idx, rule)
        _check_dangerous_port_exposed(result, idx, rule)
        _check_management_port_exposed(result, idx, rule)
        _check_wide_port_range(result, idx, rule)

    _check_duplicate_rules(result)

    return result


def _check_default_policies(result: FirewallAuditResult) -> None:
    """Flag chains with ACCEPT default policy."""
    for chain, policy in result.default_policies.items():
        if policy.upper() == "ACCEPT" and chain in {"INPUT", "FORWARD"}:
            result.findings.append(AuditFinding(
                severity="high",
                rule_index=-1,
                message=f"Chain {chain} has default policy ACCEPT — implicit allow-all if no matching rule",
                raw_rule="",
            ))


def _check_any_source_accept(result: FirewallAuditResult, idx: int, rule: FirewallRule) -> None:
    """Flag rules that accept traffic from any source."""
    if rule.is_accept and rule.allows_any_source:
        sev = "critical" if rule.dst_port in DANGEROUS_PORTS else "high"
        result.findings.append(AuditFinding(
            severity=sev,
            rule_index=idx,
            message=f"Rule accepts traffic from ANY source"
                    f"{f' to port {rule.dst_port}' if rule.dst_port else ''}",
            raw_rule=rule.raw,
        ))


def _check_dangerous_port_exposed(result: FirewallAuditResult, idx: int, rule: FirewallRule) -> None:
    """Flag dangerous ports exposed to any source."""
    if rule.dst_port in DANGEROUS_PORTS and rule.allows_any_source and rule.is_accept:
        result.findings.append(AuditFinding(
            severity="critical",
            rule_index=idx,
            message=f"Dangerous service port {rule.dst_port} ({rule.protocol}) exposed to all sources",
            raw_rule=rule.raw,
        ))


def _check_management_port_exposed(result: FirewallAuditResult, idx: int, rule: FirewallRule) -> None:
    """Flag management ports (SSH, RDP, VNC) exposed to any source."""
    if rule.dst_port in MANAGEMENT_PORTS and rule.allows_any_source and rule.is_accept:
        result.findings.append(AuditFinding(
            severity="high",
            rule_index=idx,
            message=f"Management port {rule.dst_port} exposed to all sources",
            raw_rule=rule.raw,
        ))


def _check_wide_port_range(result: FirewallAuditResult, idx: int, rule: FirewallRule) -> None:
    """Flag rules with very wide port ranges."""
    size = rule.port_range_size
    if size is not None and size > 10000 and rule.is_accept and rule.allows_any_source:
        result.findings.append(AuditFinding(
            severity="medium",
            rule_index=idx,
            message=f"Very wide port range ({size} ports) accepted from any source",
            raw_rule=rule.raw,
        ))


def _check_duplicate_rules(result: FirewallAuditResult) -> None:
    """Flag duplicate rules (same chain, target, source, dst, port)."""
    seen: dict[tuple[str, str, str, str, int | None], int] = {}
    for idx, rule in enumerate(result.rules):
        key = (rule.chain, rule.target, rule.source, rule.destination, rule.dst_port)
        if key in seen:
            result.findings.append(AuditFinding(
                severity="low",
                rule_index=idx,
                message=f"Duplicate rule (same as rule index {seen[key]})",
                raw_rule=rule.raw,
            ))
        else:
            seen[key] = idx
