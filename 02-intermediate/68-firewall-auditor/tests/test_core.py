"""Tests for project 68 Firewall Rule Auditor."""

from __future__ import annotations

from project_68.core import (
    FirewallRule,
    _parse_port,
    audit_rules,
    parse_iptables_line,
    parse_iptables_output,
)

# ---------------------------------------------------------------------------
# Helper factory
# ---------------------------------------------------------------------------

def _rule(
    chain: str = "INPUT",
    target: str = "ACCEPT",
    protocol: str = "tcp",
    source: str = "0.0.0.0/0",
    destination: str = "0.0.0.0/0",
    dst_port: int | None = None,
    dst_port_end: int | None = None,
    raw: str = "",
) -> FirewallRule:
    return FirewallRule(
        chain=chain, target=target, protocol=protocol,
        source=source, destination=destination,
        dst_port=dst_port, dst_port_end=dst_port_end,
        raw=raw or f"INPUT ACCEPT {protocol} -- {source} {destination}",
    )


# ---------------------------------------------------------------------------
# _parse_port
# ---------------------------------------------------------------------------

class TestParsePort:
    def test_single_port(self) -> None:
        start, end = _parse_port("tcp dpt:22")
        assert start == 22
        assert end is None

    def test_port_range(self) -> None:
        start, end = _parse_port("tcp dpt:1024:65535")
        assert start == 1024
        assert end == 65535

    def test_no_port(self) -> None:
        start, end = _parse_port("all -- 0.0.0.0/0")
        assert start is None
        assert end is None


# ---------------------------------------------------------------------------
# FirewallRule properties
# ---------------------------------------------------------------------------

class TestFirewallRuleProperties:
    def test_allows_any_source_cidr(self) -> None:
        r = _rule(source="0.0.0.0/0")
        assert r.allows_any_source

    def test_allows_any_source_anywhere(self) -> None:
        r = _rule(source="anywhere")
        assert r.allows_any_source

    def test_specific_source_not_any(self) -> None:
        r = _rule(source="10.0.0.1/32")
        assert not r.allows_any_source

    def test_is_accept(self) -> None:
        assert _rule(target="ACCEPT").is_accept
        assert not _rule(target="DROP").is_accept

    def test_port_range_size(self) -> None:
        r = _rule(dst_port=80, dst_port_end=89)
        assert r.port_range_size == 10

    def test_single_port_range_size(self) -> None:
        r = _rule(dst_port=443)
        assert r.port_range_size == 1

    def test_no_port_range_size_none(self) -> None:
        r = _rule()
        assert r.port_range_size is None


# ---------------------------------------------------------------------------
# parse_iptables_line
# ---------------------------------------------------------------------------

class TestParseIptablesLine:
    def test_skip_header(self) -> None:
        assert parse_iptables_line("Chain INPUT (policy ACCEPT)") is None
        assert parse_iptables_line("target     prot opt source  destination") is None
        assert parse_iptables_line("") is None

    def test_accept_rule(self) -> None:
        line = "ACCEPT     tcp  --  0.0.0.0/0  0.0.0.0/0  tcp dpt:22"
        rule = parse_iptables_line(line, chain_context="INPUT")
        assert rule is not None
        assert rule.target == "ACCEPT"
        assert rule.dst_port == 22
        assert rule.chain == "INPUT"

    def test_drop_rule(self) -> None:
        line = "DROP       all  --  10.0.0.5   0.0.0.0/0"
        rule = parse_iptables_line(line, chain_context="INPUT")
        assert rule is not None
        assert rule.target == "DROP"
        assert not rule.is_accept


# ---------------------------------------------------------------------------
# parse_iptables_output
# ---------------------------------------------------------------------------

_SAMPLE_OUTPUT = """
Chain INPUT (policy ACCEPT 1234 packets, 9876 bytes)
 pkts bytes target     prot opt in     out     source               destination
  100  8000 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0   tcp dpt:80
   50  4000 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0   tcp dpt:22
    0     0 DROP       all  --  *      *       10.0.0.5             0.0.0.0/0

Chain FORWARD (policy DROP 0 packets, 0 bytes)

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
"""


class TestParseIptablesOutput:
    def test_rule_count(self) -> None:
        rules, _policies = parse_iptables_output(_SAMPLE_OUTPUT)
        assert len(rules) == 3

    def test_default_policies(self) -> None:
        _, policies = parse_iptables_output(_SAMPLE_OUTPUT)
        assert policies.get("INPUT") == "ACCEPT"
        assert policies.get("FORWARD") == "DROP"

    def test_port_extracted(self) -> None:
        rules, _ = parse_iptables_output(_SAMPLE_OUTPUT)
        ports = {r.dst_port for r in rules}
        assert 80 in ports
        assert 22 in ports


# ---------------------------------------------------------------------------
# audit_rules
# ---------------------------------------------------------------------------

class TestAuditRules:
    def test_empty_rules_no_findings(self) -> None:
        result = audit_rules([])
        assert not result.findings

    def test_any_source_accept_flagged(self) -> None:
        rules = [_rule(source="0.0.0.0/0", target="ACCEPT")]
        result = audit_rules(rules)
        assert result.findings

    def test_specific_source_no_finding(self) -> None:
        rules = [_rule(source="192.168.1.0/24", target="ACCEPT")]
        result = audit_rules(rules)
        # No any-source or dangerous-port findings
        assert not any(f.severity in {"critical", "high"} for f in result.findings)

    def test_dangerous_port_critical(self) -> None:
        rules = [_rule(source="0.0.0.0/0", target="ACCEPT", dst_port=3389)]
        result = audit_rules(rules)
        assert result.critical_count >= 1

    def test_management_port_high(self) -> None:
        rules = [_rule(source="0.0.0.0/0", target="ACCEPT", dst_port=5900)]
        result = audit_rules(rules)
        assert result.high_count >= 1

    def test_default_accept_policy_flagged(self) -> None:
        result = audit_rules([], default_policies={"INPUT": "ACCEPT"})
        assert any("default policy ACCEPT" in f.message for f in result.findings)

    def test_default_drop_policy_no_finding(self) -> None:
        result = audit_rules([], default_policies={"INPUT": "DROP"})
        assert not result.findings

    def test_duplicate_rule_flagged(self) -> None:
        rules = [
            _rule(dst_port=80),
            _rule(dst_port=80),
        ]
        result = audit_rules(rules)
        assert any(f.severity == "low" for f in result.findings)

    def test_wide_port_range_medium(self) -> None:
        rules = [_rule(source="0.0.0.0/0", target="ACCEPT", dst_port=1, dst_port_end=60000)]
        result = audit_rules(rules)
        assert any(f.severity == "medium" for f in result.findings)

    def test_drop_rule_not_flagged(self) -> None:
        rules = [_rule(source="0.0.0.0/0", target="DROP")]
        result = audit_rules(rules)
        # DROP rules don't generate any-source findings
        assert not any("accepts traffic" in f.message for f in result.findings)
