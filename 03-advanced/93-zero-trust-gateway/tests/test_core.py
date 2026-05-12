"""Tests for project_93 core — Zero Trust Network Gateway."""

from __future__ import annotations

import json
from pathlib import Path

from project_93.core import (
    AccessRequest,
    AuditLog,
    NetworkRule,
    ZeroTrustPolicy,
    calculate_risk_score,
    load_policy_file,
)


def _request(
    principal: str = "alice",
    source_ip: str = "10.0.0.1",
    destination: str = "app.internal",
    port: int = 443,
    protocol: str = "tcp",
    mfa: bool = True,
    risk_score: int = 0,
) -> AccessRequest:
    return AccessRequest(
        request_id="test-req",
        principal=principal,
        source_ip=source_ip,
        destination=destination,
        port=port,
        protocol=protocol,
        mfa_verified=mfa,
        risk_score=risk_score,
    )


def _allow_rule(
    rule_id: str = "R001",
    principals: frozenset[str] | None = None,
    source_cidrs: frozenset[str] | None = None,
    destinations: frozenset[str] | None = None,
    ports: frozenset[int] | None = None,
    require_mfa: bool = False,
    max_risk_score: int = 100,
) -> NetworkRule:
    return NetworkRule(
        rule_id=rule_id,
        description="allow",
        principals=principals or frozenset({"*"}),
        source_cidrs=source_cidrs or frozenset({"*"}),
        destinations=destinations or frozenset({"*"}),
        ports=ports or frozenset(),
        protocols=frozenset({"tcp"}),
        action="ALLOW",
        require_mfa=require_mfa,
        max_risk_score=max_risk_score,
    )


# ── ZeroTrustPolicy.evaluate ──────────────────────────────────────────────────

class TestPolicyEvaluate:
    def test_allow_matching_rule(self) -> None:
        policy = ZeroTrustPolicy(rules=[_allow_rule()])
        decision = policy.evaluate(_request())
        assert decision.allowed is True

    def test_deny_by_default(self) -> None:
        policy = ZeroTrustPolicy(rules=[], default_action="DENY")
        decision = policy.evaluate(_request())
        assert decision.allowed is False
        assert decision.matched_rule_id is None

    def test_principal_filter(self) -> None:
        rule = _allow_rule(principals=frozenset({"bob"}))
        policy = ZeroTrustPolicy(rules=[rule])
        assert policy.evaluate(_request(principal="alice")).allowed is False
        assert policy.evaluate(_request(principal="bob")).allowed is True

    def test_source_cidr_filter(self) -> None:
        rule = _allow_rule(source_cidrs=frozenset({"10.0.0.0/8"}))
        policy = ZeroTrustPolicy(rules=[rule])
        assert policy.evaluate(_request(source_ip="10.5.5.5")).allowed is True
        assert policy.evaluate(_request(source_ip="172.16.0.1")).allowed is False

    def test_destination_filter(self) -> None:
        rule = _allow_rule(destinations=frozenset({"app.internal"}))
        policy = ZeroTrustPolicy(rules=[rule])
        assert policy.evaluate(_request(destination="app.internal")).allowed is True
        assert policy.evaluate(_request(destination="db.internal")).allowed is False

    def test_port_filter(self) -> None:
        rule = _allow_rule(ports=frozenset({443}))
        policy = ZeroTrustPolicy(rules=[rule])
        assert policy.evaluate(_request(port=443)).allowed is True
        assert policy.evaluate(_request(port=80)).allowed is False

    def test_mfa_required_deny_without_mfa(self) -> None:
        rule = _allow_rule(require_mfa=True)
        policy = ZeroTrustPolicy(rules=[rule])
        assert policy.evaluate(_request(mfa=False)).allowed is False

    def test_mfa_required_allow_with_mfa(self) -> None:
        rule = _allow_rule(require_mfa=True)
        policy = ZeroTrustPolicy(rules=[rule])
        assert policy.evaluate(_request(mfa=True)).allowed is True

    def test_risk_score_exceeded(self) -> None:
        rule = _allow_rule(max_risk_score=30)
        policy = ZeroTrustPolicy(rules=[rule])
        assert policy.evaluate(_request(risk_score=50)).allowed is False

    def test_risk_score_within_limit(self) -> None:
        rule = _allow_rule(max_risk_score=100)
        policy = ZeroTrustPolicy(rules=[rule])
        assert policy.evaluate(_request(risk_score=50)).allowed is True

    def test_first_matching_rule_wins(self) -> None:
        deny_rule = NetworkRule(
            rule_id="R001", description="deny all",
            principals=frozenset({"*"}), source_cidrs=frozenset({"*"}),
            destinations=frozenset({"*"}), ports=frozenset(), protocols=frozenset({"tcp"}),
            action="DENY",
        )
        allow_rule = _allow_rule(rule_id="R002")
        policy = ZeroTrustPolicy(rules=[deny_rule, allow_rule])
        decision = policy.evaluate(_request())
        assert decision.allowed is False
        assert decision.matched_rule_id == "R001"

    def test_wildcard_principal(self) -> None:
        rule = _allow_rule(principals=frozenset({"user-*"}))
        policy = ZeroTrustPolicy(rules=[rule])
        assert policy.evaluate(_request(principal="user-alice")).allowed is True
        assert policy.evaluate(_request(principal="svc-backend")).allowed is False

    def test_wildcard_destination_suffix(self) -> None:
        rule = _allow_rule(destinations=frozenset({"*.internal"}))
        policy = ZeroTrustPolicy(rules=[rule])
        assert policy.evaluate(_request(destination="app.internal")).allowed is True
        assert policy.evaluate(_request(destination="app.external")).allowed is False


# ── calculate_risk_score ──────────────────────────────────────────────────────

class TestRiskScore:
    def test_internal_mfa_low_risk(self) -> None:
        req = _request(source_ip="10.0.0.1", port=443, mfa=True)
        score = calculate_risk_score(req)
        assert score < 30

    def test_external_no_mfa_high_risk(self) -> None:
        req = _request(source_ip="203.0.113.5", port=3389, mfa=False)
        score = calculate_risk_score(req)
        assert score >= 50

    def test_high_risk_port_adds_score(self) -> None:
        req_safe = _request(port=443)
        req_risky = _request(port=3389)
        assert calculate_risk_score(req_risky) > calculate_risk_score(req_safe)

    def test_max_capped_at_100(self) -> None:
        req = _request(source_ip="203.0.113.1", port=3389, mfa=False, protocol="custom")
        assert calculate_risk_score(req) <= 100


# ── AuditLog ──────────────────────────────────────────────────────────────────

class TestAuditLog:
    def test_record_and_count(self) -> None:
        policy = ZeroTrustPolicy(rules=[_allow_rule()])
        log = AuditLog()
        req = _request()
        decision = policy.evaluate(req)
        log.record(req, decision)
        assert len(log) == 1
        assert log.allowed_count() == 1
        assert log.denied_count() == 0

    def test_to_jsonl(self) -> None:
        policy = ZeroTrustPolicy(rules=[])
        log = AuditLog()
        req = _request()
        decision = policy.evaluate(req)
        log.record(req, decision)
        jsonl = log.to_jsonl()
        parsed = json.loads(jsonl.splitlines()[0])
        assert "principal" in parsed
        assert "allowed" in parsed


# ── load_policy_file ──────────────────────────────────────────────────────────

class TestLoadPolicyFile:
    def test_loads_json_policy(self, tmp_path: Path) -> None:
        policy_data = {
            "default_action": "DENY",
            "rules": [
                {
                    "rule_id": "R001",
                    "description": "Allow internal HTTPS",
                    "principals": ["*"],
                    "source_cidrs": ["10.0.0.0/8"],
                    "destinations": ["*.internal"],
                    "ports": [443],
                    "protocols": ["tcp"],
                    "action": "ALLOW",
                    "require_mfa": True,
                    "max_risk_score": 50,
                }
            ],
        }
        f = tmp_path / "policy.json"
        f.write_text(json.dumps(policy_data))
        policy = load_policy_file(f)
        assert len(policy.rules) == 1
        assert policy.rules[0].rule_id == "R001"
        assert policy.rules[0].require_mfa is True
        assert 443 in policy.rules[0].ports
