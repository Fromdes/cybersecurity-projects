"""Tests for ABAC Policy Engine core logic."""

from __future__ import annotations

import pytest

from project_40.core import (
    ABACDecision,
    ABACEngine,
    AttributeSet,
    CombiningAlgorithm,
    Condition,
    Effect,
    Operator,
    PolicyRule,
)

SAMPLE_POLICY = """
combining_algorithm: deny-overrides
rules:
  - name: deny-external-sensitive
    effect: deny
    priority: 100
    conditions:
      - attribute: subject.location
        operator: eq
        value: external
      - attribute: resource.classification
        operator: eq
        value: sensitive

  - name: permit-admin-all
    effect: permit
    priority: 50
    conditions:
      - attribute: subject.role
        operator: eq
        value: admin

  - name: permit-internal-read
    effect: permit
    priority: 10
    conditions:
      - attribute: subject.location
        operator: eq
        value: internal
      - attribute: resource.action
        operator: eq
        value: read
"""


@pytest.fixture()
def engine() -> ABACEngine:
    return ABACEngine.from_yaml(SAMPLE_POLICY)


class TestCondition:
    def test_eq_match(self) -> None:
        c = Condition("subject", "role", Operator.EQ, "admin")
        subj = AttributeSet.from_dict({"role": "admin"})
        assert c.evaluate(subj, AttributeSet.from_dict({}), AttributeSet.from_dict({}))

    def test_eq_no_match(self) -> None:
        c = Condition("subject", "role", Operator.EQ, "admin")
        subj = AttributeSet.from_dict({"role": "viewer"})
        assert not c.evaluate(subj, AttributeSet.from_dict({}), AttributeSet.from_dict({}))

    def test_in_operator(self) -> None:
        c = Condition("resource", "type", Operator.IN, ["doc", "pdf"])
        res = AttributeSet.from_dict({"type": "doc"})
        assert c.evaluate(AttributeSet.from_dict({}), res, AttributeSet.from_dict({}))

    def test_not_in_operator(self) -> None:
        c = Condition("resource", "type", Operator.NOT_IN, ["exe", "dll"])
        res = AttributeSet.from_dict({"type": "pdf"})
        assert c.evaluate(AttributeSet.from_dict({}), res, AttributeSet.from_dict({}))

    def test_gt_operator(self) -> None:
        c = Condition("subject", "clearance", Operator.GT, 2)
        subj = AttributeSet.from_dict({"clearance": 3})
        assert c.evaluate(subj, AttributeSet.from_dict({}), AttributeSet.from_dict({}))

    def test_lte_operator(self) -> None:
        c = Condition("subject", "age", Operator.LTE, 30)
        subj = AttributeSet.from_dict({"age": 25})
        assert c.evaluate(subj, AttributeSet.from_dict({}), AttributeSet.from_dict({}))

    def test_contains_operator(self) -> None:
        c = Condition("resource", "path", Operator.CONTAINS, "admin")
        res = AttributeSet.from_dict({"path": "/admin/panel"})
        assert c.evaluate(AttributeSet.from_dict({}), res, AttributeSet.from_dict({}))

    def test_matches_regex(self) -> None:
        c = Condition("subject", "email", Operator.MATCHES, r".*@corp\.com$")
        subj = AttributeSet.from_dict({"email": "alice@corp.com"})
        assert c.evaluate(subj, AttributeSet.from_dict({}), AttributeSet.from_dict({}))

    def test_missing_attribute_returns_false(self) -> None:
        c = Condition("subject", "nonexistent", Operator.EQ, "value")
        assert not c.evaluate(AttributeSet.from_dict({}), AttributeSet.from_dict({}), AttributeSet.from_dict({}))

    def test_unknown_namespace_returns_false(self) -> None:
        c = Condition("unknown_ns", "attr", Operator.EQ, "val")
        assert not c.evaluate(AttributeSet.from_dict({}), AttributeSet.from_dict({}), AttributeSet.from_dict({}))


class TestABACEngine:
    def test_permit_admin(self, engine: ABACEngine) -> None:
        decision = engine.evaluate(
            AttributeSet.from_dict({"role": "admin", "location": "external"}),
            AttributeSet.from_dict({"classification": "sensitive", "action": "delete"}),
        )
        # deny-overrides: deny-external-sensitive matches AND permit-admin matches → DENY wins
        assert not decision.allowed

    def test_permit_internal_read(self, engine: ABACEngine) -> None:
        decision = engine.evaluate(
            AttributeSet.from_dict({"location": "internal", "role": "viewer"}),
            AttributeSet.from_dict({"action": "read", "classification": "public"}),
        )
        assert decision.allowed
        assert decision.matched_rule == "permit-internal-read"

    def test_deny_external_sensitive(self, engine: ABACEngine) -> None:
        decision = engine.evaluate(
            AttributeSet.from_dict({"location": "external"}),
            AttributeSet.from_dict({"classification": "sensitive"}),
        )
        assert not decision.allowed
        assert decision.matched_rule == "deny-external-sensitive"

    def test_no_matching_rule_denied(self, engine: ABACEngine) -> None:
        decision = engine.evaluate(
            AttributeSet.from_dict({"location": "unknown"}),
            AttributeSet.from_dict({"classification": "unknown"}),
        )
        assert not decision.allowed
        assert decision.matched_rule is None

    def test_permit_overrides_algorithm(self) -> None:
        engine = ABACEngine(combining=CombiningAlgorithm.PERMIT_OVERRIDES)
        engine.add_rule(PolicyRule("deny-all", Effect.DENY, []))
        engine.add_rule(PolicyRule("permit-admin", Effect.PERMIT, [
            Condition("subject", "role", Operator.EQ, "admin")
        ]))
        decision = engine.evaluate(
            AttributeSet.from_dict({"role": "admin"}),
            AttributeSet.from_dict({}),
        )
        assert decision.allowed

    def test_first_applicable_algorithm(self) -> None:
        engine = ABACEngine(combining=CombiningAlgorithm.FIRST_APPLICABLE)
        engine.add_rule(PolicyRule("first-deny", Effect.DENY, [], priority=10))
        engine.add_rule(PolicyRule("second-permit", Effect.PERMIT, [], priority=5))
        decision = engine.evaluate(AttributeSet.from_dict({}), AttributeSet.from_dict({}))
        # first-deny has higher priority so it appears first → DENY
        assert not decision.allowed

    def test_environment_attributes(self, engine: ABACEngine) -> None:
        env_engine = ABACEngine.from_yaml("""
combining_algorithm: deny-overrides
rules:
  - name: deny-after-hours
    effect: deny
    priority: 100
    conditions:
      - attribute: environment.hour
        operator: gt
        value: 18
  - name: permit-daytime
    effect: permit
    priority: 10
    conditions:
      - attribute: environment.hour
        operator: lte
        value: 18
""")
        day = env_engine.evaluate(
            AttributeSet.from_dict({"role": "user"}),
            AttributeSet.from_dict({"name": "report"}),
            AttributeSet.from_dict({"hour": 14}),
        )
        assert day.allowed

        night = env_engine.evaluate(
            AttributeSet.from_dict({"role": "user"}),
            AttributeSet.from_dict({"name": "report"}),
            AttributeSet.from_dict({"hour": 22}),
        )
        assert not night.allowed

    def test_serialization_roundtrip(self, engine: ABACEngine) -> None:
        data = engine.to_dict()
        import yaml
        restored = ABACEngine.from_yaml(yaml.dump(data))
        decision = restored.evaluate(
            AttributeSet.from_dict({"location": "external"}),
            AttributeSet.from_dict({"classification": "sensitive"}),
        )
        assert not decision.allowed

    def test_invalid_combining_raises(self) -> None:
        with pytest.raises(ValueError):
            ABACEngine.from_yaml("combining_algorithm: invalid-algo\nrules: []")

    def test_invalid_condition_attr_format(self) -> None:
        with pytest.raises(ValueError):
            ABACEngine.from_yaml("""
combining_algorithm: deny-overrides
rules:
  - name: bad
    effect: deny
    conditions:
      - attribute: no_dot_here
        operator: eq
        value: x
""")
