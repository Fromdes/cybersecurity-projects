"""ABAC Policy Engine — Attribute-Based Access Control with YAML policies.

Defends against: T1078 (Valid Accounts), T1548 (Abuse Elevation Control Mechanism),
T1530 (Data from Cloud Storage), T1565 (Data Manipulation).

Implements a simplified XACML-inspired model:
  Subject attributes + Resource attributes + Environment attributes → Policy rules → Decision
"""

from __future__ import annotations

import logging
import operator
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Effect & condition operators
# ---------------------------------------------------------------------------

class Effect(StrEnum):
    """Policy rule effect."""

    PERMIT = "permit"
    DENY = "deny"


class Operator(StrEnum):
    """Supported condition operators."""

    EQ = "eq"
    NEQ = "neq"
    IN = "in"
    NOT_IN = "not_in"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    CONTAINS = "contains"
    MATCHES = "matches"  # regex


_OP_FUNCS: dict[Operator, Any] = {
    Operator.EQ: operator.eq,
    Operator.NEQ: operator.ne,
    Operator.GT: operator.gt,
    Operator.GTE: operator.ge,
    Operator.LT: operator.lt,
    Operator.LTE: operator.le,
}


# ---------------------------------------------------------------------------
# Attributes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AttributeSet:
    """Arbitrary key-value attributes for subject, resource, or environment."""

    attrs: dict[str, Any]

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve an attribute by key."""
        return self.attrs.get(key, default)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttributeSet:
        """Create from a plain dict."""
        return cls(attrs=dict(data))


# ---------------------------------------------------------------------------
# Condition
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Condition:
    """A single attribute condition within a policy rule.

    Syntax: <namespace>.<attribute_name> <operator> <value>
    Namespaces: subject, resource, environment
    """

    namespace: str   # subject | resource | environment
    attribute: str
    op: Operator
    value: Any

    def evaluate(
        self,
        subject: AttributeSet,
        resource: AttributeSet,
        environment: AttributeSet,
    ) -> bool:
        """Evaluate this condition against the request context.

        Args:
            subject: Subject attributes.
            resource: Resource attributes.
            environment: Environment attributes.

        Returns:
            True if the condition is satisfied.
        """
        ns_map: dict[str, AttributeSet] = {
            "subject": subject,
            "resource": resource,
            "environment": environment,
        }
        attr_set = ns_map.get(self.namespace)
        if attr_set is None:
            logger.warning("Unknown namespace in condition: %s", self.namespace)
            return False

        actual = attr_set.get(self.attribute)
        if actual is None:
            return False

        return self._apply(actual)

    def _apply(self, actual: Any) -> bool:
        if self.op == Operator.IN:
            return actual in self.value
        if self.op == Operator.NOT_IN:
            return actual not in self.value
        if self.op == Operator.CONTAINS:
            return self.value in str(actual)
        if self.op == Operator.MATCHES:
            return bool(re.match(self.value, str(actual)))
        fn = _OP_FUNCS.get(self.op)
        if fn is None:
            logger.warning("Unknown operator: %s", self.op)
            return False
        try:
            return bool(fn(actual, self.value))
        except TypeError:
            return False


# ---------------------------------------------------------------------------
# Policy rule
# ---------------------------------------------------------------------------

@dataclass
class PolicyRule:
    """A named policy rule with conditions and an effect."""

    name: str
    effect: Effect
    conditions: list[Condition] = field(default_factory=list)
    description: str = ""
    priority: int = 0

    def matches(
        self,
        subject: AttributeSet,
        resource: AttributeSet,
        environment: AttributeSet,
    ) -> bool:
        """Return True if all conditions are satisfied.

        Args:
            subject: Subject attributes.
            resource: Resource attributes.
            environment: Environment attributes.

        Returns:
            True when every condition in this rule evaluates to True.
        """
        return all(c.evaluate(subject, resource, environment) for c in self.conditions)


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ABACDecision:
    """Result of an ABAC policy evaluation."""

    effect: Effect | None
    allowed: bool
    matched_rule: str | None
    subject_attrs: dict[str, Any]
    resource_attrs: dict[str, Any]

    def __str__(self) -> str:
        verdict = "PERMIT" if self.allowed else "DENY"
        return f"[{verdict}] rule={self.matched_rule}"


# ---------------------------------------------------------------------------
# Combining algorithms
# ---------------------------------------------------------------------------

class CombiningAlgorithm(StrEnum):
    """Rule combining algorithm."""

    DENY_OVERRIDES = "deny-overrides"
    PERMIT_OVERRIDES = "permit-overrides"
    FIRST_APPLICABLE = "first-applicable"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class ABACEngine:
    """Attribute-Based Access Control policy engine."""

    def __init__(self, combining: CombiningAlgorithm = CombiningAlgorithm.DENY_OVERRIDES) -> None:
        self._rules: list[PolicyRule] = []
        self._combining = combining

    def add_rule(self, rule: PolicyRule) -> None:
        """Register a policy rule.

        Args:
            rule: PolicyRule to add.
        """
        self._rules.append(rule)
        self._rules.sort(key=lambda r: -r.priority)

    def evaluate(
        self,
        subject: AttributeSet,
        resource: AttributeSet,
        environment: AttributeSet | None = None,
    ) -> ABACDecision:
        """Evaluate all rules against the request context.

        Args:
            subject: Attributes of the subject (user/service).
            resource: Attributes of the target resource.
            environment: Optional environment attributes (time, IP, etc.).

        Returns:
            ABACDecision with permit/deny verdict and matched rule.
        """
        env = environment or AttributeSet.from_dict({})
        matched_rules: list[PolicyRule] = [r for r in self._rules if r.matches(subject, resource, env)]

        decision = self._combine(matched_rules, subject, resource)
        logger.info("ABAC %s sub=%s res=%s", decision, subject.attrs, resource.attrs)
        return decision

    def _combine(
        self,
        matched: list[PolicyRule],
        subject: AttributeSet,
        resource: AttributeSet,
    ) -> ABACDecision:
        if not matched:
            return ABACDecision(
                effect=None,
                allowed=False,
                matched_rule=None,
                subject_attrs=dict(subject.attrs),
                resource_attrs=dict(resource.attrs),
            )

        if self._combining == CombiningAlgorithm.DENY_OVERRIDES:
            for rule in matched:
                if rule.effect == Effect.DENY:
                    return self._make_decision(rule, subject, resource)
            return self._make_decision(matched[0], subject, resource)

        if self._combining == CombiningAlgorithm.PERMIT_OVERRIDES:
            for rule in matched:
                if rule.effect == Effect.PERMIT:
                    return self._make_decision(rule, subject, resource)
            return self._make_decision(matched[0], subject, resource)

        # first-applicable
        return self._make_decision(matched[0], subject, resource)

    @staticmethod
    def _make_decision(rule: PolicyRule, subject: AttributeSet, resource: AttributeSet) -> ABACDecision:
        return ABACDecision(
            effect=rule.effect,
            allowed=rule.effect == Effect.PERMIT,
            matched_rule=rule.name,
            subject_attrs=dict(subject.attrs),
            resource_attrs=dict(resource.attrs),
        )

    @classmethod
    def from_yaml(cls, yaml_text: str) -> ABACEngine:
        """Load engine from a YAML policy string.

        Args:
            yaml_text: YAML policy definition.

        Returns:
            Configured ABACEngine.
        """
        data: dict[str, Any] = yaml.safe_load(yaml_text)
        combining_str: str = data.get("combining_algorithm", "deny-overrides")
        engine = cls(combining=CombiningAlgorithm(combining_str))

        for rdata in data.get("rules", []):
            conditions: list[Condition] = []
            for cdata in rdata.get("conditions", []):
                parts = cdata["attribute"].split(".", 1)
                if len(parts) != 2:
                    raise ValueError(f"Condition attribute must be 'namespace.attr', got: {cdata['attribute']}")
                conditions.append(Condition(
                    namespace=parts[0],
                    attribute=parts[1],
                    op=Operator(cdata["operator"]),
                    value=cdata["value"],
                ))
            engine.add_rule(PolicyRule(
                name=rdata["name"],
                effect=Effect(rdata["effect"]),
                conditions=conditions,
                description=rdata.get("description", ""),
                priority=rdata.get("priority", 0),
            ))

        return engine

    def to_dict(self) -> dict[str, Any]:
        """Serialize engine rules to a plain dict.

        Returns:
            Dict with combining_algorithm and rules list.
        """
        return {
            "combining_algorithm": self._combining.value,
            "rules": [
                {
                    "name": r.name,
                    "effect": r.effect.value,
                    "priority": r.priority,
                    "description": r.description,
                    "conditions": [
                        {
                            "attribute": f"{c.namespace}.{c.attribute}",
                            "operator": c.op.value,
                            "value": c.value,
                        }
                        for c in r.conditions
                    ],
                }
                for r in self._rules
            ],
        }
