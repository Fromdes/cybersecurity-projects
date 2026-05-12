"""Cloud IAM Policy Analyzer — analyze AWS IAM policy JSON for dangerous permissions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ── Finding model ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class IAMFinding:
    """A finding from IAM policy analysis."""

    rule_id: str
    severity: str
    title: str
    description: str
    statement_sid: str
    actions: list[str]
    resources: list[str]
    mitre_technique: str = "T1078.004"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "statement_sid": self.statement_sid,
            "actions": self.actions,
            "resources": self.resources,
            "mitre_technique": self.mitre_technique,
        }


# ── Dangerous action sets ─────────────────────────────────────────────────────

_ADMIN_ACTIONS: frozenset[str] = frozenset({"*", "iam:*", "sts:*"})

_DATA_EXFIL_ACTIONS: frozenset[str] = frozenset({
    "s3:GetObject", "s3:ListBucket", "s3:GetBucketPolicy",
    "s3:*", "dynamodb:GetItem", "dynamodb:Scan", "dynamodb:*",
    "rds:*", "secretsmanager:GetSecretValue", "ssm:GetParameter",
    "ssm:GetParameters", "ssm:GetParametersByPath",
})

_PRIVILEGE_ESCALATION_ACTIONS: frozenset[str] = frozenset({
    "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
    "iam:CreateAccessKey", "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile", "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy", "iam:AttachRolePolicy",
    "iam:PutUserPolicy", "iam:PutGroupPolicy", "iam:PutRolePolicy",
    "iam:AddUserToGroup", "iam:UpdateAssumeRolePolicy",
    "iam:PassRole", "sts:AssumeRole",
})

_INFRA_DESTROY_ACTIONS: frozenset[str] = frozenset({
    "ec2:TerminateInstances", "ec2:DeleteVpc", "ec2:DeleteSubnet",
    "rds:DeleteDBInstance", "rds:DeleteDBCluster",
    "s3:DeleteBucket", "s3:DeleteObject",
    "cloudformation:DeleteStack", "lambda:DeleteFunction",
    "iam:DeleteUser", "iam:DeleteRole", "iam:DeletePolicy",
})

_LOGGING_DISABLE_ACTIONS: frozenset[str] = frozenset({
    "cloudtrail:DeleteTrail", "cloudtrail:StopLogging",
    "cloudtrail:UpdateTrail", "guardduty:DeleteDetector",
    "guardduty:DisassociateMembers", "config:DeleteConfigRule",
    "config:DeleteDeliveryChannel", "logs:DeleteLogGroup",
})


def _normalize_actions(raw: Any) -> list[str]:
    """Normalize Action field to a list of strings."""
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(a) for a in raw]
    return []


def _normalize_resources(raw: Any) -> list[str]:
    """Normalize Resource field to a list of strings."""
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(r) for r in raw]
    return []


def _matches(actions: list[str], dangerous: frozenset[str]) -> bool:
    """Check if any action in the list is in the dangerous set or is a wildcard prefix."""
    action_set = {a.lower() for a in actions}
    dangerous_lower = {d.lower() for d in dangerous}
    if "*" in action_set or "iam:*" in action_set:
        return True
    # Check for service wildcards like "s3:*"
    for action in action_set:
        if action in dangerous_lower:
            return True
        # service:* matches any service:action in dangerous set
        if action.endswith(":*"):
            prefix = action[:-1]
            if any(d.startswith(prefix) for d in dangerous_lower):
                return True
    return False


def _has_wildcard_resource(resources: list[str]) -> bool:
    return "*" in resources or any(r.endswith("*") and len(r) <= 3 for r in resources)


# ── Statement analyzers ───────────────────────────────────────────────────────

def analyze_statement(stmt: dict[str, Any], policy_name: str) -> list[IAMFinding]:
    """Analyze a single IAM policy statement for dangerous permissions."""
    findings: list[IAMFinding] = []

    effect = stmt.get("Effect", "Allow")
    if effect != "Allow":
        return findings

    actions = _normalize_actions(stmt.get("Action", []))
    resources = _normalize_resources(stmt.get("Resource", []))
    sid = stmt.get("Sid", "(no sid)")

    # IAM-001: Full admin wildcard
    if "*" in actions and "*" in resources:
        findings.append(IAMFinding(
            rule_id="IAM-001",
            severity="CRITICAL",
            title="Full administrator access",
            description=f"{policy_name}: Statement grants Action:* on Resource:*",
            statement_sid=str(sid),
            actions=actions,
            resources=resources,
        ))
        return findings  # No need to check further

    # IAM-002: Wildcard actions on wildcard resource
    if "*" in actions and _has_wildcard_resource(resources):
        findings.append(IAMFinding(
            rule_id="IAM-002",
            severity="CRITICAL",
            title="Wildcard action on all resources",
            description=f"{policy_name}: Action:* with broad resource scope",
            statement_sid=str(sid),
            actions=actions,
            resources=resources,
        ))

    # IAM-003: Privilege escalation actions
    if _matches(actions, _PRIVILEGE_ESCALATION_ACTIONS):
        findings.append(IAMFinding(
            rule_id="IAM-003",
            severity="HIGH",
            title="Privilege escalation via IAM actions",
            description=f"{policy_name}: Can modify IAM permissions",
            statement_sid=str(sid),
            actions=actions,
            resources=resources,
        ))

    # IAM-004: Data exfiltration risk
    if _matches(actions, _DATA_EXFIL_ACTIONS) and _has_wildcard_resource(resources):
        findings.append(IAMFinding(
            rule_id="IAM-004",
            severity="HIGH",
            title="Broad data read access",
            description=f"{policy_name}: Can read sensitive data across all resources",
            statement_sid=str(sid),
            actions=actions,
            resources=resources,
        ))

    # IAM-005: Infrastructure destruction
    if _matches(actions, _INFRA_DESTROY_ACTIONS):
        findings.append(IAMFinding(
            rule_id="IAM-005",
            severity="HIGH",
            title="Infrastructure destruction permissions",
            description=f"{policy_name}: Can delete critical infrastructure",
            statement_sid=str(sid),
            actions=actions,
            resources=resources,
        ))

    # IAM-006: Logging/monitoring disable
    if _matches(actions, _LOGGING_DISABLE_ACTIONS):
        findings.append(IAMFinding(
            rule_id="IAM-006",
            severity="HIGH",
            title="Can disable security monitoring",
            description=f"{policy_name}: Can delete/stop CloudTrail or GuardDuty",
            statement_sid=str(sid),
            actions=actions,
            resources=resources,
        ))

    return findings


# ── Policy document analysis ──────────────────────────────────────────────────

@dataclass
class PolicyAnalysis:
    """Result of analyzing one IAM policy document."""

    policy_name: str
    source: str
    findings: list[IAMFinding]
    statement_count: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        by_sev: dict[str, int] = {}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {
            "policy_name": self.policy_name,
            "source": self.source,
            "statement_count": self.statement_count,
            "total_findings": len(self.findings),
            "by_severity": by_sev,
            "findings": [f.to_dict() for f in self.findings],
        }


def analyze_policy_dict(policy: dict[str, Any], policy_name: str = "policy", source: str = "") -> PolicyAnalysis:
    """Analyze an IAM policy document dict."""
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    all_findings: list[IAMFinding] = []
    for stmt in statements:
        if isinstance(stmt, dict):
            all_findings.extend(analyze_statement(stmt, policy_name))
    return PolicyAnalysis(
        policy_name=policy_name,
        source=source,
        findings=all_findings,
        statement_count=len(statements),
    )


def analyze_policy_file(path: Path) -> PolicyAnalysis:
    """Load and analyze an IAM policy JSON file."""
    content = path.read_text(encoding="utf-8")
    policy = json.loads(content)
    return analyze_policy_dict(policy, policy_name=path.stem, source=str(path))
