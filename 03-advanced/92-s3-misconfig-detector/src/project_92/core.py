"""S3 Misconfiguration Detector — static analysis of S3 bucket policy JSON."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ── Finding model ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class S3Finding:
    """A finding from S3 bucket policy analysis."""

    rule_id: str
    severity: str
    title: str
    description: str
    statement_sid: str
    principal: str
    actions: list[str]
    resources: list[str]
    mitre_technique: str = "T1530"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "statement_sid": self.statement_sid,
            "principal": self.principal,
            "actions": self.actions,
            "resources": self.resources,
            "mitre_technique": self.mitre_technique,
        }


# ── Helper functions ──────────────────────────────────────────────────────────

def _normalize_list(value: Any) -> list[str]:
    """Normalize a string or list to a list of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def _principal_str(principal: Any) -> str:
    """Flatten principal to a display string."""
    if isinstance(principal, str):
        return principal
    if isinstance(principal, dict):
        parts: list[str] = []
        for k, v in principal.items():
            vals = _normalize_list(v)
            parts.extend(f"{k}:{x}" for x in vals)
        return ", ".join(parts)
    return str(principal)


def _is_public_principal(principal: Any) -> bool:
    """Return True if the principal is * (everyone)."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS", "")
        service = principal.get("Service", "")
        federated = principal.get("Federated", "")
        for val in (_normalize_list(aws) + _normalize_list(service) + _normalize_list(federated)):
            if val == "*":
                return True
    return False


def _has_condition(stmt: dict[str, Any]) -> bool:
    """Return True if the statement has a Condition block."""
    cond = stmt.get("Condition")
    return bool(cond)


def _actions_include(actions: list[str], *targets: str) -> bool:
    """Check if any action matches a target (case-insensitive, supports prefix wildcards)."""
    action_set = {a.lower() for a in actions}
    for target in targets:
        t = target.lower()
        if t in action_set or "*" in action_set:
            service = t.split(":")[0] + ":*"
            if service in action_set:
                return True
            if t in action_set:
                return True
    return False


# ── Check functions ───────────────────────────────────────────────────────────

def check_public_read(stmt: dict[str, Any], bucket_name: str) -> S3Finding | None:
    """S3-001: Public read access (Principal: * with s3:GetObject)."""
    if stmt.get("Effect") != "Allow":
        return None
    principal = stmt.get("Principal", "")
    if not _is_public_principal(principal):
        return None
    actions = _normalize_list(stmt.get("Action", []))
    if not _actions_include(actions, "s3:GetObject", "s3:*", "s3:ListBucket"):
        return None
    if _has_condition(stmt):
        return None
    return S3Finding(
        rule_id="S3-001",
        severity="CRITICAL",
        title="Public read access without condition",
        description=f"Bucket {bucket_name}: Anyone can read objects",
        statement_sid=str(stmt.get("Sid", "(no sid)")),
        principal=_principal_str(principal),
        actions=actions,
        resources=_normalize_list(stmt.get("Resource", [])),
    )


def check_public_write(stmt: dict[str, Any], bucket_name: str) -> S3Finding | None:
    """S3-002: Public write/delete access (Principal: * with s3:PutObject/DeleteObject)."""
    if stmt.get("Effect") != "Allow":
        return None
    principal = stmt.get("Principal", "")
    if not _is_public_principal(principal):
        return None
    actions = _normalize_list(stmt.get("Action", []))
    if not _actions_include(actions, "s3:PutObject", "s3:DeleteObject", "s3:*"):
        return None
    return S3Finding(
        rule_id="S3-002",
        severity="CRITICAL",
        title="Public write/delete access",
        description=f"Bucket {bucket_name}: Anyone can write or delete objects",
        statement_sid=str(stmt.get("Sid", "(no sid)")),
        principal=_principal_str(principal),
        actions=actions,
        resources=_normalize_list(stmt.get("Resource", [])),
    )


def check_public_list(stmt: dict[str, Any], bucket_name: str) -> S3Finding | None:
    """S3-003: Public bucket listing (Principal: * with s3:ListBucket)."""
    if stmt.get("Effect") != "Allow":
        return None
    principal = stmt.get("Principal", "")
    if not _is_public_principal(principal):
        return None
    actions = _normalize_list(stmt.get("Action", []))
    if not _actions_include(actions, "s3:ListBucket", "s3:ListBucketVersions", "s3:*"):
        return None
    return S3Finding(
        rule_id="S3-003",
        severity="HIGH",
        title="Public bucket listing",
        description=f"Bucket {bucket_name}: Anyone can list bucket contents",
        statement_sid=str(stmt.get("Sid", "(no sid)")),
        principal=_principal_str(principal),
        actions=actions,
        resources=_normalize_list(stmt.get("Resource", [])),
    )


def check_public_acl_change(stmt: dict[str, Any], bucket_name: str) -> S3Finding | None:
    """S3-004: Public ACL modification (Principal: * with s3:PutBucketAcl)."""
    if stmt.get("Effect") != "Allow":
        return None
    principal = stmt.get("Principal", "")
    if not _is_public_principal(principal):
        return None
    actions = _normalize_list(stmt.get("Action", []))
    if not _actions_include(actions, "s3:PutBucketAcl", "s3:PutObjectAcl", "s3:*"):
        return None
    return S3Finding(
        rule_id="S3-004",
        severity="CRITICAL",
        title="Public ACL modification allowed",
        description=f"Bucket {bucket_name}: Anyone can change bucket/object ACLs",
        statement_sid=str(stmt.get("Sid", "(no sid)")),
        principal=_principal_str(principal),
        actions=actions,
        resources=_normalize_list(stmt.get("Resource", [])),
    )


def check_wildcard_action_authenticated(stmt: dict[str, Any], bucket_name: str) -> S3Finding | None:
    """S3-005: Wildcard s3:* granted to any AWS principal without condition."""
    if stmt.get("Effect") != "Allow":
        return None
    principal = stmt.get("Principal", "")
    if _is_public_principal(principal):
        return None
    actions = _normalize_list(stmt.get("Action", []))
    if "*" not in actions and "s3:*" not in actions:
        return None
    if _has_condition(stmt):
        return None
    return S3Finding(
        rule_id="S3-005",
        severity="HIGH",
        title="Wildcard S3 action granted",
        description=f"Bucket {bucket_name}: s3:* grants full bucket control",
        statement_sid=str(stmt.get("Sid", "(no sid)")),
        principal=_principal_str(principal),
        actions=actions,
        resources=_normalize_list(stmt.get("Resource", [])),
    )


_CHECK_FUNCTIONS = (
    check_public_read,
    check_public_write,
    check_public_list,
    check_public_acl_change,
    check_wildcard_action_authenticated,
)


# ── Policy analysis ───────────────────────────────────────────────────────────

@dataclass
class BucketAnalysis:
    """Result of analyzing one S3 bucket policy."""

    bucket_name: str
    source: str
    findings: list[S3Finding]
    statement_count: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        by_sev: dict[str, int] = {}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {
            "bucket_name": self.bucket_name,
            "source": self.source,
            "statement_count": self.statement_count,
            "total_findings": len(self.findings),
            "by_severity": by_sev,
            "findings": [f.to_dict() for f in self.findings],
        }


def analyze_bucket_policy(
    policy: dict[str, Any],
    bucket_name: str = "unknown-bucket",
    source: str = "",
) -> BucketAnalysis:
    """Analyze an S3 bucket policy dict for misconfigurations."""
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    all_findings: list[S3Finding] = []
    seen: set[str] = set()
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        for check_fn in _CHECK_FUNCTIONS:
            result = check_fn(stmt, bucket_name)
            if result and result.rule_id not in seen:
                seen.add(result.rule_id)
                all_findings.append(result)
    return BucketAnalysis(
        bucket_name=bucket_name,
        source=source,
        findings=all_findings,
        statement_count=len(statements),
    )


def analyze_policy_file(path: Path) -> BucketAnalysis:
    """Load and analyze an S3 bucket policy JSON file."""
    content = path.read_text(encoding="utf-8")
    policy = json.loads(content)
    bucket_name = path.stem
    return analyze_bucket_policy(policy, bucket_name=bucket_name, source=str(path))
