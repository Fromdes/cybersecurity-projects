"""Kubernetes RBAC Auditor — analyse Role/ClusterRole YAML for privilege escalation risks."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore[import-untyped]
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


# ── Risk rules ────────────────────────────────────────────────────────────────

WILDCARD_RESOURCE = "*"
WILDCARD_VERB = "*"

DANGEROUS_VERB_COMBOS: tuple[tuple[frozenset[str], frozenset[str], str, str, str], ...] = (
    (frozenset({"*"}), frozenset({"*"}), "RBAC-001", "CRITICAL", "Wildcard on all resources and verbs"),
    (frozenset({"*"}), frozenset({"get", "list", "watch", "create", "update", "delete", "patch"}),
     "RBAC-002", "CRITICAL", "All verbs on wildcard resource"),
    (frozenset({"pods", "pods/exec"}), frozenset({"create", "get"}),
     "RBAC-003", "HIGH", "Pod exec access — potential container escape"),
    (frozenset({"secrets"}), frozenset({"get", "list", "watch"}),
     "RBAC-004", "HIGH", "Read access to Secrets — can expose credentials"),
    (frozenset({"clusterroles", "clusterrolebindings", "roles", "rolebindings"}),
     frozenset({"create", "update", "patch", "bind", "escalate"}),
     "RBAC-005", "CRITICAL", "RBAC escalation — can grant permissions to self"),
    (frozenset({"nodes"}), frozenset({"*", "proxy"}),
     "RBAC-006", "HIGH", "Node proxy access — can reach kubelet API"),
    (frozenset({"deployments", "daemonsets", "statefulsets", "replicationcontrollers"}),
     frozenset({"create", "update", "patch"}),
     "RBAC-007", "MEDIUM", "Can create/modify workloads — potential for privilege escalation"),
    (frozenset({"serviceaccounts/token"}), frozenset({"create"}),
     "RBAC-008", "HIGH", "Can create service account tokens"),
    (frozenset({"namespaces"}), frozenset({"create", "delete"}),
     "RBAC-009", "MEDIUM", "Can create/delete namespaces"),
    (frozenset({"pods"}), frozenset({"create", "update"}),
     "RBAC-010", "MEDIUM", "Can create pods — may mount host paths or run privileged"),
)


@dataclass(frozen=True)
class RBACFinding:
    """An RBAC audit finding."""

    rule_id: str
    severity: str
    title: str
    description: str
    resource_name: str
    kind: str
    matched_resources: list[str] = field(default_factory=list)
    matched_verbs: list[str] = field(default_factory=list)
    mitre_technique: str = "T1548"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "resource_name": self.resource_name,
            "kind": self.kind,
            "matched_resources": self.matched_resources,
            "matched_verbs": self.matched_verbs,
            "mitre_technique": self.mitre_technique,
        }


# ── YAML / dict parser ────────────────────────────────────────────────────────

@dataclass
class RBACResource:
    """A parsed Kubernetes RBAC resource."""

    kind: str
    name: str
    namespace: str
    rules: list[dict[str, Any]]
    subjects: list[dict[str, Any]] = field(default_factory=list)
    role_ref: dict[str, Any] = field(default_factory=dict)


def parse_rbac_yaml(path: Path) -> list[RBACResource]:
    """Parse a YAML file containing RBAC resources."""
    if not YAML_AVAILABLE:
        raise RuntimeError("PyYAML not installed. Run: pip install pyyaml")
    resources: list[RBACResource] = []
    with path.open() as fh:
        for doc in yaml.safe_load_all(fh):
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind", "")
            if kind not in ("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"):
                continue
            name = doc.get("metadata", {}).get("name", "unknown")
            namespace = doc.get("metadata", {}).get("namespace", "cluster-wide")
            rules = doc.get("rules", []) or []
            subjects = doc.get("subjects", []) or []
            role_ref = doc.get("roleRef", {}) or {}
            resources.append(RBACResource(kind, name, namespace, rules, subjects, role_ref))
    return resources


def parse_rbac_dict(data: dict[str, Any]) -> RBACResource | None:
    """Parse a single RBAC resource from a dict."""
    kind = data.get("kind", "")
    if kind not in ("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"):
        return None
    return RBACResource(
        kind=kind,
        name=data.get("metadata", {}).get("name", "unknown"),
        namespace=data.get("metadata", {}).get("namespace", "cluster-wide"),
        rules=data.get("rules", []) or [],
        subjects=data.get("subjects", []) or [],
        role_ref=data.get("roleRef", {}) or {},
    )


# ── Audit engine ──────────────────────────────────────────────────────────────

def audit_role(resource: RBACResource) -> list[RBACFinding]:
    """Audit a single Role or ClusterRole for dangerous permissions."""
    findings: list[RBACFinding] = []
    seen_rule_ids: set[str] = set()

    for rule in resource.rules:
        rule_resources = {resource_name.lower() for resource_name in (rule.get("resources") or [])}
        rule_verbs = {v.lower() for v in (rule.get("verbs") or [])}

        for req_resources, req_verbs, rule_id, severity, title in DANGEROUS_VERB_COMBOS:
            if rule_id in seen_rule_ids:
                continue
            # Check if rule grants the dangerous combo
            resources_match = (
                WILDCARD_RESOURCE in rule_resources
                or bool(rule_resources & req_resources)
            )
            verbs_match = (
                WILDCARD_VERB in rule_verbs
                or bool(rule_verbs & req_verbs)
            )
            if resources_match and verbs_match:
                seen_rule_ids.add(rule_id)
                findings.append(RBACFinding(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    description=f"{resource.kind}/{resource.name}: {title}",
                    resource_name=resource.name,
                    kind=resource.kind,
                    matched_resources=sorted(rule_resources),
                    matched_verbs=sorted(rule_verbs),
                ))
    return findings


@dataclass
class AuditReport:
    """Full RBAC audit report."""

    findings: list[RBACFinding]
    resources_audited: int
    source: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        by_sev: dict[str, int] = {}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {
            "source": self.source,
            "resources_audited": self.resources_audited,
            "total_findings": len(self.findings),
            "by_severity": by_sev,
            "findings": [f.to_dict() for f in self.findings],
        }


def audit_file(path: Path) -> AuditReport:
    """Audit all RBAC resources in a YAML file."""
    resources = parse_rbac_yaml(path)
    all_findings: list[RBACFinding] = []
    for res in resources:
        if res.kind in ("Role", "ClusterRole"):
            all_findings.extend(audit_role(res))
    return AuditReport(
        findings=all_findings,
        resources_audited=len(resources),
        source=str(path),
    )
