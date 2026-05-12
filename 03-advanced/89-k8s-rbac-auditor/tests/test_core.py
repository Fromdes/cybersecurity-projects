"""Tests for project_89 core — Kubernetes RBAC Auditor."""

from __future__ import annotations

from project_89.core import (
    AuditReport,
    RBACFinding,
    RBACResource,
    audit_file,
    audit_role,
    parse_rbac_dict,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_role(rules: list[dict]) -> RBACResource:
    return RBACResource(kind="ClusterRole", name="test-role", namespace="cluster-wide", rules=rules)


# ── audit_role ────────────────────────────────────────────────────────────────

class TestAuditRoleWildcard:
    """RBAC-001 / RBAC-002 — wildcard checks."""

    def test_full_wildcard_triggers_rbac001(self) -> None:
        role = _make_role([{"resources": ["*"], "verbs": ["*"]}])
        findings = audit_role(role)
        ids = {f.rule_id for f in findings}
        assert "RBAC-001" in ids

    def test_all_verbs_on_wildcard_resource_triggers_rbac002(self) -> None:
        role = _make_role([{
            "resources": ["*"],
            "verbs": ["get", "list", "watch", "create", "update", "delete", "patch"],
        }])
        findings = audit_role(role)
        ids = {f.rule_id for f in findings}
        assert "RBAC-002" in ids

    def test_severity_critical_for_rbac001(self) -> None:
        role = _make_role([{"resources": ["*"], "verbs": ["*"]}])
        findings = audit_role(role)
        crit = [f for f in findings if f.rule_id == "RBAC-001"]
        assert crit[0].severity == "CRITICAL"


class TestAuditRolePodExec:
    """RBAC-003 — pod exec detection."""

    def test_pod_exec_triggers_rbac003(self) -> None:
        role = _make_role([{"resources": ["pods", "pods/exec"], "verbs": ["create", "get"]}])
        findings = audit_role(role)
        ids = {f.rule_id for f in findings}
        assert "RBAC-003" in ids

    def test_pods_only_no_exec_no_trigger(self) -> None:
        role = _make_role([{"resources": ["pods"], "verbs": ["list"]}])
        findings = audit_role(role)
        ids = {f.rule_id for f in findings}
        assert "RBAC-003" not in ids


class TestAuditRoleSecrets:
    """RBAC-004 — secret read detection."""

    def test_secret_read_triggers_rbac004(self) -> None:
        role = _make_role([{"resources": ["secrets"], "verbs": ["get", "list"]}])
        findings = audit_role(role)
        ids = {f.rule_id for f in findings}
        assert "RBAC-004" in ids

    def test_secret_create_no_trigger(self) -> None:
        role = _make_role([{"resources": ["secrets"], "verbs": ["create"]}])
        findings = audit_role(role)
        ids = {f.rule_id for f in findings}
        assert "RBAC-004" not in ids


class TestAuditRoleRBACEscalation:
    """RBAC-005 — RBAC escalation."""

    def test_clusterrole_bind_triggers_rbac005(self) -> None:
        role = _make_role([{
            "resources": ["clusterroles", "clusterrolebindings"],
            "verbs": ["bind", "escalate"],
        }])
        findings = audit_role(role)
        ids = {f.rule_id for f in findings}
        assert "RBAC-005" in ids


class TestAuditRoleServiceAccountToken:
    """RBAC-008 — SA token creation."""

    def test_sa_token_create_triggers_rbac008(self) -> None:
        role = _make_role([{"resources": ["serviceaccounts/token"], "verbs": ["create"]}])
        findings = audit_role(role)
        ids = {f.rule_id for f in findings}
        assert "RBAC-008" in ids


class TestAuditRoleDeduplication:
    """Each rule_id should appear only once per resource."""

    def test_no_duplicate_findings(self) -> None:
        role = _make_role([
            {"resources": ["secrets"], "verbs": ["get"]},
            {"resources": ["secrets"], "verbs": ["list"]},
        ])
        findings = audit_role(role)
        ids = [f.rule_id for f in findings]
        assert len(ids) == len(set(ids))


class TestAuditRoleClean:
    """Clean role with no dangerous permissions."""

    def test_read_only_configmap_no_findings(self) -> None:
        role = _make_role([{"resources": ["configmaps"], "verbs": ["get", "list", "watch"]}])
        findings = audit_role(role)
        assert findings == []


# ── parse_rbac_dict ───────────────────────────────────────────────────────────

class TestParseRbacDict:
    def test_parses_role(self) -> None:
        data = {
            "kind": "Role",
            "metadata": {"name": "my-role", "namespace": "default"},
            "rules": [{"resources": ["pods"], "verbs": ["get"]}],
        }
        res = parse_rbac_dict(data)
        assert res is not None
        assert res.kind == "Role"
        assert res.name == "my-role"
        assert res.namespace == "default"

    def test_ignores_non_rbac_kind(self) -> None:
        data = {"kind": "Deployment", "metadata": {"name": "app"}}
        assert parse_rbac_dict(data) is None

    def test_missing_namespace_defaults(self) -> None:
        data = {"kind": "ClusterRole", "metadata": {"name": "cr"}, "rules": []}
        res = parse_rbac_dict(data)
        assert res is not None
        assert res.namespace == "cluster-wide"


# ── audit_file ────────────────────────────────────────────────────────────────

class TestAuditFile:
    def test_audit_file_returns_report(self, tmp_path) -> None:
        yaml_content = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dangerous-role
rules:
  - resources: ["*"]
    verbs: ["*"]
"""
        f = tmp_path / "rbac.yaml"
        f.write_text(yaml_content)
        report = audit_file(f)
        assert isinstance(report, AuditReport)
        assert report.resources_audited == 1
        assert len(report.findings) > 0

    def test_audit_file_multi_doc(self, tmp_path) -> None:
        yaml_content = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: role-a
rules:
  - resources: ["secrets"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: role-b
rules:
  - resources: ["pods", "pods/exec"]
    verbs: ["create", "get"]
"""
        f = tmp_path / "multi.yaml"
        f.write_text(yaml_content)
        report = audit_file(f)
        assert report.resources_audited == 2
        assert len(report.findings) >= 2

    def test_audit_file_clean_role(self, tmp_path) -> None:
        yaml_content = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: reader
rules:
  - resources: ["configmaps"]
    verbs: ["get", "list"]
"""
        f = tmp_path / "clean.yaml"
        f.write_text(yaml_content)
        report = audit_file(f)
        assert report.findings == []

    def test_audit_file_bindings_not_audited(self, tmp_path) -> None:
        yaml_content = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rb
subjects:
  - kind: User
    name: alice
roleRef:
  kind: Role
  name: reader
  apiGroup: rbac.authorization.k8s.io
"""
        f = tmp_path / "binding.yaml"
        f.write_text(yaml_content)
        report = audit_file(f)
        assert report.resources_audited == 1
        assert report.findings == []


# ── RBACFinding serialization ─────────────────────────────────────────────────

class TestRBACFindingToDict:
    def test_to_dict_keys(self) -> None:
        finding = RBACFinding(
            rule_id="RBAC-001",
            severity="CRITICAL",
            title="Wildcard",
            description="desc",
            resource_name="test",
            kind="ClusterRole",
            matched_resources=["*"],
            matched_verbs=["*"],
        )
        d = finding.to_dict()
        assert set(d.keys()) >= {"rule_id", "severity", "title", "description",
                                  "resource_name", "kind", "matched_resources", "matched_verbs"}


class TestAuditReportToDict:
    def test_to_dict_structure(self, tmp_path) -> None:
        yaml_content = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: bad-role
rules:
  - resources: ["*"]
    verbs: ["*"]
"""
        f = tmp_path / "rbac.yaml"
        f.write_text(yaml_content)
        report = audit_file(f)
        d = report.to_dict()
        assert "findings" in d
        assert "resources_audited" in d
        assert "total_findings" in d
        assert "by_severity" in d
