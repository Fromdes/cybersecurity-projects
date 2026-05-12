# Project 89 — Kubernetes RBAC Auditor

> Detects privilege escalation risks in Kubernetes Role and ClusterRole YAML manifests.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Abuse Elevation Control Mechanism | T1548 | Detects over-privileged RBAC roles |
| Valid Accounts: Cloud Accounts | T1078.004 | Catches wildcard permissions granting full cluster access |
| Steal Application Access Token | T1528 | Detects ServiceAccount token creation permissions |
| Container Escape | T1611 | Finds pod exec / privileged workload creation rights |

## Features

- Parses multi-document RBAC YAML (Role, ClusterRole, RoleBinding, ClusterRoleBinding)
- 10 built-in detection rules (RBAC-001 through RBAC-010)
- Severity levels: CRITICAL / HIGH / MEDIUM / LOW
- `--min-severity` filter for threshold-based CI gating
- `--exit-code` flag returns exit 1 on CRITICAL/HIGH (CI pipeline integration)
- JSON report output with `by_severity` summary

## Detection Rules

| Rule | Severity | Description |
|---|---|---|
| RBAC-001 | CRITICAL | Wildcard on all resources and verbs |
| RBAC-002 | CRITICAL | All verbs on wildcard resource |
| RBAC-003 | HIGH | Pod exec — potential container escape |
| RBAC-004 | HIGH | Read access to Secrets |
| RBAC-005 | CRITICAL | RBAC escalation — can grant permissions to self |
| RBAC-006 | HIGH | Node proxy — can reach kubelet API |
| RBAC-007 | MEDIUM | Can create/modify workloads |
| RBAC-008 | HIGH | Can create ServiceAccount tokens |
| RBAC-009 | MEDIUM | Can create/delete namespaces |
| RBAC-010 | MEDIUM | Can create pods (may run privileged) |

## Install & Run on Kali

```bash
cd 03-advanced/89-k8s-rbac-auditor
pip install -e .
k8s-rbac-auditor audit examples/dangerous-role.yaml
k8s-rbac-auditor audit rbac.yaml --min-severity HIGH --exit-code -o report.json
```

## Testing

```bash
pytest tests/ -v --cov=project_89
```

## What You'll Learn

- Kubernetes RBAC model (Roles, Bindings, verbs, resources)
- Privilege escalation paths in Kubernetes clusters
- YAML multi-document parsing with PyYAML
- Building policy-as-code audit tools
- CI/CD security gate integration with exit codes
