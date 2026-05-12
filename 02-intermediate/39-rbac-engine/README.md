# Project 39 — RBAC Engine

> Role-Based Access Control engine with role hierarchy, wildcard permissions, and structured audit logging — defending against privilege escalation and unauthorized access.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Defence |
|-----------|----|---------|
| Valid Accounts | T1078 | Explicit role assignment; unknown users denied |
| Abuse Elevation Control Mechanism | T1548 | Access checked at every operation |
| Access Token Manipulation | T1134 | Policy computed fresh; no cached token |
| Role escalation via inheritance | — | DFS cycle guard prevents infinite loops |

## Features

- **Roles with inheritance** — `editor` inherits `viewer` permissions automatically
- **Wildcard permissions** — `*:*`, `reports:*`, `*:read`
- **`check`** command — CLI access check with exit code 0/1 (pipeline-friendly)
- **`list-permissions`** — show all effective permissions for a user
- **`init-policy`** — generate sample YAML policy to start from
- YAML policy format, serializable to/from dict
- Every allow/deny decision logged with structured metadata
- Cycle detection in role inheritance graph

## Tech Stack

- Python 3.11+, PyYAML, click

## Install & Run on Kali

```bash
cd 02-intermediate/39-rbac-engine
pip install -e .

# Generate sample policy
rbac init-policy --output policy.yaml

# Check access
rbac check --policy policy.yaml --user alice --resource reports --action write

# List all permissions
rbac list-permissions --policy policy.yaml --user bob

# Dump parsed policy as JSON
rbac dump --policy policy.yaml
```

## Policy Format

```yaml
roles:
  viewer:
    permissions:
      - reports:read
      - dashboard:view
    parents: []
  editor:
    permissions:
      - reports:write
    parents: [viewer]
  admin:
    permissions:
      - "*:*"
    parents: [editor]

users:
  alice:
    roles: [admin]
  bob:
    roles: [editor]
```

## Testing

```bash
pytest --cov=project_39 --cov-report=term-missing
```

## What You'll Learn

- RBAC model (NIST RBAC standard)
- Role hierarchy and permission inheritance
- Principle of least privilege in practice
- Wildcard permission patterns and their risks

## References

- NIST SP 800-162 — RBAC Guide
- MITRE T1078, T1548, T1134
