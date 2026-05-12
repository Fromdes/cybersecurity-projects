# Project 40 — ABAC Policy Engine

> Attribute-Based Access Control engine with XACML-inspired YAML policies, multiple combining algorithms, and environment-aware rules — defending against privilege escalation and context-blind authorization.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Defence |
|-----------|----|---------|
| Valid Accounts (context-blind authz) | T1078 | Fine-grained attribute checks beyond role membership |
| Abuse Elevation Control Mechanism | T1548 | deny-overrides prevents any permit from bypassing explicit deny |
| Data from Cloud Storage | T1530 | Resource classification attribute gates sensitive access |
| Data Manipulation | T1565 | Action attribute checked per-resource |

## Features

- **Rich conditions** — `eq`, `neq`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`, `contains`, `matches` (regex)
- **Three attribute namespaces** — `subject.*`, `resource.*`, `environment.*`
- **Three combining algorithms** — `deny-overrides`, `permit-overrides`, `first-applicable`
- **Priority ordering** — higher-priority rules evaluated first
- YAML policy format, serializable to/from dict
- CLI `evaluate` command with exit code 0/1 for pipeline use
- Default closed — no matching rule → DENY

## Tech Stack

- Python 3.11+, PyYAML, click

## ABAC vs RBAC

| Feature | RBAC (project 39) | ABAC (project 40) |
|---------|-------------------|-------------------|
| Authorization based on | Role membership | Any attribute combination |
| Context-aware | No | Yes (time, IP, classification) |
| Rule complexity | Low | High |
| Best for | Simple hierarchies | Fine-grained, dynamic policies |

## Install & Run on Kali

```bash
cd 02-intermediate/40-abac-engine
pip install -e .

# Generate sample policy
abac init-policy --output policy.yaml

# Evaluate access (CLI exit code: 0=PERMIT, 1=DENY)
abac evaluate --policy policy.yaml \
  -s role=admin -s location=internal \
  -r classification=sensitive -r action=read

# With environment attributes (time-of-day check)
abac evaluate --policy policy.yaml \
  -s role=user \
  -r name=report \
  -e hour=14

# Dump parsed policy
abac dump --policy policy.yaml
```

## Policy Format

```yaml
combining_algorithm: deny-overrides   # or permit-overrides, first-applicable
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
```

## Testing

```bash
pytest --cov=project_40 --cov-report=term-missing
```

## What You'll Learn

- XACML concepts (PEP, PDP, PAP)
- ABAC vs RBAC trade-offs
- Combining algorithms and their security implications
- Context-aware authorization (time, IP, classification)

## References

- NIST SP 800-162 — Attribute-Based Access Control
- XACML 3.0 Specification
- MITRE T1078, T1548, T1530
