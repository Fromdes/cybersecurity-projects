# Architecture — Kubernetes RBAC Auditor

## Components

```
cli.py          → Click interface (audit command)
core.py         → Parser + audit engine
  parse_rbac_yaml()   → multi-doc YAML → list[RBACResource]
  parse_rbac_dict()   → dict → RBACResource
  audit_role()        → RBACResource → list[RBACFinding]
  audit_file()        → Path → AuditReport
```

## Data Flow

```
YAML file → parse_rbac_yaml() → [RBACResource]
                                      │
                               audit_role() per resource
                                      │
                               [RBACFinding] → AuditReport
                                                    │
                                            JSON / stdout
```

## Rule Matching

Each rule in a Kubernetes Role is checked against `DANGEROUS_VERB_COMBOS`. A match occurs when:
- The rule's `resources` list intersects with the required resources (or contains `*`)
- The rule's `verbs` list intersects with the required verbs (or contains `*`)

Findings are deduplicated per rule_id per resource to prevent noise from multiple matching rules.
