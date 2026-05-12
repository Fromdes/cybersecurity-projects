# Architecture — Zero Trust Network Gateway

## Components

```
cli.py          → Click interface (check, evaluate commands)
core.py         → Policy engine + risk scorer + audit log
  NetworkRule            → Immutable rule definition
  AccessRequest          → Inbound access request
  AccessDecision         → Allow/Deny result with reason
  ZeroTrustPolicy        → Ordered rule list + default action
    .evaluate()          → AccessRequest → AccessDecision
  calculate_risk_score() → AccessRequest → int (0-100)
  AuditLog               → Append-only decision log
  load_policy_file()     → Path → ZeroTrustPolicy
```

## Evaluation Flow

1. Calculate effective risk score (max of provided and computed)
2. Iterate rules in order; first matching rule wins
3. Check MFA requirement before allowing
4. Check risk score threshold before allowing
5. Fall back to default_action if no rule matches

## Zero Trust Principles Implemented

- **Never trust**: Default action is DENY
- **Always verify**: Every request evaluated against identity + context
- **Least privilege**: Rules restrict by principal, source, destination, port
- **Assume breach**: Risk scoring adds context-aware controls
