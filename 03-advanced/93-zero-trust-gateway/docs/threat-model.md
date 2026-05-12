# Threat Model — Zero Trust Network Gateway

## STRIDE Analysis

| Threat | Component | Mitigation |
|---|---|---|
| Spoofing | Principal identity | Principal field validated against rule patterns |
| Tampering | Policy files | Load-only at startup; immutable rule objects |
| Repudiation | Access decisions | Append-only JSONL audit log with timestamps |
| Information Disclosure | Rule details | Reasons logged but not returned to caller in prod |
| Denial of Service | Batch evaluation | Bounded by input file size |
| Elevation of Privilege | Source IP bypass | CIDR matching prevents internal network spoofing |

## Threat Scenarios Mitigated

1. **Lateral movement**: Compromised workstation at 10.5.x.x cannot reach databases unless explicitly allowed by CIDR rule
2. **MFA bypass**: Even a valid principal is denied if MFA is required and not verified
3. **High-risk access**: External IPs automatically receive elevated risk scores, potentially triggering max_risk_score limits
4. **Audit evasion**: Every decision, including ALLOW decisions, is logged with full context
