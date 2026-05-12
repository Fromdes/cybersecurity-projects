# Threat Model — Cloud IAM Policy Analyzer

## STRIDE Analysis

| Threat | Component | Mitigation |
|---|---|---|
| Elevation of Privilege | IAM escalation actions | IAM-003 detects policy/role manipulation |
| Information Disclosure | Broad data access | IAM-004 catches wildcard S3/Secrets access |
| Tampering | Infrastructure delete | IAM-005 detects destroy permissions |
| Repudiation | Logging disable | IAM-006 catches CloudTrail/GuardDuty disable |

## Attack Scenarios

1. **Admin takeover**: `Action:* Resource:*` allows complete account compromise — IAM-001
2. **Lateral movement**: `iam:PassRole` allows attacker to assume high-privilege roles — IAM-003
3. **Secret exfil**: `secretsmanager:GetSecretValue` on `*` exposes all secrets — IAM-004
4. **Cover tracks**: `cloudtrail:DeleteTrail` removes audit trail — IAM-006
