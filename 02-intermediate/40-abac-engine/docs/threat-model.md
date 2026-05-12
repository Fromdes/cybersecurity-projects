# Threat Model — ABAC Policy Engine

## STRIDE Table

| Threat | Example | Control |
|--------|---------|---------|
| Spoofing | User sends fake subject attributes | Caller must authenticate before calling evaluate() |
| Tampering | Modify YAML policy on disk | Policy loaded at startup; file integrity via project 03 |
| Repudiation | No audit trail | Every decision logged with subject/resource/rule |
| Info Disclosure | Error reveals policy internals | Errors logged server-side; only verdict returned |
| Elevation of Privilege | permit-overrides + attacker adds permit rule | deny-overrides as default; policy changes require review |
| DoS | Deeply nested conditions | All operators are O(1); no recursive evaluation |

## MITRE ATT&CK Coverage

- T1078 — Valid Accounts: fine-grained attribute checks beyond role membership
- T1548 — Abuse Elevation Control Mechanism: deny-overrides ensures explicit denies cannot be bypassed
- T1530 — Data from Cloud Storage: resource classification attribute gates sensitive access
- T1565 — Data Manipulation: action attribute checked per-resource
