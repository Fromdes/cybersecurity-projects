# Threat Model — RBAC Engine

## STRIDE Table

| Threat | Example | Control |
|--------|---------|---------|
| Spoofing | User claims admin identity | User lookup is authoritative; no self-assertion |
| Tampering | Modify policy YAML at runtime | Policy loaded once; immutable Permission dataclass |
| Repudiation | No record of who was denied | Every check/allow/deny logged with user+resource+action |
| Info Disclosure | Overly broad wildcard role | Wildcard requires explicit `*:*` — not implicit |
| Elevation of Privilege | Role escalation via inheritance loop | DFS cycle guard prevents infinite inheritance |
| DoS | Deeply nested role hierarchy | visited set caps recursion depth |

## MITRE ATT&CK Coverage

- T1078 — Valid Accounts: explicit role assignment; unknown users denied
- T1548 — Abuse Elevation Control Mechanism: privilege checks enforced at every call
- T1134 — Access Token Manipulation: no token; decisions computed fresh from policy
