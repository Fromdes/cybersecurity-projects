# Threat Model — Session Manager Service

## STRIDE Table

| Threat | Example | Control |
|--------|---------|---------|
| Spoofing | Forged session token | 32-byte CSPRNG token; not guessable |
| Tampering | Modify session data | Immutable session store; no client-side state |
| Repudiation | Deny session was active | Fingerprinted audit log on every create/rotate/revoke |
| Info Disclosure | Session ID in logs | Only SHA-256 fingerprint prefix logged |
| Elevation of Privilege | Reuse old token after privilege drop | rotate() issues new CSRF + session ID |
| DoS | Session flooding per user | Per-user cap revokes oldest on overflow |

## MITRE ATT&CK Coverage

- T1550.004 — Web Session Cookie: 32-byte entropy tokens defeat prediction
- T1185 — Browser Session Hijacking: HttpOnly + Secure cookie guidance + rotation
- T1539 — Steal Web Session Cookie: CSRF binding limits stolen-cookie impact
- T1078 — Valid Accounts: idle + absolute timeout limits window of abuse
