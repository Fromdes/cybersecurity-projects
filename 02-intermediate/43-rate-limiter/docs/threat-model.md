# Threat Model — Rate Limiter

## STRIDE Table

| Threat | Example | Control |
|--------|---------|---------|
| Spoofing | Attacker rotates IPs to bypass per-IP limits | Key can be user ID + IP combined |
| Tampering | Direct store manipulation | State is private to limiter instance |
| Repudiation | No record of blocked requests | DENY logged with key + retry_after |
| Info Disclosure | `Retry-After` reveals limit size | Standard HTTP behaviour; acceptable |
| Elevation of Privilege | Credential stuffing at login | SlidingWindow on login endpoint per-IP |
| DoS | Memory exhaustion via unique keys | Production use should add eviction / Redis |

## MITRE ATT&CK Coverage

- T1110 — Brute Force: limits attempts per key per window
- T1078 — Valid Accounts (credential stuffing): rate-limits login endpoints
- T1498 — Network DoS: application-layer flood protection

## Recommended Key Strategies

| Endpoint | Key |
|----------|-----|
| Login | `login:{ip}` |
| Password reset | `reset:{email}` |
| API | `api:{user_id}` |
| Registration | `register:{ip}` |
