# Architecture — Session Manager Service

## Components

```
core.py   Session, SessionStore, ValidationResult dataclasses; full lifecycle logic
cli.py    Click CLI (create / validate / demo commands)
```

## Session Lifecycle

```
create()   → Session(ACTIVE)
validate() → touches last_accessed; enforces expiry + idle
rotate()   → new Session(ACTIVE); old→ROTATED (grace window)
revoke()   → Session(REVOKED)
purge()    → removes non-ACTIVE sessions from memory
```

## Security Properties

| Property | Implementation |
|----------|---------------|
| Session ID entropy | 32 bytes → 43-char URL-safe base64 |
| CSRF token | 32 bytes, verified with hmac.compare_digest |
| Absolute expiry | configurable TTL (default 1 h) |
| Idle timeout | configurable (default 15 min) |
| Per-user cap | max 5 concurrent sessions; oldest revoked |
| Rotation grace | 5 s overlap during token handoff |
| Logging | only fingerprint (SHA-256) logged, not raw ID |
