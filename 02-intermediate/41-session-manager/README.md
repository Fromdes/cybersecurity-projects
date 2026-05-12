# Project 41 — Session Manager Service

> Secure session lifecycle engine — creation, validation, rotation, CSRF binding, and forced revocation — defending against session hijacking and fixation.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Defence |
|-----------|----|---------|
| Web Session Cookie abuse | T1550.004 | 32-byte CSPRNG tokens, HttpOnly/Secure guidance |
| Browser Session Hijacking | T1185 | Session rotation on privilege change |
| Steal Web Session Cookie | T1539 | CSRF token binding via `hmac.compare_digest` |
| Valid Accounts (session replay) | T1078 | Idle + absolute timeout; revoke-all |

## Features

- **`create`** — new session with CSPRNG ID + CSRF token
- **`rotate`** — issue fresh token on privilege change (5 s grace overlap)
- **`revoke` / `revoke_all`** — instant logout, single or all devices
- **`verify_csrf`** — constant-time CSRF token check
- Per-user session cap (oldest revoked on overflow)
- Idle timeout + absolute TTL
- SHA-256 fingerprint logging (raw ID never logged)

## Install & Run

```bash
cd 02-intermediate/41-session-manager
pip install -e .
session-mgr demo          # full lifecycle walkthrough
session-mgr create --user alice --ip 10.0.0.1 --json
```

## Testing

```bash
pytest --cov=project_41 --cov-report=term-missing
```

## What You'll Learn

- Session fixation vs session hijacking
- CSRF token pattern and why `compare_digest` matters
- Session rotation after privilege changes
- Per-user concurrent session limits

## References

- OWASP Session Management Cheat Sheet
- MITRE T1550.004, T1185, T1539
