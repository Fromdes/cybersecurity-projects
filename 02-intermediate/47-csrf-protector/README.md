# Project 47 — CSRF Token Service

> HMAC-signed CSRF token generation, validation, and rotation library with double-submit support.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Cross-Site Request Forgery | T1185 | Synchronized-token pattern blocks forged requests |
| Session Hijacking | T1563 | Per-session tokens prevent replay across sessions |

## Features

- Cryptographically random tokens (`secrets.token_urlsafe`)
- HMAC-SHA256 signed storage to detect store tampering
- TTL-based expiry with automatic purge
- Token rotation after use
- Framework-agnostic token extractor (header + form field)
- CLI for demo and manual testing

## Install & Run

```bash
cd 02-intermediate/47-csrf-protector
pip install -e .
CSRF_SECRET="your-32-byte-secret-key-here!!" csrf-protector demo
```

## Testing

```bash
pytest tests/ -v --cov=project_47
```

## What You'll Learn

- Synchronized-token CSRF pattern
- HMAC signing for token integrity
- Double-submit cookie vs server-side storage tradeoffs
