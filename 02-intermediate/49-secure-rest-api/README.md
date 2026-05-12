# Project 49 — Secure REST API Template

> FastAPI template with API-key auth, HMAC request signing, rate limiting, and security headers baked in.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Brute Force API | T1110 | Rate limiting + HMAC replay prevention |
| Credentials Theft | T1528 | SHA-256 hashed key storage, Bearer-token auth |
| Man-in-the-Middle | T1557 | HSTS header + HMAC request signing |
| Unauthorized Access | T1078 | Scope-based API key authorization |

## Features

- API key creation with scope assignment
- SHA-256 hashed key storage (original never stored)
- Scope-based authorization per endpoint
- HMAC-SHA256 request signing with replay-window check
- Fixed-window rate limiter middleware
- Security headers on every response (HSTS, CSP, nosniff, …)
- FastAPI TestClient integration tests

## Install & Run

```bash
cd 02-intermediate/49-secure-rest-api
pip install -e .
secure-api serve --reload
```

## Testing

```bash
pytest tests/ -v --cov=project_49
```

## What You'll Learn

- Secure API key lifecycle (create, hash, scope, revoke)
- HMAC request signing and replay protection
- FastAPI middleware patterns
- Security header best practices
