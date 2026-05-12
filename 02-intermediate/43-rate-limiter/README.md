# Project 43 — Rate Limiter

> Three rate-limiting algorithms (token bucket, sliding window, fixed window) with per-key tracking, retry-after headers, and side-by-side comparison — defending against brute force, credential stuffing, and application-layer floods.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Defence |
|-----------|----|---------|
| Brute Force | T1110 | Strict per-key request limit |
| Valid Accounts (credential stuffing) | T1078 | Login endpoint rate limiting |
| Network DoS (app layer) | T1498 | Flood throttling per IP |

## Features

- **Token Bucket** — continuous refill, burst-friendly
- **Sliding Window Log** — precise timestamp tracking, no boundary bursts
- **Fixed Window Counter** — simplest; educational comparison of boundary-burst risk
- `peek()` — check without consuming (pre-flight checks)
- `reset()` — unblock a key (admin override)
- `RateLimitDecision` — `remaining`, `reset_at`, `retry_after` → ready for HTTP headers
- `compare` command — show all three algorithms side by side for the same request burst

## Tech Stack

- Python 3.11+, stdlib only (collections.deque, time), click

## Install & Run

```bash
cd 02-intermediate/43-rate-limiter
pip install -e .

rate-limiter demo --algo sliding-window --limit 5 --requests 8
rate-limiter compare --limit 5 --requests 8
rate-limiter check --key "user:alice" --limit 10 --window 60 --json
```

## Testing

```bash
pytest --cov=project_43 --cov-report=term-missing
```

## What You'll Learn

- Token bucket vs sliding window vs fixed window trade-offs
- Boundary-burst attack on fixed windows
- `Retry-After` / `X-RateLimit-*` HTTP header design
- Key strategies: per-IP, per-user, per-endpoint

## References

- OWASP — Blocking Brute Force Attacks
- RFC 6585 — 429 Too Many Requests
- MITRE T1110, T1078, T1498
