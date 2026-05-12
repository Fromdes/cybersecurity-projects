# Project 38 — OAuth2 PKCE Client

> RFC 7636 Proof Key for Code Exchange — generate challenges, build authorization URLs, and exchange codes securely without client secrets.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Defence |
|-----------|----|---------|
| Steal Application Access Token | T1528 | PKCE verifier proof prevents code interception |
| Use Alternate Auth Material | T1550.001 | Short-lived tokens bound to verifier |
| Valid Accounts (CSRF) | T1078 | State parameter with constant-time comparison |
| Authorization Code Interception | T1550 | S256 challenge cannot be reversed by eavesdropper |

## Features

- **`challenge`** — generate cryptographically random verifier + S256 challenge
- **`auth-url`** — build authorization URL with all required PKCE parameters
- **`exchange`** — POST code + verifier to token endpoint; verify state
- Only S256 supported (plain method intentionally excluded)
- State CSRF check with `secrets.compare_digest`
- `describe_pkce()` omits verifier to prevent accidental logging
- JSON output for all commands

## Tech Stack

- Python 3.11+, requests, click (no OAuth library dependency by design — teaches the protocol)

## Install & Run on Kali

```bash
cd 02-intermediate/38-oauth2-pkce-client
pip install -e .

# Step 1: Generate PKCE challenge
pkce-client challenge --json

# Step 2: Build authorization URL
pkce-client auth-url \
  --endpoint https://accounts.google.com/o/oauth2/v2/auth \
  --client-id YOUR_CLIENT_ID \
  --redirect-uri http://localhost:8080/callback \
  --scope "openid profile email"

# Step 3: After user authorizes, exchange the code
pkce-client exchange \
  --token-endpoint https://oauth2.googleapis.com/token \
  --code AUTH_CODE_FROM_CALLBACK \
  --verifier YOUR_VERIFIER \
  --client-id YOUR_CLIENT_ID \
  --redirect-uri http://localhost:8080/callback \
  --state ORIGINAL_STATE \
  --returned-state STATE_FROM_CALLBACK
```

## Testing

```bash
pytest --cov=project_38 --cov-report=term-missing
```

## What You'll Learn

- RFC 7636 PKCE flow end-to-end
- Why `plain` code challenge method is insecure
- CSRF protection with state parameter
- Difference between public and confidential OAuth2 clients

## References

- RFC 7636 — Proof Key for Code Exchange
- RFC 6749 — OAuth 2.0 Authorization Framework
- MITRE T1528, T1550.001
