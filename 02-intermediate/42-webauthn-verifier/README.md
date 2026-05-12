# Project 42 — WebAuthn/FIDO2 Verifier

> Server-side WebAuthn ceremony verifier — parse authenticator data, verify challenges and origins, detect sign-counter replay attacks — defending against phishing and credential theft.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Defence |
|-----------|----|---------|
| Valid Accounts (phishing bypass) | T1078 | Public-key auth; no password to steal |
| Modify Authentication Process | T1556 | Origin + RP ID binding prevents MITM |
| Brute Force | T1110 | No shared secret; hardware-bound private key |
| Credential Replay | T1550 | Single-use challenge + sign counter |

## Features

- **`parse-authdata`** — decode base64url authenticator data, display all flags
- **`demo`** — full registration + authentication + replay-attack simulation
- **`issue-challenge`** — generate cryptographically random WebAuthn challenge
- Sign counter replay detection (stored > received → COUNTER_REPLAY)
- Single-use challenge store (prevents challenge replay)
- Origin and RP ID hash binding (constant-time comparison)
- No external WebAuthn library dependency — teaches the W3C spec directly

## Tech Stack

- Python 3.11+, stdlib only (struct, hashlib, secrets, json), click

## Install & Run

```bash
cd 02-intermediate/42-webauthn-verifier
pip install -e .
webauthn-verifier demo
webauthn-verifier issue-challenge --json
webauthn-verifier parse-authdata <base64url-auth-data>
```

## Testing

```bash
pytest --cov=project_42 --cov-report=term-missing
```

## What You'll Learn

- W3C WebAuthn Level 2 ceremony structure (§7.1, §7.2)
- Authenticator data binary format (rpIdHash, flags, signCount)
- Why origin binding defeats phishing
- Sign counter replay attack and detection

## References

- W3C WebAuthn Level 2 — https://www.w3.org/TR/webauthn-2/
- FIDO2 CTAP2 Specification
- MITRE T1078, T1556, T1110
