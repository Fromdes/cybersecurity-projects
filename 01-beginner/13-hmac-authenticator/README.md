# Project 13 — HMAC Message Authenticator

> Sign and verify arbitrary messages and files with HMAC-SHA256/512 to detect tampering.

## What Attack Does This Defend Against?

| MITRE ATT&CK | Technique |
|---|---|
| T1565 | Data Manipulation — HMAC detects any modification to authenticated data |
| T1557 | Adversary-in-the-Middle — message authentication prevents undetected data injection |
| T1553 | Subvert Trust Controls — verifies that data originates from the keyed party |

## Features

- HMAC-SHA256 and HMAC-SHA512 computation
- Constant-time verification (`hmac.compare_digest`) to prevent timing attacks
- File signing and verification
- Passphrase-to-key derivation for CLI convenience
- Zero external dependencies (stdlib only)

## Tech Stack

- Python 3.11+, stdlib `hmac` + `hashlib`
- `argparse` CLI

## Architecture

```
hmac-auth --key PASS sign MESSAGE      → compute_hmac()
hmac-auth --key PASS verify MSG DIGEST → verify_hmac()
hmac-auth --key PASS sign-file FILE    → sign_file()
hmac-auth --key PASS verify-file FILE DIGEST → verify_file()
```

## Threat Model (STRIDE)

| Threat | Mitigation |
|---|---|
| **S**poofing | Without the secret key, HMAC cannot be forged |
| **T**ampering | Any bit change in the message invalidates the HMAC |
| **R**epudiation | Both parties share the key; HMAC proves authenticity to the key-holder |
| **I**nformation disclosure | HMAC reveals nothing about the message content |
| **D**enial of service | Stateless; no replay protection without sequence numbers |
| **E**levation of privilege | HMAC is MAC-only; for encryption use AES-GCM (Project 08) |

## Install & Run on Kali

```bash
cd 01-beginner/13-hmac-authenticator
pip install -e . --break-system-packages

hmac-auth --key "my secret" sign "Hello, world!"
hmac-auth --key "my secret" verify "Hello, world!" <digest>
hmac-auth --key "my secret" sign-file important.txt
hmac-auth --key "my secret" verify-file important.txt <digest>
```

## Privileges

Root is **not** required.

## Testing

```bash
pytest --tb=short -q
```

## What You'll Learn

- HMAC construction: `HMAC(K, m) = H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ m))`
- Why timing attacks matter and how `compare_digest` prevents them
- Difference between encryption (confidentiality) and MAC (integrity/authenticity)
- RFC 2104 HMAC specification

## References

- [RFC 2104 — HMAC](https://datatracker.ietf.org/doc/html/rfc2104)
- [Python hmac module](https://docs.python.org/3/library/hmac.html)
- [MITRE ATT&CK T1565](https://attack.mitre.org/techniques/T1565/)
