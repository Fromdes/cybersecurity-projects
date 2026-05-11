# Project 15 - Secure Token Generator
> Generate cryptographically strong tokens, API keys, and session secrets using Python's CSPRNG.

## What Attack Does This Defend Against? (MITRE ATT&CK IDs)
| Technique | ID | Description |
|---|---|---|
| Valid Accounts – weak session IDs | T1078 | Predictable tokens allow session hijacking |
| Use Alternate Authentication Material | T1550 | Guessable API keys enable credential misuse |
| Brute Force – credential stuffing | T1110.004 | Short/low-entropy tokens are brute-forceable |

## Features
- **Four formats**: hex, URL-safe base64, alphanumeric, UUID4
- **Configurable size**: 16–512 bytes of entropy
- **Entropy estimator**: bits of entropy per token with STRONG/ADEQUATE/WEAK rating
- **Bulk generation**: `--count N` for multiple tokens at once
- **Zero external dependencies**: uses stdlib `secrets` module only

## Tech Stack
- Python 3.11+, `secrets`, `uuid`, `base64` (stdlib only)

## Architecture
```
CLI (cli.py)
  └─ generate_token(fmt, byte_length) → TokenResult
  └─ estimate_entropy(length, charset) → float
```

## Threat Model (STRIDE)
| Category | Threat | Mitigation |
|---|---|---|
| Spoofing | Attacker guesses token | CSPRNG ensures unpredictability |
| Tampering | Token modified in transit | Use HMAC or signed tokens at higher layers |
| Info Disclosure | Token in logs | Use `--quiet` mode; avoid logging raw tokens |
| Elevation | Weak token grants admin | Enforce 32+ byte minimum (256 bits) |

## Install & Run on Kali
```bash
cd 01-beginner/15-secure-token-generator
pip install -e .
sectoken generate --format hex --bytes 32
sectoken generate --format uuid4
sectoken generate --format base64url --count 5 --quiet
sectoken entropy 64 --charset 16
```

## Privileges
No root required.

## Example Output
```
a3f8d2b91c6e7f4a5b0d3e8c1f6a9b2d4e7f0c3a5b8d1e4f7a2c5b8e1f4a7d0  [hex, 256.0 bits]
Df9kL2mQ7nR4pS1tU6wX3yZ5  [base64url, 256.0 bits]
Estimated entropy: 256.0 bits
Strength: STRONG
```

## Testing
```bash
pip install -r requirements.txt
pytest --cov=project_15 --cov-report=term-missing
```

## What You'll Learn
- Python `secrets` module vs `random` module (why CSPRNG matters)
- Entropy calculation and what "256 bits of entropy" means
- Token encoding formats and trade-offs (hex vs base64 vs UUID)
- Designing secure defaults (minimum 16 bytes, URL-safe output)

## References
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [Python secrets module docs](https://docs.python.org/3/library/secrets.html)
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
