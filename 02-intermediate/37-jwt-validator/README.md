# Project 37 — JWT Validator & Inspector

> Decode, validate, and audit JSON Web Tokens — catching weak algorithms, expired credentials, and forged tokens before they reach your application.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Defence |
|-----------|----|---------|
| Forge Web Credentials | T1606 | Mandatory signature verification |
| Use Alternate Auth Material: App Access Token | T1550.001 | `exp` + 24-hour age hard cap |
| Valid Accounts (token replay) | T1078 | `iss`/`aud` binding |
| Algorithm confusion (alg:none) | T1606.002 | `none` rejected unconditionally |

## Features

- **Inspect mode** — decode header + payload without signature verification (safe audit)
- **Validate mode** — full cryptographic signature check with PyJWT
- Rejects `alg:none` unconditionally; warns on symmetric (HS*) algorithms
- Checks `exp`, `nbf`, `iat`, 24-hour token age cap
- Issuer and audience validation
- Required-claims enforcement
- SHA-256 token fingerprint for audit logging
- JSON output for pipeline integration

## Tech Stack

- Python 3.11+, PyJWT 2.8+, cryptography, click

## Install & Run on Kali

```bash
cd 02-intermediate/37-jwt-validator
pip install -e .
jwt-validator inspect <token>
jwt-validator validate <token> --key mysecret --alg HS256
jwt-validator validate <token> --key public.pem --alg RS256 --iss https://auth.example.com
```

## Example Output

```
Status : VALID
Valid  : True
SHA256 : 3f2a1b...
Alg    : RS256
Sub    : alice@example.com
Iss    : https://auth.example.com
Exp    : 1716000000
Iat    : 1715996400
```

## Testing

```bash
pytest --cov=project_37 --cov-report=term-missing
```

## What You'll Learn

- JWT structure (JOSE header, payload, signature)
- Algorithm confusion attacks and the `alg:none` CVE pattern
- PyJWT secure usage patterns
- Token replay prevention via temporal claims

## References

- RFC 7519 — JSON Web Token
- CVE-2015-9235 — JWT `alg:none` bypass
- MITRE T1606, T1550.001
