# Project 11 — TOTP/HOTP Authenticator

> Generate and verify time-based (TOTP) and counter-based (HOTP) one-time passwords per RFC 6238/4226.

## What Attack Does This Defend Against?

| MITRE ATT&CK | Technique |
|---|---|
| T1078 | Valid Accounts — stolen credentials alone cannot authenticate without the second factor |
| T1110 | Brute Force — 6-digit OTPs expire every 30 s, making brute-force infeasible |
| T1539 | Steal Web Session Cookie — session hijacking blocked by per-login OTP challenge |
| T1556 | Modify Authentication Process — demonstrates correct RFC-compliant MFA implementation |

## Features

- TOTP generation & verification (RFC 6238, SHA-1 HMAC, 30-second window)
- HOTP generation & verification (RFC 4226, counter-based)
- Clock-skew tolerance (configurable ±*window* time steps)
- HOTP look-ahead to handle client/server counter desynchronisation
- `otpauth://` provisioning URI for QR code scanning (Google Authenticator, Aegis, etc.)
- Cryptographically random secret generation via `pyotp.random_base32()`
- CLI subcommands: `generate-secret`, `totp`, `hotp`

## Tech Stack

- Python 3.11+
- `pyotp` — RFC-compliant TOTP/HOTP implementation
- `argparse` — CLI
- `pytest` — tests

## Architecture

```
otp generate-secret           → generate_secret()
otp totp --generate           → generate_totp(TOTPConfig)
otp totp --verify CODE        → verify_totp(code, TOTPConfig)
otp hotp --generate --counter N → generate_hotp(secret, N)
otp hotp --verify CODE --counter N → verify_hotp(code, secret, N)
```

See [docs/architecture.md](docs/architecture.md) for full details.

## Threat Model (STRIDE)

| Threat | Mitigation |
|---|---|
| **S**poofing | Shared secret never transmitted; only derived OTPs are sent |
| **T**ampering | HMAC-SHA1 integrity; wrong code → immediate rejection |
| **R**epudiation | OTP is single-use within its time step |
| **I**nformation disclosure | Secret stored only client-side; API never exposes it |
| **D**enial of service | Stateless verification — no lockout risk from verification calls |
| **E**levation of privilege | OTP adds second factor; compromised password alone is insufficient |

## Install & Run on Kali

```bash
cd 01-beginner/11-totp-hotp-authenticator
pip install -e . --break-system-packages

# Generate a new shared secret
otp generate-secret

# Generate current TOTP code
otp totp --secret JBSWY3DPEHPK3PXP --generate

# Verify a TOTP code
otp totp --secret JBSWY3DPEHPK3PXP --verify 123456

# Get provisioning URI (paste into QR generator)
otp totp --secret JBSWY3DPEHPK3PXP --generate --uri

# HOTP at counter 0
otp hotp --secret JBSWY3DPEHPK3PXP --counter 0 --generate
```

## Privileges

Root is **not** required.

## Example Output

```
$ otp generate-secret
JBSWY3DPEHPK3PXP

$ otp totp --secret JBSWY3DPEHPK3PXP --generate
482921

$ otp totp --secret JBSWY3DPEHPK3PXP --verify 482921
VALID

$ otp totp --secret JBSWY3DPEHPK3PXP --generate --uri
otpauth://totp/DefensivePortfolio%3Auser%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=DefensivePortfolio
```

## Testing

```bash
pytest --tb=short -q
```

Target: 80 %+ coverage.

## What You'll Learn

- RFC 6238 (TOTP) and RFC 4226 (HOTP) protocol internals
- HMAC-based OTP derivation
- Time-step windowing and counter look-ahead for production robustness
- `otpauth://` URI scheme for QR provisioning
- Why MFA defeats credential-stuffing attacks

## References

- [RFC 6238 — TOTP](https://datatracker.ietf.org/doc/html/rfc6238)
- [RFC 4226 — HOTP](https://datatracker.ietf.org/doc/html/rfc4226)
- [pyotp documentation](https://pyauth.github.io/pyotp/)
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)
