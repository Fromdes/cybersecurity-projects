# Project 12 — QR Code TOTP Provisioner

> Render `otpauth://` QR codes for scanning with Google Authenticator, Aegis, and any RFC-compliant authenticator app.

## What Attack Does This Defend Against?

| MITRE ATT&CK | Technique |
|---|---|
| T1078 | Valid Accounts — enables MFA provisioning to prevent stolen-credential attacks |
| T1110 | Brute Force — QR-provisioned TOTP secrets make online brute-force infeasible |
| T1539 | Steal Web Session Cookie — per-login OTP blocks session-hijacking without the secret |

## Features

- Generates RFC-compliant `otpauth://totp/` provisioning URIs
- Renders QR codes as PNG files (scannable by authenticator apps)
- Renders QR codes as Unicode block characters in the terminal
- Configurable issuer, account label, digit count, and time interval
- Zero secret transmission — the shared secret stays local

## Tech Stack

- Python 3.11+
- `pyotp` — OTP URI construction
- `qrcode[pil]` — QR rendering
- `argparse` — CLI

## Architecture

```
totp-qr --secret S --uri        → generate_uri(TOTPParams) → print
totp-qr --secret S --terminal   → render_terminal(uri) → print
totp-qr --secret S --png out.png → render_png(uri, path) → PNG file
```

See [docs/architecture.md](docs/architecture.md).

## Threat Model (STRIDE)

| Threat | Mitigation |
|---|---|
| **S**poofing | QR encodes the exact secret; attacker cannot substitute a different key |
| **T**ampering | QR error-correction (level L) detects partial physical damage |
| **R**epudiation | Provisioning event should be logged by the calling application |
| **I**nformation disclosure | PNG file contains the secret — store with restricted permissions |
| **D**enial of service | Offline rendering; no network dependency |
| **E**levation of privilege | QR provisioning is a one-time enrollment step; subsequent logins require OTP |

## Install & Run on Kali

```bash
cd 01-beginner/12-qr-totp-provisioner
pip install -e . --break-system-packages

# Print URI only
totp-qr --secret JBSWY3DPEHPK3PXP --uri

# Print QR in terminal
totp-qr --secret JBSWY3DPEHPK3PXP --terminal

# Save QR as PNG
totp-qr --secret JBSWY3DPEHPK3PXP --png qr.png --issuer MyApp --account alice@corp.com
```

## Privileges

Root is **not** required.

## Example Output

```
$ totp-qr --secret JBSWY3DPEHPK3PXP --uri
otpauth://totp/DefensivePortfolio%3Auser%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=DefensivePortfolio&digits=6&period=30&algorithm=SHA1

$ totp-qr --secret JBSWY3DPEHPK3PXP --png qr.png
QR code saved to qr.png
```

## Testing

```bash
pytest --tb=short -q
```

## What You'll Learn

- `otpauth://` URI scheme (Google Authenticator Key URI Format)
- QR error correction levels and their trade-offs
- Why QR-based provisioning is more secure than manually typed secrets
- PIL/Pillow image generation in Python

## References

- [Google Authenticator Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
- [RFC 6238 — TOTP](https://datatracker.ietf.org/doc/html/rfc6238)
- [qrcode library](https://github.com/lincolnloop/python-qrcode)
