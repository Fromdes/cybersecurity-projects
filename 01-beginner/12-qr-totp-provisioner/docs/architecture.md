# Architecture — Project 12: QR Code TOTP Provisioner

## Module Layout

```
src/project_12/
├── __init__.py    # public API exports
├── __main__.py    # python -m project_12
├── core.py        # URI generation + QR rendering (no I/O except PNG write)
└── cli.py         # argparse CLI
```

## Data Flow

```
TOTPParams(secret, issuer, account, digits, interval)
        │
        ▼
  generate_uri()  →  otpauth://totp/Issuer:Account?secret=...
        │
   ┌────┴──────────────────┐
   │                        │
   ▼                        ▼
render_png(uri, path)   render_terminal(uri)
   │                        │
   ▼                        ▼
PNG file (Pillow)       Unicode block string
```

## URI Format

Per the [Google Authenticator Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format):

```
otpauth://totp/{issuer}:{account}
  ?secret={base32_secret}
  &issuer={issuer}
  &digits={6|8}
  &period={30|60}
  &algorithm=SHA1
```

Label and issuer are percent-encoded. The secret is the raw base32 string (not encoded again).

## QR Code Parameters

| Parameter | Value | Rationale |
|---|---|---|
| Error correction | L (7%) | Sufficient for clean digital display |
| Box size | 10 px | Readable when printed or displayed |
| Border | 4 modules | Spec-required quiet zone |
