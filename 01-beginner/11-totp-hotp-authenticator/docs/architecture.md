# Architecture — Project 11: TOTP/HOTP Authenticator

## Module Layout

```
src/project_11/
├── __init__.py    # public API exports
├── __main__.py    # python -m project_11
├── core.py        # RFC 6238/4226 logic (no I/O)
└── cli.py         # argparse CLI
```

## Core Data Flow

### TOTP

```
shared_secret (base32)
        │
        ▼
  pyotp.TOTP(secret, digits, interval)
        │
   ┌────┴────┐
   │  at(T)  │   T = floor(unix_time / interval)
   └────┬────┘
        ▼
  HMAC-SHA1(key, T_bytes)
        │
  dynamic truncation
        │
        ▼
  N-digit OTP string
```

### HOTP

```
shared_secret (base32)  +  counter
        │
        ▼
  pyotp.HOTP(secret, digits)
        │
   ┌────┴────┐
   │  at(C)  │
   └────┬────┘
        ▼
  HMAC-SHA1(key, C_bytes)
        │
  dynamic truncation
        │
        ▼
  N-digit OTP string
```

## Clock Skew & Counter Resync

- **TOTP**: `verify_totp` accepts codes from `[now - window*interval, now + window*interval]`. Default window = 1 (±30 s).
- **HOTP**: `verify_hotp` checks counter values `[counter, counter + look_ahead]`. Returns next expected counter on success so the server can advance its state.

## Provisioning URI

Format: `otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&digits={d}&period={p}`

Compatible with Google Authenticator, Aegis, and any RFC-compliant authenticator app.
