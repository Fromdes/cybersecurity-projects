# Threat Model — Project 11: TOTP/HOTP Authenticator

## Assets

| Asset | Sensitivity |
|---|---|
| Shared secret (base32) | Critical — compromise allows OTP forgery |
| OTP code | Medium — valid for one 30-second window only |
| Provisioning URI | High — contains the shared secret |

## Threat Actors

- Remote attacker with stolen credentials (credential stuffing)
- MitM intercepting an OTP in transit
- Local attacker with access to the device storing the secret

## STRIDE Analysis

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Attacker generates valid OTP without knowing the secret | HMAC-SHA1 with 160-bit secret — computationally infeasible to forge |
| **Tampering** | OTP modified in transit | OTP is derived deterministically; any change produces an invalid code |
| **Repudiation** | User denies using a particular OTP | Server-side audit log records OTP verification attempts with timestamps |
| **Information Disclosure** | Secret leaked from QR code scan or URI | URI should be transmitted only over TLS; QR displayed once and not stored |
| **Denial of Service** | Replay attack reusing an accepted OTP | TOTP: codes expire after 30 s; HOTP: counter advances past used codes |
| **Elevation of Privilege** | Attacker bypasses MFA with stolen password | Without the shared secret, OTP cannot be generated — second factor required |

## Assumptions

1. The shared secret is provisioned securely (e.g., encrypted at rest, transmitted over TLS).
2. Client and server clocks are roughly synchronised (NTP); `window=1` tolerates ±30 s drift.
3. The server advances the HOTP counter atomically to prevent replay.

## Out of Scope

- Secret storage (use a hardware authenticator or encrypted vault in production)
- TLS transport (assumed to be handled by the calling application layer)
- Phishing-resistant alternatives (FIDO2/WebAuthn — see Project 42)
