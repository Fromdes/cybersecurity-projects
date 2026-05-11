# Threat Model — Project 12: QR Code TOTP Provisioner

## Assets

| Asset | Sensitivity |
|---|---|
| Shared secret (base32) | Critical — embedded in QR code |
| QR PNG file | High — contains the secret; compromise = OTP forgery |
| Provisioning URI | High — equivalent to the raw secret |

## Threat Actors

- Attacker with filesystem access to the QR PNG
- Shoulder-surfing during terminal QR display
- MitM intercepting the provisioning URI over HTTP

## STRIDE Analysis

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Attacker substitutes their QR during enrollment | Serve provisioning page over TLS; show hash of secret to user for out-of-band confirmation |
| **Tampering** | QR image modified on disk | Application layer should verify URI integrity before display |
| **Repudiation** | User denies scanning the QR | Log provisioning timestamp and device ID in the application |
| **Information Disclosure** | PNG stored with world-readable permissions | Restrict file permissions (0600); delete after scanning |
| **Denial of Service** | Provisioning page repeatedly re-generating QRs | Rate-limit provisioning endpoint in production |
| **Elevation of Privilege** | Attacker scans QR and adds it to their authenticator | One-time provisioning flow; invalidate secret after confirmed enrollment |

## Assumptions

1. The QR provisioning page is served over TLS (not in scope for this CLI).
2. The PNG is stored temporarily and deleted after the user scans it.
3. Terminal display occurs in a private environment (no screen recording or shoulder-surfing).

## Out of Scope

- Secret storage — handled by the caller (e.g., a vault or encrypted database)
- Enrollment confirmation — the caller must verify the user has successfully enrolled
