# Threat Model — Project 15: Secure Token Generator

## Assets
- Generated tokens used as session IDs, API keys, password-reset links

## Threat Actors
- Remote attacker attempting session hijacking
- Insider attempting to predict future tokens

## STRIDE Analysis
| Threat | Example | Mitigation |
|---|---|---|
| Spoofing | Attacker guesses a 4-byte token (32 bits) | Enforce `--bytes 32` minimum (256 bits) |
| Tampering | Token value modified during transit | Sign tokens with HMAC at application layer |
| Repudiation | Token reuse across sessions | Implement single-use + expiry at app layer |
| Info Disclosure | Token appears in access logs | Use `--quiet` mode; rotate tokens regularly |
| Elevation of Privilege | Weak API key grants admin access | Separate token namespaces by privilege level |

## Assumptions
- The OS CSPRNG (`/dev/urandom` on Linux) is not compromised
- The generated token is transmitted over TLS
- Token storage uses a server-side store, not client-readable cookies
