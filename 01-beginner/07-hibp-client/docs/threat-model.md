# Threat Model — Project 07: Have-I-Been-Pwned Client

## STRIDE

| Threat | Notes |
|---|---|
| Spoofing | DNS spoofing could redirect to a fake HIBP server — use HTTPS |
| Tampering | MITM could return false "safe" responses — HTTPS + cert pinning |
| Repudiation | HIBP server logs request timestamps and IP, not passwords |
| **Information Disclosure** | **k-Anonymity prevents full hash exposure** |
| DoS | Rate-limited by HIBP; back off on 429 responses |
| Elevation of Privilege | N/A — read-only network check |

## Privacy Guarantee

Even if the HIBP server is compromised, the attacker only learns which 5-char
prefixes were queried — not which specific passwords. SHA-1 pre-image resistance
means the full password cannot be recovered from the 5-char prefix.

## SHA-1 Note

SHA-1 is used here because it matches the HIBP database format. SHA-1 collision
attacks require a chosen-prefix attack that is impractical for this use case
(checking a specific password against a fixed database).
