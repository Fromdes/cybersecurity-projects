# Threat Model — Project 02: File Hash Calculator

## Asset

Integrity of files being verified (binaries, configs, downloads).

## STRIDE

| Threat | Rating | Notes |
|---|---|---|
| Spoofing | Low | Hashes don't prove identity; pair with signatures (Project 09) |
| **Tampering** | **High** | Primary defence — detects modified files |
| Repudiation | Medium | Attacker can claim hash was wrong originally |
| Information Disclosure | Low | Hash is not reversible (pre-image resistance) |
| DoS | Low | Hashing a 10 GB file is slow but will complete |
| Elevation of Privilege | None | Read-only; no execution |

## Known Weaknesses

- **MD5/SHA-1**: Collision attacks exist. Accept only for legacy interop. Always
  prefer SHA-256 or BLAKE2b for new use cases.
- **Hash alone ≠ authenticity**: A hash verifies content, not source. Use Project 09
  (RSA signatures) or Project 94 (SLSA) for supply-chain authenticity.
