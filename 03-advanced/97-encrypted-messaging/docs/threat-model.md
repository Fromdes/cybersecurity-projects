# Threat Model — Encrypted Messaging Library

## STRIDE Analysis

| Threat | Component | Mitigation |
|---|---|---|
| Spoofing | Session identity | Associated data binds messages to session context |
| Tampering | Ciphertext | AES-256-GCM authentication tag detects modification |
| Repudiation | Message origin | Authenticated encryption prevents forgery |
| Information Disclosure | Key compromise | Forward secrecy: past messages can't be decrypted |
| DoS | Skipped message flood | MAX_SKIP=100 limit prevents memory exhaustion |
| Elevation of Privilege | Protocol downgrade | Fixed algorithm suite; no negotiation |

## Cryptographic Assumptions

- X25519 DH is computationally indistinguishable from random
- AES-256-GCM is IND-CCA2 secure
- HKDF-SHA256 is a secure PRF
- Nonces are generated from a cryptographically secure PRNG
