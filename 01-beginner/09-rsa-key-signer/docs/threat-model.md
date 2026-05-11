# Threat Model — Project 09: RSA Key Pair Generator & File Signer

## STRIDE

| Threat | Rating | Notes |
|---|---|---|
| **Spoofing** | **Critical** | Core defence — valid signature proves content origin |
| **Tampering** | **Critical** | Any modification invalidates the PSS signature |
| Repudiation | High | Signing non-repudiably binds the key holder to the content |
| Info Disclosure | Medium | Private key must be kept confidential; encrypted at rest |
| DoS | Low | RSA-4096 signing is slow (~100ms) but not a bottleneck for files |
| Elevation of Privilege | None | No system calls beyond file I/O |

## Private Key Compromise

If the private key is stolen, the attacker can sign arbitrary files and claim they
are authentic. Mitigations:
1. Store private key with a strong passphrase (Project 05/06)
2. Store private key on hardware token (HSM/YubiKey) — out of scope here
3. Revoke the public key and reissue with a new key pair

## Quantum Threat

RSA is vulnerable to Shor's algorithm on a sufficiently powerful quantum computer.
For post-quantum security, see NIST PQC standards (ML-DSA/CRYSTALS-Dilithium).
