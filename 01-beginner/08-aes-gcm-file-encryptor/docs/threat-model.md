# Threat Model — Project 08: AES-256-GCM File Encryptor

## Asset

Plaintext content of encrypted files.

## STRIDE

| Threat | Rating | Mitigation |
|---|---|---|
| Spoofing | Low | N/A for file encryption |
| **Tampering** | **Critical** | GCM authentication tag detects any modification |
| Repudiation | Medium | No identity attached to encryption — use Project 09 to sign too |
| **Info Disclosure** | **Critical** | AES-256 provides 256-bit key security |
| DoS | Low | Scrypt is slow on purpose; but only for the encryptor, not an attacker vector here |
| Elevation of Privilege | None | Read/write file permissions only |

## Key Threats

1. **Weak password** — Scrypt slows brute force but a weak password is still
   vulnerable. Combine with Project 05/06 to generate strong passphrases.

2. **Key/password compromise** — If the password is exposed, all files encrypted
   with it are exposed. Use separate passwords for different sensitivity levels.

3. **Encrypted-file integrity** — GCM tag detects tampering, but an attacker who
   can replace the entire file bypasses this. Store encrypted files in an
   integrity-monitored directory (Project 03).
