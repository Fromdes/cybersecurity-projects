# Threat Model — Project 14: Argon2id/PBKDF2 Password Hasher

## Assets

| Asset | Sensitivity |
|---|---|
| Plaintext password | Critical — must never be stored |
| Stored hash | High — exposure enables offline cracking attempts |
| Salt | Low — may be stored alongside the hash (its purpose is to prevent rainbow tables) |

## Threat Actors

- Attacker with database dump (offline cracking)
- Insider with read access to the password store
- Side-channel attacker measuring hash computation time

## STRIDE Analysis

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Attacker submits a hash instead of a password | Verification always re-hashes; the hash is never compared directly against input |
| **Tampering** | Attacker replaces a hash with one for a known password | Application layer must enforce integrity of the password store (e.g., database ACLs) |
| **Repudiation** | User denies setting a particular password | Hash proves the password was set at enrollment time |
| **Information Disclosure** | Hash database leaked | Argon2id's 64 MiB/hash makes cracking infeasible at scale even with GPUs |
| **Denial of Service** | Attacker triggers many simultaneous hash computations | Rate-limit login attempts; Argon2id time_cost can be tuned per server capacity |
| **Elevation of Privilege** | Weak hash (MD5/SHA-1) cracked in seconds | Argon2id/PBKDF2 with current parameters: state-of-the-art resistance |

## Assumptions

1. The password store (database) is protected by access controls.
2. Passwords are transmitted only over TLS (not in scope here).
3. The `needs_rehash` upgrade runs at login time, not in a batch job (to avoid re-hashing with the old password).
