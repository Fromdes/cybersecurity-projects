# Project 14 — Argon2id/PBKDF2 Password Hasher

> Securely hash and verify passwords with Argon2id (recommended) or PBKDF2-SHA256, protecting stored credentials against offline cracking.

## What Attack Does This Defend Against?

| MITRE ATT&CK | Technique |
|---|---|
| T1110.002 | Password Cracking — memory-hard Argon2id makes GPU/ASIC attacks prohibitively expensive |
| T1078 | Valid Accounts — secure hashing ensures leaked databases are not directly usable |
| T1552.001 | Credentials in Files — demonstrates PHC-encoded hashes that are safe to store |

## Features

- **Argon2id** (OWASP recommended): time_cost=2, memory=64 MiB, parallelism=1
- **PBKDF2-SHA256** (NIST SP 800-132): 210 000 iterations, 256-bit derived key
- Unique random salt per hash (no rainbow table attacks)
- `needs_rehash()` for transparent hash upgrades on login
- Constant-time verification
- Interactive passphrase prompt or `--stdin` for scripting

## Tech Stack

- Python 3.11+
- `argon2-cffi` — Argon2id
- stdlib `hashlib` — PBKDF2

## Architecture

```
passwd-hash hash              → hash_password(password, algorithm)
passwd-hash verify HASH       → verify_password(password, hash, algorithm)
passwd-hash check-rehash HASH → needs_rehash(hash)
```

## Threat Model (STRIDE)

| Threat | Mitigation |
|---|---|
| **S**poofing | Verification only possible with the original password |
| **T**ampering | Stored hash encodes the salt; cannot be recomputed without the password |
| **R**epudiation | Hash proves the password was set; audit log records when |
| **I**nformation disclosure | Password never stored or logged; only the hash |
| **D**enial of service | Argon2id's 64 MiB cost slows both attacker and server — tune time_cost |
| **E**levation of privilege | Cracking even a single hash requires ~64 MiB and several hundred ms |

## Install & Run on Kali

```bash
cd 01-beginner/14-password-hasher
pip install -e . --break-system-packages

passwd-hash hash                        # interactive prompt
echo "mypassword" | passwd-hash --stdin hash
echo "mypassword" | passwd-hash --stdin verify '$argon2id$...'
passwd-hash check-rehash '$argon2id$...'
```

## Privileges

Root is **not** required.

## Testing

```bash
pytest --tb=short -q
```

Note: PBKDF2 tests with 210 000 iterations are intentionally slow (~0.5 s each).

## What You'll Learn

- Argon2id memory-hard function (winner of the Password Hashing Competition)
- PBKDF2 as a NIST-approved alternative
- PHC string format for portable hash storage
- Why `bcrypt`/`md5crypt` are obsolete against modern GPUs
- `needs_rehash` pattern for zero-downtime parameter upgrades

## References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [RFC 9106 — Argon2](https://datatracker.ietf.org/doc/html/rfc9106)
- [NIST SP 800-132](https://doi.org/10.6028/NIST.SP.800-132)
- [MITRE ATT&CK T1110.002](https://attack.mitre.org/techniques/T1110/002/)
