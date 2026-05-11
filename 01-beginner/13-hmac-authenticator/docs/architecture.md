# Architecture — Project 13: HMAC Message Authenticator

## Module Layout

```
src/project_13/
├── __init__.py    # public API exports
├── __main__.py    # python -m project_13
├── core.py        # HMAC logic (no I/O except file read)
└── cli.py         # argparse CLI
```

## Data Flow

```
passphrase ──► derive_key_from_passphrase() ──► key (bytes)
                                                    │
message/file ──────────────────────────────────────►│
                                                    ▼
                                           compute_hmac(msg, key)
                                                    │
                                                    ▼
                                           HMACResult.digest (hex)
```

## Constant-Time Comparison

`verify_hmac` uses `hmac.compare_digest(a, b)` rather than `a == b`.
String equality short-circuits on the first differing byte, allowing an
attacker to measure response time and recover the expected digest one nibble
at a time. `compare_digest` always takes the same number of operations
regardless of where the strings diverge.

## Key Derivation Note

The CLI derives a key from a passphrase using a single SHA-256/512 hash.
This is fast and therefore susceptible to offline dictionary attacks.
For production, use Argon2id (Project 14) or PBKDF2 with ≥100 000 iterations.
The simple derivation is used here to keep the project dependency-free and
focused on the HMAC concept.
