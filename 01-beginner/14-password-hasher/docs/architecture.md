# Architecture — Project 14: Argon2id/PBKDF2 Password Hasher

## Module Layout

```
src/project_14/
├── __init__.py    # public API exports
├── __main__.py    # python -m project_14
├── core.py        # hashing logic (no I/O)
└── cli.py         # argparse CLI
```

## Algorithm Selection

| Algorithm | When to Use |
|---|---|
| Argon2id | Default. Best resistance against GPU/ASIC and side-channel attacks |
| PBKDF2-SHA256 | When FIPS 140-2 compliance is required (Argon2 is not FIPS-approved) |

## Argon2id Parameters (OWASP 2023)

| Parameter | Value | Notes |
|---|---|---|
| `time_cost` | 2 | Iterations over memory |
| `memory_cost` | 65 536 KiB | 64 MiB per hash computation |
| `parallelism` | 1 | Single-thread; increase for multi-core servers |

## PBKDF2 Parameters

| Parameter | Value | Notes |
|---|---|---|
| Hash function | SHA-256 | NIST-approved |
| Iterations | 210 000 | OWASP 2023 minimum |
| Salt length | 16 bytes | 128-bit, CSPRNG |
| Key length | 32 bytes | 256-bit output |

## Stored Hash Formats

**Argon2id** — PHC String Format:
```
$argon2id$v=19$m=65536,t=2,p=1$<base64-salt>$<base64-hash>
```

**PBKDF2** — custom hex:
```
<salt-hex>:<dk-hex>
```

## needs_rehash Flow

```
user logs in with correct password
        │
        ▼
verify_password() → True
        │
        ▼
needs_rehash(stored_hash) → True?
        │ yes
        ▼
hash_password(password) → new_hash
        │
        ▼
store new_hash, replacing old
```
