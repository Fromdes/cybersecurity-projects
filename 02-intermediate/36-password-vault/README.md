# Project 36 - Personal Password Vault
> A fully encrypted local password manager — stores credentials in AES-256-GCM ciphertext with Argon2id key derivation, and generates cryptographically secure passwords on demand.

## What Attack Does This Defend Against? (MITRE ATT&CK IDs)
| Technique | ID | Description |
|---|---|---|
| Credentials in Files | T1552.001 | Plaintext password files are trivially exfiltrated |
| Brute Force – Password Spraying | T1110.003 | Strong unique passwords per site prevent password-spray success |
| Credential Stuffing | T1110.004 | Unique generated passwords per site contain breach blast radius |
| Steal Application Access Token | T1528 | Vault never stores tokens in plain text |

## Features
- **AES-256-GCM encryption**: authenticated — tampering detected on open
- **Argon2id KDF**: 64 MiB memory-hard derivation resists GPU brute-force
- **CRUD**: add, list, get, update, delete credential entries
- **Search**: case-insensitive filter by site or username
- **Password generator**: cryptographically secure, configurable length
- **0600 file permissions**: vault unreadable by other OS users

## Tech Stack
- Python 3.11+, `cryptography>=41`, `argon2-cffi>=23`

## Architecture
```
CLI (cli.py): add | list | get | delete | generate
  Vault(path, master_password)
    ├─ _load() → Argon2id → AESGCM.decrypt() → [VaultEntry]
    ├─ _save() → Argon2id → AESGCM.encrypt() → file(0600)
    ├─ add(site, username, password, notes) → VaultEntry
    ├─ get(id) → VaultEntry
    ├─ search(query) → [VaultEntry]
    ├─ update(id, **kwargs) → VaultEntry
    └─ delete(id)
  generate_password(length) → str
```

## Threat Model (STRIDE)
| Category | Threat | Mitigation |
|---|---|---|
| Spoofing | Fake vault crafted to extract master password | GCM tag rejects tampered files immediately |
| Tampering | Attacker modifies vault file | AES-GCM authentication detects any change |
| Info Disclosure | Vault file stolen from disk | AES-256 ciphertext; Argon2id brute-force resistance |
| Repudiation | Deny storing a particular credential | Timestamps in every entry |

## Install & Run on Kali
```bash
cd 02-intermediate/36-password-vault
pip install -e .
vault add github.com alice@example.com --generate
vault list
vault get <uuid>
vault generate --length 32
```

## Privileges
No root required.

## Example Output
```
$ vault add github.com alice --generate
Master password:
Generated password: X#m9Kj$P2@qW8nRvLy!eZ6Fc
Entry added: a1b2c3d4-...

$ vault list
Master password:
ID                                     SITE                      USERNAME
--------------------------------------------------------------------------------
a1b2c3d4-...                           github.com                alice
```

## Testing
```bash
pip install -r requirements.txt
pytest --cov=project_36 --cov-report=term-missing
```

## What You'll Learn
- AES-256-GCM: authenticated encryption prevents both tampering and disclosure
- Argon2id: why memory-hard KDFs matter for master password protection
- `secrets.choice()` vs `random.choice()` — CSPRNG for password generation
- Password manager design: separate master key from per-entry encryption

## References
- [MITRE ATT&CK T1552.001 – Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)
- [NIST Digital Identity Guidelines SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106)
