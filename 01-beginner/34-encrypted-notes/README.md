# Project 34 - Encrypted Notes CLI
> Store sensitive notes locally with AES-256-GCM authenticated encryption, protected by an Argon2id-derived master password — no plaintext ever touches disk.

## What Attack Does This Defend Against? (MITRE ATT&CK IDs)
| Technique | ID | Description |
|---|---|---|
| Data from Local System | T1005 | Attacker reads local files for sensitive notes/passwords |
| Credentials in Files | T1552.001 | Plaintext notes containing passwords, keys, or PII |
| Unsecured Credentials | T1552 | Notes stored without encryption |
| Exfiltration over Physical Medium | T1052 | Stolen laptop reveals unencrypted note files |

## Features
- **AES-256-GCM encryption**: authenticated — any tampering is detected on open
- **Argon2id key derivation**: resistant to GPU brute-force attacks
- **CRUD operations**: add, list, get, update, delete notes
- **600 file permissions**: store file unreadable by other users
- **Zero dependencies on network**: fully offline

## Tech Stack
- Python 3.11+, `cryptography>=41`, `argon2-cffi>=23`

## Architecture
```
CLI (cli.py)
  NotesStore(path, password)
    ├─ _load() → derive_key() → AESGCM.decrypt()
    ├─ save()  → derive_key() → AESGCM.encrypt() → write(salt+nonce+ciphertext)
    ├─ add_note(title, body) → Note
    ├─ get_note(id) → Note
    ├─ list_notes() → [Note]
    ├─ update_note(id, ...) → Note
    └─ delete_note(id)
```

## Threat Model (STRIDE)
| Category | Threat | Mitigation |
|---|---|---|
| Spoofing | Attacker replaces store file to inject content | GCM authentication tag rejects tampered ciphertexts |
| Tampering | Bit-flip attack on encrypted file | AES-GCM authentication tag detects any modification |
| Info Disclosure | Attacker reads store file directly | AES-256 ciphertext without key is opaque |
| Repudiation | Deny note contents were written | Local audit; cryptographic integrity proves authenticity |

## Install & Run on Kali
```bash
cd 01-beginner/34-encrypted-notes
pip install -e .
enc-notes add "SSH Key Passphrase" "hunter2 for dev server"
enc-notes list
enc-notes get <uuid>
enc-notes delete <uuid>
```

## Privileges
No root required.

## Example Output
```
$ enc-notes list
Master password:
ID                                     TITLE
----------------------------------------------------------------------
a1b2c3d4-...                           SSH Key Passphrase
e5f6g7h8-...                           API Keys — AWS dev

$ enc-notes get a1b2c3d4-...
Master password:
ID      : a1b2c3d4-...
Title   : SSH Key Passphrase
Created : 2024-01-15T10:30:00+00:00
Updated : 2024-01-15T10:30:00+00:00

hunter2 for dev server
```

## Testing
```bash
pip install -r requirements.txt
pytest --cov=project_34 --cov-report=term-missing
```

## What You'll Learn
- AES-256-GCM authenticated encryption (confidentiality + integrity)
- Argon2id key derivation to prevent brute-force of master password
- Why salt must be random per store (prevents rainbow tables)
- Why nonce must be random per encrypt call (prevents nonce reuse attacks)

## References
- [MITRE ATT&CK T1552.001 – Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)
- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106)
- [NIST AES-GCM guidelines (SP 800-38D)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
