# Project 35 - Encrypted Backup Tool
> Create AES-256-GCM encrypted, gzip-compressed backups of files and directories — protecting data at rest from ransomware, theft, and unauthorized access.

## What Attack Does This Defend Against? (MITRE ATT&CK IDs)
| Technique | ID | Description |
|---|---|---|
| Data Encrypted for Impact (Ransomware) | T1486 | Encrypted backups are the primary ransomware recovery mechanism |
| Data from Local System | T1005 | Stolen backup files are useless without the passphrase |
| Exfiltration over Physical Medium | T1052 | Encrypted backups are safe even if physical media is stolen |
| Inhibit System Recovery | T1490 | Offline encrypted backups survive ransomware that targets shadow copies |

## Features
- **create**: compress directory (gzip tar) then encrypt with AES-256-GCM
- **restore**: decrypt, decompress, and extract files to target directory
- **verify**: decrypt and check content against SHA-256 manifest hash
- **Manifest file**: stores source path, timestamps, file count, hash for auditing
- **Argon2id KDF**: passphrase-to-key derivation resistant to GPU brute-force

## Tech Stack
- Python 3.11+, `cryptography>=41`, `argon2-cffi>=23`

## Architecture
```
CLI (cli.py): create | restore | verify
  create_backup(source, output, password) → BackupManifest
    └─ tar.gz → bytes → Argon2id key → AESGCM.encrypt() → .encbak
  restore_backup(backup, output_dir, password) → int
    └─ AESGCM.decrypt() → tar.gz → extract
  verify_backup(backup, password) → bool
    └─ decrypt → SHA-256 → compare to manifest
```

## Threat Model (STRIDE)
| Category | Threat | Mitigation |
|---|---|---|
| Tampering | Attacker modifies .encbak file | GCM auth tag detects any modification |
| Info Disclosure | Stolen backup exposes data | AES-256 ciphertext without passphrase is opaque |
| Denial of Service | Ransomware encrypts backup file | Store backups offline/offsite |
| Spoofing | Attacker provides malicious restore path | tarfile extraction uses relative paths |

## Install & Run on Kali
```bash
cd 01-beginner/35-encrypted-backup
pip install -e .
enc-backup create ~/documents backup.encbak
enc-backup restore backup.encbak ./restored
enc-backup verify backup.encbak
```

## Privileges
No root required. Backup file created with mode 0600.

## Example Output
```
$ enc-backup create ~/docs backup.encbak
Backup password:
Confirm password:
Backup created successfully.
Source      : /home/user/docs
Created     : 2024-01-15T10:30:00+00:00
Files       : 42
Original    : 1,234,567 bytes
Compressed  : 456,789 bytes
Ratio       : 63.0% compression
SHA-256     : a1b2c3...
```

## Testing
```bash
pip install -r requirements.txt
pytest --cov=project_35 --cov-report=term-missing
```

## What You'll Learn
- Combining gzip compression with AES-256-GCM in a single pipeline
- Why backup integrity verification (SHA-256 manifest) matters
- The MAGIC header pattern for self-describing binary file formats
- Ransomware recovery: 3-2-1 backup rule and encryption

## References
- [MITRE ATT&CK T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [NIST AES-GCM (SP 800-38D)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [tarfile Python docs](https://docs.python.org/3/library/tarfile.html)
