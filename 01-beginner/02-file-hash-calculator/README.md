# Project 02 — File Hash Calculator

> Verify file authenticity and detect tampering using cryptographic hash functions.

## What Attack Does This Defend Against?

| MITRE ATT&CK | Technique |
|---|---|
| T1036 | Masquerading (detect fake/altered binaries) |
| T1027 | Obfuscated Files or Information |
| T1565.001 | Stored Data Manipulation |

Hash verification is the first step in any malware analysis or incident response workflow.

## Features

- Hash files and text strings with MD5, SHA-1, SHA-256, SHA-512, SHA-3-256, SHA-3-512, BLAKE2b
- Hash a file against **all algorithms** in one pass (single file read)
- **Constant-time** hash comparison (prevents timing side-channel)
- JSON output for pipeline integration
- Streams large files in 1 MiB chunks — handles multi-GB files

## Tech Stack

- Python 3.11+, stdlib only (`hashlib`, `hmac`, `pathlib`)

## Architecture

```
cli.py ──► core.py
            ├── hash_file()       single algorithm, streaming
            ├── hash_text()       in-memory string
            ├── hash_file_all()   all algorithms, single pass
            └── verify_hash()     constant-time comparison
```

## Threat Model (STRIDE)

| Threat | Notes |
|---|---|
| Tampering | Hash mismatch reveals modified files |
| Information Disclosure | MD5/SHA-1 are legacy — prefer SHA-256+ |
| Repudiation | Hash alone doesn't prove origin; sign with Project 09 |

## Install & Run on Kali

```bash
cd 01-beginner/02-file-hash-calculator
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Hash a file
file-hash hash --file /bin/ls
file-hash hash --file /bin/ls --algorithm sha512

# Hash all algorithms in one pass
file-hash hash --file /bin/ls --all

# Hash text
file-hash hash --text "Hello, World!" --json

# Verify against known digest
file-hash verify /bin/ls <expected-sha256-hex>
```

## Privileges

None required.

## Example Output

```
$ file-hash hash --file /bin/ls --all
blake2b      a1b2c3...
md5          d4e5f6...
sha1         a7b8c9...
sha256       1a2b3c...
sha3_256     4d5e6f...
sha3_512     7g8h9i...
sha512       0j1k2l...
```

## Testing

```bash
pip install -r requirements.txt
pytest --cov=src --cov-report=term-missing
```

## What You'll Learn

- `hashlib` streaming API for large files
- `hmac.compare_digest` for timing-safe comparison
- Why MD5/SHA-1 are deprecated for security (collision attacks)
- BLAKE2b as a modern, fast alternative

## References

- [MITRE T1036](https://attack.mitre.org/techniques/T1036/)
- [NIST Hash Function Policy](https://csrc.nist.gov/projects/hash-functions)
- [Why timing attacks matter](https://codahale.com/a-lesson-in-timing-attacks/)
