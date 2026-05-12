# Project 83 — Disk Image Hash & Chain-of-Custody

> Computes forensic-grade multi-algorithm hashes (MD5, SHA1, SHA256, SHA512) of disk images in a single streaming pass and maintains a tamper-evident chain-of-custody JSON record.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Indicator Removal | T1070 | Detects evidence tampering via hash mismatch |
| Data Manipulation | T1565 | Verifies disk image integrity at each transfer |
| Forensic Artifact Integrity | — | Maintains legally admissible chain-of-custody |

## Features

- Single-pass computation of MD5, SHA1, SHA256, SHA512
- Streaming 1MB chunk reads for multi-GB images
- Chain-of-custody record: ACQUIRED → TRANSFERRED → ANALYZED
- Auto-captures actor (user@hostname) and timestamp for each event
- Integrity verification before recording custody transfers
- JSON persistence (portable, human-readable)

## Tech Stack

- Python 3.11+, hashlib, click, json, socket, getpass

## Architecture

```
hash_image(path) ──► single streaming pass ──► HashResult(md5, sha1, sha256, sha512)

create_custody_record() ──► CustodyRecord
                                 │
                    ┌────────────┴────────────┐
                    │                         │
               HashResult               CustodyEntry[]
                                         (action, actor,
                                          timestamp, location)

transfer / verify ──► verify_image() ──► hash mismatch? ABORT / add entry
```

## Threat Model (STRIDE)

| STRIDE | Risk | Mitigation |
|---|---|---|
| Tampering | Custody JSON modified | Store on read-only media; add HMAC signing |
| Repudiation | Deny performing action | Auto-captured user@hostname and timestamp |
| Info Disclosure | Image content leaked | File permissions; encrypt custody record |
| Integrity | Image modified in transit | Mandatory re-hash before transfer event |

## Install & Run on Kali

```bash
cd 03-advanced/83-disk-image-custody
pip install -e .
disk-custody hash /mnt/evidence/disk.dd
disk-custody acquire /mnt/evidence/disk.dd -c custody.json -n "Case #2024-001"
disk-custody verify /mnt/evidence/disk.dd <sha256hash>
disk-custody transfer custody.json /mnt/evidence/disk.dd -n "To forensics lab"
disk-custody log custody.json
```

## Privileges

No special privileges; read access to image file required.

## Example Output

```
Acquiring disk.dd …
SHA256: 3a4b5c6d...
Chain-of-custody record saved to custody.json

Chain of Custody (2 event(s)):
1. [2024-05-12T10:00:00+00:00] ACQUIRED
   Actor:    analyst@kali
   Notes:    Case #2024-001
2. [2024-05-12T14:30:00+00:00] TRANSFERRED
   Actor:    analyst@kali
   Notes:    To forensics lab
```

## Testing

```bash
pytest tests/ -v --cov=project_83
```

## What You'll Learn

- Multi-algorithm streaming file hashing
- Forensic chain-of-custody principles
- Tamper detection via hash verification

## References

- [NIST SP 800-86: Guide to Integrating Forensic Techniques](https://csrc.nist.gov/publications/detail/sp/800-86/final)
- [RFC 6962: Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)
