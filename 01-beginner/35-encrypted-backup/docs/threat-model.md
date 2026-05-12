# Threat Model — Project 35: Encrypted Backup Tool

## Assets
- Source files being backed up (documents, keys, configs)
- Backup archive (.encbak) stored on disk or external media
- Encryption passphrase

## Threat Actors
- Ransomware encrypting local storage (T1486)
- Attacker with physical access to laptop / external drive
- Insider copying backup files for exfiltration

## STRIDE Analysis
| Threat | Example | Mitigation |
|---|---|---|
| Spoofing | Attacker crafts fake .encbak to get oracle access | Magic header + GCM auth rejects non-backup inputs |
| Tampering | Flip a bit in ciphertext to alter decrypted file | 128-bit GCM tag detects any modification immediately |
| Info Disclosure | Backup stolen from cloud storage | AES-256 ciphertext; Argon2id makes brute-force infeasible |
| Repudiation | Dispute over what was backed up | SHA-256 content hash in manifest provides verifiable record |
| Denial of Service | Backup deleted by ransomware before use | Maintain offsite / air-gapped copies |

## Backup File Format
```
.encbak binary layout:
  [0:8]    MAGIC "ENCBAK01"
  [8:24]   salt  (16 random bytes)
  [24:36]  nonce (12 random bytes)
  [36:]    AES-256-GCM(gzip(tar)) + 16-byte auth tag

.manifest.json alongside:
  source_path, created_at, file_count, sizes, SHA-256(compressed tar)
```
