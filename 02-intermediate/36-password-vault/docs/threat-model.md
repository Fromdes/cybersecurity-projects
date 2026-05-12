# Threat Model — Project 36: Personal Password Vault

## Assets
- Stored credentials (site, username, password, notes)
- Master password knowledge
- Vault file on disk

## Threat Actors
- Malware with local filesystem access
- Attacker who obtains vault file (theft, cloud sync exfiltration)
- Attacker with temporary local access attempting offline brute-force

## STRIDE Analysis
| Threat | Example | Mitigation |
|---|---|---|
| Spoofing | Crafted vault to decode known plaintext | GCM tag rejects; attacker can't forge valid ciphertext |
| Tampering | Bit-flip ciphertext to alter stored password | 128-bit GCM auth tag detects immediately |
| Repudiation | Dispute that a credential was stored | Entry timestamps provide record |
| Info Disclosure | Vault stolen and brute-forced offline | Argon2id: 64 MiB/3 iterations slows GPU attacks |
| Elevation of Privilege | Vault run as root exposes secrets | Designed for user-space only; file mode 0600 |
| Denial of Service | Vault file deleted | Keep encrypted offsite backup (pair with Project 35) |

## Key Derivation Parameters
```
Algorithm   : Argon2id
time_cost   : 3
memory_cost : 65536 KiB (64 MiB)
parallelism : 1
hash_len    : 32 bytes (AES-256 key)
```
At 64 MiB memory per attempt, GPU-based brute-force is severely limited.
