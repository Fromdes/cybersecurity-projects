# Threat Model — Project 34: Encrypted Notes CLI

## Assets
- Sensitive note contents (passwords, keys, PII)
- Master password knowledge

## Threat Actors
- Attacker with local filesystem access (malware, stolen laptop, physical access)
- Nosy co-worker on a shared workstation

## STRIDE Analysis
| Threat | Example | Mitigation |
|---|---|---|
| Spoofing | Attacker replaces encrypted store with known-plaintext to get decryption oracle | GCM auth tag; wrong password raises InvalidTag immediately |
| Tampering | Bit-flip on ciphertext to alter decrypted content | 128-bit GCM authentication tag detects any modification |
| Repudiation | User claims notes were altered | HMAC-equivalent GCM tag ties ciphertext to key |
| Info Disclosure | Attacker reads ~/.local/share/enc-notes/notes.enc | AES-256 ciphertext; 0600 permissions prevent other users |
| Elevation of Privilege | Malware runs as same user to read plaintext via /proc | Plaintext only in memory during session; minimise session time |

## Data at Rest
```
notes.enc layout:
  [0:16]   salt       (16 random bytes, new each store creation)
  [16:28]  nonce      (12 random bytes, new each save)
  [28:]    AES-GCM ciphertext + 16-byte auth tag
```

## Key Derivation
- Algorithm: Argon2id (time=3, memory=65536 KiB, threads=1)
- Output: 32 bytes → AES-256 key
- Prevents GPU brute-force attacks on master password
