# Architecture — Project 08: AES-256-GCM File Encryptor

## Encryption Flow

```
password + random_salt
        │
        ▼  Scrypt(N=2^17, r=8, p=1)
     32-byte AES key
        │
        ▼  AESGCM.encrypt(nonce, plaintext)
  ciphertext || 16-byte GCM tag
        │
        ▼  write to file
  MAGIC | SALT | NONCE | ciphertext+tag
```

## Decryption Flow

```
read file → validate MAGIC → extract SALT, NONCE, ciphertext+tag
        │
        ▼  Scrypt(password, SALT)  →  32-byte AES key
        │
        ▼  AESGCM.decrypt(NONCE, ciphertext+tag)
      plaintext  (or raises InvalidTag if tampered/wrong password)
```

## Security Properties

- **Confidentiality**: AES-256 is unbroken; even quantum computers only halve
  the effective key length to 128 bits (still infeasible to brute-force)
- **Integrity**: GCM authentication tag detects any bit-flip in the ciphertext
- **Key derivation**: Scrypt with N=2^17 requires ~128 MB RAM per attempt,
  making GPU-based password cracking ≈1000× slower than PBKDF2-SHA256
- **Random nonce**: Each encryption uses `os.urandom(12)` — nonce reuse (which
  catastrophically breaks GCM) is statistically impossible
