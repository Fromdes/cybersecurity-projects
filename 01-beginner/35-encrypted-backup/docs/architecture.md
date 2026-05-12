# Architecture — Project 35: Encrypted Backup Tool

## Create Flow
```
source (dir/file)
    │
    └─ tarfile.open(mode="w:gz") → compressed tar in memory (BytesIO)
    │
    ├─ content_hash = SHA-256(compressed_tar)
    │
    ├─ Argon2id(password, random_salt) → 32-byte key
    │
    ├─ AESGCM(key).encrypt(random_nonce, compressed_tar) → ciphertext
    │
    └─ write: MAGIC || salt || nonce || ciphertext → output.encbak (0600)
    └─ write: manifest JSON → output.manifest.json
```

## Restore Flow
```
output.encbak
    │
    ├─ check MAGIC bytes
    ├─ extract salt, nonce, ciphertext
    ├─ Argon2id(password, salt) → key
    ├─ AESGCM.decrypt(nonce, ciphertext) → compressed_tar
    │       └─ InvalidTag if wrong password OR file tampered
    └─ tarfile.extractall(output_dir)
```

## Verify Flow
```
output.encbak
    │
    ├─ decrypt (same as restore)
    ├─ SHA-256(compressed_tar) → current_hash
    ├─ load manifest.content_hash
    └─ current_hash == manifest.content_hash → True/False
```

## Security Properties
- Confidentiality: AES-256-GCM (IND-CCA2 secure)
- Integrity: GCM auth tag + SHA-256 manifest
- Passphrase hardening: Argon2id (memory=64 MiB, time=3 iterations)
- File permissions: 0600 prevents other OS users from reading backup
