# Architecture — Project 36: Personal Password Vault

## Vault File Format (binary)
```
[0:16]   salt  (16 random bytes — fixed for vault lifetime)
[16:28]  nonce (12 random bytes — fresh on every save)
[28:]    AES-256-GCM ciphertext + 16-byte auth tag
```

## Plaintext JSON Schema
```json
{
  "entries": [
    {
      "id": "<uuid4>",
      "site": "github.com",
      "username": "alice@example.com",
      "password": "X#m9Kj...",
      "notes": "work account",
      "created_at": "2024-01-15T10:30:00+00:00",
      "modified_at": "2024-01-15T10:30:00+00:00"
    }
  ]
}
```

## Component Interaction
```
CLI args ──► Vault(path, master_password)
               │
               ├─ Argon2id(master_password, salt) → 32-byte key
               │
               ├─ AESGCM.decrypt(nonce, ciphertext) → JSON → [VaultEntry]
               │         [InvalidTag if wrong pw or tampered]
               │
               ├─ CRUD operations on [VaultEntry] list
               │
               └─ AESGCM.encrypt(new_nonce, JSON) → write file(0600)
```

## Password Generation
```python
secrets.choice(charset)  # CSPRNG — never use random.choice for security-critical data
charset = uppercase + lowercase + digits + special_chars
```
`secrets` module uses OS entropy (getrandom syscall on Linux) — not predictable.
