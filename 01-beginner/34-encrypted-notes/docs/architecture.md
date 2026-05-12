# Architecture — Project 34: Encrypted Notes CLI

## Storage Format
```
notes.enc (binary):
┌─────────────────────────────────────────────────────┐
│ salt  (16 bytes)   — fixed per store lifetime       │
│ nonce (12 bytes)   — fresh random per save()        │
│ AES-256-GCM ciphertext + auth tag (16 bytes)        │
└─────────────────────────────────────────────────────┘
```

## Encryption Flow
```
password + salt ──Argon2id──► 32-byte key
                                   │
plaintext JSON ──AESGCM.encrypt(nonce)──► ciphertext
                                   │
           write: salt || nonce || ciphertext → notes.enc (mode 0600)
```

## Decryption Flow
```
read notes.enc
  salt   = raw[:16]
  nonce  = raw[16:28]
  cipher = raw[28:]
password + salt ──Argon2id──► 32-byte key
AESGCM.decrypt(nonce, cipher) ──► plaintext JSON ──► [Note, ...]
  └─ InvalidTag raised if password wrong OR file tampered
```

## JSON Schema (plaintext)
```json
{
  "notes": [
    {
      "id": "<uuid4>",
      "title": "...",
      "body": "...",
      "created_at": "<ISO8601>",
      "updated_at": "<ISO8601>"
    }
  ]
}
```
