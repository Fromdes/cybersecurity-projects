# Architecture — Double Ratchet Encrypted Messaging

## Modules

```
crypto.py      → Low-level primitives (X25519, HKDF, HMAC, AES-GCM)
core.py        → Double Ratchet state machine + Session API
  RatchetState             → Full ratchet state (DH keys, root/chain keys, counters)
  initialize_sender()      → RatchetState (sender perspective)
  initialize_receiver()    → RatchetState (receiver perspective)
  ratchet_encrypt()        → RatchetState + plaintext → Message
  ratchet_decrypt()        → RatchetState + Message → plaintext
  create_session_pair()    → (Session, Session) for testing
```

## Ratchet Steps

```
KDF_RK(rk, DH(DHs, DHr))  → new root key + chain key  (DH ratchet)
KDF_CK(CKs)                → new chain key + message key  (symmetric ratchet)
ENCRYPT(mk, plaintext, AD+header)  → ciphertext  (AES-256-GCM)
```

## Security Properties

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM per-message key |
| Forward secrecy | Message keys deleted after use |
| Break-in recovery | DH ratchet introduces new entropy each round-trip |
| Integrity | GCM authentication tag + associated data |
| Replay prevention | One-time message keys; failed AEAD decryption |
