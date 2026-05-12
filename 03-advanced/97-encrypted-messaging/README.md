# Project 97 — Encrypted Messaging Library (Double Ratchet)

> Implements the Double Ratchet Algorithm providing end-to-end encryption with perfect forward secrecy and break-in recovery.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Network Sniffing | T1040 | All messages encrypted with ephemeral AES-256-GCM keys |
| Adversary-in-the-Middle | T1557 | DH ratchet prevents key compromise from decrypting past/future messages |
| Credential Replay | T1550 | Message keys are one-time-use; replay attacks rejected by AEAD tag |

## Features

- **Double Ratchet Algorithm** (as specified by Signal): DH ratchet + symmetric-key ratchet
- **X25519** Diffie-Hellman for ratchet key exchange
- **HKDF-SHA256** for root key and chain key derivation
- **AES-256-GCM** for authenticated message encryption
- Out-of-order message delivery with skipped key caching
- Associated data (additional authenticated data) support
- Forward secrecy: past messages can't be decrypted after key compromise
- Break-in recovery: future messages become secure after ratchet step

## Install & Run on Kali

```bash
cd 03-advanced/97-encrypted-messaging
pip install -e .
encrypted-messaging demo --messages 5
encrypted-messaging test-ratchet
```

## Testing

```bash
pytest tests/ -v --cov=project_97
```
