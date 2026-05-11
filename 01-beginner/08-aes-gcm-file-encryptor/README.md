# Project 08 — AES-256-GCM File Encryptor

> Protect sensitive files at rest with authenticated encryption and memory-hard key derivation.

## What Attack Does This Defend Against?

| MITRE ATT&CK | Technique |
|---|---|
| T1005 | Data from Local System |
| T1552 | Unsecured Credentials |
| T1565.001 | Stored Data Manipulation |

Attackers who exfiltrate files still need the key. AES-256-GCM provides both
confidentiality and integrity — the decryption will fail if even one byte is tampered.

## Features

- **AES-256-GCM** — authenticated encryption (AEAD); detects any tampering
- **Scrypt KDF** (N=2^17) — memory-hard key derivation resists GPU/ASIC brute force
- Random 32-byte salt + 12-byte nonce per encryption — no ciphertext reuse
- Magic header for format detection
- `getpass` for secure password input (no terminal echo)
- Custom file format: `MAGIC | SALT | NONCE | CIPHERTEXT+TAG`

## Tech Stack

- Python 3.11+
- `cryptography>=42` (AES-GCM, Scrypt)

## File Format

```
Offset  Size  Field
──────  ────  ─────────────────────────
0       4     Magic: b"AES1"
4       32    Scrypt salt (random)
36      12    AES-GCM nonce (random)
48      N+16  Ciphertext + GCM tag
```

## Install & Run on Kali

```bash
cd 01-beginner/08-aes-gcm-file-encryptor
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Encrypt a file
aes-crypt encrypt secrets.txt
# → creates secrets.txt.enc

# Decrypt
aes-crypt decrypt secrets.txt.enc --output secrets.txt
```

## Privileges

None required.

## Example Output

```
$ aes-crypt encrypt secrets.txt
Password: ****
Confirm password: ****
Encrypted: secrets.txt.enc

$ aes-crypt decrypt secrets.txt.enc
Password: ****
Decryption failed: wrong password or file has been tampered with.
```

## Testing

```bash
pip install -r requirements.txt
pytest --cov=src --cov-report=term-missing
```

## What You'll Learn

- AES-GCM AEAD construction (confidentiality + integrity in one primitive)
- Scrypt memory-hard KDF and why it defeats GPU brute force
- Why random nonces are critical (nonce reuse breaks GCM)
- File format design with magic headers

## References

- [NIST SP 800-38D — GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [cryptography.io AESGCM docs](https://cryptography.io/en/latest/hazmat/primitives/aead/)
