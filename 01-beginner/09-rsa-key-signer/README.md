# Project 09 — RSA Key Pair Generator & File Signer

> Prove file authenticity and detect tampering using RSA-4096 digital signatures.

## What Attack Does This Defend Against?

| MITRE ATT&CK | Technique |
|---|---|
| T1553 | Subvert Trust Controls |
| T1553.002 | Code Signing |
| T1036 | Masquerading |

An attacker who replaces a binary with malware cannot produce a valid signature
without the private key. Signatures bind identity to content.

## Features

- **RSA-4096** key pair generation (exceeds NIST 2030+ recommendations)
- **PSS-SHA-256** signatures — probabilistic PSS padding is secure; PKCS#1v1.5 is not
- AES-256-encrypted private key storage (PKCS#8 PEM)
- Streaming SHA-256 digest of signed file — handles large files
- `.sig` sidecar file for portable signatures
- Exit code 2 on invalid signature (distinguishes from other errors)

## Tech Stack

- Python 3.11+
- `cryptography>=42`

## Architecture

```
cli.py  ──► core.py
             ├── generate_key_pair()   RSA-4096
             ├── save_private_key()    PKCS#8 + AES-256-CBC PEM
             ├── save_public_key()     SubjectPublicKeyInfo PEM
             ├── sign_file()           PSS-SHA-256 over SHA-256(file)
             └── verify_file()        raises SignatureVerificationError on failure
```

## Install & Run on Kali

```bash
cd 01-beginner/09-rsa-key-signer
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Generate key pair
rsa-sign generate-key --private private.pem --public public.pem

# Sign a file
rsa-sign sign release.tar.gz --key private.pem

# Verify
rsa-sign verify release.tar.gz --key public.pem --signature release.tar.gz.sig
```

## Privileges

None required.

## Example Output

```
$ rsa-sign verify firmware.bin --key public.pem
VALID — signature verified for firmware.bin

$ rsa-sign verify firmware.bin --key public.pem  # after tampering
INVALID — Signature verification failed — file may have been modified.
```

## Testing

Key generation is slow (RSA-4096). Test suite uses `scope="module"` fixture
to generate one key pair per test session.

```bash
pip install -r requirements.txt
pytest --cov=src --cov-report=term-missing
```

## What You'll Learn

- RSA-PSS vs PKCS#1v1.5 padding (PSS is the modern standard)
- PKCS#8 encrypted private key format
- Prehashed signing for large files
- Digital signature as non-repudiation proof

## References

- [NIST FIPS 186-5 — Digital Signature Standard](https://csrc.nist.gov/publications/detail/fips/186/5/final)
- [MITRE T1553](https://attack.mitre.org/techniques/T1553/)
- [cryptography.io RSA signing docs](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)
