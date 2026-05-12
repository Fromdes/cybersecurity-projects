# Project 94 — Supply Chain Verifier (SLSA/Sigstore)

> Verifies software artifact integrity using cryptographic hashes and SLSA in-toto provenance attestations.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Supply Chain Compromise | T1195 | Detects tampered release artifacts |
| Compromise Software Dependencies | T1195.001 | Verifies upstream package integrity |
| Subvert Trust Controls | T1553 | Validates SLSA provenance builder trust |

## Features

- Multi-algorithm hash verification (SHA-256, SHA-512, SHA-384, SHA-1, MD5)
- `sha256sums`-style checksums file verification
- SLSA in-toto provenance attestation parsing and verification
- SLSA level inference (0-3) from attestation fields
- Trusted builder allowlist
- Artifact-to-provenance subject matching
- `--exit-code` flag for CI/CD pipeline blocking

## Install & Run on Kali

```bash
cd 03-advanced/94-supply-chain-verifier
pip install -e .
# Hash an artifact:
supply-chain-verifier hash myapp.tar.gz
# Verify against expected hash:
supply-chain-verifier verify myapp.tar.gz --expected-hash <sha256>
# Verify with SLSA attestation:
supply-chain-verifier verify myapp.tar.gz --attestation provenance.json --min-slsa-level 2
# Verify all files in a checksums file:
supply-chain-verifier check-sums sha256sums --exit-code
```

## Testing

```bash
pytest tests/ -v --cov=project_94
```
