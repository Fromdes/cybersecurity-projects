# Project 66 — TLS Configuration Auditor

> Connect to any HTTPS endpoint and score its TLS configuration against cipher suites, protocol versions, and certificate health.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Adversary-in-the-Middle | T1557 | Weak ciphers/protocols enable downgrade attacks |
| Exploit Public-Facing Application | T1190 | Expired/self-signed certs indicate neglected security posture |
| Network Sniffing | T1040 | Weak encryption (RC4, DES) allows passive decryption |

## Features

- Pure stdlib TLS connection (`ssl` module — no sslyze required)
- Protocol version check (flags SSLv2/3, TLSv1.0/1.1)
- Cipher suite weakness detection (RC4, DES, NULL, EXPORT, anon)
- Certificate expiry warning with severity levels
- Signature algorithm check (flags SHA-1, MD5)
- SAN validation
- Letter grade (A–F) with numeric score

## Install & Run

```bash
cd 02-intermediate/66-tls-auditor
pip install -e .
tls-auditor audit example.com
tls-auditor audit example.com --json
```

## Testing

```bash
pytest tests/ -v --cov=project_66
```

## What You'll Learn

- Python `ssl` module internals
- TLS cipher suite naming conventions
- Certificate parsing and expiry checking
- Security scoring systems
