# Project 48 — Secure File Upload Service

> Upload validator that enforces MIME-type allowlists, magic-byte verification, size limits, and path-traversal prevention.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Upload Malicious File | T1105 | MIME + magic-byte checks reject disguised executables |
| Path Traversal | T1083 | Filename sanitisation + resolved-path check |
| Ingress Tool Transfer | T1105 | Size limits and type restrictions block binary uploads |

## Features

- MIME-type allowlist (images, PDF, plain text)
- Magic-byte signature verification (PNG, JPEG, GIF, WEBP, PDF)
- Filename sanitisation (no path traversal, no special chars)
- Configurable size limit (default 10 MiB)
- Randomised stored filenames (unpredictable URL)
- chmod 600 on stored files
- SHA-256 digest logged for every upload

## Install & Run

```bash
cd 02-intermediate/48-secure-file-upload
pip install -e .
secure-upload validate /path/to/file.png
secure-upload upload /path/to/file.png --storage-dir /tmp/uploads
```

## Testing

```bash
pytest tests/ -v --cov=project_48
```

## What You'll Learn

- Magic-byte file-type detection vs extension spoofing
- Path traversal mitigations
- Safe storage naming patterns
