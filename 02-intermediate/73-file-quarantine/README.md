# Project 73 — File Quarantine Service

> Safely isolate suspicious files with SHA-256 integrity tracking, strict permissions, and a persistent manifest.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Malicious File | T1204.002 | Isolate and track suspected malware files |
| Data Destruction | T1485 | Prevent accidental re-execution of quarantined files |
| Indicator Removal | T1070 | Preserve file evidence with hash chain |

## Features

- Move-to-quarantine with SHA-256 hash recorded
- `chmod 600` on quarantined files, `chmod 700` on directory
- Pre-release hash verification (detects in-quarantine tampering)
- Zero-fill before delete (evidence wipe)
- JSON manifest persisted to disk (survives restarts)
- Integrity check command verifies all stored files

## Install & Run

```bash
cd 02-intermediate/73-file-quarantine
pip install -e .
file-quarantine --store /var/quarantine add /tmp/suspicious.exe --reason malware
file-quarantine --store /var/quarantine list
file-quarantine --store /var/quarantine verify
```

## Testing

```bash
pytest tests/ -v --cov=project_73
```

## What You'll Learn

- Secure file handling and permissions in Python
- Hash-based file integrity verification
- Audit trail design with JSON manifests
