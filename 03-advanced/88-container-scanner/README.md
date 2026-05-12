# Project 88 — Container Image Scanner

> Scans Docker image tarballs (docker save output) for root user configuration, hardcoded secrets in ENV variables, and sensitive files in image layers.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Escape to Host | T1611 | Detects root container configuration |
| Credentials from Files | T1552.001 | Finds private keys / credentials in layers |
| Unsecured Credentials | T1552 | Detects secrets in ENV variables |

## Features

- Parses Docker image tarball structure (manifest.json + config + layers)
- Checks image config: root user, secret ENV vars, shell -c patterns
- Scans all layer tarballs for sensitive files (shadow, .pem, id_rsa, .env, etc.)
- Extracts dpkg installed package list
- JSON report output

## Install & Run on Kali

```bash
docker save myimage:latest -o image.tar.gz
cd 03-advanced/88-container-scanner
pip install -e .
container-scanner scan image.tar.gz -o report.json
```

## Testing

```bash
pytest tests/ -v --cov=project_88
```
