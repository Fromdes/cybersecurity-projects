# Project 87 — Dockerfile Linter & CIS Checker

> Static analysis of Dockerfiles against CIS Docker Benchmark v1.6 security controls — detects root users, untagged images, hardcoded secrets, curl-pipe-sh, and more.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Escape to Host | T1611 | Detects missing non-root USER |
| Supply Chain Compromise | T1195.001 | Flags untagged/mutable base images |
| Unsecured Credentials | T1552 | Detects secrets in ENV/ARG |
| Ingress Tool Transfer | T1105 | Flags curl/wget piped to shell |

## Features

- 9 CIS and security rules
- Severity levels: CRITICAL / ERROR / WARN / INFO
- Line numbers in findings
- CI-friendly `--exit-code` flag
- Batch directory scanning
- JSON report output

## Install & Run on Kali

```bash
cd 03-advanced/87-dockerfile-linter
pip install -e .
dockerfile-linter lint Dockerfile
dockerfile-linter lint Dockerfile --exit-code --min-severity WARN
dockerfile-linter batch ./services/ -o report.json
```

## Testing

```bash
pytest tests/ -v --cov=project_87
```
