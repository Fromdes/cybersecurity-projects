# Project 95 — DLP Engine

> Data Loss Prevention engine that scans files and directories for sensitive data (PII, PCI, credentials) and redacts it.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Data from Local System | T1005 | Detects exposed credentials in local files |
| Credentials from Files | T1552.001 | Finds private keys, passwords, API keys |
| Exfiltration of Data | T1048 | Identifies PII/PCI data at risk of exfiltration |
| Collection: Data Staged | T1074 | Detects sensitive data aggregated in files |

## Features

- 15 built-in detection rules across PII, PCI, Credential, and Network categories
- Line/column-level reporting with context excerpt
- Recursive directory scanning
- `--category` filter for focused scanning
- Text redaction command (replaces matches with `[REDACTED]`)
- `--exit-code` flag for CI/CD pipeline integration
- JSON report output

## Detection Rules

| Rule | Category | Severity | Pattern |
|---|---|---|---|
| DLP-001 | PII | CRITICAL | US Social Security Number |
| DLP-002 | PCI | CRITICAL | Credit card numbers (Visa, MC, Amex, Discover) |
| DLP-003 | PII | MEDIUM | Email addresses |
| DLP-004 | PII | LOW | US phone numbers |
| DLP-005 | Network | LOW | IPv4 addresses |
| DLP-006 | Credential | CRITICAL | AWS Access Key ID |
| DLP-007 | Credential | CRITICAL | PEM private key headers |
| DLP-008 | Credential | HIGH | Password assignments in config |
| DLP-009 | Credential | HIGH | Database connection strings with credentials |
| DLP-010 | Credential | CRITICAL | GitHub personal access tokens |
| DLP-011 | PCI | HIGH | IBAN bank account numbers |
| DLP-012 | PII | HIGH | Passport numbers |
| DLP-013 | Credential | MEDIUM | JWT tokens |
| DLP-014 | Credential | HIGH | Generic API key assignments |
| DLP-015 | PII | MEDIUM | Date of birth fields |

## Install & Run on Kali

```bash
cd 03-advanced/95-dlp-engine
pip install -e .
dlp-engine scan ./src --min-severity HIGH --exit-code
dlp-engine scan report.txt --category credential -o findings.json
dlp-engine redact sensitive.txt -o redacted.txt
```

## Testing

```bash
pytest tests/ -v --cov=project_95
```
