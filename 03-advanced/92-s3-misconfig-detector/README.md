# Project 92 — S3 Misconfiguration Detector

> Analyzes AWS S3 bucket policy JSON files to detect public exposure, overpermissive grants, and data exfiltration risks.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Data from Cloud Storage | T1530 | Public S3 buckets expose sensitive data |
| Data Staged: Cloud Storage | T1074.002 | Attackers use public write access to exfiltrate data |
| Account Manipulation | T1098 | Detects ability to change bucket ACLs |

## Features

- Pure static analysis of S3 bucket policy JSON
- 5 detection rules (S3-001 through S3-005)
- Detects: public read, public write, public list, ACL modification, wildcard grants
- Condition-aware: policies with IP/VPC conditions are not flagged
- `--exit-code` for CI/CD gating

## Detection Rules

| Rule | Severity | Description |
|---|---|---|
| S3-001 | CRITICAL | Public read without condition |
| S3-002 | CRITICAL | Public write/delete access |
| S3-003 | HIGH | Public bucket listing |
| S3-004 | CRITICAL | Public ACL modification |
| S3-005 | HIGH | Wildcard s3:* to authenticated principal |

## Install & Run on Kali

```bash
cd 03-advanced/92-s3-misconfig-detector
pip install -e .
s3-misconfig-detector check bucket-policy.json
s3-misconfig-detector check policy.json --bucket-name my-bucket --exit-code -o report.json
```

## Testing

```bash
pytest tests/ -v --cov=project_92
```
