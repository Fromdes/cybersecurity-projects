# Project 91 — Cloud IAM Policy Analyzer

> Detects overpermissive AWS IAM policy documents that enable privilege escalation or data exfiltration.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Overpermissive IAM policies |
| Data from Cloud Storage | T1530 | Broad S3/DynamoDB read access |
| Impair Defenses: Disable Cloud Logs | T1562.008 | Permissions to stop CloudTrail |
| Abuse Elevation Control | T1548 | IAM privilege escalation paths |

## Features

- Parses AWS IAM policy JSON (single or multi-statement)
- 6 detection rules: IAM-001 through IAM-006
- Covers full admin, privilege escalation, data exfil, infrastructure destroy, logging disable
- `--exit-code` flag for CI/CD integration
- JSON report output

## Install & Run on Kali

```bash
cd 03-advanced/91-cloud-iam-analyzer
pip install -e .
cloud-iam-analyzer analyze policy.json
cloud-iam-analyzer analyze policy.json --min-severity HIGH --exit-code -o report.json
```

## Testing

```bash
pytest tests/ -v --cov=project_91
```
