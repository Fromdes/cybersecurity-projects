# Project 90 — Terraform Security Scanner

> Static analysis tool that detects security misconfigurations in Terraform HCL files.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Detects overly permissive IAM policies |
| Data from Cloud Storage | T1530 | Finds publicly accessible S3 buckets |
| Network Sniffing | T1040 | Detects unrestricted security group ingress rules |
| Credentials in Files | T1552.001 | Finds hardcoded secrets in Terraform configs |

## Features

- Pure regex-based HCL parser (no external Terraform dependency)
- 10 built-in checks across S3, EC2, RDS, IAM, CloudTrail, Security Groups
- Recursive directory scanning
- `--exit-code` for CI/CD pipeline integration
- JSON report output

## Checks

| Check | Severity | Description |
|---|---|---|
| TF-S3-001 | CRITICAL | S3 bucket with public ACL |
| TF-S3-002 | MEDIUM | S3 bucket versioning not enabled |
| TF-SG-001 | HIGH | Security group with 0.0.0.0/0 ingress |
| TF-SG-002 | CRITICAL | SSH open to 0.0.0.0/0 |
| TF-IAM-001 | CRITICAL | IAM policy with wildcard Action+Resource |
| TF-RDS-001 | HIGH | RDS publicly accessible |
| TF-RDS-002 | HIGH | RDS storage not encrypted |
| TF-EC2-001 | MEDIUM | EC2 instance without IMDSv2 |
| TF-CT-001 | HIGH | CloudTrail logging disabled |
| TF-SEC-001 | CRITICAL | Hardcoded secret in config |

## Install & Run on Kali

```bash
cd 03-advanced/90-terraform-scanner
pip install -e .
terraform-scanner scan examples/insecure.tf
terraform-scanner scan ./terraform-dir --min-severity HIGH --exit-code -o report.json
```

## Testing

```bash
pytest tests/ -v --cov=project_90
```
