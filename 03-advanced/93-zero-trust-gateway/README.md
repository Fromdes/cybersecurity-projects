# Project 93 — Zero Trust Network Gateway

> Policy-based network access control engine implementing Zero Trust principles: never trust, always verify.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Lateral Movement | T1021 | Enforces per-request authentication and authorization |
| Valid Accounts | T1078 | Blocks access even for valid accounts missing MFA |
| Exploit Public-Facing Application | T1190 | Restricts source IPs via CIDR rules |
| Credential Access | T1555 | Requires MFA for sensitive resource access |

## Features

- Policy-as-JSON: ordered rules with principal, CIDR, destination, port, protocol matching
- MFA enforcement per rule
- Risk scoring engine (considers port risk, external IP, MFA status)
- Default-deny posture
- Batch request evaluation from JSONL files
- Append-only JSONL audit log

## Install & Run on Kali

```bash
cd 03-advanced/93-zero-trust-gateway
pip install -e .
# Single request check:
zero-trust-gateway check --policy policy.json --principal alice --source-ip 10.0.0.1 \
  --destination app.internal --port 443 --mfa
# Batch evaluation:
zero-trust-gateway evaluate --policy policy.json --requests requests.jsonl -o audit.jsonl
```

## Testing

```bash
pytest tests/ -v --cov=project_93
```
