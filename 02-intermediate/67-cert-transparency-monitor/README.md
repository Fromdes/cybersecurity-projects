# Project 67 — Certificate Transparency Monitor

> Query public CT logs (crt.sh) to detect unauthorized certificates issued for your domains.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Phishing | T1566 | Detect look-alike certs issued for typosquatted domains |
| Adversary-in-the-Middle | T1557 | Spot unauthorized CA issuances enabling MITM |
| Establish Accounts | T1585 | Identify infrastructure set up by adversaries via cert issuance |

## Features

- crt.sh JSON API query (no API key needed)
- Deduplication and datetime parsing for all crt.sh date formats
- Wildcard cert detection
- Expiry tracking per certificate
- Anomaly detection: unexpected issuers, issuance spikes, deep subdomains
- Entry filtering by date, domain glob, or expiry status

## Install & Run

```bash
cd 02-intermediate/67-cert-transparency-monitor
pip install -e .
ct-monitor watch example.com --issuers "Let's Encrypt" --issuers DigiCert
ct-monitor watch example.com --json
```

## Testing

```bash
pytest tests/ -v --cov=project_67
```

## What You'll Learn

- Certificate Transparency log structure
- crt.sh API integration
- Automated cert monitoring for blue teams
