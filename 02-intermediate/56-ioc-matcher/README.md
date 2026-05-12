# Project 56 — IOC Matcher

> Load threat-intel feeds (CSV/JSON) and match Indicators of Compromise against log files in real time.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| C2 Communication | T1071 | Match known C2 IP/domain IOCs in network logs |
| Malicious File | T1204 | Hash-based matching detects known malware artifacts |
| Phishing | T1566 | Email and URL IOC detection |

## Features

- IOC types: IPv4, domain, URL, MD5, SHA1, SHA256, email, CVE
- Regex-based extractor from arbitrary text
- `IOCStore` backed by CSV or JSON threat-intel feeds
- `IOCMatcher` scans log files line-by-line with context capture
- Case-insensitive lookups; SHA-256 not mis-classified as MD5

## Install & Run

```bash
cd 02-intermediate/56-ioc-matcher
pip install -e .
ioc-matcher match access.log --ioc-json examples/iocs.json
ioc-matcher extract suspicious.txt
```

## Testing

```bash
pytest tests/ -v --cov=project_56
```

## What You'll Learn

- IOC taxonomy and normalization
- Regex-based threat indicator extraction
- Threat-intel feed ingestion patterns
