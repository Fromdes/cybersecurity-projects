# Project 72 — Email Phishing Detector (NLP)

> Parse raw .eml files and score them for phishing using keyword matching, URL analysis, and header anomaly checks.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Phishing | T1566 | Detect credential-harvesting and social-engineering emails |
| Spearphishing Link | T1566.002 | Flag suspicious URLs, shorteners, and IP-based links |
| Compromise Accounts | T1586 | Detect Reply-To redirect and spoofed sender patterns |

## Features

- Pure stdlib email parser (`email.policy.default`)
- Phishing keyword dictionary (50+ phrases)
- Urgency word detection
- Credential harvesting regex patterns
- URL analysis (shorteners, IP hosts, suspicious TLDs, IDN homoglyphs)
- Sender/Reply-To domain mismatch detection
- Authentication-Results SPF/DKIM/DMARC fail detection
- Scored 0–100 with verdict: clean / suspicious / phishing

## Install & Run

```bash
cd 02-intermediate/72-email-phishing-detector
pip install -e .
email-phishing-detector analyse suspicious.eml
```

## Testing

```bash
pytest tests/ -v --cov=project_72
```

## What You'll Learn

- RFC 2822 email structure and Python email library
- Heuristic scoring systems
- NLP feature extraction without ML dependencies
