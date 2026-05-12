# Project 59 — DNS DGA Detector

> Detect Domain Generation Algorithm (DGA) domains using entropy, consonant ratio, n-gram analysis, and length heuristics.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Dynamic Resolution | T1568.002 | DGA-based C2 channel detection |
| C2 over DNS | T1071.004 | Identify malware beaconing via random-looking FQDNs |

## Features

- Shannon entropy per domain label
- Consonant-to-vowel ratio scoring
- Digit ratio detection
- English bigram frequency scoring
- Domain keyword whitelist
- Configurable confidence threshold
- Processes single domains or bulk files

## Install & Run

```bash
cd 02-intermediate/59-dns-dga-detector
pip install -e .
dns-dga-detector --domain kzjqxvbwymfplrts.net --domain google.com --show-all
dns-dga-detector dns_queries.txt --threshold 0.5
```

## Testing

```bash
pytest tests/ -v --cov=project_59
```

## What You'll Learn

- Shannon entropy as a randomness measure
- N-gram language modeling for domain classification
- DGA taxonomy (pure random, dictionary-based, hash-based)
