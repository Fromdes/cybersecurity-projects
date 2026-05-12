# Project 74 — Phishing URL ML Detector

> Extract 17 structural features from URLs and classify phishing vs. legitimate using a RandomForest classifier (heuristic fallback without scikit-learn).

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Spearphishing Link | T1566.002 | Detect malicious links in emails and messages |
| Drive-by Compromise | T1189 | Flag typosquatted or homoglyph domains |
| Phishing | T1566 | Classify URLs before users click them |

## Features

- 17 structural URL features (length, entropy, hyphens, subdomains, TLD, IP host, etc.)
- Brand-in-subdomain detection (paypal.attacker.com patterns)
- Heuristic fallback classifier (no ML required)
- RandomForest ML classifier via scikit-learn (optional)
- Shannon entropy of domain string
- URL shortener and suspicious TLD detection

## Install & Run

```bash
cd 02-intermediate/74-phishing-url-ml
pip install -e ".[ml]"
phishing-url-detector check "http://secure-paypal.attacker.tk/login"
phishing-url-detector scan urls.txt
```

## Testing

```bash
pytest tests/ -v --cov=project_74
```

## What You'll Learn

- URL feature engineering for ML
- scikit-learn pipeline (StandardScaler + RandomForest)
- Heuristic scoring systems as ML fallback
