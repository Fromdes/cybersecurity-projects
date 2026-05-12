# Project 57 — STIX/TAXII Feed Parser

> Parse STIX 2.x bundles and query TAXII 2.1 threat-intelligence servers to extract actionable IOCs.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| C2 Communication | T1071 | Ingest STIX Indicators and block known C2 IPs/domains |
| Phishing | T1566 | Consume threat-actor and campaign intel for email defense |
| Lateral Movement | T1021 | Map kill-chain phases to detection coverage gaps |

## Features

- STIX 2.1 bundle parser (Indicator, Malware, Threat-Actor, Attack-Pattern, …)
- `STIXIndicator.extract_ioc_value()` — pulls IOC from STIX pattern syntax
- `STIXBundle.summary()` — object-type counts
- Lightweight TAXII 2.1 client (discovery, collections, objects fetch)
- No heavy stix2/taxii2-client dependency — stdlib + optional requests

## Install & Run

```bash
cd 02-intermediate/57-stix-taxii-parser
pip install -e .
stix-taxii-parser parse examples/bundle.json --indicators-only
stix-taxii-parser discover https://cti-taxii.mitre.org
```

## Testing

```bash
pytest tests/ -v --cov=project_57
```

## What You'll Learn

- STIX 2.1 data model (SDOs, SCOs, SROs)
- TAXII 2.1 API endpoints
- Pattern language for indicators
- Kill-chain phase mapping
