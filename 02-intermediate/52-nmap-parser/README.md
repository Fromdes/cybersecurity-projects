# Project 52 — Nmap Result Parser & Diff

> Parse Nmap XML scan output and diff two scans to detect new hosts, opened/closed ports, and service changes.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Network Service Discovery | T1046 | Detect unexpected services appearing on the network |
| Exploit Public-Facing Application | T1190 | Alert when new ports open on exposed hosts |
| Defense Evasion | T1036 | Track service version changes that may indicate compromise |

## Features

- Pure-stdlib XML parser (no external nmap-python dependency)
- Host, port, service, OS-guess extraction
- Two-scan diff: new hosts, removed hosts, opened/closed ports, service changes
- CLI: `parse`, `diff`

## Install & Run

```bash
cd 02-intermediate/52-nmap-parser
pip install -e .
nmap-parser parse scan.xml --open-only
nmap-parser diff baseline.xml current.xml
```

## Testing

```bash
pytest tests/ -v --cov=project_52
```

## What You'll Learn

- Nmap XML schema structure
- Change detection between scan snapshots
- Baseline-vs-current diff patterns for network monitoring
