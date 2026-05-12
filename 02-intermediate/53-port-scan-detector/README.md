# Project 53 — Port Scan Detection from Logs

> Detects horizontal and vertical port scans by analysing iptables/ufw firewall logs.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Network Service Discovery | T1046 | Detect reconnaissance port sweeps |
| Active Scanning | T1595 | Flag IPs probing many ports in a short window |

## Features

- Parses iptables/ufw log format (`SRC=... DPT=...`)
- Sliding time-window detection engine
- Classifies scan type: horizontal (sequential), vertical, sweep
- Severity rating: low/medium/high
- Multiple source IP tracking
- CLI with configurable threshold and window

## Install & Run

```bash
cd 02-intermediate/53-port-scan-detector
pip install -e .
port-scan-detector /var/log/ufw.log --threshold 15 --window 60 --verbose
```

## Testing

```bash
pytest tests/ -v --cov=project_53
```

## What You'll Learn

- Log-based intrusion detection patterns
- Sliding time-window aggregation
- Port scan taxonomy (SYN, sweep, vertical)
