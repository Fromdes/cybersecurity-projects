# Project 68 — Firewall Rule Auditor

> Parse iptables rules and surface misconfigurations: open management ports, overly broad ACCEPTs, and duplicate rules.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Network Service Discovery | T1046 | Detect services inadvertently exposed by permissive rules |
| Exploit Public-Facing Application | T1190 | Flag dangerous ports open to all sources |
| Remote Services | T1021 | Identify management ports (SSH/RDP/VNC) exposed globally |

## Features

- iptables `-L -n -v` output parser
- Default policy extraction (chain-level ACCEPT/DROP)
- Findings: any-source ACCEPT, dangerous ports, management ports, wide port ranges, duplicates
- Severity levels: critical / high / medium / low
- Live audit mode (reads live iptables rules, requires root)
- File audit mode (from saved iptables output)

## Install & Run

```bash
cd 02-intermediate/68-firewall-auditor
pip install -e .
sudo firewall-auditor live
# or from file:
iptables -L -n -v > rules.txt
firewall-auditor file rules.txt
```

## Testing

```bash
pytest tests/ -v --cov=project_68
```

## What You'll Learn

- iptables rule structure and policy logic
- Regex-based log/config parsing
- Severity-based finding classification
