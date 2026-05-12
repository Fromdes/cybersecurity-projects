# Project 71 — Rogue DHCP Detector

> Identify unauthorised DHCP servers in PCAP captures by checking DHCPOFFER/DHCPACK sources against an authorised list.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Adversary-in-the-Middle: DHCP Spoofing | T1557.003 | Detect rogue DHCP server handing out attacker-controlled gateways |
| Network Configuration Discovery | T1016 | Spot unauthorised DNS/gateway changes via DHCP |

## Features

- Pure stdlib Ethernet/IP/UDP/DHCP parser (no scapy)
- PCAP reader (Ethernet link type)
- DHCP options parser (message type, server ID, router, DNS, subnet)
- Authorised server allowlist comparison
- Severity: critical (OFFER), high (ACK)

## Install & Run

```bash
cd 02-intermediate/71-rogue-dhcp-detector
pip install -e .
rogue-dhcp-detector analyse capture.pcap --authorised 192.168.1.1
```

## Testing

```bash
pytest tests/ -v --cov=project_71
```

## What You'll Learn

- DHCP packet format and option encoding
- BOOTP/DHCP header structure
- Rogue server detection strategy
