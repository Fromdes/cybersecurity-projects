# Project 70 — ARP Spoofing Detector

> Detect ARP cache poisoning by tracking IP-to-MAC binding changes in PCAP captures or `ip neigh` output.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Adversary-in-the-Middle: ARP Cache Poisoning | T1557.002 | Detect conflicting IP-to-MAC mappings |
| Network Sniffing | T1040 | ARP spoofing enables passive credential interception |

## Features

- Pure stdlib Ethernet + ARP frame parser (no scapy)
- PCAP reader (Ethernet link type)
- ARPTable with conflict detection on MAC change
- Gratuitous ARP flood detection
- Severity classification (critical/high/medium)
- `ip neigh` / `arp -n` log file analysis

## Install & Run

```bash
cd 02-intermediate/70-arp-spoofing-detector
pip install -e .
arp-detector pcap capture.pcap
arp-detector neigh arp_table.txt
```

## Testing

```bash
pytest tests/ -v --cov=project_70
```

## What You'll Learn

- ARP protocol format and spoofing mechanics
- Ethernet frame structure
- Gratuitous ARP and its abuse in MITM attacks
