# Project 69 — WiFi Deauth Detector

> Detect 802.11 deauthentication flood attacks from PCAP captures without scapy or external dependencies.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Network Denial of Service | T1498 | Deauth floods disconnect clients from access points |
| Wireless Eavesdropping | T1040 | Deauth + reconnect enables PMKID/WPA handshake capture |
| Rogue Access Point | T1557.002 | Deauth forces clients to reconnect to rogue AP |

## Features

- Pure stdlib 802.11 frame parser (no scapy)
- PCAP reader supporting IEEE 802.11 (link type 105) and Radiotap (127)
- Deauth and disassociation frame detection
- Broadcast vs. unicast deauth classification
- Per-source alarm generation with severity (high/medium)
- Reason code extraction

## Install & Run

```bash
cd 02-intermediate/69-wifi-deauth-detector
pip install -e .
wifi-deauth-detector analyse capture.pcap --threshold 5
```

## Testing

```bash
pytest tests/ -v --cov=project_69
```

## What You'll Learn

- IEEE 802.11 frame control field parsing
- PCAP file format (global header + per-packet headers)
- Radiotap header stripping
- Deauthentication attack mechanics
