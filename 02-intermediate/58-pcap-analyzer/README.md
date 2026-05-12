# Project 58 — PCAP Analyzer

> Pure-Python PCAP reader and analyser: flow aggregation, top-talker rankings, port-scan and SYN-flood detection.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Network Service Discovery | T1046 | Detect port-scan patterns in captured traffic |
| Network DoS | T1498 | SYN-flood anomaly detection |
| Exfiltration over C2 | T1041 | Identify large-transfer top-talker IPs |

## Features

- Pure-Python PCAP reader (no Scapy/libpcap required)
- TCP/UDP/ICMP packet parsing from raw Ethernet frames
- 5-tuple flow aggregation with packet/byte counters
- Top-talker ranking by bytes
- Anomaly detection: port scan, SYN flood

## Install & Run

```bash
cd 02-intermediate/58-pcap-analyzer
pip install -e .
pcap-analyzer capture.pcap --flows --top-n 10
pcap-analyzer capture.pcap --anomalies-only
```

## Testing

```bash
pytest tests/ -v --cov=project_58
```

## What You'll Learn

- PCAP file format (global header, packet records)
- Ethernet + IPv4 + TCP/UDP header parsing with `struct`
- Network flow aggregation
- Statistical anomaly detection in packet captures
