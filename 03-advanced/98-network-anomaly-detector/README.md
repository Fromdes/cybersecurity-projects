# Project 98 — Network ML Anomaly Detector

> Statistical anomaly detection on network flow data — identifies port scans, DDoS, data exfiltration, and C2 beaconing.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Network Service Discovery | T1046 | Detects port scanning via unique destination port count |
| Network Denial of Service | T1498 | Detects DDoS via many-sources-to-one-destination pattern |
| Exfiltration Over Alternative Protocol | T1048 | Flags anomalously large flows (z-score) |
| Application Layer Protocol | T1071 | Detects C2 beaconing via regular flow intervals |

## Detection Methods

| Detector | Method | MITRE |
|---|---|---|
| Volume Anomaly | Z-score on bytes_total (threshold: 3σ) | T1048 |
| Packet Rate Anomaly | Z-score on packets/second | T1498 |
| Port Scan | Unique dst_ports per src_ip ≥ threshold | T1046 |
| DDoS | Unique src_ips per (dst_ip, dst_port) ≥ threshold | T1498 |
| Beaconing | Coefficient of variation of inter-flow intervals | T1071 |

## Input Formats

**CSV** (with header):
```
src_ip,dst_ip,src_port,dst_port,protocol,bytes_total,packets,duration_ms,flags,timestamp
```

**JSONL** (one flow per line as JSON object)

## Install & Run on Kali

```bash
cd 03-advanced/98-network-anomaly-detector
pip install -e .
network-anomaly-detector analyze flows.csv --z-threshold 3.0 --exit-code -o report.json
```

## Testing

```bash
pytest tests/ -v --cov=project_98
```
