# Project 65 — NetFlow/IPFIX Analyzer

> Parse NetFlow v5 UDP datagrams, aggregate flow statistics, and detect scanning and exfiltration anomalies.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Network Service Discovery | T1046 | Detect IP scanning (one source, many destinations) |
| Exfiltration over C2 | T1041 | Flag large single-flow data transfers |
| Internal Reconnaissance | T1018 | Baseline normal traffic vs. scan bursts |

## Features

- Pure-Python NetFlow v5 binary parser (no nfdump required)
- 5-tuple flow record extraction with TCP flag decoding
- Top-talker / top-destination rankings
- Protocol distribution
- Anomaly detection: scan candidates, large flows
- CSV flow import for offline analysis
- UDP listener for live collection

## Install & Run

```bash
cd 02-intermediate/65-netflow-analyzer
pip install -e .
netflow-analyzer collect --port 2055 --packets 100
netflow-analyzer analyse flows.csv
```

## Testing

```bash
pytest tests/ -v --cov=project_65
```

## What You'll Learn

- NetFlow v5 binary format and struct parsing
- Flow-level traffic aggregation
- Anomaly detection in flow data
- UDP collector pattern
