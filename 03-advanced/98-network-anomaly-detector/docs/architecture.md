# Architecture — Network ML Anomaly Detector

## Components

```
cli.py         → Click interface (analyze command)
core.py        → Flow model + parsers + detectors + report
  NetworkFlow            → Immutable flow record + derived metrics
  parse_csv()            → str → list[NetworkFlow]
  parse_jsonl()          → str → list[NetworkFlow]
  detect_volume_anomalies()    → z-score on bytes_total
  detect_packet_rate_anomalies() → z-score on pps
  detect_port_scan()     → count unique dst_ports per src
  detect_ddos()          → count unique src_ips per dst
  detect_beaconing()     → interval coefficient of variation
  analyze_flows()        → all detectors → AnomalyReport
```

## Statistical Methods

- **Z-score**: `|x - μ| / σ` — flags values >3σ from mean
- **IQR**: Tukey's fence at Q1 - 1.5×IQR / Q3 + 1.5×IQR (available in FlowStats)
- **CV (beaconing)**: `σ / μ` of inter-flow intervals — low CV = regular/automated behavior
