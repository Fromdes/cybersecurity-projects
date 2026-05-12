# Threat Model — Network ML Anomaly Detector

## STRIDE Analysis

| Threat | Component | Mitigation |
|---|---|---|
| Spoofing | Source IP | Detect external IPs; is_external_src property |
| Tampering | Flow records | Input validation in parsers; skip malformed rows |
| Repudiation | Anomaly decisions | JSON report with flow_index and metric values |
| Information Disclosure | Internal topology | Report limited to anomalous flows |
| DoS | Large flow files | Streaming CSV reader; no full-file buffering |
| Elevation of Privilege | Network access | Port scan detection catches lateral movement recon |

## False Positive Considerations

- High-traffic servers (CDN, NTP) may trigger volume anomalies — tune z_threshold
- Batch backup jobs create legitimate large flows — add allowlists
- Regular health checks may resemble beaconing — adjust CV threshold
