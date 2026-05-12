# Threat Model — Mini SIEM Platform

## Assets

- Log files (integrity critical)
- Alert store (confidentiality/integrity)
- Detection rules (availability)

## STRIDE Analysis

| Threat | Description | Mitigation |
|---|---|---|
| Spoofing | Attacker injects crafted log lines | Hash-based event IDs; monitor log file owner |
| Tampering | Log rotation truncates evidence | Use append-only storage; integrate with Project 78 FIM |
| Repudiation | Deny malicious action occurred | Immutable JSONL alert log |
| Info Disclosure | Sensitive data in log alerts | Redact PII before alerting |
| DoS | Flood log file to exhaust disk | Log rotation limits; streaming reader |
| Elevation | Exploit SIEM process | Run as non-root; drop capabilities |

## MITRE Coverage

T1110, T1110.001, T1078, T1078.003, T1136.001, T1053.003, T1505.003, T1485
