# Project 76 — Mini SIEM Platform

> A lightweight Security Information and Event Management engine that ingests logs, normalizes events, applies regex detection rules, and emits structured alerts.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Brute Force | T1110 / T1110.001 | Detects SSH password spray / brute-force patterns |
| Valid Accounts | T1078 / T1078.003 | Alerts on direct root logins and privilege escalation |
| Create Account | T1136.001 | Detects new local account creation |
| Scheduled Task/Job | T1053.003 | Flags cron job modifications |
| Server Software Component | T1505.003 | Detects webshell execution indicators |
| Data Destruction | T1485 | Alerts on mass file deletion commands |

## Features

- Multi-source log ingestion: syslog, Apache/Nginx, generic text
- 8 built-in detection rules with MITRE ATT&CK mapping
- Real-time tail mode for live log monitoring
- JSONL alert output for downstream processing
- Alert severity filtering (LOW / MEDIUM / HIGH / CRITICAL)
- Extensible rule engine — add regex rules via code

## Tech Stack

- Python 3.11+, click, stdlib (re, threading, hashlib, json)

## Architecture

```
Log File ──► Parser ──► LogEvent ──► SIEMEngine ──► DetectionRules
                                                          │
                                                    Alert Store ──► JSONL File
                                                          │
                                                    CLI Output
```

## Threat Model (STRIDE)

| STRIDE | Risk | Mitigation |
|---|---|---|
| Spoofing | Forged log entries | Event ID hashing; log source authentication |
| Tampering | Log file modification | Append-only output; FIM integration |
| Repudiation | Alert deletion | Immutable JSONL append |
| Info Disclosure | Alert data exposure | File permission controls |
| DoS | Huge log files | Streaming line-by-line ingestion |
| Elevation | Privilege via SIEM | Non-root operation supported |

## Install & Run on Kali

```bash
cd 03-advanced/76-mini-siem
pip install -e .
mini-siem rules
mini-siem ingest /var/log/auth.log --parser syslog -o alerts.jsonl
mini-siem tail /var/log/syslog --parser syslog
mini-siem summary alerts.jsonl
```

## Privileges

No root required. Read access to log files may need `adm` group membership.

## Example Output

```
[HIGH]    SSH_BRUTE_FORCE    — SSH brute-force attempt detected (T1110.001)
[MEDIUM]  SUDO_PRIVILEGE_ESCALATION — Sudo command execution logged (T1078)
Processed 1024 lines → 3 alert(s) fired.
```

## Testing

```bash
pytest tests/ -v --cov=project_76
```

## What You'll Learn

- Log normalization and event correlation
- Regex-based intrusion detection rules
- Thread-safe alert storage patterns
- JSONL structured logging for SIEM pipelines

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Syslog RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424)
