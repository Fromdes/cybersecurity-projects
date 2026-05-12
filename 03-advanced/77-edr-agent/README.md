# Project 77 — Lightweight EDR Agent

> An endpoint detection and response agent that monitors running processes, network connections, and command-line arguments for suspicious activity.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Command and Scripting Interpreter | T1059 | Detects shell, Python, Perl abuse in cmdline |
| Sudo and Sudo Caching | T1548.003 | Alerts on sudo/su/pkexec execution |
| Application Layer Protocol | T1071 | Detects processes with abnormal connection counts |
| System Network Connections | T1049 | Flags listening on suspicious port numbers |
| Process Injection | T1055 | Detects processes with no executable path |

## Features

- One-shot scan or continuous monitoring mode
- Process command-line anomaly detection (netcat, base64 decode, /tmp executions)
- Privileged process execution alerting
- Suspicious network port detection
- Hidden process detection (no exe path)
- JSONL finding output for SIEM integration

## Tech Stack

- Python 3.11+, psutil, click

## Architecture

```
EDRAgent.scan_once()
    │
    ├── snapshot_processes() ──► ProcessSnapshot list
    │       │
    │       ├── detect_suspicious_cmdline()
    │       ├── detect_privileged_execution()
    │       └── detect_suspicious_connections()
    │
    ├── detect_suspicious_listening_ports()
    └── detect_hidden_processes()
         │
         └── Finding ──► AlertStore ──► JSONL
```

## Threat Model (STRIDE)

| STRIDE | Risk | Mitigation |
|---|---|---|
| Spoofing | Process impersonation | PID + exe path cross-check |
| Tampering | EDR process killed by attacker | Watchdog / systemd service |
| Repudiation | Finding log deleted | Append-only JSONL; integrate with FIM |
| Info Disclosure | Sensitive cmdlines logged | Cmdline truncated to 200 chars |
| DoS | Thousands of processes slow scan | Streaming psutil iteration |
| Elevation | EDR itself exploited | Run as unprivileged user where possible |

## Install & Run on Kali

```bash
cd 03-advanced/77-edr-agent
pip install -e .
edr-agent scan --min-level MEDIUM
edr-agent monitor --interval 30 -o findings.jsonl
edr-agent report findings.jsonl
```

## Privileges

Some checks (net_connections per-process) require root. The agent degrades gracefully.

## Example Output

```
[HIGH]    suspicious_cmdline — Suspicious command pattern 'nc ' in PID 4321
[MEDIUM]  privilege_execution — Privileged process 'sudo' running (PID 1234)
Scan complete: 2 finding(s) total.
```

## Testing

```bash
pytest tests/ -v --cov=project_77
```

## What You'll Learn

- psutil process and network inspection
- Behavioral anomaly detection without signatures
- MITRE ATT&CK mapping for endpoint telemetry

## References

- [MITRE ATT&CK Endpoint](https://attack.mitre.org/tactics/TA0002/)
- [psutil docs](https://psutil.readthedocs.io/)
