# Project 61 — auditd Log Parser

> Parse Linux auditd records, correlate multi-record events by serial number, and detect privilege escalation indicators.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Privilege Escalation | T1548 | Detect setuid, sudo, and chroot syscalls |
| Defense Evasion | T1562 | Monitor auditd rule gaps via correlated events |
| Execution from Temp | T1059 | Flag execve from /tmp or /dev/shm |

## Features

- Regex-based auditd record parser (type, timestamp, serial, KV fields)
- Multi-record event correlation by serial number
- Syscall name mapping (execve=59, setuid=105, chroot=161, …)
- Anomaly detection: privilege commands, setuid calls, /tmp execution
- CLI: `parse`, `detect`

## Install & Run

```bash
cd 02-intermediate/61-auditd-parser
pip install -e .
auditd-parser parse /var/log/audit/audit.log --syscall execve
auditd-parser detect /var/log/audit/audit.log
```

## Testing

```bash
pytest tests/ -v --cov=project_61
```

## What You'll Learn

- auditd log format and record correlation
- Linux syscall numbers and privilege indicators
- Serial-number based event correlation
