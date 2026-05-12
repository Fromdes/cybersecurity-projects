# Project 62 — SSH Brute-Force Detection Daemon

> Parse /var/log/auth.log for failed SSH logins and alert when a source IP exceeds the threshold within a sliding window.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Brute Force: Password Spraying | T1110.003 | Multi-username enumeration detection |
| Brute Force: Credential Stuffing | T1110.004 | High-volume single-IP failure alerting |
| Valid Accounts | T1078 | Successful login after failures flagged |

## Features

- Parses `Failed password`, `Invalid user`, `Accepted` syslog lines
- Sliding time-window aggregation per source IP
- Severity: medium (≥ threshold) / high (≥ 3× threshold)
- Multi-username tracking per IP
- CLI: `analyse` (batch) and `tail` (live follow)

## Install & Run

```bash
cd 02-intermediate/62-ssh-brute-force-detector
pip install -e .
ssh-brute-detector analyse /var/log/auth.log --threshold 5 --window 60
sudo ssh-brute-detector tail /var/log/auth.log --interval 10
```

## Testing

```bash
pytest tests/ -v --cov=project_62
```

## What You'll Learn

- Syslog parsing patterns
- Sliding-window thresholding
- Real-time log tail-follow in Python
