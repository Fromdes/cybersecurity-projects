# Project 75 — Login Anomaly Detector

> Build baseline user login profiles and flag deviations: new countries, impossible travel, brute force, and credential stuffing.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Brute Force | T1110 | Detect consecutive login failures per account |
| Credential Stuffing | T1110.004 | Single IP targeting many accounts |
| Valid Accounts | T1078 | Detect logins from unexpected countries or IPs |
| Impossible Travel | T1078 | Flag geographically impossible login sequences |

## Features

- Login event parser (structured log format)
- Per-user baseline profile (IPs, countries, typical hours)
- Anomaly detection: brute force, new country, new IP, unusual hour, impossible travel, credential stuffing
- Confidence score (0.0–1.0) per anomaly
- Severity: critical / high / medium / low
- Baseline loading from historical log file

## Install & Run

```bash
cd 02-intermediate/75-login-anomaly-detector
pip install -e .
login-anomaly-detector analyse auth.log --baseline history.log
```

## Log Format

```
YYYY-MM-DDTHH:MM:SS username src_ip status [country]
2024-06-15T10:30:00 alice 192.168.1.1 success US
2024-06-15T10:31:00 alice 192.168.1.1 failure
```

## Testing

```bash
pytest tests/ -v --cov=project_75
```

## What You'll Learn

- Behavioural baselining and anomaly detection
- Impossible travel detection logic
- Credential stuffing pattern recognition
