# Project 63 — SSH Honeypot Logger

> Low-interaction SSH honeypot that logs attacker IPs, client banners, and credential attempts without granting any real access.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Brute Force | T1110 | Capture credentials used by attackers |
| Reconnaissance | T1595 | Identify scanner IPs and client software |
| Credential Access | T1078 | Collect attacker username/password combos |

## Features

- Sends realistic OpenSSH banner to trigger attacker automation
- Logs connect, banner, auth attempt, and disconnect events as JSONL
- Thread-safe `HoneypotLogger` with credential summary
- Never performs SSH key exchange — purely passive capture
- CLI: `serve`, `report`

## Install & Run

```bash
cd 02-intermediate/63-ssh-honeypot
pip install -e .
ssh-honeypot serve --port 2222 --log-file /var/log/ssh-honeypot.jsonl
ssh-honeypot report /var/log/ssh-honeypot.jsonl
```

## Testing

```bash
pytest tests/ -v --cov=project_63
```

## What You'll Learn

- Low-interaction honeypot design
- TCP socket server in Python
- Attacker tool fingerprinting via banners
- JSONL structured event logging
