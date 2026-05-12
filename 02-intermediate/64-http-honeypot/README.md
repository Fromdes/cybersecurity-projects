# Project 64 — HTTP Honeypot Logger

> Flask-based HTTP honeypot that captures all requests, detects exploit attempts, and classifies threats with severity ratings.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Detect SQLi, XSS, LFI, Log4Shell probes |
| Web Shell Upload | T1505.003 | Alert on known web-shell path probes |
| Reconnaissance | T1595 | Identify scanner User-Agents and tools |

## Features

- Flask catch-all honeypot (every path logged)
- Pre-defined honeypot paths: `.env`, `wp-admin`, `phpmyadmin`, …
- Attack pattern detection: path traversal, SQLi, XSS, Log4Shell, LFI
- Scanner UA detection (sqlmap, nikto, masscan, …)
- JSONL structured logging
- `/._honeypot/stats` JSON endpoint
- CLI: `serve`, `report`

## Install & Run

```bash
cd 02-intermediate/64-http-honeypot
pip install -e .
http-honeypot serve --port 8080 --log-file /var/log/http-honeypot.jsonl
http-honeypot report /var/log/http-honeypot.jsonl
```

## Testing

```bash
pytest tests/ -v --cov=project_64
```

## What You'll Learn

- HTTP request capture and analysis
- Attack pattern detection with regex
- Flask middleware pattern (`before_request`)
- Honeypot deployment strategy
