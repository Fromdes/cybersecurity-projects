# Project 51 — Centralized Structured Logger

> Drop-in JSON log formatter with automatic PII/secret redaction and sampling filter.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Credentials in Files | T1552.001 | Sensitive keys redacted before writing to disk |
| Log Scraping | T1005 | PII (emails, card numbers) scrubbed from log output |
| Defense Evasion via Log Gaps | T1562 | Structured format enables reliable SIEM ingestion |

## Features

- `StructuredFormatter` — single-line JSON output compatible with Elasticsearch/Splunk
- Automatic redaction of sensitive keys (password, token, secret, …)
- Regex-based PII scrubbing (email addresses, credit card numbers)
- Exception traceback included in JSON payload
- `get_structured_logger()` factory for zero-config usage
- `SamplingFilter` for high-volume log rate control

## Install & Run

```bash
cd 02-intermediate/51-structured-logger
pip install -e .
structured-logger demo
structured-logger emit --level WARNING "Suspicious login attempt"
structured-logger redact '{"user":"alice","password":"s3cr3t"}'
```

## Testing

```bash
pytest tests/ -v --cov=project_51
```

## What You'll Learn

- Python `logging.Formatter` extension
- Structured JSON logging for SIEM ingestion
- PII and credential redaction patterns
- Log sampling for performance
