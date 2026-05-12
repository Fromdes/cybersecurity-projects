# Project 50 — Audit Log System

> Append-only, hash-chained audit log with structured events, query filtering, and tamper detection.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Indicator Removal on Host | T1070 | Hash chain detects log tampering |
| Account Manipulation | T1098 | All privilege changes recorded with actor/outcome |
| Defense Evasion | T1562 | Append-only design prevents retroactive deletion |

## Features

- Immutable `AuditEvent` dataclass with actor, action, resource, outcome, severity
- JSONL append-only file storage
- SHA-256 hash chaining for tamper evidence
- Query by actor, action, outcome, severity, time range
- Chain integrity verifier
- CLI: `log`, `query`, `verify`

## Install & Run

```bash
cd 02-intermediate/50-audit-logger
pip install -e .
audit-logger log --actor alice --action LOGIN --resource /auth --outcome success
audit-logger query --actor alice
audit-logger verify
```

## Testing

```bash
pytest tests/ -v --cov=project_50
```

## What You'll Learn

- Hash-chained log design for forensic integrity
- Append-only storage patterns
- JSONL structured logging
- Log query and filtering patterns
