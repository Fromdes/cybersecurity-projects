# Architecture — GDPR/KVKK Compliance Auditor

## Overview

The auditor is a pure-Python, stateless compliance engine. It reads a JSON inventory
of data assets, runs each asset through a battery of compliance checks, and produces a
structured report.

## Component Diagram

```
┌─────────────────────────────────────────────────────┐
│                    CLI (cli.py)                      │
│  audit <inventory.json> [--min-severity] [--output]  │
└────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────┐
│             audit_inventory_file()                   │
│  Reads JSON → _parse_asset() → audit_asset()        │
└────────────────────┬────────────────────────────────┘
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
     check_fn1  check_fn2 ... check_fn8
     (GDPR-001) (GDPR-002)    (KVKK-001)
          │          │          │
          └──────────┴──────────┘
                     │
                     ▼
          ┌─────────────────────┐
          │   ComplianceReport   │
          │  findings[]          │
          │  assets_audited      │
          │  compliant (bool)    │
          └─────────────────────┘
```

## Data Flow

1. **Input**: JSON file with `assets` array; each entry maps to `DataAsset`
2. **Parsing**: `_parse_asset()` validates and coerces field types
3. **Checking**: Each `DataAsset` passes through 8 check functions in order
4. **Aggregation**: All findings collected into `ComplianceReport`
5. **Output**: Human-readable table (CLI) or JSON file (`--output`)

## Compliance Check Registry

| Check ID | Function | Regulation | Article |
|---|---|---|---|
| GDPR-001 | `check_legal_basis` | GDPR | Article 6 |
| GDPR-002 | `check_purpose_limitation` | GDPR | Article 5(1)(b) |
| GDPR-003 | `check_retention_period` | GDPR/KVKK | Article 5(1)(e) / Art. 7 |
| GDPR-004 | `check_cross_border_transfer` | GDPR/KVKK | Chapter V / Art. 9 |
| GDPR-005 | `check_sensitive_data_consent` | GDPR/KVKK | Article 9 / Art. 6 |
| GDPR-006 | `check_encryption` | GDPR | Article 32 |
| GDPR-007 | `check_dpo_notification` | GDPR/KVKK | Articles 37-39 / Art. 12 |
| KVKK-001 | `check_kvkk_explicit_consent` | KVKK | Articles 5-6 |

## Key Design Decisions

- **Frozen dataclasses**: `DataAsset` and `ComplianceFinding` are immutable to prevent
  accidental mutation during parallel audits
- **No external dependencies**: The check engine uses only the stdlib; `click` is only
  needed at the CLI boundary
- **Fail-open parsing**: Malformed asset entries are skipped with `continue`; the
  audit does not abort on bad input
- **Condition ANY rule**: Each check function returns at most one `ComplianceFinding`
  per asset per check ID, preventing duplicate findings
