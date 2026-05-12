# Project 100 - GDPR/KVKK Compliance Auditor

> Audit data asset inventories against GDPR and Turkish KVKK regulation requirements, producing actionable compliance findings.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Attack Vector | MITRE ID | Description |
|---|---|---|
| Data exfiltration via misconfigured storage | T1530 | Unencrypted cross-border transfers enable data theft |
| Credential access via plaintext PII | T1552 | Unencrypted sensitive data at rest |
| Collection of sensitive personal data | T1213 | Processing without legal basis |

## Features

- **8 compliance checks**: GDPR Articles 5, 6, 9, 32, 37-39 + KVKK Articles 5-9, 12
- **Special category detection**: health, biometric, genetic, racial, religious, and more
- **Cross-border transfer analysis**: adequacy country list (EU/EEA, Japan, UK, etc.)
- **Severity grading**: CRITICAL / HIGH / MEDIUM / LOW per finding
- **Regulation filter**: show only GDPR or only KVKK findings
- **JSON report export** for CI/CD pipeline integration
- **Exit code support** for automated compliance gates

## Tech Stack

- Python 3.11+
- Click (CLI)
- Standard library only (no external data dependencies)

## Architecture

```
inventory.json ──► audit_inventory_file()
                        │
                        ▼
                  _parse_asset() ──► DataAsset
                        │
                        ▼
                  audit_asset() ──► [check_fn(asset) for check_fn in checks]
                        │
                        ▼
                  ComplianceReport ──► JSON / CLI output
```

## Threat Model (STRIDE)

| Threat | Component | Mitigation |
|---|---|---|
| Spoofing | Inventory data | Validate required fields; reject malformed assets |
| Tampering | JSON inventory | File integrity via hash before audit |
| Repudiation | Audit results | Timestamped JSON reports |
| Information Disclosure | Audit report | Reports contain no raw PII |
| Denial of Service | Large inventories | Streaming per-asset processing |
| Elevation of Privilege | DPO bypass | GDPR-007 check flags missing DPO involvement |

## Install & Run on Kali

```bash
cd 03-advanced/100-gdpr-kvkk-auditor
pip install -e . --break-system-packages

# Audit a data inventory
gdpr-kvkk-auditor audit examples/sample-inventory.json

# Show only CRITICAL findings
gdpr-kvkk-auditor audit examples/sample-inventory.json --min-severity CRITICAL

# Export JSON report and fail CI on violations
gdpr-kvkk-auditor audit examples/sample-inventory.json -o report.json --exit-code
```

## Privileges

No elevated privileges required.

## Example Output

```
GDPR/KVKK Compliance Audit — sample-inventory.json
Assets audited : 3
Total findings : 7
Displayed      : 7 (min-severity=INFO)
Overall status : NON-COMPLIANT

Findings:
  [CRITICAL] GDPR-001 — Missing or invalid legal basis for processing
    Asset: health_records | Article 6 GDPR
    Define a valid legal basis: consent, contract, legal_obligation, ...

  [CRITICAL] GDPR-004 — Cross-border transfer to non-adequate country
    Asset: analytics_db | Chapter V GDPR / KVKK Article 9
    Use SCCs, BCRs, or obtain explicit consent; or restrict transfer ...
```

## Testing

```bash
pytest tests/ -v --cov=project_100 --cov-report=term-missing
```

## What You'll Learn

- GDPR data protection principles (Articles 5-9, 32, 37-39)
- Turkish KVKK law and its relationship to GDPR
- Data asset inventory design (controller, processor, legal basis)
- Special category personal data and heightened protections
- Adequacy decisions and cross-border transfer rules
- Compliance automation for CI/CD pipelines

## References

- [GDPR Full Text](https://gdpr-info.eu/)
- [KVKK (Turkish DPA)](https://www.kvkk.gov.tr/)
- [GDPR Adequacy Decisions](https://ec.europa.eu/info/law/law-topic/data-protection/international-dimension-data-protection/adequacy-decisions_en)
- [Article 29 Working Party Guidelines](https://ec.europa.eu/newsroom/article29/items/613051)
