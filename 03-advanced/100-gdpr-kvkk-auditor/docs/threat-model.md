# Threat Model — GDPR/KVKK Compliance Auditor

## Assets

| Asset | Sensitivity | Description |
|---|---|---|
| Data inventory JSON | HIGH | Contains metadata about personal data processing |
| Audit report JSON | MEDIUM | Describes compliance gaps; no raw PII |
| CLI output | LOW | Human-readable summary |

## STRIDE Analysis

| Threat | Description | Impact | Mitigation |
|---|---|---|---|
| **Spoofing** | Attacker submits crafted inventory with false legal basis claims | Medium | Reports are advisory; actual processing systems enforce legal basis |
| **Tampering** | Inventory file modified to suppress findings | High | Hash inventory before auditing in CI/CD; store reports in append-only log |
| **Repudiation** | Organization denies receiving compliance warnings | Medium | JSON reports with timestamps for audit trail |
| **Information Disclosure** | Audit report exposes data categories / processing details | Low | Reports contain no raw PII; only category names and controller names |
| **Denial of Service** | Extremely large inventory file exhausts memory | Low | Streaming per-asset processing; no full DOM load required |
| **Elevation of Privilege** | Attacker uses compliance check bypass to process data without consent | High | GDPR-005 CRITICAL finding; CI gate rejects non-compliant inventories |

## Attack Scenarios

### Scenario 1: Cross-Border Transfer Without Safeguards
- **Threat**: Data transferred to country without adequacy decision
- **MITRE**: T1530 (Data from Cloud Storage Object)
- **Detection**: GDPR-004 CRITICAL finding
- **Mitigation**: Standard Contractual Clauses (SCCs) or Binding Corporate Rules (BCRs)

### Scenario 2: Special Category Data Without Consent
- **Threat**: Health/biometric data processed without explicit consent
- **MITRE**: T1213 (Data from Information Repositories)
- **Detection**: GDPR-005 CRITICAL + GDPR-007 HIGH findings
- **Mitigation**: Explicit consent collection; DPO review; DPIA

### Scenario 3: Unencrypted Sensitive Data at Rest
- **Threat**: Database breach exposes plaintext health records
- **MITRE**: T1552 (Unsecured Credentials / Data)
- **Detection**: GDPR-006 HIGH finding
- **Mitigation**: AES-256 at rest; TLS 1.3 in transit

## KVKK-Specific Risks

Turkish KVKK requires explicit consent for most processing activities. Without a
legal exception (legal obligation, vital interests, or contract), processing is
unlawful regardless of GDPR compliance. KVKK-001 specifically flags this gap.

Cross-border transfers under KVKK require either:
1. Recipient country has adequate protections (KVKK Board determination), OR
2. Explicit written consent from data subject, OR
3. Adequate safeguards with KVKK Board approval
