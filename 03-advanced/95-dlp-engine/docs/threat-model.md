# Threat Model — DLP Engine

## STRIDE Analysis

| Threat | Component | Mitigation |
|---|---|---|
| Information Disclosure | PII in files | DLP-001–004 detects SSN, CC, email, phone |
| Credential Theft | Hardcoded secrets | DLP-006–010, DLP-014 detects keys/tokens/passwords |
| Tampering | Redacted output | Redact command replaces matches in-place |
| Repudiation | Scan results | JSON report with file paths and line numbers |

## Data Loss Scenarios Detected

1. **PII in log files**: Email addresses, SSNs logged by accident in application logs
2. **Hardcoded credentials**: AWS keys / GitHub tokens committed to source control
3. **Database dump exposure**: Connection strings with passwords in backup files
4. **PCI scope creep**: Credit card numbers in support tickets or CSV exports
5. **Private key leakage**: TLS/SSH private keys accidentally included in packages
