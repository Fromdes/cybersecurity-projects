# Threat Model — Terraform Security Scanner

## STRIDE Analysis

| Threat | Component | Mitigation |
|---|---|---|
| Tampering | .tf files | Scan in CI before apply; pin module versions |
| Information Disclosure | Hardcoded secrets | TF-SEC-001 detects plaintext credentials |
| Elevation of Privilege | Overpermissive IAM | TF-IAM-001 detects wildcard policies |
| Denial of Service | Open SGs | TF-SG-001/002 detect unrestricted access |

## Infrastructure Attack Scenarios Detected

1. **Data exfiltration via public S3**: Attackers can read any object from publicly accessible buckets
2. **SSH brute-force**: Port 22 open to 0.0.0.0/0 exposes instances to internet-scale attacks
3. **Privilege escalation via IAM**: Wildcard policies allow full AWS account takeover
4. **SSRF via IMDSv1**: Without IMDSv2, SSRF vulnerabilities can access instance metadata credentials
5. **RDS data breach**: Publicly accessible database instances expose data to internet
