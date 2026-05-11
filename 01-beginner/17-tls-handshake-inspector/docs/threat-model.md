# Threat Model — Project 17: TLS Handshake Inspector

## Assets
- TLS configuration of production services
- Certificate validity and expiry state

## Threat Actors
- MITM attackers exploiting weak TLS configurations
- Certificate mis-issuance / domain impersonation

## STRIDE Analysis
| Threat | Example | Mitigation |
|---|---|---|
| Spoofing | Rogue cert for a trusted domain | Verify SAN matches expected hostname |
| Tampering | TLS downgrade to SSLv3/TLS 1.0 | Alert if protocol_version is not TLS 1.2/1.3 |
| Info Disclosure | Sensitive data in TLS session (log) | Do not log raw cipher material |
| Denial of Service | Certificate expiry breaks service | Alert when days_until_expiry < 30 |
| Elevation | Weak 512-bit export cipher | Alert if cipher_bits < 128 |

## Integration Recommendation
Run `tls-inspect` in CI/CD or as a cron job for every public-facing endpoint. Alert when:
- `is_expired` is `true`
- `days_until_expiry < 30`
- `protocol_version` is not `TLSv1.3` or `TLSv1.2`
- `cipher_bits < 128`
